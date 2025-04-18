#include <string.h>
#include <sys/queue.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "conf.h"
#include "caster.h"
#include "http.h"
#include "jobs.h"
#include "ntripcli.h"
#include "ntrip_common.h"
#include "ntrip_task.h"
#include "packet.h"
#include "rtcm.h"
#include "util.h"

const char *client_ntrip_version = "Ntrip/2.0";
const char *client_user_agent = "NTRIP " CLIENT_VERSION_STRING;

static void display_headers(struct ntrip_state *st, struct evkeyvalq *headers) {
	struct evkeyval *np;
	TAILQ_FOREACH(np, headers, next) {
		if (!strcasecmp(np->key, "authorization"))
			ntrip_log(st, LOG_DEBUG, "Header %s: *****", np->key);
		else
			ntrip_log(st, LOG_DEBUG, "Header %s: %s", np->key, np->value);
	}
}

/*
 * Build a full HTTP request, including headers.
 */
static char *ntripcli_http_request_str(struct ntrip_state *st,
	const char *method, char *host, unsigned short port, char *uri, int version,
	struct evkeyvalq *opt_headers, struct mime_content *m) {

	struct evkeyvalq headers;
	struct evkeyval *np;

	char *host_port = host_port_str(host, port);
	if (host_port == NULL) {
		return NULL;
	}
	unsigned long long content_len = 0;
	char content_len_str[20];
	if (m)
		content_len = m->len;
	snprintf(content_len_str, sizeof content_len_str, "%lld", content_len);

	TAILQ_INIT(&headers);
	if (evhttp_add_header(&headers, "Host", host_port) < 0
	 || evhttp_add_header(&headers, "User-Agent", client_user_agent) < 0
	 || evhttp_add_header(&headers, "Content-Length", content_len_str) < 0
	 || (m && evhttp_add_header(&headers, "Content-Type", m->mime_type) < 0)
	 || evhttp_add_header(&headers, "Connection", st->connection_keepalive?"keep-alive":"close") < 0
	 || (version == 2 && evhttp_add_header(&headers, "Ntrip-Version", client_ntrip_version) < 0)) {
		evhttp_clear_headers(&headers);
		strfree(host_port);
		return NULL;
	}

	P_RWLOCK_RDLOCK(&st->caster->configlock);

	if (st->caster->host_auth) {
		for (struct auth_entry *a = &st->caster->host_auth[0]; a->user != NULL; a++) {
			if (!strcasecmp(a->key, host)) {
				if (http_headers_add_auth(&headers, a->user, a->password) < 0) {
					evhttp_clear_headers(&headers);
					strfree(host_port);
					P_RWLOCK_UNLOCK(&st->caster->configlock);
					return NULL;
				} else
					break;
			}
		}
	}

	P_RWLOCK_UNLOCK(&st->caster->configlock);

	int hlen = 0;
	TAILQ_FOREACH(np, &headers, next) {
		// lengths of key + value + " " + "\r\n"
		hlen += strlen(np->key) + strlen(np->value) + 4;
	}
	if (st->task)
		TAILQ_FOREACH(np, &st->task->headers, next)
			hlen += strlen(np->key) + strlen(np->value) + 4;

	char *format = "%s %s HTTP/1.1";
	size_t s = strlen(format) + strlen(method) + strlen(uri) + hlen + 2;
	char *r = (char *)strmalloc(s);
	if (r == NULL) {
		evhttp_clear_headers(&headers);
		strfree(host_port);
		return NULL;
	}
	sprintf(r, format, method, uri);

	ntrip_log(st, LOG_DEBUG, "Method %s", r);
	display_headers(st, &headers);
	if (st->task)
		display_headers(st, &st->task->headers);

	strcat(r, "\r\n");
	TAILQ_FOREACH(np, &headers, next) {
		strcat(r, np->key);
		strcat(r, ": ");
		strcat(r, np->value);
		strcat(r, "\r\n");
	}
	if (st->task)
		TAILQ_FOREACH(np, &st->task->headers, next) {
			strcat(r, np->key);
			strcat(r, ": ");
			strcat(r, np->value);
			strcat(r, "\r\n");
		}

	strcat(r, "\r\n");
	evhttp_clear_headers(&headers);
	strfree(host_port);
	return r;
}

static void ntripcli_log_close(struct ntrip_state *st) {
	struct timeval t1;

	gettimeofday(&t1, NULL);
	timersub(&t1, &st->start, &t1);
	int bytes_left = evbuffer_get_length(st->input);
	ntrip_log(st, bytes_left ? LOG_NOTICE:LOG_INFO,
		"Connection closed, duration %.3f ms, bytes received %zu sent %zu left %zu.",
		t1.tv_sec*1000 + t1.tv_usec/1000.,
		st->received_bytes, st->sent_bytes, bytes_left);
}

void ntripcli_readcb(struct bufferevent *bev, void *arg) {
	int end = 0;
	struct ntrip_state *st = (struct ntrip_state *)arg;
	char *line;
	size_t len;
	size_t waiting_len;

	ntrip_log(st, LOG_EDEBUG, "ntripcli_readcb state %d len %d", st->state, evbuffer_get_length(st->filter.raw_input));

	if (ntrip_filter_run_input(st) < 0)
		return;

	while (!end && st->state != NTRIP_WAIT_CLOSE && (waiting_len = evbuffer_get_length(st->input)) > 0) {
		if (st->state == NTRIP_WAIT_HTTP_STATUS) {
			char *token, *status, **arg;

			ntrip_clear_request(st);

			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if ((line?len:waiting_len) > st->caster->config->http_header_max_size) {
				end = 1;
				break;
			}
			if (!line)
				break;
			ntrip_log(st, LOG_DEBUG, "Status \"%s\" on %s", line, st->uri);

			char *septmp = line;
			for (arg = &st->http_args[0];
				arg < &st->http_args[SIZE_HTTP_ARGS] && (token = strsep(&septmp, " \t")) != NULL;
				arg++) {
				*arg = mystrdup(token);
				if (*arg == NULL) {
					end = 1;
					break;
				}
			}
			if (end) {
				free(line);
				break;
			}

			if (!strcmp(st->http_args[0], "ERROR")) {
				ntrip_log(st, LOG_NOTICE, "NTRIP1 error reply: %s", line);
				free(line);
				end = 1;
				break;
			}
			free(line);
			unsigned int status_code;
			status = st->http_args[1];
			if (!status || strlen(status) != 3 || sscanf(status, "%3u", &status_code) != 1) {
				end = 1;
				break;
			}
			st->status_code = status_code;

			if (!strcmp(st->http_args[0], "ICY") && !strcmp(st->mountpoint, "") && status_code == 200) {
				// NTRIP1 connection, don't look for headers
				st->state = NTRIP_REGISTER_SOURCE;
				struct timeval read_timeout = { st->caster->config->source_read_timeout, 0 };
				bufferevent_set_timeouts(bev, &read_timeout, NULL);
			}

			if (st->task && st->task->status_cb)
				st->task->status_cb(st->task->status_cb_arg, status_code, st->task->cb_arg2);

			if (st->status_code == 200)
				st->state = NTRIP_WAIT_HTTP_HEADER;
			else {
				ntrip_log(st, LOG_NOTICE, "failed request on %s, status_code %d", st->uri, st->status_code);
				end = 1;
			}

		} else if (st->state == NTRIP_WAIT_HTTP_HEADER) {
			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if ((line?len:waiting_len) > st->caster->config->http_header_max_size) {
				end = 1;
				break;
			}
			if (!line)
				break;
			st->received_bytes += len + 2;
			if (len == 0) {
				ntrip_log(st, LOG_DEBUG, "[End headers]");
				if (st->chunk_state == CHUNK_INIT && ntrip_chunk_decode_init(st) < 0) {
					end = 1;
				} else if (strlen(st->mountpoint)) {
					st->state = NTRIP_REGISTER_SOURCE;
					struct timeval read_timeout = { st->caster->config->source_read_timeout, 0 };
					bufferevent_set_timeouts(bev, &read_timeout, NULL);
				} else if (st->task && st->task->line_cb)
					st->state = NTRIP_WAIT_CALLBACK_LINE;
				else if (st->content_length)
					st->state = NTRIP_WAIT_SERVER_CONTENT;
				else if (st->chunk_state != CHUNK_NONE && st->chunk_state != CHUNK_END)
					st->state = NTRIP_WAIT_CHUNKED_CONTENT;
				else if (st->connection_keepalive && st->received_keepalive) {
					st->state = NTRIP_IDLE_CLIENT;
					if (st->task)
						ntrip_task_send_next_request(st);
				} else {
					ntrip_log(st, LOG_INFO, "closing connection due to connection_keepalive=%d received_keepalive=%d",
						st->connection_keepalive, st->received_keepalive);
					end = 1;
				}
			} else {
				char *key, *value;
				ntrip_log(st, LOG_DEBUG, "Header \"%s\"", line);
				if (!parse_header(line, &key, &value)) {
					free(line);
					ntrip_log(st, LOG_DEBUG, "parse_header failed");
					end = 1;
					break;
				}

				if (!strcasecmp(key, "transfer-encoding")) {
					if (!strcasecmp(value, "chunked"))
						st->chunk_state = CHUNK_INIT;
				} else if (!strcasecmp(key, "connection")) {
					if (!strcasecmp(value, "keep-alive"))
						st->received_keepalive = 1;
				} else if (!strcasecmp(key, "content-length")) {
					unsigned long content_length;
					int length_err;
					if (sscanf(value, "%lu", &content_length) == 1) {
						length_err = (content_length > st->caster->config->http_content_length_max);
						if (length_err) {
							ntrip_log(st, LOG_NOTICE, "Content-Length %d: exceeds max configured value %d",
									content_length, st->caster->config->http_content_length_max);
							end = 1;
							break;
						}
						st->content_length = content_length;
						st->content_done = 0;
					}
				} else if (!strcasecmp(key, "content-type")) {
					st->content_type = mystrdup(value);
				}
			}
			free(line);
		} else if (st->state == NTRIP_WAIT_CALLBACK_LINE) {
			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			/* Add 1 for the trailing LF or CR LF. We don't care for the exact count. */
			st->received_bytes += len + 1;

			if (st->task && st->task->line_cb(st, st->task->line_cb_arg, line, st->task->cb_arg2)) {
				st->task = NULL;
				end = 1;
			}
			free(line);
		} else if (st->state == NTRIP_WAIT_SERVER_CONTENT) {
			len = waiting_len;
			if (len > st->content_length - st->content_done)
				len = st->content_length - st->content_done;
			if (len) {
				evbuffer_drain(st->input, len);
				st->received_bytes += len;
				st->content_done += len;
			}
			if (st->content_length == st->content_done && st->connection_keepalive && st->received_keepalive) {
				st->state = NTRIP_IDLE_CLIENT;
				if (st->task)
					ntrip_task_send_next_request(st);
			} else
				end = 1;
		} else if (st->state == NTRIP_WAIT_CHUNKED_CONTENT) {
			if (st->chunk_state == CHUNK_END) {
				if (st->connection_keepalive && st->received_keepalive) {
					st->state = NTRIP_IDLE_CLIENT;
					if (st->task)
						ntrip_task_send_next_request(st);
				} else
					end = 1;
			} else {
				len = waiting_len;
				if (len) {
					evbuffer_drain(st->input, len);
					st->received_bytes += len;
					st->content_done += len;
				}
			}
		} else if (st->state == NTRIP_IDLE_CLIENT) {
			len = waiting_len;
			if (len) {
				st->received_bytes += len;
				char data[65];
				data[64] = '\0';
				ntrip_log(st, LOG_NOTICE, "Server sent %d bytes on idle connection, closing", len);
				int rlen = len > 64 ? 64:len;
				evbuffer_remove(st->input, data, rlen);
				data[rlen] = '\0';
				ntrip_log(st, LOG_INFO, "Data (truncated to 64 bytes): \"%s\"", data);
				end = 1;
			}
		} else if (st->state == NTRIP_REGISTER_SOURCE) {
			if (st->own_livesource) {
				livesource_set_state(st->own_livesource, st->caster, LIVESOURCE_RUNNING);
				ntrip_log(st, LOG_INFO, "starting redistribute for %s", st->mountpoint);
			}
			st->state = NTRIP_WAIT_STREAM_GET;
			ntrip_set_rtcm_cache(st);
		} else if (st->state == NTRIP_WAIT_STREAM_GET) {
			int r = rtcm_packet_handle(st);
			if (st->persistent || r == 0)
				break;
			int idle_time = time(NULL) - st->last_send;
			if (idle_time > st->caster->config->idle_max_delay) {
				ntrip_log(st, LOG_NOTICE, "last_send %s: %d seconds ago, dropping", st->mountpoint, idle_time);
				end = 1;
			}
		}
	}
	if (end || st->state == NTRIP_FORCE_CLOSE) {
		ntrip_notify_close(st);
		ntripcli_log_close(st);
		ntrip_decref_end(st, "ntripcli_readcb");
	}
}

void ntripcli_writecb(struct bufferevent *bev, void *arg)
{
	struct ntrip_state *st = (struct ntrip_state *)arg;
	ntrip_log(st, LOG_EDEBUG, "ntripcli_writecb");

	struct evbuffer *output = bufferevent_get_output(bev);
	if (evbuffer_get_length(output) == 0) {
		ntrip_log(st, LOG_EDEBUG, "flushed answer ntripcli");
	}
}

void ntripcli_send_request(struct ntrip_state *st, struct mime_content *m, int send_mime) {
	int len;
	struct evbuffer *output = bufferevent_get_output(st->bev);
	char *s = ntripcli_http_request_str(st, st->task?st->task->method:"GET", st->host, st->port, st->uri, 2, NULL, m);
	if (s) {
		len = strlen(s);
		st->sent_bytes += len + (m ? m->len : 0);
	}
	if (s == NULL
	 || evbuffer_add_reference(output, s, len, strfree_callback, s) < 0
	 || (m && send_mime && evbuffer_add_reference(output, m->s, m->len, mime_free_callback, m) < 0)) {
		ntrip_log(st, LOG_CRIT, "Not enough memory, dropping connection to %s:%d", st->host, st->port);
		ntripcli_log_close(st);
		ntrip_decref_end(st, "ntripcli_send_request");
		return;
	}
	st->state = NTRIP_WAIT_HTTP_STATUS;
}

void ntripcli_eventcb(struct bufferevent *bev, short events, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;

	if (events & BEV_EVENT_CONNECTED) {
		// Has to be done now: not known from libevent before the connection is complete
		ntrip_set_fd(st);

		ntrip_set_peeraddr(st, NULL, 0);
		ntrip_set_localaddr(st);
		ntrip_log(st, LOG_INFO, "Connected to %s:%d for %s", st->host, st->port, st->uri);
		if (st->task && st->task->use_mimeq) {
			st->state = NTRIP_IDLE_CLIENT;
			ntrip_task_send_next_request(st);
		} else
			ntripcli_send_request(st, NULL, 0);
		return;
	} else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (events & BEV_EVENT_ERROR) {
			ntrip_log(st, LOG_NOTICE, "Error: %s", strerror(errno));
		} else {
			ntrip_log(st, LOG_INFO, "Server EOF");
		}
	} else if (events & BEV_EVENT_TIMEOUT) {
		if (events & BEV_EVENT_READING)
			ntrip_log(st, LOG_NOTICE, "ntripcli read timeout");
		if (events & BEV_EVENT_WRITING)
			ntrip_log(st, LOG_NOTICE, "ntripcli write timeout");
	}

	ntrip_notify_close(st);
	ntripcli_log_close(st);
	ntrip_decref_end(st, "ntripcli_eventcb");
}

struct ntrip_state *
ntripcli_new(struct caster_state *caster, char *host, unsigned short port, int tls, const char *uri,
	const char *type, struct ntrip_task *task,
	struct livesource *livesource,
	int persistent) {

	struct bufferevent *bev;

	SSL *ssl = NULL;
	if (tls) {
		ssl = SSL_new(caster->ssl_client_ctx);
		if (ssl == NULL) {
			ERR_print_errors_cb(caster_tls_log_cb, caster);
			return NULL;
		}

		/* Set the Server Name Indication TLS extension, for virtual server handling */
		if (SSL_set_tlsext_host_name(ssl, host) < 0) {
			ERR_print_errors_cb(caster_tls_log_cb, caster);
			return NULL;
		}
		/* Set hostname for certificate verification. */
		if (SSL_set1_host(ssl, host) != 1) {
			ERR_print_errors_cb(caster_tls_log_cb, caster);
			return NULL;
		}
		SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

		if (threads)
			bev = bufferevent_openssl_socket_new(caster->base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
		else
			bev = bufferevent_openssl_socket_new(caster->base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);

	} else {
		if (threads)
			bev = bufferevent_socket_new(caster->base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
		else
			bev = bufferevent_socket_new(caster->base, -1, BEV_OPT_CLOSE_ON_FREE);
	}

	if (bev == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Error constructing bufferevent in ntripcli_start!");
		return NULL;
	}
	struct ntrip_state *st = ntrip_new(caster, bev, host, port, uri, livesource?livesource->mountpoint:NULL);
	if (st == NULL) {
		bufferevent_free(bev);
		logfmt(&caster->flog, LOG_ERR, "Error constructing ntrip_state in ntripcli_start!");
		return NULL;
	}
	st->type = type;
	st->task = task;
	st->ssl = ssl;
	st->client = 1;
	st->own_livesource = livesource;
	st->persistent = persistent;
	if (task) {
		task->st = st;
		task->start = st->start;
	}
	return st;
}

int
ntripcli_start(struct ntrip_state *st) {

	struct bufferevent *bev = st->bev;

	ntrip_register(st);
	ntrip_log(st, LOG_NOTICE, "Starting %s from %s:%d", st->type, st->host, st->port);
	if (st->task) {
		ntrip_log(st, LOG_NOTICE, "Connection: (keepalive) %d", st->task->connection_keepalive);
		st->connection_keepalive = st->task->connection_keepalive;
	}

	if (threads)
		bufferevent_setcb(bev, ntripcli_workers_readcb, ntripcli_workers_writecb, ntripcli_workers_eventcb, st);
	else
		bufferevent_setcb(bev, ntripcli_readcb, ntripcli_writecb, ntripcli_eventcb, st);

	bufferevent_enable(bev, EV_READ|EV_WRITE);

	struct timeval read_timeout = {
		st->task && st->task->read_timeout ? st->task->read_timeout : st->caster->config->ntripcli_default_read_timeout, 0 };
	struct timeval write_timeout = {
		st->task && st->task->write_timeout ? st->task->write_timeout : st->caster->config->ntripcli_default_write_timeout, 0 };
	bufferevent_set_timeouts(bev, &read_timeout, &write_timeout);

	bufferevent_socket_connect_hostname(bev, st->caster->dns_base, AF_UNSPEC, st->host, st->port);

	return 0;
}

void ntripcli_workers_readcb(struct bufferevent *bev, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	joblist_append(st->caster->joblist, ntripcli_readcb, NULL, bev, arg, 0);
}

void ntripcli_workers_writecb(struct bufferevent *bev, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	joblist_append(st->caster->joblist, ntripcli_writecb, NULL, bev, arg, 0);
}

void ntripcli_workers_eventcb(struct bufferevent *bev, short events, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	joblist_append(st->caster->joblist, NULL, ntripcli_eventcb, bev, arg, events);
}
