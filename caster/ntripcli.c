#include <string.h>

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
#include "redistribute.h"
#include "util.h"

const char *client_ntrip_version = "Ntrip/2.0";
const char *client_user_agent = "NTRIP " CLIENT_VERSION_STRING;

static void display_headers(struct ntrip_state *st, struct evkeyvalq *headers) {
	struct evkeyval *np;
	TAILQ_FOREACH(np, headers, next) {
		if (!strcasecmp(np->key, "authorization"))
			ntrip_log(st, LOG_DEBUG, "%s: *****\n", np->key);
		else
			ntrip_log(st, LOG_DEBUG, "%s: %s\n", np->key, np->value);
	}
}

/*
 * Build a full HTTP request, including headers.
 */
static char *ntripcli_http_request_str(struct ntrip_state *st, char *method, char *host, unsigned short port, char *uri, int version, struct evkeyvalq *opt_headers) {
	struct evkeyvalq headers;
	struct evkeyval *np;

	char *host_port = host_port_str(host, port);
	if (host_port == NULL) {
		return NULL;
	}

	TAILQ_INIT(&headers);
	if (evhttp_add_header(&headers, "Host", host_port) < 0
	 || evhttp_add_header(&headers, "User-Agent", client_user_agent) < 0
	 || evhttp_add_header(&headers, "Connection", "close") < 0
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

	display_headers(st, &headers);

	int hlen = 0;
	TAILQ_FOREACH(np, &headers, next) {
		// lengths of key + value + " " + "\r\n"
		hlen += strlen(np->key) + strlen(np->value) + 4;
	}

	char *format = "%s %s HTTP/1.1\r\n";
	size_t s = strlen(format) + strlen(method) + strlen(uri) + hlen + 2;
	char *r = (char *)strmalloc(s);
	if (r == NULL) {
		evhttp_clear_headers(&headers);
		strfree(host_port);
		return NULL;
	}
	sprintf(r, format, method, uri);
	TAILQ_FOREACH(np, &headers, next) {
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

void ntripcli_readcb(struct bufferevent *bev, void *arg) {
	int end = 0;
	struct ntrip_state *st = (struct ntrip_state *)arg;
	char *line;
	size_t len;

	ntrip_log(st, LOG_EDEBUG, "ntripcli_readcb state %d len %d\n", st->state, evbuffer_get_length(st->filter.raw_input));

	if (ntrip_filter_run_input(st) < 0)
		return;

	while (!end && st->state != NTRIP_WAIT_CLOSE && evbuffer_get_length(st->input) > 5) {
		if (st->state == NTRIP_WAIT_HTTP_STATUS) {
			char *token, *status, **arg;

			st->chunk_state = CHUNK_NONE;
			if (st->chunk_buf) {
				evbuffer_free(st->chunk_buf);
				st->chunk_buf = NULL;
			}

			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			ntrip_log(st, LOG_DEBUG, "Got \"%s\", %zd bytes on /%s\n", line, len, st->mountpoint);

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
				ntrip_log(st, LOG_NOTICE, "NTRIP1 error reply: %s\n", line);
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
			if (status_code == 200)
				st->state = NTRIP_WAIT_HTTP_HEADER;
			else {
				ntrip_log(st, LOG_NOTICE, "failed request on /%s, status_code %d\n", st->mountpoint, st->status_code);
				end = 1;
			}

		} else if (st->state == NTRIP_WAIT_HTTP_HEADER) {
			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			ntrip_log(st, LOG_DEBUG, "Got header \"%s\", %zd bytes\n", line, len);
			if (strlen(line) == 0) {
				ntrip_log(st, LOG_DEBUG, "[End headers]\n");
				if (st->chunk_state == CHUNK_INIT && ntrip_chunk_decode_init(st) < 0) {
					end = 1;
				} else if (strlen(st->mountpoint)) {
					st->state = NTRIP_REGISTER_SOURCE;
					struct timeval read_timeout = { st->caster->config->source_read_timeout, 0 };
					bufferevent_set_timeouts(bev, &read_timeout, NULL);
				} else if (st->task)
					st->state = NTRIP_WAIT_CALLBACK_LINE;
				else
					end = 1;
			} else {
				char *key, *value;
				if (!parse_header(line, &key, &value)) {
					free(line);
					ntrip_log(st, LOG_DEBUG, "parse_header failed\n");
					end = 1;
					break;
				}

				if (!strcasecmp(key, "transfer-encoding")) {
					if (!strcasecmp(value, "chunked"))
						st->chunk_state = CHUNK_INIT;
				}
			}
			free(line);
		} else if (st->state == NTRIP_WAIT_CALLBACK_LINE) {
			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			/* Add 1 for the trailing LF or CR LF. We don't care for the exact count. */
			st->received_bytes += len + 1;

			if (st->task && st->task->line_cb(st, st->task->line_cb_arg, line)) {
				st->task = NULL;
				end = 1;
			}
			free(line);
		} else if (st->state == NTRIP_REGISTER_SOURCE) {
			if (st->own_livesource) {
				livesource_set_state(st->own_livesource, LIVESOURCE_RUNNING);
				ntrip_log(st, LOG_INFO, "starting redistribute for %s\n", st->mountpoint);
			}
			st->state = NTRIP_WAIT_STREAM_GET;
		} else if (st->state == NTRIP_WAIT_STREAM_GET) {
			if (!ntrip_handle_raw(st))
				break;
			if (st->persistent)
				continue;
			int idle_time = time(NULL) - st->last_send;
			if (idle_time > st->caster->config->idle_max_delay) {
				ntrip_log(st, LOG_NOTICE, "last_send %s: %d seconds ago, dropping\n", st->mountpoint, idle_time);
				end = 1;
			}
		}
	}
	if (end || st->state == NTRIP_FORCE_CLOSE) {
		if (st->task != NULL) {
			/* Notify the callback the transfer is over, and failed. */
			st->task->end_cb(0, st->task->end_cb_arg);
			st->task = NULL;
		}
		ntrip_deferred_free(st, "ntripcli_readcb/sourcetable");
	}
}

void ntripcli_writecb(struct bufferevent *bev, void *arg)
{
	struct ntrip_state *st = (struct ntrip_state *)arg;
	ntrip_log(st, LOG_DEBUG, "ntripcli_writecb\n");

	struct evbuffer *output = bufferevent_get_output(bev);
	if (evbuffer_get_length(output) == 0) {
		ntrip_log(st, LOG_EDEBUG, "flushed answer ntripcli\n");
	}
}

void ntripcli_eventcb(struct bufferevent *bev, short events, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;

	if (events & BEV_EVENT_CONNECTED) {
		// Has to be done now: not known from libevent before the connection is complete
		ntrip_set_fd(st);

		ntrip_set_peeraddr(st, NULL, 0);
		ntrip_log(st, LOG_INFO, "Connected to %s:%d for /%s\n", st->host, st->port, st->mountpoint);
		char *uri = (char *)strmalloc(strlen(st->mountpoint) + 3);
		if (uri == NULL) {
			ntrip_log(st, LOG_CRIT, "Not enough memory, dropping connection to %s:%d\n", st->host, st->port);
			ntrip_deferred_free(st, "ntripcli_eventcb");

			return;
		}
		sprintf(uri, "/%s", st->mountpoint);
		char *s = ntripcli_http_request_str(st, "GET", st->host, st->port, uri, 2, NULL);
		strfree(uri);
		if (s == NULL) {
			ntrip_log(st, LOG_CRIT, "Not enough memory, dropping connection from %s:%d\n", st->host, st->port);
			ntrip_deferred_free(st, "ntripcli_eventcb");

			return;
		}
		bufferevent_write(bev, s, strlen(s));
		strfree(s);
		st->state = NTRIP_WAIT_HTTP_STATUS;
		return;
	} else if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (events & BEV_EVENT_ERROR) {
			ntrip_log(st, LOG_NOTICE, "Error: %s\n", strerror(errno));
		} else {
			ntrip_log(st, LOG_INFO, "Server EOF\n");
		}
	} else if (events & BEV_EVENT_TIMEOUT) {
		if (events & BEV_EVENT_READING)
			ntrip_log(st, LOG_NOTICE, "ntripcli read timeout\n");
		if (events & BEV_EVENT_WRITING)
			ntrip_log(st, LOG_NOTICE, "ntripcli write timeout\n");
	}

	if (st->own_livesource) {
		if (st->redistribute && st->persistent) {
			struct redistribute_cb_args *redis_args;
			redis_args = redistribute_args_new(st->caster, st->own_livesource, st->mountpoint, &st->mountpoint_pos, st->caster->config->reconnect_delay, 0);
			if (redis_args)
				redistribute_schedule(st->caster, st, redis_args);
		} else
			ntrip_unregister_livesource(st);
	}
	if (st->task != NULL) {
		/* Notify the callback the transfer is over, and failed. */
		st->task->end_cb(0, st->task->end_cb_arg);
		st->task = NULL;
	}
	int bytes_left = evbuffer_get_length(st->input);
	ntrip_log(st, bytes_left ? LOG_NOTICE:LOG_INFO, "Connection closed, %zu bytes left.\n", evbuffer_get_length(st->input));

	ntrip_deferred_free(st, "ntripcli_eventcb");
}

void
ntripcli_start(struct caster_state *caster, char *host, unsigned short port, int tls, const char *type, struct ntrip_task *task) {
	struct bufferevent *bev;

	SSL *ssl = NULL;
	if (tls) {
		ssl = SSL_new(caster->ssl_client_ctx);
		if (ssl == NULL) {
			ERR_print_errors_cb(caster_tls_log_cb, caster);
			return;
		}

		/* Set the Server Name Indication TLS extension, for virtual server handling */
		if (SSL_set_tlsext_host_name(ssl, host) < 0) {
			ERR_print_errors_cb(caster_tls_log_cb, caster);
			return;
		}
		/* Set hostname for certificate verification. */
		if (SSL_set1_host(ssl, host) != 1) {
			ERR_print_errors_cb(caster_tls_log_cb, caster);
			return;
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
		logfmt(&caster->flog, "Error constructing bufferevent in ntripcli_start!");
		return -1;
	}
	struct ntrip_state *st = ntrip_new(caster, bev, host, port, NULL);
	if (st == NULL) {
		bufferevent_free(bev);
		logfmt(&caster->flog, "Error constructing ntrip_state in ntripcli_start!");
		return -1;
	}
	st->type = type;
	st->task = task;
	st->ssl = ssl;

	ntrip_register(st);
	ntrip_log(st, LOG_NOTICE, "Starting %s from %s:%d\n", type, host, port);
	if (task) task->st = st;

	if (threads)
		bufferevent_setcb(bev, ntripcli_workers_readcb, ntripcli_workers_writecb, ntripcli_workers_eventcb, st);
	else
		bufferevent_setcb(bev, ntripcli_readcb, ntripcli_writecb, ntripcli_eventcb, st);

	bufferevent_enable(bev, EV_READ|EV_WRITE);

	struct timeval timeout = { caster->config->sourcetable_fetch_timeout, 0 };
	bufferevent_set_timeouts(bev, &timeout, &timeout);

	bufferevent_socket_connect_hostname(bev, caster->dns_base, AF_UNSPEC, host, port);
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
