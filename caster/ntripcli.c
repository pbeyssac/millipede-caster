#include <stdio.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "caster.h"
#include "http.h"
#include "jobs.h"
#include "ntripcli.h"
#include "ntrip_common.h"
#include "redistribute.h"
#include "util.h"
#include "fetcher_sourcetable.h"

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

	P_RWLOCK_RDLOCK(&st->caster->authlock);

	if (st->caster->host_auth) {
		for (struct auth_entry *a = &st->caster->host_auth[0]; a->user != NULL; a++) {
			if (!strcasecmp(a->key, host)) {
				if (http_headers_add_auth(&headers, a->user, a->password) < 0) {
					evhttp_clear_headers(&headers);
					strfree(host_port);
					P_RWLOCK_UNLOCK(&st->caster->authlock);
					return NULL;
				} else
					break;
			}
		}
	}

	P_RWLOCK_UNLOCK(&st->caster->authlock);

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

	struct evbuffer *input = bufferevent_get_input(bev);

	//ntrip_log(st, LOG_DEBUG, "readcb %zd bytes\n", evbuffer_get_length(input));
	while (!end && st->state != NTRIP_WAIT_CLOSE && evbuffer_get_length(input) > 5) {
		if (st->state == NTRIP_WAIT_HTTP_STATUS) {
			char *token, *status, **arg;

			line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF);
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
			line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			ntrip_log(st, LOG_DEBUG, "Got header \"%s\", %zd bytes\n", line, len);
			if (strlen(line) == 0) {
				if (strlen(st->mountpoint)) {
					st->state = NTRIP_REGISTER_SOURCE;
					struct timeval read_timeout = { st->caster->config->source_read_timeout, 0 };
					bufferevent_set_timeouts(bev, &read_timeout, NULL);
				} else {
					st->tmp_sourcetable = sourcetable_new(st->host, st->port);
					if (st->tmp_sourcetable == NULL) {
						end =1;
						ntrip_log(st, LOG_CRIT, "Out of memory when allocating sourcetable\n");
					} else {
						st->state = NTRIP_WAIT_SOURCETABLE_LINE;
					}
				}
			} else {
				char *key, *value;
				if (!parse_header(line, &key, &value)) {
					ntrip_log(st, LOG_DEBUG, "parse_header failed\n");
					end = 1;
					break;
				}

				if (!strcasecmp(key, "transfer-encoding")) {
					if (!strcasecmp(value, "chunked")) {
						st->chunk_state = CHUNK_WAIT_LEN;
						if (st->chunk_buf == NULL)
							st->chunk_buf = evbuffer_new();
						if (st->chunk_buf == NULL) {
							end = 1;
							break;
						}
					}
				}
			}
			free(line);
		} else if (st->state == NTRIP_WAIT_SOURCETABLE_LINE) {
			line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			if (!strcmp(line, "ENDSOURCETABLE")) {
				ntrip_log(st, LOG_INFO, "Complete sourcetable, %d entries\n", sourcetable_nentries(st->tmp_sourcetable, 0));
				st->tmp_sourcetable->pullable = 1;
				gettimeofday(&st->tmp_sourcetable->fetch_time, NULL);
				if (st->sourcetable_cb_arg) {
					st->sourcetable_cb_arg->sourcetable = st->tmp_sourcetable;
					st->sourcetable_cb_arg->sourcetable_cb(-1, 0, st->sourcetable_cb_arg);
					st->sourcetable_cb_arg = NULL;
				} else
					sourcetable_free(st->tmp_sourcetable);
				st->tmp_sourcetable = NULL;
				end = 1;
			} else {
				if (sourcetable_add(st->tmp_sourcetable, line, 1) < 0) {
					end = 1;
				}
			}
			free(line);
		} else if (st->state == NTRIP_REGISTER_SOURCE) {
			if (st->redistribute) {
				struct sourceline *sourceline = stack_find_pullable(&st->caster->sourcetablestack, st->mountpoint, NULL);
				if (sourceline == NULL || ntrip_add_livesource(st, st->mountpoint, &sourceline->pos, 1) == NULL) {
					end = 1;
					ntrip_log(st, LOG_NOTICE, "%p Can't register live source for %s\n", st, st->mountpoint);
					if (st->callback_subscribe) {
						st->callback_subscribe(st->callback_subscribe_arg, 0);
						st->callback_subscribe = NULL;
					}
					break;
				}
				if (sourceline) {
					ntrip_log(st, LOG_INFO, "starting redistribute for %s\n", st->mountpoint);
					if (st->callback_subscribe) {
						st->callback_subscribe(st->callback_subscribe_arg, 1);
						st->callback_subscribe = NULL;
					}
				} else if (st->callback_subscribe) {
					st->callback_subscribe(st->callback_subscribe_arg, 0);
					st->callback_subscribe = NULL;
				}
			}
			st->state = NTRIP_WAIT_STREAM_GET;
		} else if (st->state == NTRIP_WAIT_STREAM_GET) {
			//ntrip_log(st, LOG_INFO, "testing redistribute %d for %s\n", st->redistribute, st->mountpoint);
			if (!ntrip_handle_raw(st, bev))
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
	if (end) {
		if (st->sourcetable_cb_arg != NULL) {
			/* Notify the callback the transfer is over, and failed. */
			ntrip_log(st, LOG_DEBUG, "sourcetable loading failed\n");
			st->sourcetable_cb_arg->sourcetable = NULL;
			st->sourcetable_cb_arg->sourcetable_cb(-1, 0, st->sourcetable_cb_arg);
			st->sourcetable_cb_arg = NULL;
		}
		if (st->tmp_sourcetable != NULL) {
			sourcetable_free(st->tmp_sourcetable);
			st->tmp_sourcetable = NULL;
		}
		ntrip_deferred_free(st, "ntripcli_readcb/sourcetable");
		return;
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
		st->start = time(NULL);
	 	evutil_socket_t fd = bufferevent_getfd(bev);
		if (fd >= 0) {
			socklen_t psocklen = sizeof(st->peeraddr);
			if (getpeername(fd, &st->peeraddr.generic, &psocklen) >= 0) {
				st->remote = 1;
				sockaddr_ipstr(&st->peeraddr.generic, st->remote_addr, sizeof st->remote_addr);
			} else {
				ntrip_log(st, LOG_NOTICE, "getpeername failed: %s\n", strerror(errno));
			}
		}
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
			ntrip_log(st, LOG_NOTICE, "ntripcli read timeout ntrip_state %p.\n", st);
		if (events & BEV_EVENT_WRITING)
			ntrip_log(st, LOG_NOTICE, "ntripcli write timeout ntrip_state %p.\n", st);
	}

	/* Unregister live source, if any */
	if (st->own_livesource) {
		ntrip_unregister_livesource(st);
		if (st->redistribute) {
			struct redistribute_cb_args *redis_args = redistribute_args_new(st, NULL, st->mountpoint, &st->mountpoint_pos, st->caster->config->reconnect_delay, 0);
			if (redis_args)
				redistribute_schedule(st, redis_args);
		}
	}
	if (st->sourcetable_cb_arg != NULL) {
		/* Notify the callback the transfer is over, and failed. */
		st->sourcetable_cb_arg->sourcetable = NULL;
		st->sourcetable_cb_arg->sourcetable_cb(-1, 0, st->sourcetable_cb_arg);
		st->sourcetable_cb_arg = NULL;
	}
	struct evbuffer *input = bufferevent_get_input(bev);
	int bytes_left = evbuffer_get_length(input);
	ntrip_log(st, bytes_left ? LOG_NOTICE:LOG_INFO, "Connection closed, %zu bytes left.\n", evbuffer_get_length(input));

	ntrip_deferred_free(st, "ntripcli_eventcb");
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
