#include <stdio.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event_struct.h>
#include <event2/http.h>

#include "conf.h"
#include "adm.h"
#include "caster.h"
#include "jobs.h"
#include "ntrip_common.h"
#include "redistribute.h"
#include "util.h"

const char *server_headers = "Server: NTRIP " SERVER_VERSION_STRING "\r\n";

static void
send_server_reply(struct ntrip_state *this, struct evbuffer *ev, int status_code, char *status, struct evkeyvalq *headers, char *firstword) {
	char date[32];
	time_t tstamp = time(NULL);
	firstword = (this->client_version == 1 && firstword && this->user_agent_ntrip)?firstword:"HTTP/1.1";
	struct tm *t = gmtime(&tstamp);
	strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S GMT", t);
	evbuffer_add_printf(ev, "%s %d %s\r\n%sDate: %s\r\n", firstword, status_code, status, server_headers, date);
	if (this->server_version == 2)
		evbuffer_add_reference(ev, "Ntrip-Version: Ntrip/2.0\r\n", 26, NULL, NULL);
	if (headers) {
		struct evkeyval *np;
		TAILQ_FOREACH(np, headers, next) {
			evbuffer_add_printf(ev, "%s: %s\r\n", np->key, np->value);
		}
	}
	evbuffer_add_reference(ev, "\r\n", 2, NULL, NULL);
}

static int ntripsrv_send_sourcetable(struct ntrip_state *this, struct evbuffer *output) {
	struct evkeyvalq headers;
	struct sourcetable *sourcetable = stack_flatten(this->caster, &this->caster->sourcetablestack);
	char *s = sourcetable_get(sourcetable);
	sourcetable_free(sourcetable);
	if (s == NULL)
		return 503;

	char lenstr[30];
	snprintf(lenstr, sizeof lenstr, "%lu", strlen(s));
	TAILQ_INIT(&headers);
	evhttp_add_header(&headers, "Connection", "close");
	evhttp_add_header(&headers, "Content-Length", lenstr);
	evhttp_add_header(&headers, "Content-Type", this->client_version == 1?"text/plain":"gnss/sourcetable");
	send_server_reply(this, output, 200, "OK", &headers, "SOURCETABLE");
	evhttp_clear_headers(&headers);
	//logfmt(this->&caster->flog, "\"%s\"\n", s);
	if (evbuffer_add_reference(output, s, strlen(s), strfree_callback, NULL) < 0) {
		// the call failed so we need to free s instead of letting the callback do it.
		strfree(s);
	}
	return 0;
}

int ntripsrv_send_result_ok(struct ntrip_state *this, struct evbuffer *output, const char *mime_type, struct evkeyvalq *opt_headers) {
	struct evkeyvalq headers;
	struct evkeyval *np;
	if (this->client_version == 1)
		evbuffer_add_reference(output, "ICY 200 OK\r\n\r\n", 14, NULL, NULL);
	else {
		TAILQ_INIT(&headers);
		evhttp_add_header(&headers, "Connection", "close");
		if (mime_type != NULL)
			evhttp_add_header(&headers, "Content-Type", mime_type);
		evhttp_add_header(&headers, "Cache-Control", "no-store, no-cache, max-age=0");
		evhttp_add_header(&headers, "Pragma", "no-cache");

		if (opt_headers) {
			TAILQ_FOREACH(np, opt_headers, next) {
				evhttp_add_header(&headers, np->key, np->value);
			}
		}
		send_server_reply(this, output, 200, "OK", &headers, NULL);
		evhttp_clear_headers(&headers);
	}
	return 0;
}

/*
 * Compute content through a callback without any lock, then send it on the provided ntrip_state.
 *
 * Avoids keeping a lock on ntrip_state unless needed, to avoid deadlocks.
 */
void ntripsrv_deferred_output(struct ntrip_state *st, struct mime_content *(*content_cb)(struct caster_state *caster)) {
	struct mime_content *r = content_cb(st->caster);
	bufferevent_lock(st->bev);
	struct evbuffer *output = bufferevent_get_output(st->bev);
	ntripsrv_send_result_ok(st, output, r->mime_type, NULL);
	if (evbuffer_add_reference(output, r->s, r->len, mime_free_callback, r) < 0)
		mime_free(r);
	st->state = NTRIP_WAIT_CLOSE;
	bufferevent_unlock(st->bev);
}

/*
 * Check password in the base
 */
int check_password(struct ntrip_state *this, const char *mountpoint, const char *user, const char *passwd) {
	int r = 0;

	P_RWLOCK_RDLOCK(&this->caster->authlock);

	struct auth_entry *auth = this->caster->source_auth;
	if (auth == NULL) {
		P_RWLOCK_UNLOCK(&this->caster->authlock);
		return 0;
	}

	ntrip_log(this, LOG_DEBUG, "mountpoint %s user %s\n", mountpoint, user);
	for (; auth->key != NULL; auth++) {
		if (!strcmp(auth->key, mountpoint)) {
			ntrip_log(this, LOG_DEBUG, "mountpoint %s found\n", mountpoint);
			if (user && strcmp(auth->user, user))
				break;

			if (!strcmp(auth->password, passwd)) {
				ntrip_log(this, LOG_DEBUG, "source %s auth ok\n", mountpoint);
				r = 1;
				break;
			}
			break;
		}
	}

	P_RWLOCK_UNLOCK(&this->caster->authlock);

	return r;
}

/*
 * Required lock: ntrip_state
 */
void ntripsrv_redo_virtual_pos(struct ntrip_state *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	if (!st->last_pos_valid)
		return;

	struct sourcetable *pos_sourcetable = stack_flatten(st->caster, &st->caster->sourcetablestack);
	if (pos_sourcetable == NULL)
		return;

	struct dist_table *s = sourcetable_find_pos(pos_sourcetable, &st->last_pos);
	if (s == NULL) {
		sourcetable_free(pos_sourcetable);
		return;
	}

	ntrip_log(st, LOG_DEBUG, "GGAOK pos (%f, %f) list of %d\n", st->last_pos.lat, st->last_pos.lon, s->size_dist_array);
	dist_table_display(st, s, 10);

	if (st->source_virtual) {
		if (s->dist_array[0].dist > st->max_min_dist) {
			st->max_min_dist = s->dist_array[0].dist;
			ntrip_log(st, LOG_DEBUG, "New maximum distance to source: %.2f\n", st->max_min_dist);
		} else
			ntrip_log(st, LOG_DEBUG, "Current maximum distance to source: %.2f\n", st->max_min_dist);

		char *m = s->dist_array[0].mountpoint;

		if (!st->virtual_mountpoint || strcmp(m, st->virtual_mountpoint)) {
			/*
			 * The closest base has changed.
			 */

			/*
			 * Recheck with some hysteresis to favor the current station and avoid useless switching
			 * between very close stations.
			 */

			float current_dist = st->virtual_mountpoint ? (distance(&st->mountpoint_pos, &st->last_pos)-st->caster->config->hysteresis_m) : 1e10;

			if (current_dist < s->dist_array[0].dist) {
				ntrip_log(st, LOG_INFO, "Virtual source ignoring switch from %s to %s due to %.2f hysteresis\n", st->virtual_mountpoint, m, st->caster->config->hysteresis_m);
			} else {
				enum livesource_state source_state;
				struct livesource *l = livesource_find_on_demand(st->caster, st, m, &s->dist_array[0].pos, s->dist_array[0].on_demand, &source_state);
				if (l && (source_state == LIVESOURCE_RUNNING || (s->dist_array[0].on_demand && source_state == LIVESOURCE_FETCH_PENDING))) {
					if (redistribute_switch_source(st, m, &s->dist_array[0].pos, l) < 0)
						ntrip_log(st, LOG_NOTICE, "Unable to switch source from %s to %s\n", st->virtual_mountpoint, m);
				}
			}
		}
	}

	sourcetable_free(pos_sourcetable);
	dist_table_free(s);
	return;
}

/*
 * Main NTRIP server HTTP connection loop.
 */
void ntripsrv_readcb(struct bufferevent *bev, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	char *line = NULL;
	size_t len;
	int err = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evkeyvalq opt_headers;
	TAILQ_INIT(&opt_headers);

	ntrip_log(st, LOG_EDEBUG, "ntripsrv_readcb %p state %d len %d\n", st, st->state, evbuffer_get_length(input));

	while (!err && st->state != NTRIP_WAIT_CLOSE && evbuffer_get_length(input) > 0) {
		if (st->state == NTRIP_WAIT_HTTP_METHOD) {
			char *token;

			line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			ntrip_log(st, LOG_DEBUG, "Got \"%s\", %zd bytes\n", line, len);
			int i = 0;
			char *septmp = line;
			while ((token = strsep(&septmp, " \t")) != NULL && i < SIZE_HTTP_ARGS) {
				//ntrip_log(st, LOG_DEBUG, "TOKEN %s\n", token);
				st->http_args[i] = mystrdup(token);
				if (st->http_args[i] == NULL) {
					err = 503;
					break;
				}
				i++;
			}
			if (err) break;
			if (i != SIZE_HTTP_ARGS || token != NULL) {
				err = 400;
				break;
			}
			st->state = NTRIP_WAIT_HTTP_HEADER;
		} else if (st->state == NTRIP_WAIT_HTTP_HEADER) {
			line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			ntrip_log(st, LOG_DEBUG, "Got \"%s\", %zd bytes\n", line, len);
			if (strlen(line) != 0) {
				char *key, *value;
				if (!parse_header(line, &key, &value)) {
					ntrip_log(st, LOG_DEBUG, "parse_header failed\n");
					err = 1;
					break;
				}
				if (!strcasecmp(key, "host")) {
					//
				} else if (!strcasecmp(key, "transfer-encoding")) {
					if (!strcasecmp(value, "chunked")) {
						st->chunk_state = CHUNK_WAIT_LEN;
						if (st->chunk_buf == NULL)
							st->chunk_buf = evbuffer_new();
						if (st->chunk_buf == NULL) {
							err = 503;
							break;
						}
					}
				} else if (!strcasecmp(key, "ntrip-version")) {
					if (!strcasecmp(value, "ntrip/2.0"))
						st->client_version = 2;
				} else if (!strcasecmp(key, "user-agent")) {
					if (mystrcasestr(value, "ntrip"))
						st->user_agent_ntrip = 1;
					st->user_agent = mystrdup(value);
				} else if (!strcasecmp(key, "authorization")) {
					ntrip_log(st, LOG_DEBUG, "Header %s: *****\n", key);
					if (!strncmp(value, "Basic ", 6)) {
						char *auth = b64decode(value+6, strlen(value+6), 1);
						char *user, *password;
						if (auth) {
							int colon = strcspn(auth, ":");
							if (auth[colon] == ':') {
								auth[colon] = '\0';
								user = auth;
								password = auth + colon +1;
								ntrip_log(st, LOG_DEBUG, "Decoded auth: %s, %s\n", user, password);
								st->user = user;
								st->password = password;
							} else {
								ntrip_log(st, LOG_DEBUG, "No ':' in %s\n", auth);
								strfree(auth);
							}
						} else {
							if (st->caster->config->log_level >= LOG_DEBUG) {
								ntrip_log(st, LOG_DEBUG, "Can't decode Base64 string: %s\n", value+6);
							} else {
								ntrip_log(st, LOG_INFO, "Can't decode Base64 string\n");
							}
						}
					} else {
						if (st->caster->config->log_level >= LOG_DEBUG) {
							ntrip_log(st, LOG_DEBUG, "Can't decode Authorization: \"%s\"\n", value);
						} else {
							ntrip_log(st, LOG_INFO, "Can't decode Authorization\n");
						}
					}
				} else {
					ntrip_log(st, LOG_DEBUG, "Header %s: %s\n", key, value);
				}
			} else {
				ntrip_log(st, LOG_DEBUG, "[End headers]\n");
				if (!strcmp(st->http_args[0], "SOURCE")) {
					/* Don't log the password */
					ntrip_alog(st, "%s *** %s\n", st->http_args[0], st->http_args[2]);
				} else {
					ntrip_alog(st, "%s %s %s\n", st->http_args[0], st->http_args[1], st->http_args[2]);
				}
				if (!strcmp(st->http_args[0], "GET")) {
					if (st->http_args[1] == NULL || st->http_args[1][0] != '/') {
						err = 400;
						break;
					}
					if (strlen(st->http_args[1]) >= 5 && !memcmp(st->http_args[1], "/adm/", 5)) {
						st->type = "adm";
						admsrv(st, "/adm", st->http_args[1] + 4, &err, &opt_headers);
						break;
					}

					char *mountpoint = st->http_args[1]+1;
					struct sourceline *sourceline = NULL;
					if (*mountpoint)
						sourceline = stack_find_mountpoint(&st->caster->sourcetablestack, mountpoint);

					/*
					 * Source not found: reply with the sourcetable in NTRIP1, 404 in NTRIP2.
					 *
					 * Empty mountpoint name: always reply with the sourcetable.
					 */
					if (*mountpoint == '\0' || (!sourceline && st->client_version == 1)) {
						st->type = "client";
						err = ntripsrv_send_sourcetable(st, output);
						st->state = NTRIP_WAIT_CLOSE;
						break;
					}
					if (!sourceline) {
						err = 404;
						break;
					}
					st->source_virtual = sourceline->virtual;
					st->source_on_demand = sourceline->on_demand;

					st->type = "client";
					if (!st->source_virtual) {
						struct livesource *l = livesource_find_on_demand(st->caster, st, mountpoint, &sourceline->pos, st->source_on_demand, NULL);
						if (l) {
							ntrip_log(st, LOG_DEBUG, "Found requested source %s, on_demand=%d\n", mountpoint, st->source_on_demand);
							ntripsrv_send_result_ok(st, output, "gnss/data", NULL);
							st->state = NTRIP_WAIT_CLIENT_INPUT;

							/* Regular NTRIP stream client: disable read and write timeouts */
							bufferevent_set_timeouts(bev, NULL, NULL);
							livesource_add_subscriber(l, st);
						} else {
							err = ntripsrv_send_sourcetable(st, output);
							st->state = NTRIP_WAIT_CLOSE;
							break;
						}
					} else {
						ntripsrv_send_result_ok(st, output, "gnss/data", NULL);
						st->state = NTRIP_WAIT_CLIENT_INPUT;

						/* Regular NTRIP stream client: disable read and write timeouts */
						bufferevent_set_timeouts(bev, NULL, NULL);
					}

					/*
					 * We only limit the send buffer on NTRIP clients, except for the sourcetable.
					 */
					int sndbuf = st->caster->config->backlog_socket;
					if (setsockopt(bufferevent_getfd(bev), SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf) < 0)
						ntrip_log(st, LOG_NOTICE, "setsockopt SO_SNDBUF %d failed\n", sndbuf);
				} else if (!strcmp(st->http_args[0], "POST")) {
					if (st->http_args[1] == NULL || st->http_args[1][0] != '/') {
						err = 400;
						break;
					}
					char *mountpoint = st->http_args[1]+1;
					struct sourceline *sourceline = stack_find_mountpoint(&st->caster->sourcetablestack, mountpoint);
					if (!sourceline) {
						err = 404;
						break;
					}
					st->type = "source";
					if (livesource_find(st->caster, st, st->http_args[2], &sourceline->pos)) {
						err = 409;
						break;
					}
					if (!st->user || !st->password || !check_password(st, mountpoint, st->user, st->password)) {
						err = 401;
						break;
					}
					st->mountpoint = mystrdup(mountpoint);
					if (ntrip_add_livesource(st, st->mountpoint, &sourceline->pos, 0) == NULL) {
						err = 503;
						break;
					};
					ntripsrv_send_result_ok(st, output, NULL, NULL);

					struct timeval read_timeout = { st->caster->config->source_read_timeout, 0 };
					st->state = NTRIP_WAIT_STREAM_SOURCE;
					bufferevent_set_timeouts(bev, &read_timeout, NULL);
				} else if (!strcmp(st->http_args[0], "SOURCE")) {
					struct sourceline *sourceline = stack_find_mountpoint(&st->caster->sourcetablestack, st->http_args[2]);
					if (!sourceline || livesource_find(st->caster, st, st->http_args[2], &sourceline->pos)) {
						evbuffer_add_reference(output, "ERROR - Mount Point Taken or Invalid\r\n", 38, NULL, NULL);
						err = 1;
						break;
					}
					if (!check_password(st, st->http_args[2], NULL, st->http_args[1])) {
						evbuffer_add_reference(output, "ERROR - Bad Password\r\n", 22, NULL, NULL);
						err = 1;
						break;
					}
					//st->sourceline = sourceline;
					st->type = "source";
					st->mountpoint = mystrdup(st->http_args[2]);
					if (st->mountpoint == NULL) {
						err = 503;
						break;
					}
					if (ntrip_add_livesource(st, st->http_args[2], &sourceline->pos, 0) == NULL) {
						err = 503;
						break;
					};
					evbuffer_add_reference(output, "ICY 200 OK\r\n\r\n", 14, NULL, NULL);
					struct timeval read_timeout = { st->caster->config->source_read_timeout, 0 };
					st->state = NTRIP_WAIT_STREAM_SOURCE;
					bufferevent_set_timeouts(bev, &read_timeout, NULL);
				}
			}
		} else if (st->state == NTRIP_WAIT_CLIENT_INPUT) {
			line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			pos_t pos;
			ntrip_log(st, LOG_DEBUG, "GGA? \"%s\", %zd bytes\n", line, len);
			if (parse_gga(line, &pos) >= 0) {
				st->last_pos = pos;
				st->last_pos_valid = 1;
				joblist_append_ntrip_locked(st->caster->joblist, st, &ntripsrv_redo_virtual_pos);
			}
		} else if (st->state == NTRIP_WAIT_STREAM_SOURCE) {
			if (!ntrip_handle_raw(st, bev))
				break;
		}

		if (line) {
			free(line);
			line = NULL;
		}
	}
	if (line)
		free(line);

	if (err) {
		if (err == 400)
			send_server_reply(st, output, 400, "Bad Request", NULL, NULL);
		else if (err == 401) {
			send_server_reply(st, output, 401, "Unauthorized", &opt_headers, NULL);
			evbuffer_add_reference(output, "401\r\n", 5, NULL, NULL);
		} else if (err == 404)
			send_server_reply(st, output, 404, "Not Found", NULL, NULL);
		else if (err == 409)
			send_server_reply(st, output, 409, "Conflict", NULL, NULL);
		else if (err == 500)
			send_server_reply(st, output, 500, "Internal Server Error", NULL, NULL);
		else if (err == 501)
			send_server_reply(st, output, 501, "Not Implemented", NULL, NULL);
		else if (err == 503)
			send_server_reply(st, output, 503, "Service Unavailable", NULL, NULL);
		st->state = NTRIP_WAIT_CLOSE;
	}
	evhttp_clear_headers(&opt_headers);
}

/*
 * Ntrip server write loop: just wait for close.
 *
 * libevent does the job of sending queued packets without need of interference.
 */
void ntripsrv_writecb(struct bufferevent *bev, void *arg)
{
	size_t len;
	struct ntrip_state *st = (struct ntrip_state *)arg;
	struct evbuffer *output;

	output = bufferevent_get_output(bev);
	len = evbuffer_get_length(output);
	if (len == 0) {
		ntrip_log(st, LOG_EDEBUG, "flushed answer ntripsrv %p\n", st);
		if (st->state == NTRIP_WAIT_CLOSE) {
			ntrip_log(st, LOG_EDEBUG, "ntripsrv_writecb ntrip_free %p bev %p\n", st, bev);

			ntrip_deferred_free(st, "ntripsrv_writecb");
			return;
		}
	} else
		ntrip_log(st, LOG_EDEBUG, "ntripsrv_writecb %p remaining len %d\n", st, len);
}

void ntripsrv_eventcb(struct bufferevent *bev, short events, void *arg)
{
	int initial_errno = errno;
	struct ntrip_state *st = (struct ntrip_state *)arg;

	if (events & BEV_EVENT_CONNECTED) {
		ntrip_log(st, LOG_INFO, "Connected srv %p\n", st);
		return;
	}

	if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (events & BEV_EVENT_EOF)
			ntrip_log(st, LOG_INFO, "Connection closed (EOF) ntrip_state %p.\n", st);
		else {
			char err[256];
			ntrip_log(st, LOG_NOTICE, "Got an error on connection: %s\n", strerror_r(initial_errno, err, sizeof err));
		}
	} else if (events & BEV_EVENT_TIMEOUT) {
		if (events & BEV_EVENT_READING)
			ntrip_log(st, LOG_NOTICE, "ntripsrv read timeout ntrip_state %p.\n", st);
		if (events & BEV_EVENT_WRITING)
			ntrip_log(st, LOG_NOTICE, "ntripsrv write timeout ntrip_state %p.\n", st);
	}

	ntrip_log(st, LOG_DEBUG, "ntrip_free srv_eventcb %p bev %p\n", st, bev);
	ntrip_deferred_free(st, "ntripsrv_eventcb");
}

/*
 * Stub fonctions needed in threaded mode to send jobs to a worker queue,
 * as the main libevent loop can't be multithreaded.
 */
void ntripsrv_workers_readcb(struct bufferevent *bev, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	joblist_append(st->caster->joblist, ntripsrv_readcb, NULL, bev, arg, 0);
}

void ntripsrv_workers_writecb(struct bufferevent *bev, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	joblist_append(st->caster->joblist, ntripsrv_writecb, NULL, bev, arg, 0);
}

void ntripsrv_workers_eventcb(struct bufferevent *bev, short events, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	joblist_append(st->caster->joblist, NULL, ntripsrv_eventcb, bev, arg, events);
}
