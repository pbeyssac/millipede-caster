#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event_struct.h>
#include <event2/http.h>

#include "conf.h"
#include "ntripsrv.h"
#include "adm.h"
#include "caster.h"
#include "http.h"
#include "jobs.h"
#include "ntrip_common.h"
#include "packet.h"
#include "redistribute.h"
#include "rtcm.h"
#include "util.h"

const char *server_headers = "Server: NTRIP " SERVER_VERSION_STRING "\r\n";

static void
send_server_reply(struct ntrip_state *this, struct evbuffer *ev,
	int status_code, char *status, struct evkeyvalq *headers, char *firstword,
	struct mime_content *m) {
	char date[32];
	time_t tstamp = time(NULL);
	int sent = 0, len;

	firstword = (this->client_version == 1 && firstword && this->user_agent_ntrip)?firstword:"HTTP/1.1";
	struct tm *t = gmtime(&tstamp);
	strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S GMT", t);

	len = evbuffer_add_printf(ev, "%s %d %s\r\n%sDate: %s\r\n", firstword, status_code, status, server_headers, date);
	if (len > 0) sent += len;

	if (this->server_version == 2) {
		evbuffer_add_reference(ev, "Ntrip-Version: Ntrip/2.0\r\n", 26, NULL, NULL);
		sent += 26;
	}
	if (m && m->mime_type) {
		len = evbuffer_add_printf(ev, "Content-Length: %lu\r\nContent-Type: %s\r\n", m->len, m->mime_type);
		if (len > 0) sent += len;
	} else if (m) {
		len = evbuffer_add_printf(ev, "Content-Length: %lu\r\n", m->len);
		if (len > 0) sent += len;
	} if (this->connection_keepalive) {
		evbuffer_add_reference(ev, "Connection: keep-alive\r\n", 24, NULL, NULL);
		len += 24;
	} else {
		evbuffer_add_reference(ev, "Connection: close\r\n", 19, NULL, NULL);
		len += 19;
	}
	if (headers) {
		struct evkeyval *np;
		TAILQ_FOREACH(np, headers, next) {
			len = evbuffer_add_printf(ev, "%s: %s\r\n", np->key, np->value);
			if (len > 0) sent += len;
		}
	}
	evbuffer_add_reference(ev, "\r\n", 2, NULL, NULL);
	len += 2;
	if (m && evbuffer_add_reference(ev, m->s, m->len, mime_free_callback, m) < 0)
		// the call failed so we need to free m instead of letting the callback do it.
		mime_free(m);
	else if (m)
		sent += m->len;
	this->sent_bytes += sent;
}

static int ntripsrv_send_sourcetable(struct ntrip_state *this, struct evbuffer *output) {
	struct sourcetable *sourcetable = stack_flatten(this->caster, &this->caster->sourcetablestack);
	if (sourcetable == NULL)
		return 503;

	struct mime_content *m = sourcetable_get(sourcetable);
	sourcetable_free(sourcetable);
	if (m == NULL)
		return 503;

	if (this->client_version == 1)
		mime_set_type(m, "text/plain");
	send_server_reply(this, output, 200, "OK", NULL, "SOURCETABLE", m);
	return 0;
}

static int _ntripsrv_send_result_ok(struct ntrip_state *this, struct evbuffer *output, const char *mime_type, struct mime_content *m, struct evkeyvalq *opt_headers) {
	struct evkeyvalq headers;
	struct evkeyval *np;
	if (this->client_version == 1) {
		evbuffer_add_reference(output, "ICY 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 52, NULL, NULL);
		this->sent_bytes += 52;
	} else {
		TAILQ_INIT(&headers);
		if (m == NULL && mime_type != NULL)
			evhttp_add_header(&headers, "Content-Type", mime_type);
		evhttp_add_header(&headers, "Cache-Control", "no-store, no-cache, max-age=0");
		evhttp_add_header(&headers, "Pragma", "no-cache");

		if (opt_headers) {
			TAILQ_FOREACH(np, opt_headers, next) {
				evhttp_add_header(&headers, np->key, np->value);
			}
		}
		send_server_reply(this, output, 200, "OK", &headers, NULL, m);
		evhttp_clear_headers(&headers);
	}
	return 0;
}

int ntripsrv_send_result_ok(struct ntrip_state *this, struct evbuffer *output, struct mime_content *m, struct evkeyvalq *opt_headers) {
	return _ntripsrv_send_result_ok(this, output, NULL, m, opt_headers);
}

int ntripsrv_send_stream_result_ok(struct ntrip_state *this, struct evbuffer *output, const char *mime_type, struct evkeyvalq *opt_headers) {
	return _ntripsrv_send_result_ok(this, output, mime_type, NULL, opt_headers);
}

/*
 * Compute content through a callback without any lock, then send it on the provided ntrip_state.
 *
 * Avoids keeping a lock on ntrip_state unless needed, to avoid deadlocks.
 */
void ntripsrv_deferred_output(
	struct ntrip_state *st,
	struct mime_content *(*content_cb)(struct caster_state *caster, struct hash_table *hash),
	struct hash_table *hash) {

	struct mime_content *r = content_cb(st->caster, hash);
	bufferevent_lock(st->bev);
	struct evbuffer *output = bufferevent_get_output(st->bev);
	ntripsrv_send_result_ok(st, output, r, NULL);
	ntrip_log(st, LOG_DEBUG, "ntripsrv_deferred_output WAIT_CLOSE");
	st->state = NTRIP_WAIT_CLOSE;
	bufferevent_unlock(st->bev);
	if (hash)
		hash_table_free(hash);
}

/*
 * Check password in the base
 *
 * Returns:
 *	CHECKPW_MOUNTPOINT_INVALID: mountpoint not found or wrong password, doesn't match a wildcard entry
 *	CHECKPW_MOUNTPOINT_VALID: mountpoint found and password is correct
 *	CHECKPW_MOUNTPOINT_WILDCARD: mountpoint not found, but password matches a wildcard entry
 */
int check_password(struct ntrip_state *this, const char *mountpoint, const char *user, const char *passwd) {
	int r = CHECKPW_MOUNTPOINT_INVALID;
	int explicit_mountpoint = 0;
	struct auth_entry *wildcard_entry = NULL;

	P_RWLOCK_RDLOCK(&this->caster->configlock);

	struct auth_entry *auth = this->caster->source_auth;
	if (auth == NULL) {
		P_RWLOCK_UNLOCK(&this->caster->configlock);
		return CHECKPW_MOUNTPOINT_INVALID;
	}

	ntrip_log(this, LOG_DEBUG, "mountpoint %s user %s", mountpoint, user);
	for (; auth->key != NULL; auth++) {
		if (!strcmp(auth->key, "*")) {
			wildcard_entry = auth;
			continue;
		}
		if (!strcmp(auth->key, mountpoint)) {
			explicit_mountpoint = 1;
			ntrip_log(this, LOG_DEBUG, "mountpoint %s found", mountpoint);
			if (user && strcmp(auth->user, user))
				break;

			if (!strcmp(auth->password, passwd)) {
				ntrip_log(this, LOG_DEBUG, "source %s auth ok", mountpoint);
				r = CHECKPW_MOUNTPOINT_VALID;
				break;
			}
			break;
		}
	}

	if (explicit_mountpoint == 0 && wildcard_entry) {
		/* Mountpoint entry not found, use the wildcard instead */
		if (!strcmp(wildcard_entry->password, passwd)) {
			ntrip_log(this, LOG_DEBUG, "source %s auth ok using wildcard", mountpoint);
			r = CHECKPW_MOUNTPOINT_WILDCARD;
		}
	}

	P_RWLOCK_UNLOCK(&this->caster->configlock);

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

	ntrip_log(st, LOG_DEBUG, "GGAOK pos (%f, %f) list of %d", st->last_pos.lat, st->last_pos.lon, s->size_dist_array);
	dist_table_display(st, s, 10);

	if (st->source_virtual) {
		if (s->dist_array[0].dist > st->max_min_dist) {
			st->max_min_dist = s->dist_array[0].dist;
			ntrip_log(st, LOG_DEBUG, "New maximum distance to source: %.2f", st->max_min_dist);
		} else
			ntrip_log(st, LOG_DEBUG, "Current maximum distance to source: %.2f", st->max_min_dist);

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
				ntrip_log(st, LOG_INFO, "Virtual source ignoring switch from %s to %s due to %.2f hysteresis", st->virtual_mountpoint, m, st->caster->config->hysteresis_m);
			} else {
				enum livesource_state source_state;
				struct livesource *l = livesource_find_on_demand(st->caster, st, m, &s->dist_array[0].pos, s->dist_array[0].on_demand, &source_state);
				if (l && (source_state == LIVESOURCE_RUNNING || (s->dist_array[0].on_demand && source_state == LIVESOURCE_FETCH_PENDING))) {
					if (redistribute_switch_source(st, m, &s->dist_array[0].pos, l) < 0)
						ntrip_log(st, LOG_NOTICE, "Unable to switch source from %s to %s", st->virtual_mountpoint, m);
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
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evkeyvalq opt_headers;

	int method_post_source = 0;

	TAILQ_INIT(&opt_headers);

	ntrip_log(st, LOG_EDEBUG, "ntripsrv_readcb state %d len %d", st->state, evbuffer_get_length(st->filter.raw_input));

	if (ntrip_filter_run_input(st) < 0)
		return;

	while (!err && st->state != NTRIP_WAIT_CLOSE && evbuffer_get_length(st->input) > 0) {
		if (st->state == NTRIP_WAIT_HTTP_METHOD) {
			char *token;

			// Cancel chunk encoding from client by default
			st->chunk_state = CHUNK_NONE;

			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			st->received_bytes += len;
			ntrip_log(st, LOG_EDEBUG, "Method \"%s\", %zd bytes", line, len);
			int i = 0;
			char *septmp = line;
			while ((token = strsep(&septmp, " \t")) != NULL && i < SIZE_HTTP_ARGS) {
				//ntrip_log(st, LOG_EDEBUG, "TOKEN %s", token);
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
			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			st->received_bytes += len;
			ntrip_log(st, LOG_EDEBUG, "Header \"%s\", %zd bytes", line, len);
			if (len != 0) {
				char *key, *value;
				if (!parse_header(line, &key, &value)) {
					ntrip_log(st, LOG_EDEBUG, "parse_header failed on %s", line);
					err = 1;
					break;
				}
				if (!strcasecmp(key, "host")) {
					//
				} else if (!strcasecmp(key, "transfer-encoding")) {
					if (!strcasecmp(value, "chunked"))
						st->chunk_state = CHUNK_INIT;
				} else if (!strcasecmp(key, "content-length")) {
					unsigned long content_length;
					if (sscanf(value, "%lu", &content_length) == 1) {
						st->content_length = content_length;
						st->content_done = 0;
					}
				} else if (!strcasecmp(key, "content-type")) {
					st->content_type = mystrdup(value);
				} else if (!strcasecmp(key, "ntrip-version")) {
					if (!strcasecmp(value, "ntrip/2.0"))
						st->client_version = 2;
				} else if (!strcasecmp(key, "user-agent") || !strcasecmp(key, "source-agent")) {
					if (mystrcasestr(value, "ntrip")) {
						st->user_agent_ntrip = 1;
						// Set NTRIP version to 1, unless it is already known to be 2.
						if (!st->client_version) st->client_version = 1;
					}
					st->user_agent = mystrdup(value);
				} else if (!strcasecmp(key, "authorization")) {
					ntrip_log(st, LOG_EDEBUG, "Header %s: *****", key);
					if (http_decode_auth(value, &st->user, &st->password) < 0) {
						if (st->caster->config->log_level >= LOG_DEBUG) {
							ntrip_log(st, LOG_DEBUG, "Can't decode Authorization: \"%s\"", value);
						} else {
							ntrip_log(st, LOG_INFO, "Can't decode Authorization");
						}
					}
				} else {
					ntrip_log(st, LOG_EDEBUG, "Header %s: %s", key, value);
				}
			} else {
				ntrip_log(st, LOG_EDEBUG, "[End headers]");
				if (st->chunk_state == CHUNK_INIT && ntrip_chunk_decode_init(st) < 0) {
					err = 503;
					break;
				}
				if (!strcmp(st->http_args[0], "SOURCE")) {
					/* Don't log the password */
					ntrip_alog(st, "%s *** %s", st->http_args[0], st->http_args[2]);
				} else {
					// Copy query string if any, clear from the request
					char *querystring = strchr(st->http_args[1], '?');
					if (querystring) {
						st->query_string = mystrdup(querystring+1);
						*querystring = '\0';
					}
					ntrip_alog(st, "%s %s %s", st->http_args[0], st->http_args[1], st->http_args[2]);
				}
				if (!strcmp(st->http_args[0], "GET")) {
					if (st->http_args[1] == NULL || st->http_args[1][0] != '/') {
						err = 400;
						break;
					}
					if (strlen(st->http_args[1]) >= 5 && !memcmp(st->http_args[1], "/adm/", 5)) {
						st->type = "adm";
						admsrv(st, "GET", "/adm", st->http_args[1] + 4, &err, &opt_headers);
						break;
					}

					char *mountpoint = st->http_args[1]+1;
					struct sourceline *sourceline = NULL;
					if (*mountpoint)
						sourceline = stack_find_mountpoint(st->caster, &st->caster->sourcetablestack, mountpoint);

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
						P_MUTEX_LOCK(&st->caster->livesources.delete_lock);
						struct livesource *l = livesource_find_on_demand(st->caster, st, mountpoint, &sourceline->pos, st->source_on_demand, NULL);
						if (l) {
							ntrip_log(st, LOG_DEBUG, "Found requested source %s, on_demand=%d", mountpoint, st->source_on_demand);
							ntripsrv_send_stream_result_ok(st, output, "gnss/data", NULL);
							st->state = NTRIP_WAIT_CLIENT_INPUT;

							/* Regular NTRIP stream client: disable read and write timeouts */
							bufferevent_set_timeouts(bev, NULL, NULL);
							livesource_add_subscriber(l, st);
						} else {
							P_MUTEX_UNLOCK(&st->caster->livesources.delete_lock);
							if (st->client_version == 1) {
								err = ntripsrv_send_sourcetable(st, output);
								st->state = NTRIP_WAIT_CLOSE;
							} else
								err = 404;
							break;
						}
						P_MUTEX_UNLOCK(&st->caster->livesources.delete_lock);
					} else {
						ntripsrv_send_stream_result_ok(st, output, "gnss/data", NULL);
						st->state = NTRIP_WAIT_CLIENT_INPUT;

						/* Regular NTRIP stream client: disable read and write timeouts */
						bufferevent_set_timeouts(bev, NULL, NULL);
					}

					/*
					 * We only limit the send buffer on NTRIP clients, except for the sourcetable.
					 */
					int sndbuf = st->caster->config->backlog_socket;
					if (setsockopt(st->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf) < 0)
						ntrip_log(st, LOG_NOTICE, "setsockopt SO_SNDBUF %d failed", sndbuf);
				} else if (!strcmp(st->http_args[0], "POST") || !strcmp(st->http_args[0], "SOURCE")) {
					char *password;
					char *user;
					char *mountpoint;

					if (!strcmp(st->http_args[0], "POST")) {
						if (strlen(st->http_args[1]) >= 5 && !memcmp(st->http_args[1], "/adm/", 5)) {
							st->type = "adm";
							st->content = (char *)strmalloc(st->content_length+1);
							if (st->content == NULL && st->content_length) {
								err = 503;
								break;
							}
							st->state = NTRIP_WAIT_CLIENT_CONTENT;
							continue;
						}
						method_post_source = 1;
						password = st->password;
						user = st->user;
						st->client_version = 2;
						if (st->http_args[1] == NULL || st->http_args[1][0] != '/') {
							err = 400;
							break;
						}
						mountpoint = st->http_args[1]+1;
					} else {
						method_post_source = 1;
						password = st->http_args[1];
						user = NULL;
						mountpoint = st->http_args[2];
						st->client_version = 1;
					}
					struct sourceline *sourceline = stack_find_mountpoint(st->caster, &st->caster->sourcetablestack, mountpoint);
					if (st->client_version == 2 && (!st->user || !st->password)) {
						err = 401;
						break;
					}
					int r;
					r = check_password(st, mountpoint, user, password);
					if (r == CHECKPW_MOUNTPOINT_INVALID) {
						err = 401;
						break;
					}
					if (!sourceline && r != CHECKPW_MOUNTPOINT_WILDCARD) {
						err = 404;
						break;
					}
					st->wildcard = (r == CHECKPW_MOUNTPOINT_WILDCARD);
					st->type = "source";
					if (st->mountpoint)
						strfree(st->mountpoint);
					st->mountpoint = mystrdup(mountpoint);
					if (st->mountpoint == NULL) {
						err = 503;
						break;
					}
					struct livesource *old_livesource, *new_livesource;
					new_livesource = ntrip_add_livesource(st, st->mountpoint, &old_livesource);
					if (old_livesource != NULL) {
						err = 409;
						break;
					}
					if (new_livesource == NULL) {
						err = 503;
						break;
					}
					if (st->client_version == 1)
						evbuffer_add_reference(output, "ICY 200 OK\r\n\r\n", 14, NULL, NULL);
					else
						ntripsrv_send_stream_result_ok(st, output, NULL, NULL);
					struct timeval read_timeout = { st->caster->config->source_read_timeout, 0 };
					st->state = NTRIP_WAIT_STREAM_SOURCE;
					ntrip_set_rtcm_cache(st);
					bufferevent_set_timeouts(bev, &read_timeout, NULL);
				}
			}
		} else if (st->state == NTRIP_WAIT_CLIENT_INPUT) {
			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			/* Add 1 for the trailing LF or CR LF. We don't care for the exact count. */
			st->received_bytes += len + 1;
			pos_t pos;
			ntrip_log(st, LOG_EDEBUG, "GGA? \"%s\", %zd bytes", line, len);
			if (parse_gga(line, &pos) >= 0) {
				st->last_pos = pos;
				st->last_pos_valid = 1;
				joblist_append_ntrip_locked(st->caster->joblist, st, &ntripsrv_redo_virtual_pos);
			}
		} else if (st->state == NTRIP_WAIT_CLIENT_CONTENT) {
			int len;
			len = evbuffer_remove(st->input, st->content+st->content_done, st->content_length-st->content_done);
			if (len <= 0)
				break;
			st->content_done += len;
			st->received_bytes += len;
			if (st->content_done == st->content_length) {
				st->content[st->content_length] = '\0';
				admsrv(st, "POST", "/adm", st->http_args[1] + 4, &err, &opt_headers);
				break;
			}
		} else if (st->state == NTRIP_WAIT_STREAM_SOURCE) {
			// will increment st->received_bytes itself
			rtcm_packet_handle(st);
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
			send_server_reply(st, output, 400, "Bad Request", NULL, NULL, NULL);
		else if (err == 401) {
			if (st->client_version == 1 && method_post_source)
				evbuffer_add_reference(output, "ERROR - Bad Password\r\n", 22, NULL, NULL);
			else {
				send_server_reply(st, output, 401, "Unauthorized", &opt_headers, NULL, NULL);
				evbuffer_add_reference(output, "401\r\n", 5, NULL, NULL);
			}
		} else if (err == 404) {
			if (st->client_version == 1 && method_post_source)
				evbuffer_add_reference(output, "ERROR - Mount Point Taken or Invalid\r\n", 38, NULL, NULL);
			else
				send_server_reply(st, output, 404, "Not Found", NULL, NULL, NULL);
		} else if (err == 409) {
			if (st->client_version == 1 && method_post_source)
				evbuffer_add_reference(output, "ERROR - Mount Point Taken or Invalid\r\n", 38, NULL, NULL);
			else
				send_server_reply(st, output, 409, "Conflict", NULL, NULL, NULL);
		} else if (err == 500)
			send_server_reply(st, output, 500, "Internal Server Error", NULL, NULL, NULL);
		else if (err == 501)
			send_server_reply(st, output, 501, "Not Implemented", NULL, NULL, NULL);
		else if (err == 503)
			send_server_reply(st, output, 503, "Service Unavailable", NULL, NULL, NULL);
		else
			send_server_reply(st, output, err, "Unknown Error", NULL, NULL, NULL);
		ntrip_log(st, LOG_EDEBUG, "ntripsrv_readcb err %d", err);
		st->state = NTRIP_WAIT_CLOSE;
	}
	evhttp_clear_headers(&opt_headers);
	if (st->state == NTRIP_FORCE_CLOSE)
		ntrip_deferred_free(st, "ntripsrv_readcb");
}

/*
 * Ntrip server write loop: just wait for close.
 *
 * libevent does the job of sending queued packets without need of interference.
 */
void ntripsrv_writecb(struct bufferevent *bev, void *arg)
{
	struct ntrip_state *st = (struct ntrip_state *)arg;

	if (st->state == NTRIP_WAIT_CLOSE) {
		size_t len;
		struct evbuffer *output;
		output = bufferevent_get_output(bev);
		len = evbuffer_get_length(output);
		if (len == 0)
			ntrip_deferred_free(st, "ntripsrv_writecb");
		else
			ntrip_log(st, LOG_EDEBUG, "ntripsrv_writecb remaining len %d", len);
	}
}

void ntripsrv_eventcb(struct bufferevent *bev, short events, void *arg)
{
	int initial_errno = errno;
	struct ntrip_state *st = (struct ntrip_state *)arg;

	if (events & BEV_EVENT_CONNECTED) {
		ntrip_log(st, LOG_INFO, "Connected srv");
		return;
	}

	if (events & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (events & BEV_EVENT_EOF)
			ntrip_log(st, LOG_INFO, "Connection closed (EOF)");
		else {
			char err[256];
			ntrip_log(st, LOG_NOTICE, "Got an error on connection: %s", strerror_r(initial_errno, err, sizeof err));
		}
	} else if (events & BEV_EVENT_TIMEOUT) {
		if (events & BEV_EVENT_READING)
			ntrip_log(st, LOG_NOTICE, "ntripsrv read timeout");
		if (events & BEV_EVENT_WRITING)
			ntrip_log(st, LOG_NOTICE, "ntripsrv write timeout");
	}

	ntrip_log(st, LOG_EDEBUG, "ntrip_free srv_eventcb bev %p", bev);
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
