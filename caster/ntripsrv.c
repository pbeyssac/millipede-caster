#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event_struct.h>
#include <event2/http.h>

#include <openssl/err.h>

#include "conf.h"
#include "ntripsrv.h"
#include "adm.h"
#include "caster.h"
#include "file.h"
#include "http.h"
#include "jobs.h"
#include "ntrip_common.h"
#include "packet.h"
#include "redistribute.h"
#include "request.h"
#include "rtcm.h"
#include "util.h"

const char *server_headers = "Server: NTRIP " SERVER_VERSION_STRING "\r\n";

struct httpcode {
	unsigned short status;
	const char *message;
};

static struct httpcode httpcodes[] = {
	{200, "OK"},
	{400, "Bad Request"},
	{401, "Unauthorized"},
	{404, "Not Found"},
	{405, "Method Not Allowed"},
	{409, "Conflict"},
	{413, "Content Too Large"},
	{431, "Request Header Fields Too Large"},
	{500, "Internal Server Error"},
	{501, "Not Implemented"},
	{503, "Service Unavailable"},
	{0, "Unknown Error"}
};

static void
send_server_reply(struct ntrip_state *this, struct evbuffer *ev,
	int status_code, struct evkeyvalq *headers, char *firstword,
	struct mime_content *m) {
	char date[32];
	time_t tstamp = time(NULL);
	int sent = 0, len;
	const char *msg;

	struct httpcode *htc = httpcodes;
	for (htc = httpcodes; htc->status && htc->status != status_code; htc++);
	msg = htc->message;

	firstword = (this->client_version == 1 && firstword && this->user_agent_ntrip)?firstword:"HTTP/1.1";
	struct tm *t = gmtime(&tstamp);
	strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S GMT", t);

	len = evbuffer_add_printf(ev, "%s %d %s\r\n%sDate: %s\r\n", firstword, status_code, msg, server_headers, date);
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
	}
	if (this->connection_keepalive && this->received_keepalive) {
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

	if (this->client_version != 2)
		mime_set_type(m, "text/plain");
	send_server_reply(this, output, 200, NULL, "SOURCETABLE", m);
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
		send_server_reply(this, output, 200, &headers, NULL, m);
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
	struct mime_content *(*content_cb)(struct caster_state *caster, struct request *req),
	struct request *req) {

	struct mime_content *m = content_cb(st->caster, req);
	bufferevent_lock(st->bev);

	/* Check for NTRIP_END, as we should never get back from this state */
	if (st->state != NTRIP_END) {
		struct evbuffer *output = bufferevent_get_output(st->bev);
		send_server_reply(st, output, req->status, NULL, NULL, m);

		if (st->connection_keepalive && st->received_keepalive)
			st->state = NTRIP_WAIT_HTTP_METHOD;
		else
			st->state = NTRIP_WAIT_CLOSE;
	} else
		mime_free(m);
	bufferevent_unlock(st->bev);
	if (req)
		request_free(req);
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

	struct auth_entry *auth = this->config->source_auth;
	if (auth == NULL) {
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
	return r;
}

/*
 * Do rate limit checks then run ntripsrv_redo_virtual_pos()
 * if adequate.
 *
 * Required lock: ntrip_state
 */
void ntripsrv_redo_virtual_pos_limited(struct ntrip_state *st) {
	if (!st->last_pos_valid || !st->source_virtual)
		return;

	struct timeval t0, t1;
	gettimeofday(&t0, NULL);
	timersub(&t0, &st->last_recompute_date, &t1);

	/* Ignore if too soon since last recompute */
	if (t1.tv_sec < st->config->min_nearest_recompute_interval)
		return;

	/* Ignore if too close to last recompute, and max interval not reached */
	if (st->last_recompute_date.tv_sec
		&& t1.tv_sec < st->config->max_nearest_recompute_interval
		&& distance(&st->last_pos, &st->last_recompute_pos) < st->config->min_nearest_recompute_pos_delta)
		return;

	ntripsrv_redo_virtual_pos(st);
}

/*
 * Recompute the nearest base list for the current client;
 * initiate a base switch if adequate.
 *
 * Required lock: ntrip_state
 */
void ntripsrv_redo_virtual_pos(struct ntrip_state *st) {
	if (!st->last_pos_valid || !st->source_virtual)
		return;

	struct timeval t0, t1;
	gettimeofday(&t0, NULL);

	struct sourcetable *pos_sourcetable = stack_flatten_dist(st->caster, &st->caster->sourcetablestack, &st->last_pos, st->lookup_dist);
	if (pos_sourcetable == NULL)
		return;

	gettimeofday(&t1, NULL);
	timersub(&t1, &t0, &t1);
	ntrip_log(st, LOG_EDEBUG, "stack_flatten_dist %.3f ms", t1.tv_sec*1000+t1.tv_usec/1000.);

	struct dist_table *s = sourcetable_find_pos(pos_sourcetable, &st->last_pos);
	if (s == NULL) {
		sourcetable_free(pos_sourcetable);
		return;
	}

	float last_lookup_dist = st->lookup_dist;

	if (st->config->nearest_base_count_target > 0) {
		if (s->size_dist_array < st->config->nearest_base_count_target) {
			st->lookup_dist *= 2;
			if (st->lookup_dist > st->config->max_nearest_lookup_distance_m)
				st->lookup_dist = st->config->max_nearest_lookup_distance_m;
		} else
			st->lookup_dist = s->dist_array[st->config->nearest_base_count_target-1].dist + 1000;
	}

	if (s->size_dist_array == 0) {
		dist_table_free(s);
		sourcetable_free(pos_sourcetable);
		return;
	}

	st->last_recompute_pos = st->last_pos;
	st->last_recompute_date = t0;

	gettimeofday(&t1, NULL);
	timersub(&t1, &t0, &t1);

	ntrip_log(st, LOG_DEBUG, "GGAOK pos (%f, %f) list of %d lookup dist %.3f km, %.3f ms", st->last_pos.lat, st->last_pos.lon, s->size_dist_array, last_lookup_dist/1000, t1.tv_sec*1000+t1.tv_usec/1000.);
	dist_table_display(st, s, 10);

	if (s->dist_array[0].dist > st->max_min_dist) {
		st->max_min_dist = s->dist_array[0].dist;
		ntrip_log(st, LOG_DEBUG, "New maximum distance to source: %.2f", st->max_min_dist);
	} else
		ntrip_log(st, LOG_DEBUG, "Current maximum distance to source: %.2f", st->max_min_dist);

	char *m = s->dist_array[0].mountpoint;

	int current_livesource_live = 0;
	if (st->virtual_mountpoint)
		current_livesource_live = livesource_exists(st->caster, st->virtual_mountpoint, &st->mountpoint_pos);

	if (!current_livesource_live || strcmp(m, st->virtual_mountpoint)) {
		/*
		 * The closest base has changed.
		 */

		/*
		 * Recheck with some hysteresis to favor the current station and avoid useless switching
		 * between very close stations.
		 */

		float current_dist = st->virtual_mountpoint ? (distance(&st->mountpoint_pos, &st->last_pos)-st->config->hysteresis_m) : 1e10;

		if (current_livesource_live && current_dist < s->dist_array[0].dist) {
			ntrip_log(st, LOG_DEBUG, "Virtual source ignoring switch from %s to %s due to %.2f hysteresis", st->virtual_mountpoint, m, st->config->hysteresis_m);
		} else {
			enum livesource_state source_state;
			struct livesource *l = livesource_find_on_demand(st->caster, st, m, &s->dist_array[0].pos, 1, s->dist_array[0].on_demand, &source_state);
			if (l) {
				if (source_state == LIVESOURCE_RUNNING || (s->dist_array[0].on_demand && source_state == LIVESOURCE_FETCH_PENDING)) {
					struct packet *packet_pos = ntrip_get_rtcm_pos(st, m);
					if (packet_pos) {
						st->rtcm_client_state = NTRIP_RTCM_POS_OK;
						packet_send(packet_pos, st, time(NULL));
						packet_decref(packet_pos);
					} else
						st->rtcm_client_state = NTRIP_RTCM_POS_WAIT;
					st->tmp_pos = s->dist_array[0].pos;
					joblist_append_ntrip_livesource(st->caster->joblist, redistribute_switch_source, st, l, NULL);
				}
				livesource_decref(l);
			}
		}
	}

	sourcetable_free(pos_sourcetable);
	dist_table_free(s);
}

static int _handle_forwarded_header(struct ntrip_state *st, struct config *config, char *value) {
	union sock realaddr;

	int trust = 0;
	for (int i = 0; i < config->trusted_http_proxy_count; i++)
		if (ip_in_prefix(&config->trusted_http_proxy_prefixes[i], &st->peeraddr)) {
			trust = 1;
			break;
		}

	if (!trust)
		/* Ignore header, don't check quota from header IP */
		return 0;

	char *realaddr_str = strrchr(value, ',');
	if (realaddr_str == NULL)
		realaddr_str = value;
	else
		realaddr_str++;
	while (isspace(*realaddr_str)) realaddr_str++;

	memset(&realaddr, 0, sizeof realaddr);
	if (ip_convert(realaddr_str, &realaddr) <= 0)
		return 400;

	ntrip_log(st, LOG_EDEBUG, "quota changing");
	int ip_count = ntrip_quota_change(st, &realaddr);
	st->realaddr = realaddr;
	st->peeraddr = realaddr;
	int quota = ntrip_quota_get(st, &realaddr);
	ntrip_log(st, LOG_EDEBUG, "quota changed, count %d quota %d", ip_count, quota);
	if (ntrip_quota_check(st, quota, ip_count) < 0)
		return 1;
	return 0;
}

/*
 * Main NTRIP server HTTP connection loop.
 */
void ntripsrv_readcb(struct bufferevent *bev, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	char *line = NULL;
	size_t len;
	size_t waiting_len;
	int err = 0;
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evkeyvalq opt_headers;

	int method_post_source = 0;

	TAILQ_INIT(&opt_headers);

	struct config *config = ntrip_refresh_config(st);

	ntrip_log(st, LOG_EDEBUG, "ntripsrv_readcb state %d len %d", st->state, evbuffer_get_length(st->filter.raw_input));

	if (ntrip_filter_run_input(st) < 0)
		return;

	if (st->chunk_state == CHUNK_END && evbuffer_get_length(st->input) == 0) {
		st->state = NTRIP_FORCE_CLOSE;
		err = 1;
	}

	while (!err && st->state != NTRIP_WAIT_CLOSE && (waiting_len = evbuffer_get_length(st->input)) > 0) {
		if (st->state == NTRIP_WAIT_HTTP_METHOD) {
			char *token;

			ntrip_clear_request(st);
			strfree(st->mountpoint);
			st->mountpoint = NULL;

			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if ((line?len:waiting_len) > config->http_header_max_size) {
				err = 400;
				break;
			}
			if (!line)
				break;
			st->received_bytes += len;
			ntrip_log(st, LOG_DEBUG, "Method \"%s\", %zd bytes", line, len);
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
			st->n_http_args = i;
			if (err) break;

			if (i < 2 || token != NULL) {
				err = 400;
				break;
			}

			/* No http version specified, assume 0.9 */
			if (i == 2) {
				st->http_args[2] = mystrdup("HTTP/0.9");
				if (st->http_args[2] == NULL) {
					err = 503;
					break;
				}
			}
			st->state = NTRIP_WAIT_HTTP_HEADER;
			st->received_keepalive = 0;
		} else if (st->state == NTRIP_WAIT_HTTP_HEADER) {
			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if ((line?len:waiting_len) > config->http_header_max_size) {
				err = 431;
				break;
			}
			if (!line)
				break;
			st->received_bytes += len;
			ntrip_log(st, LOG_EDEBUG, "Header \"%s\", %zd bytes", line, len);
			if (len != 0) {
				char *key, *value;
				if (!parse_header(line, &key, &value)) {
					ntrip_log(st, LOG_EDEBUG, "parse_header failed on %s", line);
					err = 400;
					break;
				}
				if (!strcasecmp(key, "host")) {
					//
				} else if (!strcasecmp(key, "transfer-encoding")) {
					if (!strcasecmp(value, "chunked"))
						st->chunk_state = CHUNK_INIT;
				} else if (!strcasecmp(key, "connection")) {
					if (!strcasecmp(value, "keep-alive"))
						st->received_keepalive = 1;
				} else if (!strcasecmp(key, "content-length")) {
					unsigned long content_length;
					int length_err;
					if (sscanf(value, "%lu", &content_length) == 1) {
						length_err = (content_length > config->http_content_length_max);
						if (length_err) {
							ntrip_log(st, LOG_NOTICE, "Content-Length %d: exceeds max configured value %d",
								content_length, config->http_content_length_max);
							err = 413;
							break;
						}
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
					if (http_decode_auth(value, &st->scheme_basic, &st->user, &st->password) < 0) {
						if (config->log_level >= LOG_DEBUG) {
							ntrip_log(st, LOG_DEBUG, "Can't decode Authorization: \"%s\"", value);
						} else {
							ntrip_log(st, LOG_NOTICE, "Can't decode Authorization");
						}
					}
				} else if (!strcasecmp(key, "ntrip-gga")) {
					pos_t pos;
					ntrip_log(st, LOG_EDEBUG, "Header GGA? \"%s\"", value);
					if (parse_gga(value, &pos) >= 0) {
						st->last_pos = pos;
						st->last_pos_valid = 1;
					}
				} else if (!strcasecmp(key,
						config->trusted_http_ip_header ?
						config->trusted_http_ip_header : "x-forwarded-for")) {
					err = _handle_forwarded_header(st, config, value);
					if (err)
						break;
				} else {
					ntrip_log(st, LOG_EDEBUG, "Header %s: %s", key, value);
				}
			} else {
				ntrip_log(st, LOG_EDEBUG, "[End headers]");

				if (st->content_length) {
					st->content = (char *)strmalloc(st->content_length+1);
					if (st->content == NULL) {
						err = 503;
						break;
					}
				}
				if (st->client_version == 1)
					st->connection_keepalive = 0;
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
						admsrv(st, st->http_args[0], "/adm", st->http_args[1] + 4, &err, &opt_headers);
						break;
					}

					if (config->webroots_count) {
						if (filesrv(st, st->http_args[1], &err, &opt_headers) >= 0 || err)
							break;
					}

					char *mountpoint = st->http_args[1]+1;
					struct sourceline *sourceline = NULL;
					struct livesource *l = NULL;

					if (*mountpoint) {
						if (config->dyn->rtcm_filter && rtcm_filter_check_mountpoint(config->dyn, mountpoint))
							st->rtcm_filter = 1;
						/*
						 * Find both a relevant source line and a live source (actually live or on-demand).
						 */
						sourceline = stack_find_mountpoint(st->caster, &st->caster->sourcetablestack, mountpoint);
						l = livesource_find_and_subscribe(st->caster, st, mountpoint, NULL, 1, sourceline?sourceline->on_demand:0);
					}

					/*
					 * Source not found either in the sourcetables or as a live source:
					 * reply with the sourcetable in NTRIP1, error 404 in NTRIP2.
					 *
					 * Empty mountpoint name: always reply with the sourcetable.
					 */
					if (*mountpoint == '\0' || (!sourceline && !l && st->client_version == 1)) {
						st->type = "client";
						err = ntripsrv_send_sourcetable(st, output);
						if (st->connection_keepalive && st->received_keepalive) {
							if (st->content_length)
								st->state = NTRIP_WAIT_CLIENT_CONTENT;
							else
								st->state = NTRIP_WAIT_HTTP_METHOD;
							continue;
						} else {
							st->state = NTRIP_WAIT_CLOSE;
							break;
						}
					}
					st->connection_keepalive = 0;
					if (!sourceline && !l) {
						err = 404;
						break;
					}

					if (sourceline) {
						st->source_virtual = sourceline->virtual;
						st->source_on_demand = sourceline->on_demand;
					} else {
						st->source_virtual = 0;
						st->source_on_demand = 1;
					}

					st->type = "client";

					/* Regular NTRIP stream client: set a read timeout to check for data sent */
					struct timeval read_timeout = { config->idle_max_delay+1, 0 };
					bufferevent_set_timeouts(bev, &read_timeout, NULL);

					if (!st->source_virtual) {
						if (!l) {
							if (st->client_version == 1) {
								err = ntripsrv_send_sourcetable(st, output);
								st->state = NTRIP_WAIT_CLOSE;
							} else
								err = 404;
							break;
						}
						ntrip_log(st, LOG_DEBUG, "Found requested source %s, on_demand=%d", mountpoint, st->source_on_demand);
					}

					st->mountpoint = mystrdup(mountpoint);
					if (st->mountpoint == NULL) {
						err = 503;
						break;
					}
					ntripsrv_send_stream_result_ok(st, output, "gnss/data", NULL);
					st->state = NTRIP_WAIT_CLIENT_INPUT;
					st->rtcm_client_state = st->source_virtual ? NTRIP_RTCM_POS_WAIT : NTRIP_RTCM_POS_OK;

					/* If we have a position (Ntrip-gga header), use it */

					if (st->last_pos_valid)
						joblist_append_ntrip_locked(st->caster->joblist, st, &ntripsrv_redo_virtual_pos_limited);

					/*
					 * We only limit the send buffer on NTRIP clients, except for the sourcetable.
					 */
					int sndbuf = config->backlog_socket;
					if (setsockopt(st->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf) < 0)
						ntrip_log(st, LOG_NOTICE, "setsockopt SO_SNDBUF %d failed", sndbuf);
				} else if (!strcmp(st->http_args[0], "POST") || !strcmp(st->http_args[0], "SOURCE")) {
					char *password;
					char *user;
					char *mountpoint;

					if (!strcmp(st->http_args[0], "POST")) {
						if (strlen(st->http_args[1]) >= 5 && !memcmp(st->http_args[1], "/adm/", 5)) {
							st->type = "adm";
							if (!st->content_length) {
								err = 400;
								break;
							}
							st->state = NTRIP_WAIT_CLIENT_CONTENT;
							struct timeval adm_read_timeout = { 0, 0 };
							bufferevent_set_timeouts(bev, &adm_read_timeout, NULL);
							continue;
						}
						if (!st->scheme_basic) {
							err = 401;
							break;
						}
						method_post_source = 1;
						st->connection_keepalive = 0;
						password = st->password;
						user = st->user;
						st->client_version = 2;
						if (st->http_args[1] == NULL || st->http_args[1][0] != '/') {
							err = 400;
							break;
						}
						mountpoint = st->http_args[1]+1;
					} else {
						if (st->n_http_args == 2) {
							err = 400;
							break;
						}
						method_post_source = 1;
						st->connection_keepalive = 0;
						password = st->http_args[1];
						user = NULL;
						mountpoint = st->http_args[2];

						/*
						 * Drop the leading /, if any.
						 * The / should always be present as per the Ntrip1 spec, but most implementations
						 * don't send it.
						 */
						if (st->http_args[2][0] == '/')
							mountpoint++;
						st->client_version = 1;
					}
					struct sourceline *sourceline = stack_find_local_mountpoint(st->caster, &st->caster->sourcetablestack, mountpoint);
					if (st->client_version == 2 && (!st->scheme_basic || !st->user || !st->password)) {
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
					int connected = livesource_connected(st, st->mountpoint);
					if (!connected) {
						err = 409;
						break;
					}
					if (connected < 0) {
						err = 503;
						break;
					}
					if (st->client_version == 1)
						evbuffer_add_reference(output, "ICY 200 OK\r\n\r\n", 14, NULL, NULL);
					else
						ntripsrv_send_stream_result_ok(st, output, NULL, NULL);
					struct timeval read_timeout = { config->source_read_timeout, 0 };
					st->state = NTRIP_WAIT_STREAM_SOURCE;
					joblist_append_ntrip_locked(st->caster->joblist, st, ntrip_set_rtcm_cache);
					bufferevent_set_timeouts(bev, &read_timeout, NULL);
				} else {
					err = 501;
					break;
				}
			}
		} else if (st->state == NTRIP_WAIT_CLIENT_INPUT) {
			line = evbuffer_readln(st->input, &len, EVBUFFER_EOL_CRLF);
			if (!line)
				break;
			/* Add 1 for the trailing LF or CR LF. We don't care for the exact count. */
			st->received_bytes += len + 1;
			pos_t pos;
			if (parse_gga(line, &pos) >= 0) {
				st->last_pos = pos;
				st->last_pos_valid = 1;
				joblist_append_ntrip_locked(st->caster->joblist, st, &ntripsrv_redo_virtual_pos_limited);
			} else
				ntrip_log(st, LOG_DEBUG, "BAD GGA \"%s\", %zd bytes", line, len);
		} else if (st->state == NTRIP_WAIT_CLIENT_CONTENT) {
			int len;
			len = evbuffer_remove(st->input, st->content+st->content_done, st->content_length-st->content_done);
			if (len <= 0)
				break;
			st->content_done += len;
			st->received_bytes += len;
			if (st->content_done == st->content_length) {
				st->content[st->content_length] = '\0';
				if (strlen(st->http_args[1]) >= 5 && !memcmp(st->http_args[1], "/adm/", 5)) {
					st->type = "adm";
					admsrv(st, st->http_args[0], "/adm", st->http_args[1] + 4, &err, &opt_headers);
				}
				st->state = NTRIP_WAIT_HTTP_METHOD;
			}
		} else if (st->state == NTRIP_WAIT_STREAM_SOURCE) {
			if (st->chunk_state == CHUNK_END) {
				st->state = NTRIP_FORCE_CLOSE;
				err = 1;
				break;
			}
			// will increment st->received_bytes itself
			rtcm_packet_handle(st);
			break;
		} else if (st->state == NTRIP_FORCE_CLOSE) {
			err = 1;
			break;
		} else {
			/* Catchall for unknown states */
			st->state = NTRIP_FORCE_CLOSE;
			err = 1;
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
		if (err == 401 && st->client_version == 1 && method_post_source)
			evbuffer_add_reference(output, "ERROR - Bad Password\r\n", 22, NULL, NULL);
		else if (err == 404 && st->client_version == 1 && method_post_source)
			evbuffer_add_reference(output, "ERROR - Mount Point Taken or Invalid\r\n", 38, NULL, NULL);
		else if (err == 409 && st->client_version == 1 && method_post_source)
			evbuffer_add_reference(output, "ERROR - Mount Point Taken or Invalid\r\n", 38, NULL, NULL);
		else if (err >= 100)
			send_server_reply(st, output, err, &opt_headers, NULL, NULL);
		ntrip_log(st, LOG_EDEBUG, "ntripsrv_readcb err %d", err);
		st->state = NTRIP_WAIT_CLOSE;
	}
	evhttp_clear_headers(&opt_headers);
	if (st->state == NTRIP_FORCE_CLOSE)
		ntrip_decref_end(st, "ntripsrv_readcb");
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
			ntrip_decref_end(st, "ntripsrv_writecb");
		else
			ntrip_log(st, LOG_EDEBUG, "ntripsrv_writecb remaining len %d", len);
	}
}

void ntripsrv_eventcb(struct bufferevent *bev, short events, void *arg)
{
	int initial_errno = errno;
	struct ntrip_state *st = (struct ntrip_state *)arg;
	struct config *config;

	config = ntrip_refresh_config(st);

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
		if (events & BEV_EVENT_READING) {

			/*
			 * Special case for NTRIP clients: in case of a read timeout, check whether we have been
			 * recently sending data.
			 */
			if (st->state == NTRIP_WAIT_CLIENT_INPUT) {
				int idle_time = time(NULL) - st->last_send;
				if (idle_time <= config->idle_max_delay) {
					/* Reenable read */
					bufferevent_enable(bev, EV_READ);
					return;
				}
				/* No data sent or read, close. */
				ntrip_log(st, LOG_NOTICE, "last_send: %d seconds ago, max %d, dropping", idle_time, config->idle_max_delay);
			} else
				ntrip_log(st, LOG_NOTICE, "ntripsrv read timeout");
		}
		if (events & BEV_EVENT_WRITING)
			ntrip_log(st, LOG_NOTICE, "ntripsrv write timeout");
	}

	ntrip_log(st, LOG_EDEBUG, "ntrip_free srv_eventcb bev %p", bev);
	ntrip_decref_end(st, "ntripsrv_eventcb");
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

void ntripsrv_listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *arg)
{
	struct listener *listener_conf = arg;
	struct caster_state *caster = listener_conf->caster;
	struct event_base *base = caster->base;
	struct bufferevent *bev;
	SSL *ssl = NULL;

	if (listener_conf->tls) {
		ssl = SSL_new(listener_conf->ssl_server_ctx);
		if (ssl == NULL) {
			ERR_print_errors_cb(caster_tls_log_cb, caster);
			close(fd);
			return;
		}

		if (threads)
			bev = bufferevent_openssl_socket_new(caster->base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
		else
			bev = bufferevent_openssl_socket_new(caster->base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	} else {
		if (threads)
			bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
		else
			bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	}

	if (bev == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Error constructing bufferevent!");
		close(fd);
		return;
	}

	struct ntrip_state *st = ntrip_new(caster, bev, NULL, 0, NULL, NULL);
	if (st == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Error constructing ntrip_state for a new connection!");
		bufferevent_free(bev);
		close(fd);
		return;
	}

	st->ssl = ssl;
	st->bev_close_on_free = 1;
	st->connection_keepalive = 1;
	ntrip_set_peeraddr(st, sa, socklen);
	ntrip_set_localaddr(st);

	st->state = NTRIP_WAIT_HTTP_METHOD;

	if (ntrip_register_check(st) < 0) {
		ntrip_decref_end(st, "ntripsrv_listener_cb");
		return;
	}

	ntrip_log(st, LOG_INFO, "New connection");

	// evbuffer_defer_callbacks(bufferevent_get_output(bev), st->caster->base);

	if (threads)
		bufferevent_setcb(bev, ntripsrv_workers_readcb, ntripsrv_workers_writecb, ntripsrv_workers_eventcb, st);
	else
		bufferevent_setcb(bev, ntripsrv_readcb, ntripsrv_writecb, ntripsrv_eventcb, st);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	struct timeval read_timeout = { st->config->ntripsrv_default_read_timeout, 0 };
	struct timeval write_timeout = { st->config->ntripsrv_default_write_timeout, 0 };
	bufferevent_set_timeouts(bev, &read_timeout, &write_timeout);
}
