#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <json-c/json_tokener.h>

#include "conf.h"
#include "adm.h"
#include "api.h"
#include "hash.h"
#include "livesource.h"
#include "log_stream.h"
#include "ntripsrv.h"
#include "prometheus.h"
#include "request.h"
#include "sourcetable.h"
#include "ws_log.h"

/*
 * Constant-time string comparison to avoid timing attacks on token / password checks.
 * Returns 0 if equal, non-zero otherwise (same semantics as memcmp(3)).
 */
static int ct_strcmp(const char *a, const char *b) {
	if (a == NULL || b == NULL)
		return 1;
	const unsigned char *ua = (const unsigned char *)a;
	const unsigned char *ub = (const unsigned char *)b;
	int diff = 0;
	size_t i = 0;
	while (1) {
		unsigned char ca = ua[i];
		unsigned char cb = ub[i];
		/* If one ended before the other, the byte will be 0 — XOR catches it */
		diff |= ca ^ cb;
		if (ca == 0 || cb == 0)
			break;
		i++;
	}
	/* diff == 0 iff both strings ended at the same length and matched byte-for-byte */
	return diff != 0;
}

/*
 * Authenticate an admin /api/v1/ request.
 *
 * Tries the following auth methods in order:
 *   1. HTTP Basic (Authorization: Basic <base64(user:password)>) — already
 *      parsed by http_decode_auth() into st->user and st->password.
 *   2. HTTP Bearer (Authorization: Bearer <token>) — also parsed by
 *      http_decode_auth(); st->user holds the token, st->password is NULL.
 *      Validated against config->admin_token (constant-time compare).
 *   3. Query string / POST body: ?user=X&password=Y OR ?token=Z.
 *      The token form is validated against config->admin_token.
 *      The user/password form is validated via check_password() against
 *      config->admin_user.
 *
 * Returns:
 *   1 if authenticated,
 *   0 if not authenticated (caller should send 401),
 *  -1 on internal error (caller should send 500).
 *
 * On failure, WWW-Authenticate header(s) are added to *headers so the
 * client knows which schemes are accepted.
 */
static int check_admin_auth(struct ntrip_state *st, struct request *req,
			    struct evkeyvalq *headers, const char *root_uri) {
	struct config *cfg = st->config;

	/* 1. Bearer token from Authorization header (preferred for SSE). */
	if (st->user && st->password == NULL && cfg->admin_token) {
		if (ct_strcmp(st->user, cfg->admin_token) == 0)
			return 1;
	}

	/* 2. HTTP Basic auth header. */
	if (st->user && st->password) {
		if (check_password(st, cfg->admin_user, st->user, st->password))
			return 1;
	}

	/* 3. Query string / POST body credentials. */
	if (req && req->hash) {
		/* 3a. ?token=<admin_token> */
		if (cfg->admin_token) {
			char *tok = hash_table_get(req->hash, "token");
			if (tok && ct_strcmp(tok, cfg->admin_token) == 0)
				return 1;
		}
		/* 3b. ?user=X&password=Y */
		char *user = hash_table_get(req->hash, "user");
		char *password = hash_table_get(req->hash, "password");
		if (user && password && check_password(st, cfg->admin_user, user, password))
			return 1;
	}

	/* Not authenticated — advertise all supported schemes. */
	if (headers) {
		if (cfg->admin_token) {
			char *www_auth = (char *)strmalloc(strlen(root_uri) + 64);
			if (www_auth) {
				snprintf(www_auth, strlen(root_uri) + 64,
					"Basic realm=\"%s\", Bearer realm=\"%s\"",
					root_uri, root_uri);
				evhttp_add_header(headers, "WWW-Authenticate", www_auth);
				strfree(www_auth);
			} else
				return -1;
		} else {
			int len = strlen(root_uri) + 15;
			char *www_auth = (char *)strmalloc(len);
			if (www_auth) {
				snprintf(www_auth, len, "Basic realm=\"%s\"", root_uri);
				evhttp_add_header(headers, "WWW-Authenticate", www_auth);
				strfree(www_auth);
			} else
				return -1;
		}
	}
	return 0;
}

/*
 * Handle GET /api/v1/logs/stream — Server-Sent Events (SSE) endpoint
 * for real-time log streaming.
 *
 * Sends the HTTP response headers, registers the bufferevent as a log
 * stream subscriber, and sets the ntrip_state to NTRIP_IDLE_CLIENT so
 * the connection stays open until the client disconnects.
 *
 * Returns 0 on success (connection kept open), -1 on error (caller
 * should set *err appropriately).
 */
static int handle_logs_stream_sse(struct ntrip_state *st, struct evkeyvalq *headers) {
	struct evbuffer *output = bufferevent_get_output(st->bev);

	/* Send HTTP 200 + SSE headers. We use Connection: close because
	 * we don't want the client to pipeline another request on the
	 * same connection (we'll be streaming forever). */
	evbuffer_add_printf(output,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/event-stream; charset=utf-8\r\n"
		"Cache-Control: no-cache, no-transform\r\n"
		"Connection: close\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"X-Accel-Buffering: no\r\n"  /* disable nginx buffering */
		"\r\n");

	/* Send an initial "hello" event so the client knows we're alive. */
	evbuffer_add_printf(output,
		"event: hello\n"
		"data: {\"message\":\"SSE log stream connected\"}\n\n");

	/* Subscribe the bufferevent to the log stream. */
	void *sub = log_stream_subscribe(st->caster->log_stream, st->bev);
	if (sub == NULL) {
		evbuffer_add_printf(output,
			"event: error\n"
			"data: {\"message\":\"Could not subscribe to log stream\"}\n\n");
		/* Force close after the write completes. */
		ntrip_set_state(st, NTRIP_WAIT_CLOSE);
		return -1;
	}
	atomic_store(&st->log_stream_sub, sub);

	/* Keep the connection open. NTRIP_IDLE_CLIENT means "waiting for
	 * something to send" — which is exactly our case (the log stream
	 * timer will push new entries to us). The libevent bufferevent
	 * will notify us on EOF/error so we can clean up. */
	ntrip_set_state(st, NTRIP_IDLE_CLIENT);
	st->connection_keepalive = 0;  /* don't let the framework close us */

	return 0;
}

int admsrv(struct ntrip_state *st, const char *method, const char *root_uri, const char *uri, int *err, struct evkeyvalq *headers) {
	struct evbuffer *output = bufferevent_get_output(st->bev);
	int json_post = 0;
	struct request *req = request_new();
	if (req == NULL) {
		*err = 503;
		return -1;
	}
	req->st = st;

	st->client_version = 0;         // force a straight HTTP reply regardless of client headers

	/*
	 * Look for key=value arguments in url-encoded form, either in the request (GET) or in the body (POST).
	 *
	 * Build a hash table from them.
	 */
	if (!strcmp(method, "POST")) {
		if (st->content_type
		    && (strcmp(st->content_type, "application/x-www-form-urlencoded") && strcmp(st->content_type, "application/json"))) {
			request_free(req);
			*err = 503;
			return -1;
		}
		if (!strcmp(st->content_type, "application/json"))
			json_post = 1;

		if (!st->content) {
			request_free(req);
			*err = 400;
			return -1;
		}
		if (!strcmp(st->content_type, "application/x-www-form-urlencoded")) {
			req->hash = hash_from_urlencoding(st->content);
			if (!req->hash) {
				request_free(req);
				*err = 503;
				return -1;
			}
		}
	} else if (!strcmp(method, "GET") && st->query_string) {
		req->hash = hash_from_urlencoding(st->query_string);
		if (!req->hash) {
			request_free(req);
			*err = 503;
			return -1;
		}
	}

	/*
	 * /api/v1/ endpoints accept auth from ANY of:
	 *   - HTTP Basic auth header (Authorization: Basic <base64>)
	 *   - HTTP Bearer auth header (Authorization: Bearer <token>)
	 *     — validated against config->admin_token
	 *   - query string / POST body: ?user=X&password=Y OR ?token=Z
	 *     (token is validated against config->admin_token)
	 * The Bearer / ?token= forms are useful for EventSource (SSE),
	 * which cannot set custom headers — the Web UI passes the token
	 * in the SSE URL query string.
	 */
	int is_api_v1 = (strncmp(uri, "/api/v1/", 8) == 0);

	if (is_api_v1) {
		int auth_ok = check_admin_auth(st, req, headers, root_uri);
		if (auth_ok < 0) {
			request_free(req);
			*err = 500;
			return -1;
		}
		if (!auth_ok) {
			request_free(req);
			*err = 401;
			return -1;
		}

		/* Special-case: SSE log stream endpoint. Handle it before
		 * the regular dispatch because it doesn't return a
		 * mime_content (it keeps the connection open). */
		if (!strcmp(method, "GET") && !strcmp(uri, "/api/v1/logs/stream")) {
			request_free(req);
			return handle_logs_stream_sse(st, headers);
		}

		/* Special-case: WebSocket log stream endpoint. Handle
		 * before regular dispatch because it performs a WebSocket
		 * handshake (HTTP 101 Switching Protocols) and keeps the
		 * connection open for bidirectional messages. */
		if (!strcmp(method, "GET") && !strcmp(uri, "/api/v1/logs/ws")) {
			request_free(req);
			return handle_logs_ws(st, headers);
		}

		struct uri_calls {
			const char *uri;
			const char *method;
			struct mime_content *(*content_cb)(struct caster_state *caster, struct request *req);
		};
		const struct uri_calls calls[] = {
			{"/api/v1/net", "GET", api_ntrip_list_json},
			{"/api/v1/rtcm", "GET", api_rtcm_json},
			{"/api/v1/rtcm/frequencies", "GET", api_rtcm_freq_json},
			{"/api/v1/rtcm/ringbuffer", "GET", api_rtcm_ringbuffer_json},
			{"/api/v1/rinex", "GET", api_rinex},
			{"/api/v1/mem","GET", api_mem_json},
			{"/api/v1/nodes","GET", api_nodes_json},
			{"/api/v1/livesources", "GET", livesource_list_json},
			{"/api/v1/sourcetables", "GET", sourcetable_list_json},
			{"/api/v1/metrics", "GET", prometheus_metrics_text},
			{"/api/v1/reload", "POST", api_reload_json},
			{"/api/v1/drop", "POST", api_drop_json},
			{NULL, NULL, NULL}
		};

		int i;
		for (i = 0; calls[i].uri; i++) {
			if (!strcmp(uri, calls[i].uri))
				break;
		}

		if (calls[i].uri == NULL) {
			request_free(req);
			*err = 404;
			return -1;
		}
		if (strcmp(method, calls[i].method)) {
			request_free(req);
			*err = 405;
			return -1;
		}

		joblist_append_ntrip_unlocked_content(st->caster->joblist, ntripsrv_deferred_output, st, calls[i].content_cb, req);
		return 0;
	}

	if (req->hash) {
		/*
		 * Found url-encoded key=value pairs in the request — but
		 * the URI is not /api/v1/. Fall through to legacy auth.
		 */
	} else if (json_post) {
		req->json = st->content ? json_tokener_parse(st->content) : NULL;
		if (req->json == NULL) {
			*err = 400;
		} else if (!strcmp(uri, "/api/v1/sync") && !strcmp(method, "POST")) {
			if (st->config->syncer_auth == NULL
					|| st->password == NULL || st->scheme_basic || strcmp(st->config->syncer_auth, st->password)) {
				*err = 401;
			} else {
				ntripsrv_deferred_output(st, api_sync_json, req);
				return 0;
			}
		} else
			*err = 404;
		request_free(req);
		return -1;
	}

	/* Legacy access */

	if (!st->user || !check_password(st, st->config->admin_user, st->user, st->password)) {
		request_free(req);
		int www_auth_value_len = strlen(root_uri) + 15;
		char *www_auth_value = (char *)strmalloc(www_auth_value_len);

		if (!www_auth_value) {
			ntrip_log(st, LOG_CRIT, "ntripsrv: out of memory");
			*err = 500;
			evbuffer_add_reference(output, "Out of memory :(\n", 17, NULL, NULL);
			return -1;
		}

		snprintf(www_auth_value, www_auth_value_len, "Basic realm=\"%s\"", root_uri);
		*err = 401;
		evhttp_add_header(headers, "WWW-Authenticate", www_auth_value);
		strfree(www_auth_value);
		return 0;
	}

	if (!strcmp(uri, "/mem") || !strcmp(uri, "/mem.json")) {
		request_free(req);
		int len = strlen(uri);
		int json = (len >= 5 && !strcmp(uri+len-5, ".json"))?1:0;

		struct mime_content *m = malloc_stats_dump(json);
		if (m) {
			ntripsrv_send_result_ok(st, output, m, NULL);
		} else {
			ntrip_log(st, LOG_CRIT, "ntripsrv: out of memory");
			*err = 500;
			evbuffer_add_reference(output, "Out of memory :(\n", 17, NULL, NULL);
			return -1;
		}
		ntrip_set_state(st, NTRIP_WAIT_CLOSE);
		return 0;
	} else if (!strcmp(uri, "/net")) {
		joblist_append_ntrip_unlocked_content(st->caster->joblist, ntripsrv_deferred_output, st, api_ntrip_list_json, req);
		return 0;
	} else {
		request_free(req);
		*err = 404;
		return -1;
	}
}
