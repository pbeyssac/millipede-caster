#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <json-c/json_tokener.h>

#include "conf.h"
#include "adm.h"
#include "api.h"
#include "hash.h"
#include "livesource.h"
#include "ntripsrv.h"
#include "request.h"
#include "sourcetable.h"

int admsrv(struct ntrip_state *st, const char *method, const char *root_uri, const char *uri, int *err, struct evkeyvalq *headers) {
	struct evbuffer *output = bufferevent_get_output(st->bev);
	int json_post = 0;
	struct request *req = request_new();
	if (req == NULL) {
		*err = 503;
		return -1;
	}

	st->client_version = 0;		// force a straight HTTP reply regardless of client headers

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

	if (req->hash) {
		/*
		 * Found url-encoded key=value pairs in the request, process
		 */

		/*
		 * Check credentials
		 */
		char *user, *password;
		user = hash_table_get(req->hash, "user");
		password = hash_table_get(req->hash, "password");

		if (!user || !password || !check_password(st, st->caster->config->admin_user, user, password)) {
			request_free(req);
			*err = 401;
			return -1;
		}

		struct uri_calls {
			const char *uri;
			const char *method;
			struct mime_content *(*content_cb)(struct caster_state *caster, struct request *req);
		};
		const struct uri_calls calls[] = {
			{"/api/v1/net",	"GET", api_ntrip_list_json},
			{"/api/v1/rtcm", "GET", api_rtcm_json},
			{"/api/v1/mem","GET", api_mem_json},
			{"/api/v1/livesources", "GET", livesource_list_json},
			{"/api/v1/sourcetables", "GET", sourcetable_list_json},
			{"/api/v1/reload", "POST", api_reload_json},
			{"/api/v1/drop", "POST", api_drop_json},
			{NULL, NULL, NULL}
		};

		int i;
		for (i = 0; calls[i].uri; i++) {
			if (!strcmp(uri, calls[i].uri))
				break;
		}

		/* Check the URI */
		if (calls[i].uri == NULL) {
			request_free(req);
			*err = 404;
			return -1;
		}

		/* Check the method */
		if (strcmp(method, calls[i].method)) {
			request_free(req);
			*err = 405;
			return -1;
		}

		/* Execute */
		joblist_append_ntrip_unlocked_content(st->caster->joblist, ntripsrv_deferred_output, st, calls[i].content_cb, req);
		return 0;
	} else if (json_post) {
		req->json = st->content ? json_tokener_parse(st->content) : NULL;
		if (req->json == NULL) {
			*err = 400;
		} else if (!strcmp(uri, "/api/v1/sync") && !strcmp(method, "POST")) {
			if (st->caster->config->syncer_auth == NULL
					|| st->password == NULL || st->scheme_basic || strcmp(st->caster->config->syncer_auth, st->password)) {
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

	if (!st->user || !check_password(st, st->caster->config->admin_user, st->user, st->password)) {
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
		st->state = NTRIP_WAIT_CLOSE;
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
