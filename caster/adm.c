#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <json-c/json.h>

#include "conf.h"
#include "adm.h"
#include "api.h"
#include "hash.h"
#include "ntripsrv.h"

int admsrv(struct ntrip_state *st, const char *method, const char *root_uri, const char *uri, int *err, struct evkeyvalq *headers) {
	struct evbuffer *output = bufferevent_get_output(st->bev);
	struct hash_table *h = NULL;

	st->client_version = 0;		// force a straight HTTP reply regardless of client headers

	/*
	 * Look for key=value arguments in url-encoded form, either in the request (GET) or in the body (POST).
	 *
	 * Build a hash table from them.
	 */
	if (!strcmp(method, "POST")) {
		if (st->content_type && strcmp(st->content_type, "application/x-www-form-urlencoded")) {
			*err = 503;
			return -1;
		}
		if (!st->content) {
			*err = 503;
			return -1;
		}
		h = hash_from_urlencoding(st->content);
		if (!h) {
			*err = 503;
			return -1;
		}
	} else if (!strcmp(method, "GET") && st->query_string) {
		h = hash_from_urlencoding(st->query_string);
		if (!h) {
			*err = 503;
			return -1;
		}
	}

	if (h) {
		/*
		 * Found url-encoded key=value pairs in the request, process
		 */

		/*
		 * Check credentials
		 */
		char *user, *password;
		user = hash_table_get(h, "user");
		password = hash_table_get(h, "password");

		if (!user || !password || !check_password(st, st->caster->config->admin_user, user, password)) {
			hash_table_free(h);
			*err = 401;
			return -1;
		}

		/*
		 * Run API calls
		 */
		if (!strcmp(uri, "/api/v1/net") && !strcmp(method, "GET")) {
			joblist_append_ntrip_unlocked_content(st->caster->joblist, ntripsrv_deferred_output, st, api_ntrip_list_json, h);
			return 0;
		}
		if (!strcmp(uri, "/api/v1/mem") && !strcmp(method, "GET")) {
			joblist_append_ntrip_unlocked_content(st->caster->joblist, ntripsrv_deferred_output, st, api_mem_json, h);
			return 0;
		}
		if (!strcmp(uri, "/api/v1/reload") && !strcmp(method, "POST")) {
			joblist_append_ntrip_unlocked_content(st->caster->joblist, ntripsrv_deferred_output, st, api_reload_json, h);
			return 0;
		}
		if (!strcmp(uri, "/api/v1/drop") && !strcmp(method, "POST")) {
			joblist_append_ntrip_unlocked_content(st->caster->joblist, ntripsrv_deferred_output, st, api_drop_json, h);
			return 0;
		}

		*err = 404;
		return -1;
	}

	/* Legacy access */

	if (!st->user || !check_password(st, st->caster->config->admin_user, st->user, st->password)) {
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
		joblist_append_ntrip_unlocked_content(st->caster->joblist, ntripsrv_deferred_output, st, api_ntrip_list_json, NULL);
		return 0;
	} else {
		*err = 404;
		return -1;
	}
}
