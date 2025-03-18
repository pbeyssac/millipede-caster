#include <netinet/tcp.h>
#include <string.h>

#include <json-c/json_object.h>

#include "conf.h"
#include "livesource.h"
#include "ntrip_common.h"
#include "rtcm.h"
#include "sourcetable.h"

/*
 * JSON API routines.
 */

static json_object *api_ntrip_json(struct ntrip_state *st) {
	bufferevent_lock(st->bev);

	json_object *new_obj = json_object_new_object();

	if (st->local) {
		json_object *jip = st->local_addr[0] ? json_object_new_string(st->local_addr) : json_object_new_null();
		json_object *jport = json_object_new_int(ip_port(&st->myaddr));
		json_object *j = json_object_new_object();
		json_object_object_add(j, "ip", jip);
		json_object_object_add(j, "port", jport);
		json_object_object_add(new_obj, "local", j);
	}
	if (st->remote) {
		json_object *jip = st->remote_addr[0] ? json_object_new_string(st->remote_addr) : json_object_new_null();
		json_object *jport = json_object_new_int(ip_port(&st->peeraddr));
		json_object_object_add(new_obj, "ip", jip);
		json_object_object_add(new_obj, "port", jport);
	}

	json_object *jsonid = json_object_new_int64(st->id);
	json_object *received_bytes = json_object_new_int64(st->received_bytes);
	json_object *sent_bytes = json_object_new_int64(st->sent_bytes);
	json_object_object_add(new_obj, "id", jsonid);
	json_object_object_add(new_obj, "received_bytes", received_bytes);
	json_object_object_add(new_obj, "sent_bytes", sent_bytes);
	json_object_object_add(new_obj, "type", json_object_new_string(st->type));
	json_object_object_add(new_obj, "wildcard", json_object_new_boolean(st->wildcard));
	if (!strcmp(st->type, "source") || !strcmp(st->type, "source_fetcher"))
		json_object_object_add(new_obj, "mountpoint", json_object_new_string(st->mountpoint));
	else if (!strcmp(st->type, "client"))
		json_object_object_add(new_obj, "mountpoint", json_object_new_string(st->http_args[1]+1));

	if (st->user_agent)
		json_object_object_add(new_obj, "user_agent", json_object_new_string(st->user_agent));

	struct tcp_info ti;
	socklen_t ti_len = sizeof ti;
	if (getsockopt(st->fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len) >= 0) {
		json_object *tcpi_obj = json_object_new_object();
		json_object_object_add(tcpi_obj, "rtt", json_object_new_int64(ti.tcpi_rtt));
		json_object_object_add(tcpi_obj, "rttvar", json_object_new_int64(ti.tcpi_rttvar));
		json_object_object_add(tcpi_obj, "snd_mss", json_object_new_int64(ti.tcpi_snd_mss));
		json_object_object_add(tcpi_obj, "rcv_mss", json_object_new_int64(ti.tcpi_rcv_mss));
		json_object_object_add(tcpi_obj, "last_data_recv", json_object_new_int64(ti.tcpi_last_data_recv));
		json_object_object_add(tcpi_obj, "rcv_wnd", json_object_new_int64(ti.tcpi_rcv_space));
#ifdef __FreeBSD__
		// FreeBSD-specific
		json_object_object_add(tcpi_obj, "snd_wnd", json_object_new_int64(ti.tcpi_snd_wnd));
		json_object_object_add(tcpi_obj, "snd_rexmitpack", json_object_new_int64(ti.tcpi_snd_rexmitpack));
#endif
		json_object_object_add(new_obj, "tcp_info", tcpi_obj);
	}

	char iso_date[30];
	iso_date_from_timeval(iso_date, sizeof iso_date, &st->start);
	json_object_object_add(new_obj, "start", json_object_new_string(iso_date));

	bufferevent_unlock(st->bev);
	return new_obj;
}

/*
 * Return a list of ntrip_state as a JSON object.
 */
struct mime_content *api_ntrip_list_json(struct caster_state *caster, struct request *req) {
	char *s;
	json_object *new_list = json_object_new_object();
	struct ntrip_state *sst;

	P_RWLOCK_RDLOCK(&caster->ntrips.lock);
	TAILQ_FOREACH(sst, &caster->ntrips.queue, nextg) {
		char idstr[40];
		json_object *nj = api_ntrip_json(sst);
		snprintf(idstr, sizeof idstr, "%lld", sst->id);
		json_object_object_add(new_list, idstr, nj);
	}
	P_RWLOCK_UNLOCK(&caster->ntrips.lock);

	s = mystrdup(json_object_to_json_string(new_list));
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	json_object_put(new_list);
	return m;
}

/*
 * Return the RTCM cache as a JSON object.
 */
struct mime_content *api_rtcm_json(struct caster_state *caster, struct request *req) {
	char *s;
	json_object *new_list;

	if (!caster->rtcm_cache) {
		new_list = json_object_new_null();
	} else {
		new_list = json_object_new_object();
		struct hash_iterator hi;
		struct element *e;
		P_RWLOCK_RDLOCK(&caster->rtcm_lock);
		HASH_FOREACH(e, caster->rtcm_cache, hi) {
			json_object *j = rtcm_info_json((struct rtcm_info *)e->value);
			json_object_object_add(new_list, e->key, j);
		}
		P_RWLOCK_UNLOCK(&caster->rtcm_lock);
	}
	s = mystrdup(json_object_to_json_string(new_list));
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	json_object_put(new_list);
	return m;
}

/*
 * Return memory stats.
 */
struct mime_content *api_mem_json(struct caster_state *caster, struct request *req) {
	struct mime_content *m = malloc_stats_dump(1);
	return m;
}

/*
 * Reload the configuration and return a status code.
 */
struct mime_content *api_reload_json(struct caster_state *caster, struct request *req) {
	char result[40];
	int r = caster_reload(caster);
	snprintf(result, sizeof result, "{\"result\": %d}\n", r);
	char *s = mystrdup(result);
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	return m;
}

/*
 * Drop a connection by id.
 */
struct mime_content *api_drop_json(struct caster_state *caster, struct request *req) {
	char result[40];
	int r = 0;
	long long id = -1;
	char *idval = (char *)hash_table_get(req->hash, "id");

	if (idval && sscanf(idval, "%lld", &id) == 1)
		r = ntrip_drop_by_id(caster, id);

	snprintf(result, sizeof result, "{\"result\": %d}\n", r);
	char *s = mystrdup(result);
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	return m;
}

struct mime_content *api_sync_json(struct caster_state *caster, struct request *req) {
	const char *type = json_object_get_string(json_object_object_get(req->json, "type"));

	if (type == NULL) {
		req->status = 400;
	} else if (!strcmp(type, "sourcetable")) {
		req->status = sourcetable_update_execute(caster, req->json);
	} else
		req->status = livesource_update_execute(caster, caster->livesources, req->json);
	char *s = mystrdup("");
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	return m;
}
