#include <netinet/tcp.h>

#include <json-c/json.h>

#include "conf.h"
#include "ntrip_common.h"

/*
 * JSON API routines.
 */

static json_object *api_ntrip_json(struct ntrip_state *st) {
	bufferevent_lock(st->bev);

	char *ipstr = st->remote_addr;
	json_object *jsonip;
	unsigned port = ip_port(&st->peeraddr);
	jsonip = ipstr[0] ? json_object_new_string(ipstr) : json_object_new_null();
	json_object *new_obj = json_object_new_object();
	json_object *jsonid = json_object_new_int64(st->id);
	json_object *received_bytes = json_object_new_int64(st->received_bytes);
	json_object *sent_bytes = json_object_new_int64(st->sent_bytes);
	json_object *jsonport = json_object_new_int(port);
	json_object_object_add(new_obj, "id", jsonid);
	json_object_object_add(new_obj, "received_bytes", received_bytes);
	json_object_object_add(new_obj, "sent_bytes", sent_bytes);
	json_object_object_add(new_obj, "ip", jsonip);
	json_object_object_add(new_obj, "port", jsonport);
	json_object_object_add(new_obj, "type", json_object_new_string(st->type));
	json_object_object_add(new_obj, "wildcard", json_object_new_boolean(st->wildcard));
	if (!strcmp(st->type, "source") || !strcmp(st->type, "source_fetcher"))
		json_object_object_add(new_obj, "mountpoint", json_object_new_string(st->mountpoint));
	else if (!strcmp(st->type, "client"))
		json_object_object_add(new_obj, "mountpoint", json_object_new_string(st->http_args[1]+1));

	if (st->user_agent)
		json_object_object_add(new_obj, "user-agent", json_object_new_string(st->user_agent));

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
struct mime_content *api_ntrip_list_json(struct caster_state *caster, struct hash_table *h) {
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
 * Return memory stats.
 */
struct mime_content *api_mem_json(struct caster_state *caster, struct hash_table *h) {
	struct mime_content *m = malloc_stats_dump(1);
	return m;
}

/*
 * Reload the configuration and return a status code.
 */
struct mime_content *api_reload_json(struct caster_state *caster, struct hash_table *h) {
	char result[40];
	int r = caster_reload(caster);
	snprintf(result, sizeof result, "{\"result\": %d}\n", r);
	char *s = mystrdup(result);
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	return m;
}
