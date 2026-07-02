#include <netinet/tcp.h>
#include <string.h>

#include <json-c/json_object.h>

#include "conf.h"
#include "livesource.h"
#include "nodes.h"
#include "ntrip_common.h"
#include "rinex.h"
#include "rtcm.h"
#include "rtcm_freq.h"
#include "rtcm_ringbuffer.h"
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
		json_object_object_add_ex(j, "ip", jip, JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(j, "port", jport, JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(new_obj, "local", j, JSON_C_CONSTANT_NEW);
	}
	if (st->remote) {
		json_object *jip = st->remote_addr[0] ? json_object_new_string(st->remote_addr) : json_object_new_null();
		json_object *jport = json_object_new_int(ip_port(&st->peeraddr));
		json_object_object_add_ex(new_obj, "ip", jip, JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(new_obj, "port", jport, JSON_C_CONSTANT_NEW);
	}

	json_object *jsonid = json_object_new_int64(st->id);
	json_object *received_bytes = json_object_new_int64(st->received_bytes);
	json_object *sent_bytes = json_object_new_int64(st->sent_bytes);
	json_object_object_add_ex(new_obj, "id", jsonid, JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(new_obj, "received_bytes", received_bytes, JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(new_obj, "sent_bytes", sent_bytes, JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(new_obj, "type", json_object_new_string(st->type), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(new_obj, "wildcard", json_object_new_boolean(st->wildcard), JSON_C_CONSTANT_NEW);
	if (!strcmp(st->type, "source") || !strcmp(st->type, "source_fetcher"))
		json_object_object_add_ex(new_obj, "mountpoint", json_object_new_string(st->mountpoint), JSON_C_CONSTANT_NEW);
	else if (!strcmp(st->type, "client")) {
		if (st->mountpoint != NULL)
			json_object_object_add_ex(new_obj, "mountpoint", json_object_new_string(st->mountpoint), JSON_C_CONSTANT_NEW);
		else
			json_object_object_add_ex(new_obj, "mountpoint", json_object_new_null(), JSON_C_CONSTANT_NEW);
	}

	if (st->user_agent)
		json_object_object_add_ex(new_obj, "user_agent", json_object_new_string(st->user_agent), JSON_C_CONSTANT_NEW);

	struct tcp_info ti;
	socklen_t ti_len = sizeof ti;
	if (getsockopt(st->fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len) >= 0) {
		json_object *tcpi_obj = json_object_new_object();
		json_object_object_add_ex(tcpi_obj, "rtt", json_object_new_int64(ti.tcpi_rtt), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(tcpi_obj, "rttvar", json_object_new_int64(ti.tcpi_rttvar), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(tcpi_obj, "snd_mss", json_object_new_int64(ti.tcpi_snd_mss), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(tcpi_obj, "rcv_mss", json_object_new_int64(ti.tcpi_rcv_mss), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(tcpi_obj, "last_data_recv", json_object_new_int64(ti.tcpi_last_data_recv), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(tcpi_obj, "rcv_wnd", json_object_new_int64(ti.tcpi_rcv_space), JSON_C_CONSTANT_NEW);
#ifdef __FreeBSD__
		// FreeBSD-specific
		json_object_object_add_ex(tcpi_obj, "snd_wnd", json_object_new_int64(ti.tcpi_snd_wnd), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(tcpi_obj, "snd_rexmitpack", json_object_new_int64(ti.tcpi_snd_rexmitpack), JSON_C_CONSTANT_NEW);
#endif
		json_object_object_add_ex(new_obj, "tcp_info", tcpi_obj, JSON_C_CONSTANT_NEW);
	}

	timeval_to_json(&st->start, new_obj, "start");

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
 * Return the node table.
 */
struct mime_content *api_nodes_json(struct caster_state *caster, struct request *req) {
	struct json_object *jlist = nodes_json(caster->nodes);
	char *s = mystrdup(json_object_to_json_string(jlist));
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	json_object_put(jlist);
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
	char *idval = req->hash ? (char *)hash_table_get(req->hash, "id") : NULL;

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
	} else if (!strcmp(type, "node")) {
		req->status = node_update_execute(caster, req->json);
	} else
		req->status = livesource_update_execute(caster, caster->livesources, req);
	char *s = mystrdup("");
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	return m;
}

/*
 * Return the RTCM frequency tracker as a JSON object.
 *
 * Optional query string parameter:
 *   mountpoint=<name>   restrict the response to a single mountpoint
 */
struct mime_content *api_rtcm_freq_json(struct caster_state *caster, struct request *req) {
	json_object *j;
	char *mountpoint = req->hash ? (char *)hash_table_get(req->hash, "mountpoint") : NULL;
	if (mountpoint)
		j = rtcm_freq_mountpoint_json(caster->rtcm_freq, mountpoint);
	else
		j = rtcm_freq_tracker_json(caster->rtcm_freq);
	char *s = mystrdup(j ? json_object_to_json_string(j) : "{}");
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	if (j)
		json_object_put(j);
	return m;
}

/*
 * Return the RTCM ring buffer stats as a JSON object.
 *
 * Optional query string parameter:
 *   mountpoint=<name>   restrict the response to a single mountpoint
 *
 * Returns per-mountpoint stats: current packet count, byte usage,
 * capacity, first/last seen timestamps, and cumulative eviction count.
 * The actual RTCM bytes are NOT returned by this endpoint — a future
 *   GET /api/v1/rinex?mountpoint=...&from=...&to=...
 * endpoint will use rtcm_ringbuffer_extract_range() to emit RINEX.
 */
struct mime_content *api_rtcm_ringbuffer_json(struct caster_state *caster, struct request *req) {
	json_object *j;
	char *mountpoint = req->hash ? (char *)hash_table_get(req->hash, "mountpoint") : NULL;
	if (mountpoint)
		j = rtcm_ringbuffer_mountpoint_json(caster->rtcm_ringbuffer, mountpoint);
	else
		j = rtcm_ringbuffer_tracker_json(caster->rtcm_ringbuffer);
	char *s = mystrdup(j ? json_object_to_json_string(j) : "{}");
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	if (j)
		json_object_put(j);
	return m;
}

/*
 * Generate a RINEX 3.04 observation file on the fly from the caster's
 * recent RTCM ring buffer.
 *
 * Query parameters:
 *   mountpoint=<name>   (required) source mountpoint
 *   from=<iso8601>      (optional) start time, default = ring buffer oldest
 *   to=<iso8601>        (optional) end time, default = ring buffer newest
 *
 * Returns:
 *   200 OK with Content-Type: application/octet-stream and
 *     Content-Disposition: attachment; filename="<mountpoint>.obs"
 *     Body is a complete RINEX 3.04 file.
 *   400 Bad Request if mountpoint is missing
 *   404 Not Found if the mountpoint is unknown or has no RTCM data
 *
 * MVP limitations:
 *   - The whole RINEX file is built in memory (struct mbuf) before
 *     being returned. For windows > 1 hour at 1 Hz this can use ~10 MB
 *     of RAM per request. A streamed chunked version is a follow-up.
 *   - Only GPS (1071) and Galileo (1094) MSM7 messages are decoded.
 *   - The from/to ISO8601 parser only accepts "YYYY-MM-DDTHH:MM:SSZ".
 */
static int parse_iso8601(const char *s, struct timeval *out) {
	if (s == NULL || out == NULL)
		return -1;
	int y, mo, d, h, mi, se;
	if (sscanf(s, "%d-%d-%dT%d:%d:%dZ", &y, &mo, &d, &h, &mi, &se) != 6)
		return -1;
	struct tm tm;
	memset(&tm, 0, sizeof tm);
	tm.tm_year = y - 1900;
	tm.tm_mon = mo - 1;
	tm.tm_mday = d;
	tm.tm_hour = h;
	tm.tm_min = mi;
	tm.tm_sec = se;
	time_t t = timegm(&tm);
	if (t == (time_t)-1)
		return -1;
	out->tv_sec = t;
	out->tv_usec = 0;
	return 0;
}

struct mime_content *api_rinex(struct caster_state *caster, struct request *req) {
	char *mountpoint = req->hash ? (char *)hash_table_get(req->hash, "mountpoint") : NULL;
	if (mountpoint == NULL) {
		char *s = mystrdup("{\"error\":\"mountpoint parameter required\"}\n");
		req->status = 400;
		return mime_new(s, -1, "application/json", 1);
	}

	char *from_str = req->hash ? (char *)hash_table_get(req->hash, "from") : NULL;
	char *to_str = req->hash ? (char *)hash_table_get(req->hash, "to") : NULL;
	struct timeval from_tv, to_tv;
	struct timeval *from_p = NULL, *to_p = NULL;
	if (from_str) {
		if (parse_iso8601(from_str, &from_tv) == 0)
			from_p = &from_tv;
	}
	if (to_str) {
		if (parse_iso8601(to_str, &to_tv) == 0)
			to_p = &to_tv;
	}

	/* Extract packets from the ring buffer. */
	size_t npackets = 0;
	struct rtcm_rb_entry *entries = rtcm_ringbuffer_extract_range(
		caster->rtcm_ringbuffer, mountpoint, from_p, to_p, &npackets);
	if (entries == NULL || npackets == 0) {
		char *s = mystrdup("{\"error\":\"no RTCM data for mountpoint in requested window\"}\n");
		req->status = 404;
		return mime_new(s, -1, "application/json", 1);
	}

	/* Build an array of packet pointers for rinex_build_from_packets(). */
	struct packet **packets = (struct packet **)calloc(npackets, sizeof(*packets));
	if (packets == NULL) {
		for (size_t i = 0; i < npackets; i++)
			if (entries[i].packet)
				packet_decref(entries[i].packet);
		free(entries);
		char *s = mystrdup("{\"error\":\"out of memory\"}\n");
		req->status = 503;
		return mime_new(s, -1, "application/json", 1);
	}
	for (size_t i = 0; i < npackets; i++)
		packets[i] = entries[i].packet;

	/* Build the RINEX file. */
	struct mbuf out;
	if (mbuf_init(&out, 8192) < 0) {
		free(packets);
		for (size_t i = 0; i < npackets; i++)
			if (entries[i].packet)
				packet_decref(entries[i].packet);
		free(entries);
		char *s = mystrdup("{\"error\":\"out of memory\"}\n");
		req->status = 503;
		return mime_new(s, -1, "application/json", 1);
	}

	int rc = rinex_build_from_packets(&out, packets, npackets, mountpoint);

	/* Release our references on the packets (ring buffer still holds its own). */
	for (size_t i = 0; i < npackets; i++)
		if (entries[i].packet)
			packet_decref(entries[i].packet);
	free(entries);
	free(packets);

	if (rc != 0) {
		mbuf_free(&out);
		char *s = mystrdup("{\"error\":\"RINEX generation failed\"}\n");
		req->status = 500;
		return mime_new(s, -1, "application/json", 1);
	}

	/* Transfer ownership of out.data to the mime_content.
	 * mime_new with use_strfree=1 will free() the string when the
	 * mime_content is destroyed. */
	struct mime_content *m = mime_new(out.data, (int)out.len,
		"application/octet-stream", 1);
	return m;
}
