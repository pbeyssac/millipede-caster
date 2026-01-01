#include <event2/buffer.h>
#include "conf.h"
#include "caster.h"
#include "packet.h"
#include "ntrip_common.h"

struct packet *packet_new(size_t len_raw) {
	struct packet *this = (struct packet *)malloc(sizeof(struct packet) + len_raw);
	this->datalen = len_raw;
	atomic_init(&this->refcnt, 1);
	this->is_rtcm = 0;
	return this;
}

/*
 * Create packet with a copy of a null-terminated string.
 */
struct packet *packet_new_from_string(const char *s) {
	size_t len = strlen(s);
	struct packet *p = packet_new(len);
	if (p == NULL)
		return NULL;
	/* Don't store the final '\0' since we know the length */
	memcpy(p->data, s, len);
	return p;
}

/*
 * Packet freeing callback
 */
static void raw_free_callback(const void *data, size_t datalen, void *extra) {
	struct packet *packet = (struct packet *)extra;
	packet_decref(packet);
}

/*
 * Send a packet
 * Required lock: ntrip_state
 */
int packet_send(struct packet *packet, struct ntrip_state *st, time_t t) {
	packet_incref(packet);
	if (evbuffer_add_reference(bufferevent_get_output(st->bev), packet->data, packet->datalen, raw_free_callback, packet) < 0) {
		packet_decref(packet);
		ntrip_log(st, LOG_CRIT, "evbuffer_add_reference failed");
		return -1;
	}
	st->last_send = t;
	st->sent_bytes += packet->datalen;
	return 0;
}
