#include <stdatomic.h>

#include <event2/buffer.h>
#include "conf.h"
#include "caster.h"
#include "packet.h"
#include "ntrip_common.h"

struct packet *packet_new(size_t len_raw, struct caster_state *caster) {
	struct packet *this = (struct packet *)malloc(sizeof(struct packet) + len_raw);
	this->datalen = len_raw;
	atomic_init(&this->refcnt, 1);
	this->is_rtcm = 0;
	return this;
}

/*
 * Packet freeing function
 */
void packet_free(struct packet *packet) {
	if (atomic_fetch_add_explicit(&packet->refcnt, -1, memory_order_relaxed) == 1)
		free((void *)packet);
}

void packet_incref(struct packet *packet) {
	atomic_fetch_add(&packet->refcnt, 1);
}

void packet_decref(struct packet *packet) {
	if (atomic_fetch_add_explicit(&packet->refcnt, -1, memory_order_relaxed) == 1)
		free((void *)packet);
}

/*
 * Packet freeing callback
 */
static void raw_free_callback(const void *data, size_t datalen, void *extra) {
	struct packet *packet = (struct packet *)extra;
	packet_free(packet);
}

/*
 * Send a packet
 * Required lock: ntrip_state
 */
void packet_send(struct packet *packet, struct ntrip_state *st, time_t t) {
	if (evbuffer_add_reference(bufferevent_get_output(st->bev), packet->data, packet->datalen, raw_free_callback, packet) < 0) {
		ntrip_log(st, LOG_CRIT, "evbuffer_add_reference failed");
		return;
	}
	packet_incref(packet);
	st->last_send = t;
	st->sent_bytes += packet->datalen;
}

int packet_handle_raw(struct ntrip_state *st) {
	struct evbuffer *input = st->input;

	while (1) {
		unsigned long len_raw = evbuffer_get_length(input);
		ntrip_log(st, LOG_EDEBUG, "ntrip_handle_raw ready to get %d bytes", len_raw);
		if (len_raw < st->config->min_raw_packet)
			return 0;
		if (len_raw > st->config->max_raw_packet)
			len_raw = st->config->max_raw_packet;
		struct packet *rawp = packet_new(len_raw, st->caster);
		st->received_bytes += len_raw;
		if (rawp == NULL) {
			evbuffer_drain(input, len_raw);
			ntrip_log(st, LOG_CRIT, "Raw: Not enough memory, dropping %d bytes", len_raw);
			return 1;
		}
		evbuffer_remove(input, &rawp->data[0], len_raw);

		//ntrip_log(st, LOG_DEBUG, "Raw: packet source %s size %d", st->mountpoint, len_raw);
		if (livesource_send_subscribers(st->own_livesource, rawp, st->caster))
			st->last_useful = time(NULL);
		packet_free(rawp);
		return 1;
	}
}
