#include <event2/buffer.h>

#include "conf.h"
#include "caster.h"
#include "packet.h"
#include "ntrip_common.h"

struct packet *packet_new(size_t len_raw, struct caster_state *caster) {
	struct packet *this = (struct packet *)malloc(sizeof(struct packet) + len_raw);
	P_MUTEX_INIT(&this->mutex, NULL);
	this->datalen = len_raw;
	this->refcnt = 1;
	this->caster = caster;
	return this;
}

/*
 * Packet freeing function with a reference count
 * for zero copy mode.
 */
void packet_free(struct packet *packet) {
	/*
	 * When not in zero-copy mode, don't lock the packet as
	 * we are the only thread handling it.
	 */
	if (!packet->caster->config->zero_copy) {
		P_MUTEX_UNLOCK(&packet->mutex);
		P_MUTEX_DESTROY(&packet->mutex);
		free((void *)packet);
		return;
	}

	P_MUTEX_LOCK(&packet->mutex);
	packet->refcnt--;
	if (packet->refcnt == 0) {
		P_MUTEX_UNLOCK(&packet->mutex);
		P_MUTEX_DESTROY(&packet->mutex);
		free((void *)packet);
	} else {
		P_MUTEX_UNLOCK(&packet->mutex);
	}
}

int packet_handle_raw(struct ntrip_state *st) {
	struct evbuffer *input = st->input;

	while (1) {
		unsigned long len_raw = evbuffer_get_length(input);
		ntrip_log(st, LOG_EDEBUG, "ntrip_handle_raw ready to get %d bytes", len_raw);
		if (len_raw < st->caster->config->min_raw_packet)
			return 0;
		if (len_raw > st->caster->config->max_raw_packet)
			len_raw = st->caster->config->max_raw_packet;
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
			st->last_send = time(NULL);
		packet_free(rawp);
		return 1;
	}
}
