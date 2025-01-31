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

/*
 * Handle receipt and retransmission of 1 RTCM packet.
 * Return 0 if more data is needed.
 */
int packet_handle_rtcm(struct ntrip_state *st) {
	unsigned short len_rtcm;
	struct evbuffer_ptr p;
	struct evbuffer *input = st->input;

	/*
	 * Look for 0xd3 header byte
	 */
	evbuffer_ptr_set(input, &p, 0, EVBUFFER_PTR_SET);
	p = evbuffer_search(input, "\xd3", 1, &p);
	if (p.pos < 0) {
		unsigned long len = evbuffer_get_length(input);
#if 0
		char *drain = (char *)strmalloc(len+1);
		if (drain != NULL) {
			evbuffer_remove(input, drain, len);
			drain[len] = '\0';
			ntrip_log(st, LOG_INFO, "RTCM: draining %zd bytes: \"%s\"", len, drain);
			free(drain);
		} else
#endif
		{
			ntrip_log(st, LOG_INFO, "draining %zd bytes", len);
			evbuffer_drain(input, len);
		}
		return 0;
	}
	if (p.pos > 0) {
		ntrip_log(st, LOG_DEBUG, "RTCM: found packet start, draining %zd bytes", p.pos);
		evbuffer_drain(input, p.pos);
	}

	unsigned char *mem = evbuffer_pullup(input, 3);
	if (mem == NULL) {
		ntrip_log(st, LOG_DEBUG, "RTCM: not enough data, waiting");
		return 0;
	}

	/*
	 * Compute RTCM length from packet header
	 */
	len_rtcm = (mem[1] & 3)*256 + mem[2] + 6;
	if (len_rtcm > evbuffer_get_length(input)) {
		return 0;
	}

	struct packet *rtcmp = packet_new(len_rtcm, st->caster);
	if (rtcmp == NULL) {
		evbuffer_drain(input, len_rtcm);
		ntrip_log(st, LOG_CRIT, "RTCM: Not enough memory, dropping packet");
		return 1;
	}

	evbuffer_remove(input, &rtcmp->data[0], len_rtcm);
	unsigned long crc = crc24q_hash(&rtcmp->data[0], len_rtcm-3);
	if (crc == (rtcmp->data[len_rtcm-3]<<16)+(rtcmp->data[len_rtcm-2]<<8)+rtcmp->data[len_rtcm-1]) {
		unsigned short type = rtcmp->data[3]*16 + rtcmp->data[4]/16;
		ntrip_log(st, LOG_DEBUG, "RTCM source %s size %d type %d", st->mountpoint, len_rtcm, type);
	} else {
		ntrip_log(st, LOG_INFO, "RTCM: bad checksum! %08lx %08x", crc, (rtcmp->data[len_rtcm-3]<<16)+(rtcmp->data[len_rtcm-2]<<8)+rtcmp->data[len_rtcm-1]);
	}

	if (livesource_send_subscribers(st->own_livesource, rtcmp, st->caster))
		st->last_send = time(NULL);
	packet_free(rtcmp);
	return 1;
}
