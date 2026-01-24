#ifndef __PACKET_H__
#define __PACKET_H__

#include <assert.h>
#include <stdatomic.h>

#include "conf.h"

struct ntrip_state;

/*
 * A raw packet.
 * Variable-length structure, varies according to packet size.
 */
struct packet {
	_Atomic int refcnt;
	int is_rtcm;		// Checked to be a valid RTCM packet
	size_t datalen;
	unsigned char data[];
};

struct caster_state;
struct packet *packet_new(size_t len_raw);
struct packet *packet_new_from_string(const char *s);
int packet_send(struct packet *packet, struct ntrip_state *st, time_t t);

static inline void packet_incref(struct packet *packet) {
	assert(packet->refcnt > 0);
	atomic_fetch_add(&packet->refcnt, 1);
}

static inline void packet_decref(struct packet *packet) {
	assert(packet->refcnt > 0);
	if (atomic_fetch_add_explicit(&packet->refcnt, -1, memory_order_relaxed) == 1)
		free((void *)packet);
}

#endif
