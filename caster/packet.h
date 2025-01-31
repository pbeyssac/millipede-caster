#ifndef __PACKET_H__
#define __PACKET_H__

#include "conf.h"

struct ntrip_state;

/*
 * A raw packet.
 * Variable-length structure, varies according to packet size.
 */
struct packet {
	P_MUTEX_T mutex;
	int refcnt;		// mostly for zero-copy mode
	struct caster_state *caster;
	size_t datalen;
	unsigned char data[];
};

struct packet *packet_new(size_t len_raw, struct caster_state *caster);
void packet_free(struct packet *packet);
int packet_handle_raw(struct ntrip_state *st);
int packet_handle_rtcm(struct ntrip_state *st);

#endif
