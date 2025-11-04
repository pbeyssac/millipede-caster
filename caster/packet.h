#ifndef __PACKET_H__
#define __PACKET_H__

#include "conf.h"

struct ntrip_state;

/*
 * A raw packet.
 * Variable-length structure, varies according to packet size.
 */
struct packet {
	_Atomic u_int refcnt;	// mostly for zero-copy mode
	int is_rtcm;		// Checked to be a valid RTCM packet
	size_t datalen;
	unsigned char data[];
};

struct caster_state;
struct packet *packet_new(size_t len_raw, struct caster_state *caster);
void packet_incref(struct packet *packet);
void packet_decref(struct packet *packet);
void packet_send(struct packet *packet, struct ntrip_state *st, time_t t);
void packet_free(struct packet *packet);
int packet_handle_raw(struct ntrip_state *st);
int packet_handle_rtcm(struct ntrip_state *st);

#endif
