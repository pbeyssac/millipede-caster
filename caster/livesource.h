#ifndef __LIVESOURCE_H__
#define __LIVESOURCE_H__

#include <stdlib.h>
#include <sys/queue.h>

#include "caster.h"
#include "packet.h"

/*
 * A source subscription for a client.
 */
struct subscriber {
	TAILQ_ENTRY(subscriber) next;
	struct livesource *livesource;
	struct ntrip_state *ntrip_state;

	// backlog overflow flag.
	// if set, this subscriber structure is already off the livesource list
	int backlogged;
	int virtual;
};
TAILQ_HEAD (subscribersq, subscriber);

/*
 * A live source: either one that sends us its stream directly,
 * or one we pull from a caster.
 */
struct livesource {
#ifdef THREADS
	P_RWLOCK_T lock;
#endif
	TAILQ_ENTRY(livesource) next;
	char *mountpoint;
	struct subscribersq subscribers;
	int nsubs;
	int npackets;
};
TAILQ_HEAD (livesourceq, livesource);

struct caster_state;
struct livesource *livesource_new(char *mountpoint);
struct livesource *livesource_find(struct caster_state *this, char *mountpoint);
int livesource_kill_subscribers_unlocked(struct livesource *this, int kill_backlogged);
void livesource_free(struct livesource *this);
struct subscriber *livesource_add_subscriber(struct livesource *this, struct ntrip_state *st);
void livesource_del_subscriber(struct subscriber *sub, struct caster_state *caster);
int livesource_send_subscribers(struct livesource *this, struct packet *packet, struct caster_state *caster);
struct livesource *livesource_find_unlocked(struct caster_state *this, char *mountpoint);
struct livesource *livesource_find(struct caster_state *this, char *mountpoint);

#endif /* __LIVESOURCE_H__ */
