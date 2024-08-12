#ifndef __LIVESOURCE_H__
#define __LIVESOURCE_H__

#include <stdlib.h>
#include <sys/queue.h>

#include "packet.h"
#include "sourceline.h"

enum livesource_state {
	LIVESOURCE_INIT,
	LIVESOURCE_FETCH_PENDING,
	LIVESOURCE_RUNNING
};

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
	P_RWLOCK_T lock;
	TAILQ_ENTRY(livesource) next;
	char *mountpoint;
	struct subscribersq subscribers;
	int nsubs;
	int npackets;
	enum livesource_state state;
};
TAILQ_HEAD (livesourceq, livesource);

struct caster_state;
struct livesource *livesource_new(char *mountpoint, enum livesource_state state);
struct livesource *livesource_find(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos);
struct livesource *livesource_find_on_demand(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand, enum livesource_state *new_state);
int livesource_kill_subscribers_unlocked(struct livesource *this, int kill_backlogged);
void livesource_free(struct livesource *this);
struct subscriber *livesource_add_subscriber(struct livesource *this, struct ntrip_state *st);
void livesource_del_subscriber(struct subscriber *sub, struct ntrip_state *st);
int livesource_send_subscribers(struct livesource *this, struct packet *packet, struct caster_state *caster);
struct livesource *livesource_find_unlocked(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos,int on_demand, enum livesource_state *new_state);
struct livesource *livesource_find(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos);

#endif /* __LIVESOURCE_H__ */
