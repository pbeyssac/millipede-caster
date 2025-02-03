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
	char *mountpoint;
	struct subscribersq subscribers;
	int nsubs;
	int npackets;
	enum livesource_state state;
};

struct caster_state;
struct livesource *livesource_new(char *mountpoint, enum livesource_state state);
int livesource_del(struct livesource *this, struct caster_state *caster);
struct livesource *livesource_connected(struct ntrip_state *st, char *mountpoint, struct livesource **existing);
struct livesource *livesource_find(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos);
struct livesource *livesource_find_on_demand(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand, enum livesource_state *new_state);
int livesource_kill_subscribers_unlocked(struct livesource *this, int kill_backlogged);
void livesource_free(struct livesource *this);
void livesource_set_state(struct livesource *this, enum livesource_state state);
struct subscriber *livesource_add_subscriber(struct livesource *this, struct ntrip_state *st);
void livesource_del_subscriber(struct ntrip_state *st);
int livesource_send_subscribers(struct livesource *this, struct packet *packet, struct caster_state *caster);
struct livesource *livesource_find_unlocked(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos,int on_demand, enum livesource_state *new_state);
struct livesource *livesource_find(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos);

struct hash_table;
struct mime_content *livesource_list_json(struct caster_state *caster, struct hash_table *h);

#endif /* __LIVESOURCE_H__ */
