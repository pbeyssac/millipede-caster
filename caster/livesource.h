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

enum livesource_type {
	LIVESOURCE_TYPE_DIRECT,
	LIVESOURCE_TYPE_FETCHED
};

enum livesource_update_type {
	LIVESOURCE_UPDATE_NONE,
	LIVESOURCE_UPDATE_ADD,
	LIVESOURCE_UPDATE_DEL,
	LIVESOURCE_UPDATE_STATUS
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
	enum livesource_type type;
};

/*
 * Simplified structure for a remote live source
 */
struct livesource_remote {
	char *mountpoint;
	enum livesource_state state;
	enum livesource_type type;
};

/*
 * Table of livesources for a remote node
 */
struct livesources_remote {
	struct hash_table *hash;
	unsigned long long serial;
	char *start_date;
	char *hostname;
	struct endpoint *endpoints;
	int endpoint_count;
};

/*
 * Table of livesources.
 */
struct livesources {
	// local livesources by mountpoint
	struct hash_table *hash;
	// remote tables by hostname
	struct hash_table *remote;
	P_RWLOCK_T lock;
	P_MUTEX_T delete_lock;
	unsigned long long serial;

	// This is used to disambiguate a rolled-back serial sequence
	char *start_date;

	// Used as a key to identify this table when synchronizing
	// with other nodes.
	char *hostname;			// our hostname
};

struct caster_state;
struct request;

struct livesources *livesource_table_new(const char *hostname, struct timeval *start_date);
void livesource_table_free(struct livesources *this);
struct livesource *livesource_new(char *mountpoint, enum livesource_type type, enum livesource_state state);
int livesource_del(struct livesource *this, struct ntrip_state *st, struct caster_state *caster);
struct livesource *livesource_connected(struct ntrip_state *st, char *mountpoint, struct livesource **existing);
struct livesource *livesource_find(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos);
struct livesource *livesource_find_on_demand(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand, enum livesource_state *new_state);
struct livesource *livesource_find_and_subscribe(struct caster_state *caster, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand);
int livesource_kill_subscribers_unlocked(struct livesource *this, int kill_backlogged);
void livesource_free(struct livesource *this);
void livesource_set_state(struct livesource *this, struct caster_state *caster, enum livesource_state state);
struct subscriber *livesource_add_subscriber(struct livesource *this, struct ntrip_state *st);
void livesource_del_subscriber(struct ntrip_state *st);
int livesource_send_subscribers(struct livesource *this, struct packet *packet, struct caster_state *caster);
struct livesource *livesource_find(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos);

struct mime_content *livesource_list_json(struct caster_state *caster, struct request *req);

json_object *livesource_full_update_json(struct caster_state *caster, struct livesources *this);
json_object *livesource_checkserial_json(struct livesources *this);
int livesource_update_execute(struct caster_state *caster, struct livesources *this, json_object *j);

#endif /* __LIVESOURCE_H__ */
