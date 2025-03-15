#include <assert.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <json-c/json.h>
#include <json-c/json_object_iterator.h>

#include "conf.h"
#include "caster.h"
#include "endpoints.h"
#include "jobs.h"
#include "livesource.h"
#include "ntrip_common.h"
#include "ntripsrv.h"
#include "packet.h"
#include "queue.h"
#include "util.h"

static const char *livesource_states[4] = {"INIT", "FETCH_PENDING", "RUNNING", NULL};
static const char *livesource_types[3] = {"DIRECT", "FETCHED", NULL};
static const char *livesource_update_types[4] = {"none", "add", "del", "update"};

static void _livesource_del_subscriber_unlocked(struct ntrip_state *st);
static json_object *livesource_update_json(struct livesource *this,
	struct caster_state *caster, enum livesource_update_type utype);
static struct livesource *livesource_find_unlocked(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand, enum livesource_state *new_state, json_object **jp);

/*
 * Create a remote livesource record
 */
static struct livesource_remote *livesource_remote_new(const char *mountpoint) {
	struct livesource_remote *this = (struct livesource_remote *)malloc(sizeof(struct livesource_remote));
	if (this != NULL) {
		this->mountpoint = mystrdup(mountpoint);
		if (this->mountpoint == NULL) {
			free(this);
			return NULL;
		}
	}
	return this;
}

static void livesource_remote_free(struct livesource_remote *this) {
	strfree(this->mountpoint);
	strfree(this);
}

static void livesources_remote_free(struct livesources_remote *this) {
	if (this->hash != NULL)
		hash_table_free(this->hash);
	strfree(this->start_date);
	strfree(this->hostname);
	endpoints_free(this->endpoints, this->endpoint_count);
	free(this);
}

/*
 * Create a table of livesources for a remote node
 */
static struct livesources_remote *livesources_remote_new(const char *hostname, const char *start_date, unsigned long long serial) {
	struct livesources_remote *this = (struct livesources_remote *)malloc(sizeof(struct livesources_remote));

	if (this == NULL)
		return NULL;

	this->endpoints = NULL;
	this->endpoint_count = 0;

	char *dup_start_date = mystrdup(start_date);
	char *dup_hostname = mystrdup(hostname);

	this->serial = serial;
	this->hash = hash_table_new(509, (void(*)(void *))livesource_remote_free);
	if (dup_start_date == NULL || dup_hostname == NULL || this->hash == NULL) {
		livesources_remote_free(this);
		return NULL;
	}
	this->start_date = dup_start_date;
	this->hostname = dup_hostname;
	return this;
}

void livesource_table_free(struct livesources *this) {
	if (this->hash != NULL)
		hash_table_free(this->hash);
	if (this->remote != NULL)
		hash_table_free(this->remote);
	P_RWLOCK_DESTROY(&this->lock);
	P_MUTEX_DESTROY(&this->delete_lock);
	strfree(this->start_date);
	strfree(this->hostname);
	free(this);
}

struct livesources *livesource_table_new(const char *hostname, struct timeval *start_date) {
	struct livesources *this = (struct livesources *)malloc(sizeof(struct livesources));

	if (this == NULL)
		return NULL;

	P_RWLOCK_INIT(&this->lock, NULL);
	P_MUTEX_INIT(&this->delete_lock, NULL);
	this->serial = 0;
	this->hash = hash_table_new(509, (void(*)(void *))livesource_free);
	this->remote = hash_table_new(113, (void(*)(void *))livesources_remote_free);

	char iso_date[40];
	iso_date_from_timeval(iso_date, sizeof iso_date, start_date);
	this->start_date = mystrdup(iso_date);
	this->hostname = mystrdup(hostname);

	if (this->start_date == NULL || this->hostname == NULL
		|| this->hash == NULL || this->remote == NULL)
		livesource_table_free(this);
	return this;
}

struct livesource *livesource_new(char *mountpoint, enum livesource_type type, enum livesource_state state) {
	struct livesource *this = (struct livesource *)malloc(sizeof(struct livesource));
	if (this == NULL)
		return NULL;
	this->mountpoint = mystrdup(mountpoint);
	if (this->mountpoint == NULL) {
		free(this);
		return NULL;
	}
	TAILQ_INIT(&this->subscribers);
	this->nsubs = 0;
	this->npackets = 0;
	this->state = state;
	this->type = type;

	P_RWLOCK_INIT(&this->lock, NULL);
	return this;
}

/*
 * Kill some or all subscribers of a livesource.
 *
 * Required locks: lock on the livesource.
 *
 * If kill_backlogged is 0:
 *	unsubscribe users subscribed for a virtual source
 *	unsubscribe & kill others
 * If kill_backlogged is not 0:
 *	unsubscribe & kill subscribers flagged as backlogged
 */
int livesource_kill_subscribers_unlocked(struct livesource *this, int kill_backlogged) {
	struct subscriber *np, *tnp;
	int killed = 0;
	TAILQ_FOREACH_SAFE(np, &this->subscribers, next, tnp) {
		/* Keep a pointer because it will be possibly destroyed by ntrip_deferred_free() */
		struct bufferevent *bev = np->ntrip_state->bev;

		bufferevent_lock(bev);

		if (kill_backlogged ? np->backlogged : !np->virtual) {
			ntrip_log(np->ntrip_state, LOG_NOTICE, "dropping due to %s", kill_backlogged?"backlog":"closed source");
			killed++;
		} else if (kill_backlogged == 0 && np->virtual) {
			/*
			 * Try to resubscribe virtual sources to a new source
			 */
			joblist_append_ntrip_locked(np->ntrip_state->caster->joblist, np->ntrip_state, &ntripsrv_redo_virtual_pos);
		}

		if (kill_backlogged == 0 || np->backlogged) {
			struct ntrip_state *st = np->ntrip_state;
			_livesource_del_subscriber_unlocked(st);
			ntrip_deferred_free(st, "livesource_kill_subscribers_unlocked");
		}
		bufferevent_unlock(bev);
	}
	return killed;
}

void livesource_free(struct livesource *this) {
	P_RWLOCK_WRLOCK(&this->lock);
	livesource_kill_subscribers_unlocked(this, 0);
	P_RWLOCK_UNLOCK(&this->lock);
	P_RWLOCK_DESTROY(&this->lock);
	strfree(this->mountpoint);
	free(this);
}

void livesource_set_state(struct livesource *this, struct caster_state *caster, enum livesource_state state) {
	json_object *j = NULL;
	P_RWLOCK_WRLOCK(&this->lock);
	if (this->state != state) {
		this->state = state;
		j = livesource_update_json(this, caster, LIVESOURCE_UPDATE_STATUS);
		caster->livesources->serial++;
	}
	P_RWLOCK_UNLOCK(&this->lock);
	syncer_queue_json(caster, j);
}

/*
 * Add a subscriber to a live source.
 *
 * Required lock: ntrip_state
 */
struct subscriber *livesource_add_subscriber(struct livesource *this, struct ntrip_state *st) {
	struct subscriber *sub = (struct subscriber *)malloc(sizeof(struct subscriber));
	if (sub != NULL) {
		sub->livesource = this;
		sub->ntrip_state = st;
		sub->backlogged = 0;
		sub->virtual = 0;

		P_RWLOCK_WRLOCK(&this->lock);
		TAILQ_INSERT_TAIL(&this->subscribers, sub, next);
		this->nsubs++;
		st->subscription = sub;
		P_RWLOCK_UNLOCK(&this->lock);

		ntrip_log(st, LOG_INFO, "subscription done to %s", this->mountpoint);
	}
	return sub;
}

/*
 * Remove a subscriber from a live source.
 */
static void _livesource_del_subscriber_unlocked(struct ntrip_state *st) {
	if (st->subscription) {
		struct subscriber *sub = st->subscription;
		TAILQ_REMOVE(&sub->livesource->subscribers, sub, next);
		sub->livesource->nsubs--;
		sub->ntrip_state->subscription = NULL;
		free(sub);
	}
}

void livesource_del_subscriber(struct ntrip_state *st) {
	/*
	 * Lock order is mandatory to avoid deadlocks with livesource_send_subscribers
	 */
	P_MUTEX_LOCK(&st->caster->livesources->delete_lock);
	struct subscriber *sub = st->subscription;
	if (sub) {
		struct livesource *livesource = sub->livesource;
		P_RWLOCK_WRLOCK(&livesource->lock);
		bufferevent_lock(st->bev);

		_livesource_del_subscriber_unlocked(st);

		bufferevent_unlock(st->bev);
		P_RWLOCK_UNLOCK(&livesource->lock);
	}
	P_MUTEX_UNLOCK(&st->caster->livesources->delete_lock);
}

/*
 * Packet freeing callback
 */
static void raw_free_callback(const void *data, size_t datalen, void *extra) {
	struct packet *packet = (struct packet *)extra;
	packet_free(packet);
}

/*
 * Send a packet to all source subscribers
 *
 * Required locks: ntrip_state, packet
 */
int livesource_send_subscribers(struct livesource *this, struct packet *packet, struct caster_state *caster) {
	struct subscriber *np;
	int n = 0;
	int ns = 0;

	if (this == NULL)
		/* Dead livesource */
		return 0;

	P_RWLOCK_WRLOCK(&this->lock);

	this->npackets++;

	/* Increase reference count in one go to reduce overhead */
	if (packet->caster->config->zero_copy) {
		P_MUTEX_LOCK(&packet->mutex);
		packet->refcnt += this->nsubs;
		P_MUTEX_UNLOCK(&packet->mutex);
	}

	int nbacklogged = 0;

	TAILQ_FOREACH(np, &this->subscribers, next) {
		struct ntrip_state *st = np->ntrip_state;
		struct bufferevent *bev = st->bev;
		bufferevent_lock(bev);
		if (st->state == NTRIP_END) {
			/* Subscriber currently closing, skip */
			ntrip_log(st, LOG_DEBUG, "livesource_send_subscribers: dropping, state=%d", st->state);
			bufferevent_unlock(bev);
			ns++;
			n++;
			continue;
		}
		size_t backlog_len = evbuffer_get_length(bufferevent_get_output(st->bev));
		if (backlog_len > caster->config->backlog_evbuffer) {
			ntrip_log(st, LOG_NOTICE, "RTCM: backlog len %ld on output for %s", backlog_len, this->mountpoint);
			np->backlogged = 1;
			nbacklogged++;
			ns++;
		} else if (packet->caster->config->zero_copy) {
			if (evbuffer_add_reference(bufferevent_get_output(st->bev), packet->data, packet->datalen, raw_free_callback, packet) < 0) {
				ntrip_log(st, LOG_CRIT, "RTCM: evbuffer_add_reference failed");
				ns++;
			} else
				st->sent_bytes += packet->datalen;
		} else {
			if (evbuffer_add(bufferevent_get_output(st->bev), packet->data, packet->datalen) < 0) {
				ns++;
			} else
				st->sent_bytes += packet->datalen;
		}
		bufferevent_unlock(bev);
		n++;
	}

	assert(n == this->nsubs);

	/*
	 * Adjust reference count to account for failed calls
	 */
	if (packet->caster->config->zero_copy && ns) {
		/* Don't need to free the packet as it will be done by the caller, the refcnt should never be 0 here */
		P_MUTEX_LOCK(&packet->mutex);
		packet->refcnt -= ns;
		P_MUTEX_UNLOCK(&packet->mutex);
	}
	assert(packet->refcnt > 0);

	/*
	 * Get rid of backlogged connections
	 */
	if (nbacklogged) {
		int found_backlogs = livesource_kill_subscribers_unlocked(this, 1);
		if (found_backlogs == nbacklogged)
			logfmt(&caster->flog, LOG_INFO, "RTCM: %d backlogged clients dropped from %s", nbacklogged, this->mountpoint);
		else
			logfmt(&caster->flog, LOG_INFO, "RTCM: %d (expected %d) backlogged clients dropped from %s", found_backlogs, nbacklogged, this->mountpoint);
	}
	P_RWLOCK_UNLOCK(&this->lock);

	if (n && (this->npackets == 1 || (this->npackets % 100 == 0)))
		logfmt(&caster->flog, LOG_INFO, "RTCM: %d packets sent, current one to %d subscribers for %s", this->npackets, n, this->mountpoint);
	return n;
}

int livesource_del(struct livesource *this, struct ntrip_state *st, struct caster_state *caster) {
	json_object *j;
	int r = 0;

	P_MUTEX_LOCK(&caster->livesources->delete_lock);
	P_RWLOCK_WRLOCK(&caster->livesources->lock);
	const char *lstype = livesource_types[this->type];
	j = livesource_update_json(this, caster, LIVESOURCE_UPDATE_DEL);
	hash_table_del(caster->livesources->hash, this->mountpoint);
	r = 1;
	caster->livesources->serial++;
	P_RWLOCK_UNLOCK(&caster->livesources->lock);
	P_MUTEX_UNLOCK(&caster->livesources->delete_lock);
	syncer_queue_json(caster, j);

	if (r)
		ntrip_log(st, LOG_INFO, "Unregistered livesource %s type %s", st->mountpoint, lstype);
	return r;
}

/*
 * Required lock: ntrip_state
 * Acquires lock: livesources
 *
 */
struct livesource *livesource_connected(struct ntrip_state *st, char *mountpoint, struct livesource **existing) {
	json_object *j;
	struct livesource *existing_livesource;

	assert(st->own_livesource == NULL && st->subscription == NULL);

	/*
	 * A deadlock by lock order reversal (livesources then ntrip_state) is not possible here
	 * since we are not a source subscriber.
	 */
	P_RWLOCK_WRLOCK(&st->caster->livesources->lock);
	existing_livesource = livesource_find_unlocked(st->caster, st, mountpoint, NULL, 0, NULL, &j);
	if (existing)
		*existing = existing_livesource;
	if (existing_livesource) {
		/* Here, we should perphaps destroy & replace any existing source fetcher. */
		P_RWLOCK_UNLOCK(&st->caster->livesources->lock);
		return NULL;
	}
	struct livesource *np = livesource_new(mountpoint, LIVESOURCE_TYPE_DIRECT, LIVESOURCE_RUNNING);
	if (np == NULL) {
		st->own_livesource = NULL;
		P_RWLOCK_UNLOCK(&st->caster->livesources->lock);
		return NULL;
	}
	hash_table_add(st->caster->livesources->hash, mountpoint, np);
	j = livesource_update_json(np, st->caster, LIVESOURCE_UPDATE_ADD);
	st->caster->livesources->serial++;
	st->own_livesource = np;
	P_RWLOCK_UNLOCK(&st->caster->livesources->lock);
	ntrip_log(st, LOG_INFO, "livesource %s created RUNNING", mountpoint);
	syncer_queue_json(st->caster, j);
	return np;
}

static void livesource_find_remote_endpoint(struct caster_state *this, struct ntrip_state *st, const char *mountpoint, struct endpoint *endpoint) {
	struct hash_iterator hi;
	struct element *e;

	HASH_FOREACH(e, this->livesources->remote, hi) {
		struct livesources_remote *rem = (struct livesources_remote *)e->value;
		struct livesource_remote *rltmp = NULL;

		if (rem->endpoint_count == 0)
			continue;

		rltmp = (struct livesource_remote *)hash_table_get(rem->hash, mountpoint);
		if (rltmp && rltmp->state == LIVESOURCE_RUNNING) {
			endpoint_copy(endpoint, &rem->endpoints[0]);
			break;
		}
	}
}

/*
 * Find a livesource by mountpoint name.
 *
 * Required lock (read): livesource list.
 */
static struct livesource *livesource_find_unlocked(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand, enum livesource_state *new_state, json_object **jp) {
	struct livesource *np;
	struct livesource *result = NULL;

	*jp = NULL;

	np = (struct livesource *)hash_table_get(this->livesources->hash, mountpoint);

	if (np && (np->state == LIVESOURCE_RUNNING
			    || (on_demand && np->state == LIVESOURCE_FETCH_PENDING)))
		result = np;

	if (result == NULL && on_demand && st) {
		struct endpoint e;
		endpoint_init(&e, NULL, 0, 0);

		livesource_find_remote_endpoint(this, st, mountpoint, &e);

		struct livesource *np = livesource_new(mountpoint, LIVESOURCE_TYPE_FETCHED, LIVESOURCE_FETCH_PENDING);
		if (np == NULL) {
			return NULL;
		}
		hash_table_add(this->livesources->hash, mountpoint, np);
		*jp = livesource_update_json(np, this, LIVESOURCE_UPDATE_ADD);
		this->livesources->serial++;
		ntrip_log(st, LOG_INFO, "Trying to subscribe to on-demand source %s", mountpoint);
		struct redistribute_cb_args *redis_args = redistribute_args_new(this, np,
			&e, mountpoint, mountpoint_pos, this->config->reconnect_delay, 0);
		endpoint_free(&e);
		joblist_append_redistribute(this->joblist, redistribute_source_stream, redis_args);
		result = np;
	}

	/* Copy current state while we are locked */
	if (new_state && result)
		*new_state = result->state;
	return result;
}

/*
 * Find a livesource by mountpoint name.
 */
struct livesource *livesource_find_on_demand(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand, enum livesource_state *new_state) {
	json_object *j;
	P_RWLOCK_RDLOCK(&this->livesources->lock);
	struct livesource *result = livesource_find_unlocked(this, st, mountpoint, mountpoint_pos, on_demand, new_state, &j);
	P_RWLOCK_UNLOCK(&this->livesources->lock);
	syncer_queue_json(this, j);
	return result;
}

struct livesource *livesource_find(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos) {
	return livesource_find_on_demand(this, st, mountpoint, mountpoint_pos, 0, NULL);
}

struct livesource *livesource_find_and_subscribe(struct caster_state *caster, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand) {
	P_MUTEX_LOCK(&st->caster->livesources->delete_lock);
	struct livesource *l = livesource_find_on_demand(caster, st, mountpoint, mountpoint_pos, st->source_on_demand, NULL);
	if (l)
		livesource_add_subscriber(l, st);
	P_MUTEX_UNLOCK(&st->caster->livesources->delete_lock);
	return l;
}

/*
 * Common code for livesource remote/local
 */
static json_object *_livesource_common_json(const char *mountpoint, enum livesource_state state, enum livesource_type type, int add_state_type) {
	json_object *j = json_object_new_object();
	json_object_object_add(j, "mountpoint", json_object_new_string(mountpoint));
	if (add_state_type) {
		json_object_object_add(j, "state", json_object_new_string(livesource_states[state]));
		json_object_object_add(j, "type", json_object_new_string(livesource_types[type]));
	}
	return j;
}

/*
 * Return a local livesource structure as JSON.
 */
static json_object *livesource_json(struct livesource *this, enum livesource_update_type utype) {
	json_object *j = _livesource_common_json(this->mountpoint, this->state, this->type, utype != LIVESOURCE_UPDATE_DEL);
	if (utype == LIVESOURCE_UPDATE_NONE) {
		json_object_object_add(j, "nsubscribers", json_object_new_int(this->nsubs));
		json_object_object_add(j, "npackets", json_object_new_int(this->npackets));
	}
	return j;
}

/*
 * Return a remote livesource structure as JSON.
 */
static json_object *livesource_remote_json(struct livesource_remote *this) {
	return _livesource_common_json(this->mountpoint, this->state, this->type, 1);
}

/*
 * Return the basic parameters of the local livesource list.
 */
static json_object *_livesource_list_base_json(struct livesources *this) {
	json_object *j = json_object_new_object();
	json_object_object_add(j, "hostname", json_object_new_string(this->hostname));
	json_object_object_add(j, "serial", json_object_new_int64(this->serial));
	json_object_object_add(j, "start_date", json_object_new_string(this->start_date));
	return j;
}

/*
 * Return the full list of local livesources as JSON.
 */
static json_object *livesource_list_local_json(struct caster_state *caster, struct livesources *this) {
	json_object *jmain;
	json_object *new_list;

	jmain = _livesource_list_base_json(this);
	json_object_get(caster->endpoints_json);
	json_object_object_add(jmain, "endpoints", caster->endpoints_json);

	new_list = json_object_new_object();
	struct hash_iterator hi;
	struct element *e;
	P_RWLOCK_RDLOCK(&this->lock);
	HASH_FOREACH(e, this->hash, hi) {
		json_object *j = livesource_json((struct livesource *)e->value, LIVESOURCE_UPDATE_NONE);
		json_object_object_add(new_list, e->key, j);
	}
	P_RWLOCK_UNLOCK(&this->lock);
	json_object_object_add(jmain, "livesources", new_list);
	return jmain;
}

/*
 * Return the full list of remote livesources as JSON.
 */
static json_object *_livesource_list_remote_json(struct livesources *this, struct livesources_remote *thisr) {
	json_object *jmain;
	json_object *new_list;

	jmain = json_object_new_object();
	json_object_object_add(jmain, "hostname", json_object_new_string(thisr->hostname));
	json_object_object_add(jmain, "serial", json_object_new_int64(thisr->serial));
	json_object_object_add(jmain, "start_date", json_object_new_string(thisr->start_date));

	new_list = json_object_new_object();
	struct hash_iterator hi;
	struct element *e;
	P_RWLOCK_RDLOCK(&this->lock);
	HASH_FOREACH(e, thisr->hash, hi) {
		json_object *j = livesource_remote_json((struct livesource_remote *)e->value);
		json_object_object_add(new_list, e->key, j);
	}
	json_object *jendpoints = endpoints_to_json(thisr->endpoints, thisr->endpoint_count);
	P_RWLOCK_UNLOCK(&this->lock);
	json_object_object_add(jmain, "endpoints", jendpoints);
	json_object_object_add(jmain, "livesources", new_list);
	return jmain;
}

/*
 * Return the full list of livesources, local + remote, as JSON.
 */
static struct mime_content *_livesource_list_json(struct caster_state *caster) {
	char *s;
	json_object *jmain = json_object_new_object();

	json_object *j = livesource_list_local_json(caster, caster->livesources);
	json_object_object_add(jmain, "LOCAL", j);

	P_RWLOCK_RDLOCK(&caster->livesources->lock);
	struct hash_iterator hi;
	struct element *e;
	HASH_FOREACH(e, caster->livesources->remote, hi) {
		j = _livesource_list_remote_json(caster->livesources, (struct livesources_remote *)e->value);
		json_object_object_add(jmain, e->key, j);
	}
	P_RWLOCK_UNLOCK(&caster->livesources->lock);
	s = mystrdup(json_object_to_json_string(jmain));
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	json_object_put(jmain);
	return m;
}

struct mime_content *livesource_list_json(struct caster_state *caster, struct request *req) {
	return _livesource_list_json(caster);
}

/*
 * Generate a JSON packet for a full table update.
 */
json_object *livesource_full_update_json(struct caster_state *caster, struct livesources *this) {
	json_object *jmain = livesource_list_local_json(caster, this);
	json_object_object_add(jmain, "type", json_object_new_string("fulltable"));
	return jmain;
}

/*
 * Generate a JSON packet to request a serial + start_date check.
 */
json_object *livesource_checkserial_json(struct livesources *this) {
	json_object *j = _livesource_list_base_json(this);
	json_object_object_add(j, "type", json_object_new_string("checkserial"));
	return j;
}

/*
 * Generate a JSON incremental update packet from a local livesource record.
 */
static json_object *livesource_update_json(struct livesource *this,
	struct caster_state *caster, enum livesource_update_type utype) {

	json_object *j = json_object_new_object();
	json_object *jl = livesource_json(this, utype);
	json_object_object_add(j, "livesource", jl);

	json_object_object_add(j, "start_date", json_object_new_string(caster->livesources->start_date));
	json_object_object_add(j, "hostname", json_object_new_string(caster->livesources->hostname));
	json_object_object_add(j, "serial", json_object_new_int64(caster->livesources->serial));
	json_object_object_add(j, "type", json_object_new_string(livesource_update_types[utype]));

	return j;
}

/*
 * Update receipt routines.
 */

static enum livesource_state convert_state(const char *state) {
	const char **statep = livesource_states;
	for (int i = 0; *statep; i++) {
		if (!strcmp(*statep++, state))
			return i;
	}
	return -1;
}

static enum livesource_type convert_type(const char *type) {
	const char **typep = livesource_types;
	for (int i = 0; *typep; i++) {
		if (!strcmp(*typep++, type))
			return i;
	}
	return -1;
}

/*
 * Execute a full table update.
 */
static int livesource_update_execute_fulltable(struct caster_state *caster, struct livesources *this, json_object *j, const char *hostname) {
	struct json_object *lslist = json_object_object_get(j, "livesources");
	struct json_object *jserial = json_object_object_get(j, "serial");
	struct json_object *jendpoints = json_object_object_get(j, "endpoints");
	const char *start_date = json_object_get_string(json_object_object_get(j, "start_date"));

	if (lslist == NULL || jserial == NULL || start_date == NULL || hostname == NULL || jendpoints == NULL)
		return 503;

	int endpoint_count;

	struct endpoint *pe = endpoints_from_json(jendpoints, &endpoint_count);
	if (pe == NULL)
		return 503;

	unsigned long serial = json_object_get_int64(jserial);
	struct livesources_remote *remote = livesources_remote_new(hostname, start_date, serial);
	remote->endpoints = pe;
	remote->endpoint_count = endpoint_count;

	struct json_object_iterator it;
	struct json_object_iterator itEnd;

	it = json_object_iter_begin(lslist);
	itEnd = json_object_iter_end(lslist);

	while (!json_object_iter_equal(&it, &itEnd)) {
		const char *mountpoint = json_object_iter_peek_name(&it);
		struct json_object *ls = json_object_iter_peek_value(&it);
		const char *lstype = json_object_get_string(json_object_object_get(ls, "type"));
		const char *lsstate = json_object_get_string(json_object_object_get(ls, "state"));

		struct livesource_remote *lr = livesource_remote_new(mountpoint);
		lr->state = convert_state(lsstate);
		lr->type = convert_type(lstype);

		hash_table_add(remote->hash, mountpoint, lr);

		json_object_iter_next(&it);
	}

	hash_table_del(this->remote, hostname);
	hash_table_add(this->remote, hostname, remote);
	logfmt(&caster->flog, LOG_EDEBUG, "reload table %s serial %ld done", hostname, serial);

	return 200;
}

/*
 * Main routine to execute a received update.
 */
int livesource_update_execute(struct caster_state *caster, struct livesources *this, json_object *j) {
	const char *type = json_object_get_string(json_object_object_get(j, "type"));
	const char *hostname = json_object_get_string(json_object_object_get(j, "hostname"));

	if (type == NULL || hostname == NULL) {
		return 503;
	}

	if (!strcmp(type, "fulltable")) {
		int r = livesource_update_execute_fulltable(caster, this, j, hostname);
		return r;
	}

	struct json_object *jserial = json_object_object_get(j, "serial");
	struct json_object *jstart_date = json_object_object_get(j, "start_date");

	if (jserial == NULL || jstart_date == NULL) {
		return 503;
	}

	unsigned long long serial = json_object_get_int64(jserial);

	struct livesources_remote *lrlist = (struct livesources_remote *)hash_table_get(this->remote, hostname);

	if (lrlist == NULL) {
		logfmt(&caster->flog, LOG_NOTICE, "update failed, hostname %s not found", hostname);
		return 404;
	}

	const char *start_date = json_object_get_string(jstart_date);
	if (strcmp(start_date, lrlist->start_date)) {
		logfmt(&caster->flog, LOG_NOTICE, "bad start_date %s wanted %s", start_date, lrlist->start_date);
		return 404;
	}

	if (serial != lrlist->serial) {
		logfmt(&caster->flog, LOG_NOTICE, "bad serial %llu wanted %llu", serial, lrlist->serial);
		return 404;
	}

	if (!strcmp(type, "checkserial"))
		return 200;

	struct json_object *ls = json_object_object_get(j, "livesource");
	if (ls == NULL) {
		logfmt(&caster->flog, LOG_NOTICE, "'livesource' not found");
		return 404;
	}
	const char *mountpoint = json_object_get_string(json_object_object_get(ls, "mountpoint"));

	struct livesource_remote *lr = (struct livesource_remote *)hash_table_get(lrlist->hash, mountpoint);

	if (!strcmp(type, "add")) {
		if (lr) {
			logfmt(&caster->flog, LOG_NOTICE, "update failed: %s exists", mountpoint);
			return 404;
		}
		lr = livesource_remote_new(mountpoint);
		const char *lstype = json_object_get_string(json_object_object_get(ls, "type"));
		const char *lsstate = json_object_get_string(json_object_object_get(ls, "state"));
		lr->state = convert_state(lsstate);
		lr->type = convert_type(lstype);
		hash_table_add(lrlist->hash, mountpoint, lr);
	} else if (!strcmp(type, "del")) {
		if (!lr) {
			logfmt(&caster->flog, LOG_NOTICE, "update failed: %s does not exist", mountpoint);
			return 503;
		}
		hash_table_del(lrlist->hash, mountpoint);
	} else if (!strcmp(type, "update")) {
		if (!lr) {
			logfmt(&caster->flog, LOG_NOTICE, "update failed: %s does not exist", mountpoint);
			return 503;
		}
		const char *lstype = json_object_get_string(json_object_object_get(ls, "type"));
		const char *lsstate = json_object_get_string(json_object_object_get(ls, "state"));
		lr->state = convert_state(lsstate);
		lr->type = convert_type(lstype);
	} else {
		logfmt(&caster->flog, LOG_NOTICE, "update failed: unknown type %s", type);
		return 503;
	}

	lrlist->serial++;
	return 200;
}
