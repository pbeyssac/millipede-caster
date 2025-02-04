#include <assert.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <json-c/json.h>

#include "conf.h"
#include "caster.h"
#include "jobs.h"
#include "livesource.h"
#include "ntrip_common.h"
#include "ntripsrv.h"
#include "packet.h"
#include "queue.h"

static const char *livesource_states[3] = {"INIT", "FETCH_PENDING", "RUNNING"};
static const char *livesource_types[2] = {"DIRECT", "FETCHED"};

static void _livesource_del_subscriber_unlocked(struct ntrip_state *st);

struct livesources *livesource_table_new() {
	struct livesources *this = (struct livesources *)malloc(sizeof(struct livesources));
	P_RWLOCK_INIT(&this->lock, NULL);
	P_MUTEX_INIT(&this->delete_lock, NULL);
	this->serial = 0;
	this->hash = hash_table_new(509, (void(*)(void *))livesource_free);
	return this;
}

void livesource_table_free(struct livesources *this) {
	P_RWLOCK_DESTROY(&this->lock);
	P_MUTEX_DESTROY(&this->delete_lock);
	hash_table_free(this->hash);
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
	P_RWLOCK_WRLOCK(&this->lock);
	if (this->state != state) {
		this->state = state;
		caster->livesources->serial++;
	}
	P_RWLOCK_UNLOCK(&this->lock);
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

int livesource_del(struct livesource *this, struct caster_state *caster) {
	int r = 0;
	P_MUTEX_LOCK(&caster->livesources->delete_lock);
	P_RWLOCK_WRLOCK(&caster->livesources->lock);
	hash_table_del(caster->livesources->hash, this->mountpoint);
	r = 1;
	caster->livesources->serial++;
	P_RWLOCK_UNLOCK(&caster->livesources->lock);
	P_MUTEX_UNLOCK(&caster->livesources->delete_lock);
	return r;
}

/*
 * Required lock: ntrip_state
 * Acquires lock: livesources
 *
 */
struct livesource *livesource_connected(struct ntrip_state *st, char *mountpoint, struct livesource **existing) {
	struct livesource *existing_livesource;

	assert(st->own_livesource == NULL && st->subscription == NULL);

	/*
	 * A deadlock by lock order reversal (livesources then ntrip_state) is not possible here
	 * since we are not a source subscriber.
	 */
	P_RWLOCK_WRLOCK(&st->caster->livesources->lock);
	existing_livesource = livesource_find_unlocked(st->caster, st, mountpoint, NULL, 0, NULL);
	if (existing)
		*existing = existing_livesource;
	if (existing_livesource) {
		/* Here, we should perphaps destroy & replace any existing source fetcher. */
		P_RWLOCK_UNLOCK(&st->caster->livesources->lock);
		return NULL;
	}
	struct livesource *np = livesource_new(mountpoint, LIVESOURCE_TYPE_DIRECT, LIVESOURCE_RUNNING);
	if (np == NULL) {
		P_RWLOCK_UNLOCK(&st->caster->livesources->lock);
		st->own_livesource = NULL;
		return NULL;
	}
	hash_table_add(st->caster->livesources->hash, mountpoint, np);
	st->caster->livesources->serial++;
	st->own_livesource = np;
	P_RWLOCK_UNLOCK(&st->caster->livesources->lock);
	ntrip_log(st, LOG_INFO, "livesource %s created RUNNING", mountpoint);
	return np;
}
/*
 * Find a livesource by mountpoint name.
 *
 * Required lock (read): livesource list.
 */
struct livesource *livesource_find_unlocked(struct caster_state *this, struct ntrip_state *st, char *mountpoint, pos_t *mountpoint_pos, int on_demand, enum livesource_state *new_state) {
	struct livesource *np;
	struct livesource *result = NULL;

	np = (struct livesource *)hash_table_get(this->livesources->hash, mountpoint);

	if (np && (np->state == LIVESOURCE_RUNNING
			    || (on_demand && np->state == LIVESOURCE_FETCH_PENDING)))
		result = np;

	if (result == NULL && on_demand && st) {
		struct livesource *np = livesource_new(mountpoint, LIVESOURCE_TYPE_FETCHED, LIVESOURCE_FETCH_PENDING);
		if (np == NULL) {
			return NULL;
		}
		hash_table_add(this->livesources->hash, mountpoint, np);
		this->livesources->serial++;
		ntrip_log(st, LOG_INFO, "Trying to subscribe to on-demand source %s", mountpoint);
		struct redistribute_cb_args *redis_args = redistribute_args_new(this, np, mountpoint, mountpoint_pos, this->config->reconnect_delay, 0);
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
	P_RWLOCK_RDLOCK(&this->livesources->lock);
	struct livesource *result = livesource_find_unlocked(this, st, mountpoint, mountpoint_pos, on_demand, new_state);
	P_RWLOCK_UNLOCK(&this->livesources->lock);
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
 * Return a livesource structure as JSON.
 */
static json_object *livesource_json(struct livesource *this) {
	json_object *j = json_object_new_object();
	json_object_object_add(j, "mountpoint", json_object_new_string(this->mountpoint));
	json_object_object_add(j, "nsubscribers", json_object_new_int(this->nsubs));
	json_object_object_add(j, "npackets", json_object_new_int(this->npackets));
	json_object_object_add(j, "state", json_object_new_string(livesource_states[this->state]));
	json_object_object_add(j, "type", json_object_new_string(livesource_types[this->type]));
	return j;
}

/*
 * Return the full list of livesources as JSON.
 */
struct mime_content *livesource_list_json(struct caster_state *caster, struct hash_table *h) {
	char *s;
	json_object *jmain;
	json_object *new_list;

	jmain = json_object_new_object();
	json_object_object_add(jmain, "hostname", json_object_new_string(caster->hostname));
	json_object_object_add(jmain, "serial", json_object_new_int64(caster->livesources->serial));

	char iso_date[30];
	iso_date_from_timeval(iso_date, sizeof iso_date, &caster->start_date);
	json_object_object_add(jmain, "start_date", json_object_new_string(iso_date));

	new_list = json_object_new_object();
	struct hash_iterator hi;
	struct element *e;
	P_RWLOCK_RDLOCK(&caster->livesources->lock);
	HASH_FOREACH(e, caster->livesources->hash, hi) {
		json_object *j = livesource_json((struct livesource *)e->value);
		json_object_object_add(new_list, e->key, j);
	}
	P_RWLOCK_UNLOCK(&caster->livesources->lock);
	json_object_object_add(jmain, "livesources", new_list);

	s = mystrdup(json_object_to_json_string(jmain));
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	json_object_put(jmain);
	return m;
}
