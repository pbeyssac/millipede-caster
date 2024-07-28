#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "caster.h"
#include "livesource.h"
#include "ntrip_common.h"
#include "ntripsrv.h"
#include "packet.h"
#include "queue.h"

struct livesource *livesource_new(char *mountpoint) {
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

		P_RWLOCK_WRLOCK(&np->ntrip_state->lock);

		if (kill_backlogged ? np->backlogged : !np->virtual) {
			my_bufferevent_free(np->ntrip_state, np->ntrip_state->bev);
			np->ntrip_state->state = NTRIP_WAIT_CLOSE;

			/*
			 * Double decrement the reference count
			 * to enforce connection closing.
			 */
			ntrip_log(np->ntrip_state, LOG_NOTICE, "dropping %p due to %s\n", np->ntrip_state, kill_backlogged?"backlog":"closed source");
			np->ntrip_state->refcnt--;
			killed++;
		} else if (kill_backlogged == 0 && np->virtual) {
			/*
			 * Try to resubscribe virtual sources to a new source
			 *
			 * refcnt on the ntrip_state will be reincremented,
			 * preventing a drop of the connection while waiting for
			 * the resubscription.
			 */
			ntripsrv_redo_virtual_pos(np->ntrip_state);
		}

		if (kill_backlogged == 0 || np->backlogged) {
			TAILQ_REMOVE(&this->subscribers, np, next);
			this->nsubs--;
			np->ntrip_state->refcnt--;
			np->ntrip_state->subscription = NULL;
			ntrip_free(np->ntrip_state, "livesource_kill_subscribers_unlocked");
			free(np);
		} else
			P_RWLOCK_UNLOCK(&np->ntrip_state->lock);
	}
	return killed;
}

void livesource_free(struct livesource *this) {
	P_RWLOCK_WRLOCK(&this->lock);
	livesource_kill_subscribers_unlocked(this, 0);
	P_RWLOCK_DESTROY(&this->lock);
	strfree(this->mountpoint);
	free(this);
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
		sub->ntrip_state->refcnt++;
		sub->backlogged = 0;
		sub->virtual = 0;

		P_RWLOCK_WRLOCK(&this->lock);

		TAILQ_INSERT_TAIL(&this->subscribers, sub, next);
		this->nsubs++;

		P_RWLOCK_UNLOCK(&this->lock);

		ntrip_log(st, LOG_INFO, "subscription done to %s\n", this->mountpoint);
	}
	return sub;
}

/*
 *
 * Remove a subscriber from a live source.
 *
 * Required lock: ntrip_state
 */
void livesource_del_subscriber(struct subscriber *sub, struct caster_state *caster) {

	P_RWLOCK_WRLOCK(&sub->livesource->lock);

	TAILQ_REMOVE(&sub->livesource->subscribers, sub, next);
	sub->livesource->nsubs--;
	sub->ntrip_state->refcnt--;

	P_RWLOCK_UNLOCK(&sub->livesource->lock);

	free(sub);
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
		if (packet->caster->config->zero_copy) {
			if (evbuffer_add_reference(bufferevent_get_output(np->ntrip_state->bev), packet->data, packet->datalen, raw_free_callback, packet) < 0) {
				ntrip_log(np->ntrip_state, LOG_CRIT, "RTCM: evbuffer_add_reference failed\n");
				ns++;
			}
		} else {
			if (evbuffer_add(bufferevent_get_output(np->ntrip_state->bev), packet->data, packet->datalen) < 0) {
				ns++;
			}
		}
		size_t backlog_len = evbuffer_get_length(bufferevent_get_output(np->ntrip_state->bev));
		if (backlog_len > caster->config->backlog_evbuffer) {
			// ntrip_log(np->ntrip, LOG_NOTICE, "RTCM: backlog len %ld on output for %s\n", backlog_len, this->mountpoint);
			np->backlogged = 1;
			nbacklogged++;
		}
		n++;
	}

	if (n != this->nsubs)
		logfmt(&caster->flog, "assertion failed: nsubs != n (%d vs %d)\n", this->nsubs, n);

	/*
	 * Adjust reference count to account for failed calls
	 */
	if (packet->caster->config->zero_copy && ns) {
		/* Don't need to free the packet as it will be done by the caller, the refcnt should never be 0 here */
		P_MUTEX_LOCK(&packet->mutex);
		if (!packet->refcnt)
			logfmt(&caster->flog, "assertion failed: packet refcnt != 0 (%d instead)\n", packet->refcnt);
		packet->refcnt -= ns;
		P_MUTEX_UNLOCK(&packet->mutex);
	}

	/*
	 * Get rid of backlogged connections
	 */
	if (nbacklogged) {
		int found_backlogs = livesource_kill_subscribers_unlocked(this, 1);
		if (found_backlogs == nbacklogged)
			logfmt(&caster->flog, "RTCM: %d backlogged clients dropped from %s\n", nbacklogged, this->mountpoint);
		else
			logfmt(&caster->flog, "RTCM: %d (expected %d) backlogged clients dropped from %s\n", found_backlogs, nbacklogged, this->mountpoint);
	}
	P_RWLOCK_UNLOCK(&this->lock);

	if (n && (this->npackets == 1 || (this->npackets % 100 == 0)))
		logfmt(&caster->flog, "RTCM: %d packets sent, current one to %d subscribers for %s\n", this->npackets, n, this->mountpoint);
	return n;
}

/*
 * Display a list of current live sources.
 */
static void livesource_list(struct caster_state *caster) {
	struct livesource *np;

	P_RWLOCK_RDLOCK(&caster->livesources.lock);

	TAILQ_FOREACH(np, &caster->livesources.queue, next) {
		logfmt(&caster->flog, "Live:");
		break;
	}
	TAILQ_FOREACH(np, &caster->livesources.queue, next) {
		logfmt(&caster->flog, " %s", np->mountpoint);
	}
	TAILQ_FOREACH(np, &caster->livesources.queue, next) {
		logfmt(&caster->flog, "\n");
		break;
	}

	P_RWLOCK_UNLOCK(&caster->livesources.lock);
}

/*
 * Find a livesource by mountpoint name.
 * Warning: O(n) complexity.
 *
 * Required lock (read): livesource list.
 */
struct livesource *livesource_find_unlocked(struct caster_state *this, char *mountpoint) {
	struct livesource *np;
	struct livesource *result = NULL;
	TAILQ_FOREACH(np, &this->livesources.queue, next) {
		if (!strcmp(np->mountpoint, mountpoint)) {
			result = np;
			break;
		}
	}
	return result;
}

/*
 * Find a livesource by mountpoint name.
 * Warning: O(n) complexity.
 */
struct livesource *livesource_find(struct caster_state *this, char *mountpoint) {
	P_RWLOCK_RDLOCK(&this->livesources.lock);
	struct livesource *result = livesource_find_unlocked(this, mountpoint);
	P_RWLOCK_UNLOCK(&this->livesources.lock);
	return result;
}
