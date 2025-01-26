#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "jobs.h"
#include "redistribute.h"
#include "ntripcli.h"
#include "ntripsrv.h"

/*
 * Required lock: ntrip_state
 *
 * Switch client from a given source to another.
 */
int redistribute_switch_source(struct ntrip_state *this, char *new_mountpoint, pos_t *mountpoint_pos, struct livesource *livesource) {
	ntrip_log(this, LOG_INFO, "Switching virtual source from %s to %s", this->virtual_mountpoint, new_mountpoint);
	new_mountpoint = mystrdup(new_mountpoint);
	if (new_mountpoint == NULL)
		return -1;
	if (this->subscription) {
		livesource_del_subscriber(this);
	}
	this->subscription = livesource_add_subscriber(livesource, this);
	this->subscription->virtual = 1;
	if (this->virtual_mountpoint)
		strfree(this->virtual_mountpoint);
	this->virtual_mountpoint = new_mountpoint;
	this->mountpoint_pos = *mountpoint_pos;
	return 0;
}

/*
 * Redistribute source stream.
 * Step 1 -- prepare argument structure.
 */
struct redistribute_cb_args *
redistribute_args_new(struct caster_state *caster, struct livesource *livesource, char *mountpoint, pos_t *mountpoint_pos, int reconnect_delay, int persistent) {
	struct redistribute_cb_args *redis_args;
	redis_args = (struct redistribute_cb_args *)malloc(sizeof(struct redistribute_cb_args));
	char *dup_mountpoint = mystrdup(mountpoint);
	if (redis_args != NULL && dup_mountpoint != NULL) {
		redis_args->mountpoint = dup_mountpoint;
		if (mountpoint_pos)
			redis_args->mountpoint_pos = *mountpoint_pos;
		else {
			redis_args->mountpoint_pos.lat = 0.;
			redis_args->mountpoint_pos.lon = 0.;
		}
		redis_args->caster = caster;
		redis_args->source_st = NULL;
		redis_args->ev = NULL;
		redis_args->persistent = persistent;
		redis_args->livesource = livesource;
		return redis_args;
	} else {
		if (redis_args)
			free(redis_args);
		if (dup_mountpoint)
			strfree(dup_mountpoint);
		return NULL;
	}
}

void
redistribute_args_free(struct redistribute_cb_args *this) {
	if (this->ev)
		event_del(this->ev);
	strfree(this->mountpoint);
	free(this);
}

/*
 * Redistribute source stream.
 * Step 2 (optional) -- schedule for later
 */
int
redistribute_schedule(struct caster_state *caster, struct ntrip_state *st, struct redistribute_cb_args *redis_args) {
	struct timeval timeout_interval = { caster->config->reconnect_delay, 0 };
	struct event *ev = event_new(caster->base, -1, 0, redistribute_cb, redis_args);
	if (ev != NULL) {
		ntrip_log(st, LOG_INFO, "Scheduling retry callback for source %s in %d seconds", redis_args->mountpoint, caster->config->reconnect_delay);
		redis_args->ev = ev;
		event_add(ev, &timeout_interval);
		livesource_set_state(redis_args->livesource, LIVESOURCE_FETCH_PENDING);
		return 0;
	} else {
		ntrip_log(st, LOG_CRIT, "Can't schedule retry callback for source %s in %d seconds, canceling", redis_args->mountpoint, caster->config->reconnect_delay);
		redistribute_args_free(redis_args);
		return -1;
	}
}

/*
 * Redistribute source stream.
 *
 * Step 3 (optional) -- called back after a timeout
 */
void
redistribute_cb(evutil_socket_t fd, short what, void *cbarg) {
	struct redistribute_cb_args *redis_args = (struct redistribute_cb_args *)cbarg;
	struct caster_state *caster = redis_args->caster;
	logfmt(&caster->flog, LOG_INFO, "Trying to restart source %s", redis_args->mountpoint);
	event_del(redis_args->ev);
	redis_args->ev = NULL;
	joblist_append_redistribute(redis_args->caster->joblist, redistribute_source_stream, redis_args);
}

/*
 * Redistribute source stream.
 * Step 4 -- start a connection attempt.
 *
 * Required lock: ntrip_state
 */
void
redistribute_source_stream(struct redistribute_cb_args *redis_args) {
	struct bufferevent *bev;

	if (threads)
		bev = bufferevent_socket_new(redis_args->caster->base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
	else
		bev = bufferevent_socket_new(redis_args->caster->base, -1, BEV_OPT_CLOSE_ON_FREE);

	if (bev == NULL) {
		logfmt(&redis_args->caster->flog, LOG_CRIT, "Out of memory, cannot redistribute %s", redis_args->mountpoint);
		return;
	}

	struct sourcetable *sp = NULL;

	struct sourceline *s = stack_find_pullable(&redis_args->caster->sourcetablestack, redis_args->mountpoint, &sp);
	if (s == NULL) {
		logfmt(&redis_args->caster->flog, LOG_WARNING, "Can't find pullable mountpoint %s", redis_args->mountpoint);
		return;
	}

	/*
	 * Create new client state.
	 */
	struct ntrip_state *st = ntrip_new(redis_args->caster, bev, sp->caster, sp->port, redis_args->mountpoint);
	if (st == NULL) {
		logfmt(&redis_args->caster->flog, LOG_CRIT, "Out of memory, cannot redistribute %s", redis_args->mountpoint);
		return;
	}
	st->own_livesource = redis_args->livesource;
	st->type = "source_fetcher";
	st->redistribute = 1;
	st->persistent = redis_args->persistent;
	redis_args->source_st = st;
	ntrip_register(st);

	logfmt(&redis_args->caster->flog, LOG_INFO, "Starting socket connect to %s:%d for /%s", st->host, st->port, redis_args->mountpoint);

	if (threads)
		bufferevent_setcb(bev, ntripcli_workers_readcb, ntripcli_workers_writecb, ntripcli_workers_eventcb, st);
	else
		bufferevent_setcb(bev, ntripcli_readcb, ntripcli_writecb, ntripcli_eventcb, st);

	bufferevent_enable(bev, EV_READ|EV_WRITE);
        struct timeval read_timeout = { st->caster->config->on_demand_source_timeout, 0 };
        struct timeval write_timeout = { st->caster->config->on_demand_source_timeout, 0 };
        bufferevent_set_timeouts(bev, &read_timeout, &write_timeout);
	bufferevent_socket_connect_hostname(bev, redis_args->caster->dns_base, AF_UNSPEC, st->host, st->port);

	redistribute_args_free(redis_args);
}
