#include <event2/event.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "ntripcli.h"
#include "ntrip_common.h"
#include "fetcher_sourcetable.h"

static void
get_sourcetable_cb(int fd, short what, void *arg) {
	fetcher_sourcetable_get(arg);
}

static void
sourcetable_cb(int fd, short what, void *arg) {
	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)arg;
	struct caster_state *caster = a->caster;
	struct sourcetable *sourcetable = a->sourcetable;
	struct timeval t1;
	gettimeofday(&t1, NULL);
	timersub(&t1, &a->t0, &t1);

	if (sourcetable != NULL) {
		logfmt(&caster->flog, "sourcetable loaded from %s:%d, %d entries, %.3f ms\n",
			sourcetable->caster,
			sourcetable->port,
			sourcetable_nentries(sourcetable, 0),
			t1.tv_sec*1000 + t1.tv_usec/1000.);
		sourcetable->priority = 20;
		stack_replace_host(&a->caster->sourcetablestack, a->host, a->port, sourcetable);
		a->sourcetable = NULL;
	} else {
		logfmt(&caster->flog, "sourcetable load failed from %s:%d, %.3f ms\n",
			a->host, a->port,
			t1.tv_sec*1000 + t1.tv_usec/1000.);
	}

	if (a->refresh_delay) {
		struct timeval timeout_interval = { a->refresh_delay, 0 };
		logfmt(&caster->flog, "Starting refresh callback for sourcetable %s:%d in %d seconds\n", a->host, a->port, a->refresh_delay);
		struct event *ev = event_new(caster->base, -1, 0, get_sourcetable_cb, a);
		event_add(ev, &timeout_interval);
	}
}

/*
 * Initiate a sourcetable fetch
 */
void
fetcher_sourcetable_get(struct sourcetable_fetch_args *arg_cb) {
	struct bufferevent *bev;
	arg_cb->sourcetable_cb = sourcetable_cb;
#ifdef THREADS
	bev = bufferevent_socket_new(arg_cb->caster->base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
#else
	bev = bufferevent_socket_new(arg_cb->caster->base, -1, BEV_OPT_CLOSE_ON_FREE);
#endif
	if (bev == NULL) {
		logfmt(&arg_cb->caster->flog, "Error constructing bufferevent in get_sourcetable!");
		return;
	}
	logfmt(&arg_cb->caster->flog, "Starting sourcetable fetch from %s:%d\n", arg_cb->host, arg_cb->port);
	struct ntrip_state *st = ntrip_new(arg_cb->caster, arg_cb->host, arg_cb->port, NULL);
	st->sourcetable_cb_arg = arg_cb;
	st->bev = bev;
#ifdef THREADS
	bufferevent_setcb(bev, ntripcli_workers_readcb, ntripcli_workers_writecb, ntripcli_workers_eventcb, st);
#else
	bufferevent_setcb(bev, ntripcli_readcb, ntripcli_writecb, ntripcli_eventcb, st);
#endif
	bufferevent_enable(bev, EV_READ|EV_WRITE);

        struct timeval timeout = { arg_cb->caster->config->sourcetable_fetch_timeout, 0 };
        bufferevent_set_timeouts(bev, &timeout, &timeout);

	gettimeofday(&arg_cb->t0, NULL);
	bufferevent_socket_connect_hostname(bev, arg_cb->caster->dns_base, AF_UNSPEC, arg_cb->host, arg_cb->port);
}
