#include <event2/event.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "ntripcli.h"
#include "ntrip_common.h"
#include "fetcher_sourcetable.h"

static void
get_sourcetable_cb(int fd, short what, void *arg) {
	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)arg;
	event_free(a->ev);
	a->ev = NULL;
	fetcher_sourcetable_start(arg);
}

/*
 * Initialize, but don't start, a sourcetable fetcher.
 */
struct sourcetable_fetch_args *fetcher_sourcetable_new(struct caster_state *caster,
	const char *host, unsigned short port, int refresh_delay, int priority) {
	struct sourcetable_fetch_args *this = (struct sourcetable_fetch_args *)malloc(sizeof(struct sourcetable_fetch_args));
	if (this == NULL)
		return NULL;
	this->host = mystrdup(host);
	if (this->host == NULL) {
		free(this);
		return NULL;
	}
	this->port = port;
	this->refresh_delay = refresh_delay;
	this->caster = caster;
	this->sourcetable = NULL;
	this->sourcetable_cb = NULL;
	this->ev = NULL;
	this->st = NULL;
	this->priority = priority;
	return this;
}

/*
 * Stop fetcher.
 */
static void _fetcher_sourcetable_stop(struct sourcetable_fetch_args *this, int keep_sourcetable) {
	logfmt(&this->caster->flog, "Stopping sourcetable fetch from %s:%d\n", this->host, this->port);
	if (this->ev) {
		event_free(this->ev);
		this->ev = NULL;
	}
	if (this->st && this->st->state != NTRIP_END) {
		bufferevent_lock(this->st->bev);
		ntrip_deferred_free(this->st, "fetcher_sourcetable_stop");
		this->st = NULL;
	}
	if (!keep_sourcetable)
		stack_replace_host(&this->caster->sourcetablestack, this->host, this->port, NULL);
}

void fetcher_sourcetable_free(struct sourcetable_fetch_args *this) {
	_fetcher_sourcetable_stop(this, 0);
	strfree(this->host);
	free(this);
}

void fetcher_sourcetable_stop(struct sourcetable_fetch_args *this) {
	_fetcher_sourcetable_stop(this, 0);
}

/*
 * Reload fetcher.
 *
 * Same as a stop/start, except we keep the sourcetable during the reload.
 */
void fetcher_sourcetable_reload(struct sourcetable_fetch_args *this, int refresh_delay, int priority) {
	_fetcher_sourcetable_stop(this, 1);
	this->refresh_delay = refresh_delay;
	this->priority = priority;
	fetcher_sourcetable_start(this);
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
			a->host,
			a->port,
			sourcetable_nentries(sourcetable, 0),
			t1.tv_sec*1000 + t1.tv_usec/1000.);
		sourcetable->priority = a->priority;
		stack_replace_host(&a->caster->sourcetablestack, a->host, a->port, sourcetable);
		a->sourcetable = NULL;
	} else {
		logfmt(&caster->flog, "sourcetable load failed from %s:%d, %.3f ms\n",
			a->host, a->port,
			t1.tv_sec*1000 + t1.tv_usec/1000.);
	}
	a->st = NULL;

	if (a->refresh_delay) {
		struct timeval timeout_interval = { a->refresh_delay, 0 };
		logfmt(&caster->flog, "Starting refresh callback for sourcetable %s:%d in %d seconds\n", a->host, a->port, a->refresh_delay);
		a->ev = event_new(caster->base, -1, 0, get_sourcetable_cb, a);
		event_add(a->ev, &timeout_interval);
	}
}

/*
 * Start a sourcetable fetcher.
 */
void
fetcher_sourcetable_start(struct sourcetable_fetch_args *arg_cb) {
	struct bufferevent *bev;
	arg_cb->sourcetable_cb = sourcetable_cb;

	if (threads)
		bev = bufferevent_socket_new(arg_cb->caster->base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
	else
		bev = bufferevent_socket_new(arg_cb->caster->base, -1, BEV_OPT_CLOSE_ON_FREE);

	if (bev == NULL) {
		logfmt(&arg_cb->caster->flog, "Error constructing bufferevent in fetcher_sourcetable_start!");
		return;
	}
	struct ntrip_state *st = ntrip_new(arg_cb->caster, bev, arg_cb->host, arg_cb->port, NULL);
	if (st == NULL) {
		bufferevent_free(bev);
		logfmt(&arg_cb->caster->flog, "Error constructing ntrip_state in fetcher_sourcetable_start!");
		return;
	}
	ntrip_log(st, LOG_NOTICE, "Starting sourcetable fetch from %s:%d\n", arg_cb->host, arg_cb->port);
	arg_cb->st = st;
	st->sourcetable_cb_arg = arg_cb;
	st->type = "sourcetable_fetcher";

	if (threads)
		bufferevent_setcb(bev, ntripcli_workers_readcb, ntripcli_workers_writecb, ntripcli_workers_eventcb, st);
	else
		bufferevent_setcb(bev, ntripcli_readcb, ntripcli_writecb, ntripcli_eventcb, st);

	bufferevent_enable(bev, EV_READ|EV_WRITE);

        struct timeval timeout = { arg_cb->caster->config->sourcetable_fetch_timeout, 0 };
        bufferevent_set_timeouts(bev, &timeout, &timeout);

	gettimeofday(&arg_cb->t0, NULL);
	bufferevent_socket_connect_hostname(bev, arg_cb->caster->dns_base, AF_UNSPEC, arg_cb->host, arg_cb->port);
}
