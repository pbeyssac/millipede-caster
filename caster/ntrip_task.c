#include <event2/event.h>

#include "conf.h"
#include "ntrip_task.h"

static void
_ntrip_task_restart_cb(int fd, short what, void *arg) {
	struct ntrip_task *a = (struct ntrip_task *)arg;
	event_free(a->ev);
	a->ev = NULL;
	a->restart_cb(a->restart_cb_arg);
}

/*
 * Create a new task, with periodic rescheduling if refresh_delay is not 0.
 * Don't start it.
 */
struct ntrip_task *ntrip_task_new(struct caster_state *caster,
	const char *host, unsigned short port, int tls, int refresh_delay, const char *type) {
	struct ntrip_task *this = (struct ntrip_task *)malloc(sizeof(struct ntrip_task));
	if (this == NULL)
		return NULL;
	this->host = mystrdup(host);
	if (this->host == NULL) {
		free(this);
		return NULL;
	}
	this->port = port;
	this->refresh_delay = refresh_delay;
	this->end_cb = NULL;
	this->line_cb = NULL;
	this->st = NULL;
	this->caster = caster;
	this->ev = NULL;
	this->type = type;
	this->tls = tls;
	return this;
}

void ntrip_task_free(struct ntrip_task *this) {
	strfree(this->host);
	free(this);
}

/*
 * Clear associated rescheduling event for a task.
 */
void ntrip_task_stop(struct ntrip_task *this) {
	logfmt(&this->caster->flog, LOG_INFO, "Stopping %s from %s:%d\n", this->type, this->host, this->port);
	if (this->ev) {
		event_free(this->ev);
		this->ev = NULL;
	}
	if (this->st && this->st->state != NTRIP_END) {
		bufferevent_lock(this->st->bev);
		ntrip_deferred_free(this->st, "task_stop");
		this->st = NULL;
	}
}

void ntrip_task_reschedule(struct ntrip_task *this, void *arg_cb) {
	if (this->refresh_delay) {
		struct timeval timeout_interval = { this->refresh_delay, 0 };
		logfmt(&this->caster->flog, LOG_INFO, "Starting refresh callback for %s %s:%d in %d seconds\n", this->type, this->host, this->port, this->refresh_delay);
		this->ev = event_new(this->caster->base, -1, 0, _ntrip_task_restart_cb, this);
		event_add(this->ev, &timeout_interval);
	}
}
