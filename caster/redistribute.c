#include <string.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "endpoints.h"
#include "jobs.h"
#include "redistribute.h"
#include "ntripcli.h"
#include "ntrip_task.h"

static void redistribute_end_cb(int ok, void *arg, int n);
static void redistribute_start(void *, int n);

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
redistribute_args_new(struct caster_state *caster, struct livesource *livesource,
	struct endpoint *e,
	char *mountpoint, pos_t *mountpoint_pos, int reconnect_delay, int persistent,
	int on_demand_source_timeout) {
	struct redistribute_cb_args *this;
	this = (struct redistribute_cb_args *)malloc(sizeof(struct redistribute_cb_args));
	char *uri = (char *)strmalloc(strlen(mountpoint)+2);

	if (this == NULL || uri == NULL) {
		free(this);
		strfree(uri);
		return NULL;
	}

	/*
	 * Will set the host/port/uri later, as it will depend
	 * on the chosen caster when we start.
	 */
	this->task = ntrip_task_new(caster, NULL, 0, NULL, 0,
		persistent?caster->config->reconnect_delay:0, 0, 0,
		"source_fetcher", NULL);

	this->task->method = "GET";
	this->task->end_cb = redistribute_end_cb;
	this->task->end_cb_arg = this;
	this->task->cb_arg2 = 0;
	this->task->restart_cb = redistribute_start;
	this->task->restart_cb_arg = this;

	sprintf(uri, "/%s", mountpoint);
	this->mountpoint = uri+1;
	this->uri = uri;
	if (mountpoint_pos)
		this->mountpoint_pos = *mountpoint_pos;
	else {
		this->mountpoint_pos.lat = 0.;
		this->mountpoint_pos.lon = 0.;
	}
	this->caster = caster;
	endpoint_copy(&this->endpoint, e);
	this->persistent = persistent;
	this->livesource = livesource;
	this->on_demand_source_timeout = on_demand_source_timeout;
	return this;
}

void
redistribute_args_free(struct redistribute_cb_args *this) {
	if (this->task)
		ntrip_task_free(this->task);
	endpoint_free(&this->endpoint);
	strfree(this->uri);
	free(this);
}

/*
 * Redistribute source stream.
 * Step 2 -- start a connection attempt.
 *
 * Required lock: ntrip_state
 */
void
redistribute_source_stream(struct redistribute_cb_args *this) {
	struct sourcetable *sp = NULL;
	const char *host;
	unsigned short port;
	int tls;

	if (this->endpoint.host == NULL) {
		struct sourceline *s = stack_find_pullable(&this->caster->sourcetablestack, this->mountpoint, &sp);
		if (s == NULL) {
			logfmt(&this->caster->flog, LOG_WARNING, "Can't find pullable mountpoint %s", this->mountpoint);
			redistribute_args_free(this);
			return;
		}
		host = sp->caster;
		port = sp->port;
		tls = sp->tls;
	} else {
		host = this->endpoint.host;
		port = this->endpoint.port;
		tls = this->endpoint.tls;
	}

	strfree(this->task->host);
	this->task->host = mystrdup(host);
	strfree((char *)this->task->uri);
	this->task->uri = mystrdup(this->uri);

	if (this->task->host == NULL || this->task->uri == NULL) {
		strfree(this->task->host);
		this->task->host = NULL;
		strfree((char *)this->task->uri);
		this->task->uri = NULL;
		logfmt(&this->caster->flog, LOG_CRIT, "Can't allocate memory, cannot redistribute %s", this->mountpoint);
		return;
	}

	this->task->port = port;
	this->task->tls = tls;
	this->task->read_timeout = this->on_demand_source_timeout;
	this->task->write_timeout = this->on_demand_source_timeout;

	if (ntrip_task_start(this->task, NULL, this->livesource, this->persistent) < 0)
		logfmt(&this->caster->flog, LOG_CRIT, "ntrip_task_start failed, cannot redistribute %s", this->mountpoint);
}

/*
 * Same as redistribute_source_stream(), with a dummy argument to be
 * compatible with ntrip_task prototypes.
 */
static void
redistribute_start(void *arg_cb, int n) {
	struct redistribute_cb_args *this = (struct redistribute_cb_args *)arg_cb;
	redistribute_source_stream(this);
}

/*
 * Redistribute source stream.
 * Step 3 -- end of connection.
 * Restart if necessary.
 *
 * Required lock: ntrip_state
 */
static void
redistribute_end_cb(int ok, void *arg, int n) {
	struct redistribute_cb_args *this = (struct redistribute_cb_args *)arg;
	struct ntrip_state *st = ntrip_task_clear_st(this->task);
	if (!ok && st && st->own_livesource) {
		if (this->persistent) {
			livesource_set_state(this->livesource, this->caster, LIVESOURCE_FETCH_PENDING);
			ntrip_task_reschedule(this->task, this);
		} else {
			ntrip_unregister_livesource(st);
			redistribute_args_free(this);
		}
	}
}
