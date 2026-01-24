#include <assert.h>
#include <string.h>

#include "conf.h"
#include "caster.h"
#include "ntrip_task.h"
#include "ntripcli.h"
#include "fetcher_sourcetable.h"

static void sourcetable_end_cb(int ok, void *arg, int n);
static int sourcetable_line_cb(struct ntrip_state *st, void *arg_cb, const char *line, int n);

/*
 * Initialize, but don't start, a sourcetable fetcher.
 */
struct sourcetable_fetch_args *fetcher_sourcetable_new(struct caster_state *caster,
	const char *host, unsigned short port, int tls, int refresh_delay, int priority,
	struct config *config) {
	struct sourcetable_fetch_args *this = (struct sourcetable_fetch_args *)malloc(sizeof(struct sourcetable_fetch_args));
	if (this == NULL)
		return NULL;

	this->task = ntrip_task_new(caster, host, port, "/", tls, refresh_delay, 0, 0, "sourcetable_fetcher", NULL);
	if (this->task == NULL) {
		free(this);
		return NULL;
	}
	this->task->end_cb = sourcetable_end_cb;
	this->task->end_cb_arg = this;
	this->task->cb_arg2 = 0;
	this->task->line_cb = sourcetable_line_cb;
	this->task->line_cb_arg = this;
	this->task->restart_cb = fetcher_sourcetable_start;
	this->task->restart_cb_arg = this;
	this->task->read_timeout = config->sourcetable_fetch_timeout;
	this->task->write_timeout = config->sourcetable_fetch_timeout;
	this->task->status_timeout = this->task->read_timeout;

	this->sourcetable = NULL;
	this->priority = priority;
	this->refcnt = 1;
	return this;
}

static void task_stop(struct sourcetable_fetch_args *this) {
	ntrip_task_stop(this->task);
	/*
	 * Needed in case a fetch is in progress right now
	 */
	if (this->sourcetable) {
		sourcetable_decref(this->sourcetable);
		this->sourcetable = NULL;
	}
}

static void fetcher_sourcetable_free(struct sourcetable_fetch_args *this) {
	fetcher_sourcetable_stop(this);
	ntrip_task_decref(this->task);
	free(this);
}

void fetcher_sourcetable_incref(struct sourcetable_fetch_args *this) {
	assert(this->refcnt > 0);
	atomic_fetch_add(&this->refcnt, 1);
}

void fetcher_sourcetable_decref(struct sourcetable_fetch_args *this) {
	assert(this->refcnt > 0);
	if (atomic_fetch_sub(&this->refcnt, 1) == 1)
		fetcher_sourcetable_free(this);
}

void fetcher_sourcetable_stop(struct sourcetable_fetch_args *this) {
	task_stop(this);
	stack_replace_host(this->task->caster, &this->task->caster->sourcetablestack, this->task->host, this->task->port, NULL);
}

/*
 * Reload fetcher, possibly modifying the refresh_delay and priority.
 *
 * Same as a stop/start, except we keep the sourcetable during the reload.
 */
void fetcher_sourcetable_reload(struct sourcetable_fetch_args *this, int refresh_delay, int sourcetable_priority) {
	task_stop(this);
	this->task->refresh_delay = refresh_delay;
	this->priority = sourcetable_priority;
	fetcher_sourcetable_start(this, 0);
}

/*
 * Callback called at the end of the ntrip session.
 *
 * Required lock: ntrip_state
 */
static void
sourcetable_end_cb(int ok, void *arg, int n) {
	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)arg;
	struct timeval t1;

	if (!ok) {
		gettimeofday(&t1, NULL);
		timersub(&t1, &a->task->start, &t1);
		if (a->sourcetable) {
			sourcetable_decref(a->sourcetable);
			a->sourcetable = NULL;
		}
		logfmt(&a->task->caster->flog, LOG_NOTICE, "sourcetable load failed or canceled, %.3f ms",
			t1.tv_sec*1000 + t1.tv_usec/1000.);
	}
	ntrip_task_clear_st(a->task);

	ntrip_task_reschedule(a->task, a);
}

static int sourcetable_line_cb(struct ntrip_state *st, void *arg_cb, const char *line, int n) {
	struct timeval t1;
	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)arg_cb;

	if (a->sourcetable == NULL) {
		sourcetable_end_cb(0, a, 0);
		return 0;
	}

	if (!strcmp(line, "ENDSOURCETABLE")) {
		struct sourcetable *sourcetable = a->sourcetable;

		gettimeofday(&t1, NULL);
		timersub(&t1, &a->task->st->start, &t1);
		gettimeofday(&sourcetable->fetch_time, NULL);

		sourcetable->pullable = 1;
		ntrip_log(st, LOG_INFO, "sourcetable loaded, %d entries, %.3f ms",
			sourcetable_nentries(sourcetable, 0),
			t1.tv_sec*1000 + t1.tv_usec/1000.);
		stack_replace_host(a->task->caster, &a->task->caster->sourcetablestack, a->task->host, a->task->port, sourcetable);
		if (st->config->dyn->syncers_count >= 1) {
			json_object *j = sourcetable_json(sourcetable);
			json_object *type = json_object_new_string("sourcetable");
			json_object_object_add(j, "type", type);
			syncer_queue_json(st->caster, j);
		}

		sourcetable_decref(a->sourcetable);
		a->sourcetable = NULL;
		sourcetable_end_cb(1, a, 0);
		return 1;
	}

	if (sourcetable_add(a->sourcetable, line, 1, st->caster) < 0) {
		ntrip_log(st, LOG_INFO, "Error when inserting sourcetable line from %s:%d", a->sourcetable->caster, a->sourcetable->port);
		sourcetable_decref(a->sourcetable);
		a->sourcetable = NULL;
		sourcetable_end_cb(0, a, 0);
		return 1;
	}
	return 0;
}

/*
 * Start a sourcetable fetcher.
 */
void
fetcher_sourcetable_start_with_config(void *arg_cb, int n, struct config *new_config) {
	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)arg_cb;
	assert(a->sourcetable == NULL);
	a->sourcetable = sourcetable_new(a->task->host, a->task->port, a->task->tls);
	a->sourcetable->priority = a->priority;

	if (ntrip_task_start(a->task, a, NULL, 0, new_config) < 0) {
		sourcetable_decref(a->sourcetable);
		a->sourcetable = NULL;
	}
}

void
fetcher_sourcetable_start(void *arg_cb, int n) {
	fetcher_sourcetable_start_with_config(arg_cb, n, NULL);
}
