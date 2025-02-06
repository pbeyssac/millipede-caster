#include <assert.h>

#include "conf.h"
#include "ntrip_task.h"
#include "ntripcli.h"
#include "fetcher_sourcetable.h"

static void sourcetable_end_cb(int ok, void *arg, int n);
static int sourcetable_line_cb(struct ntrip_state *st, void *arg_cb, const char *line, int n);

/*
 * Initialize, but don't start, a sourcetable fetcher.
 */
struct sourcetable_fetch_args *fetcher_sourcetable_new(struct caster_state *caster,
	const char *host, unsigned short port, int tls, int refresh_delay, int priority) {
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
	this->task->read_timeout = caster->config->sourcetable_fetch_timeout;
	this->task->write_timeout = caster->config->sourcetable_fetch_timeout;

	this->sourcetable = NULL;
	this->priority = priority;
	return this;
}

static void task_stop(struct sourcetable_fetch_args *this) {
	ntrip_task_stop(this->task);
	/*
	 * Needed in case a fetch is in progress right now
	 */
	if (this->sourcetable) {
		sourcetable_free(this->sourcetable);
		this->sourcetable = NULL;
	}
}

void fetcher_sourcetable_free(struct sourcetable_fetch_args *this) {
	stack_replace_host(this->task->caster, &this->task->caster->sourcetablestack, this->task->host, this->task->port, NULL);
	ntrip_task_free(this->task);
	free(this);
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
 */
static void
sourcetable_end_cb(int ok, void *arg, int n) {
	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)arg;
	struct timeval t1;

	if (!ok) {
		gettimeofday(&t1, NULL);
		timersub(&t1, &a->task->st->start, &t1);
		if (a->sourcetable) {
			sourcetable_free(a->sourcetable);
			a->sourcetable = NULL;
		}
		ntrip_log(a->task->st, LOG_NOTICE, "sourcetable load failed, %.3f ms",
			t1.tv_sec*1000 + t1.tv_usec/1000.);
	}
	a->task->st = NULL;

	ntrip_task_reschedule(a->task, a);
}

static int sourcetable_line_cb(struct ntrip_state *st, void *arg_cb, const char *line, int n) {
	struct timeval t1;
	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)arg_cb;

	if (!strcmp(line, "ENDSOURCETABLE")) {
		struct sourcetable *sourcetable = a->sourcetable;

		gettimeofday(&t1, NULL);
		timersub(&t1, &a->task->st->start, &t1);
		gettimeofday(&sourcetable->fetch_time, NULL);

		sourcetable->pullable = 1;
		sourcetable->priority = a->priority;
		ntrip_log(st, LOG_INFO, "sourcetable loaded, %d entries, %.3f ms",
			sourcetable_nentries(sourcetable, 0),
			t1.tv_sec*1000 + t1.tv_usec/1000.);
		stack_replace_host(a->task->caster, &a->task->caster->sourcetablestack, a->task->host, a->task->port, sourcetable);
		a->sourcetable = NULL;
		sourcetable_end_cb(1, a, 0);
		return 1;
	}

	if (sourcetable_add(a->sourcetable, line, 1) < 0) {
		ntrip_log(st, LOG_INFO, "Error when inserting sourcetable line from %s:%d", a->sourcetable->caster, a->sourcetable->port);
		sourcetable_free(a->sourcetable);
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
fetcher_sourcetable_start(void *arg_cb, int n) {
	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)arg_cb;
	assert(a->sourcetable == NULL);
	a->sourcetable = sourcetable_new(a->task->host, a->task->port, a->task->tls);

	if (ntripcli_start(a->task->caster, a->task->host, a->task->port, a->task->tls, a->task->uri, a->task->type, a->task, NULL, 0) < 0) {
		sourcetable_free(a->sourcetable);
		a->sourcetable = NULL;
		a->task->st = NULL;
		ntrip_task_reschedule(a->task, a);
	}
}
