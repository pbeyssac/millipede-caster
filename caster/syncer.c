#include <string.h>

#include <event2/http.h>

#include "conf.h"
#include "config.h"
#include "ntrip_task.h"
#include "ntripcli.h"
#include "syncer.h"
#include "util.h"

/*
 * Module to synchronize our livesource table to other nodes.
 */

/*
 * Queue a JSON API request to 1 node.
 */
static void queue_json(struct syncer *this, int n, json_object *j) {
	struct ntrip_task *task = this->task[n];
	char *s = mystrdup(json_object_get_string(j));
	json_object_put(j);
	if (s == NULL) {
		logfmt(&task->caster->flog, LOG_CRIT, "out of memory in queue_json");
		return;
	}
	ntrip_task_queue(this->task[n], s);
	strfree(s);
}

/*
 * Queue a full livesources table to 1 node.
 */
static void queue_full(struct syncer *this, int n) {
	struct ntrip_task *task = this->task[n];
	json_object *j = livesource_full_update_json(task->caster, task->caster->livesources);
	logfmt(&task->caster->flog, LOG_DEBUG, "syncer queue full table, serial %lld", task->caster->livesources->serial);
	queue_json(this, n, j);
}

/*
 * Queue a serial check to 1 node.
 */
static void queue_checkserial(struct syncer *this, int n) {
	struct ntrip_task *task = this->task[n];
	json_object *j = livesource_checkserial_json(task->caster->livesources);
	logfmt(&task->caster->flog, LOG_DEBUG, "syncer queue checkserial, serial %lld", task->caster->livesources->serial);
	queue_json(this, n, j);
}

/*
 * Queue a JSON update provided as a char *, to all nodes.
 */
void syncer_queue(struct syncer *this, char *json) {
	for (int i = 0; i < this->ntask; i++) {
		if (this->task[i]->st)
			ntrip_log(this->task[i]->st, LOG_DEBUG, "syncer %d queueing %s", i, json);
		else
			logfmt(&this->caster->flog, LOG_DEBUG, "syncer %d queueing %s (not running)", i, json);
		ntrip_task_queue(this->task[i], json);
	}
}

/*
 * Convert and send a Json object
 */
void syncer_queue_json(struct caster_state *caster, json_object *j) {
	if (j == NULL)
		return;

	if (caster->syncers_count >= 1) {
		char *s = mystrdup(json_object_to_json_string(j));
		if (s != NULL) {
			logfmt(&caster->flog, LOG_DEBUG, "livesource_send_json syncer %s", s);
			syncer_queue(caster->syncers[0], s);
			strfree(s);
		}
	}

	json_object_put(j);
}

/*
 * Callback called at the end of the http session.
 *
 * Required lock: ntrip_state
 */
static void
end_cb(int ok, void *arg, int n) {
	struct syncer *a = (struct syncer *)arg;
	ntrip_task_clear_st(a->task[n]);

	/*
	 * Queue a serial check for the next connection, to handle
	 * cases where the node has been rebooted/restarted.
	 */
	queue_checkserial(a, n);

	if (a->task[n]->state != TASK_STOPPED)
		ntrip_task_reschedule(a->task[n], a);
}

/*
 * Handle status code in server reply.
 */
static void
status_cb(void *arg, int status, int n) {
	struct syncer *a = (struct syncer *)arg;
	ntrip_log(a->task[n]->st, LOG_EDEBUG, "syncer status %d", a->task[n]->st->status_code);

	/* acknowledge/purge pending data anyway */
	ntrip_task_ack_pending(a->task[n]);

	/* If the call failed, requeue a full table */
	if (a->task[n]->st->status_code != 200)
		queue_full(a, n);
}

/*
 * Initialize a sender task.
 */
struct syncer *syncer_new(struct caster_state *caster,
	struct config_node *node, int node_count, const char *uri,
	int retry_delay, int bulk_max_size) {

	if (bulk_max_size != 0)
		/* Not yet implemented on the API side */
		return NULL;

	if (node_count == 0)
		return NULL;

	struct syncer *this = (struct syncer *)malloc(sizeof(struct syncer));
	if (this == NULL)
		return NULL;

	this->task = (struct ntrip_task **)malloc(sizeof(struct ntrip_task *)*node_count);
	this->ntask = node_count;
	if (this->task == NULL) {
		free(this);
		return NULL;
	}

	int err = 0;

	for (int i = 0; i < this->ntask; i++) {
		int authkeylen = strlen(node[i].authorization) + 10;
		char *authkey = (char *)malloc(authkeylen);
		if (authkey == NULL) {
			this->task[i] = NULL;
			err = 1;
			continue;
		}
		snprintf(authkey, authkeylen, "internal %s", node[i].authorization);

		this->task[i] = ntrip_task_new(caster, node[i].host, node[i].port, uri,
			node[i].tls, 10, bulk_max_size, node[i].queue_max_size, "syncer", NULL);
		if (evhttp_add_header(&this->task[i]->headers, "Authorization", authkey) < 0)
			err = 1;
		strfree(authkey);
	}

	if (err) {
		for (int i = 0; i < this->ntask; i++)
			if (this->task[i] != NULL)
				ntrip_task_free(this->task[i]);
		free(this);
		return NULL;
	}

	this->caster = caster;

	for (int i = 0; i < this->ntask; i++) {
		struct ntrip_task *task = this->task[i];
		task->method = "POST";
		task->status_cb = status_cb;
		task->status_cb_arg = this;
		task->end_cb = end_cb;
		task->end_cb_arg = this;
		task->restart_cb = syncer_start;
		task->restart_cb_arg = this;
		task->cb_arg2 = i;
		task->connection_keepalive = 1;
		task->bulk_content_type = "application/json";
		task->bulk_max_size = bulk_max_size;
		task->use_mimeq = 1;
		queue_full(this, i);
	}
	return this;
}

void syncer_free(struct syncer *this) {
	for (int i = 0; i < this->ntask; i++) {
		ntrip_task_stop(this->task[i]);
		ntrip_task_free(this->task[i]);
	}
	free(this->task);
	free(this);
}

/*
 * Start a syncer.
 */
void
syncer_start(void *arg_cb, int n) {
	struct syncer *a = (struct syncer *)arg_cb;
	struct ntrip_task *task = a->task[n];

	ntrip_task_start(task, a, NULL, 0);
}
