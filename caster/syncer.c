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

static void syncer_start(void *arg_cb, int n);

/*
 * Queue a JSON API request to 1 node.
 */
static void queue_json(struct syncer *this, struct ntrip_task *task, json_object *j) {
	struct packet *packet = packet_new_from_string(json_object_get_string(j));
	json_object_put(j);
	if (packet == NULL) {
		logfmt(&task->caster->flog, LOG_CRIT, "out of memory in queue_json");
		return;
	}
	ntrip_task_queue(task, packet);
	packet_decref(packet);
}

/*
 * Queue a full livesources table to 1 node.
 */
static void queue_full(struct syncer *this, struct ntrip_task *task) {
	json_object *j = livesource_full_update_json(task->caster, task->caster->livesources);
	logfmt(&task->caster->flog, LOG_DEBUG, "syncer queue full table, serial %lld", task->caster->livesources->serial);
	queue_json(this, task, j);
}

/*
 * Queue a serial check to 1 node.
 */
static void queue_checkserial(struct syncer *this, int n) {
	struct ntrip_task *task = this->task[n];
	json_object *j = livesource_checkserial_json(task->caster->livesources);
	logfmt(&task->caster->flog, LOG_DEBUG, "syncer queue checkserial, serial %lld", task->caster->livesources->serial);
	queue_json(this, task, j);
}

/*
 * Queue a JSON update provided as a char *, to all nodes.
 */
void syncer_queue(struct syncer *this, char *json) {
	struct packet *packet = packet_new_from_string(json);
	if (packet == NULL) {
		logfmt(&this->caster->flog, LOG_CRIT, "Out of memory when allocating syncer output, dropping");
		return;
	}

	for (int i = 0; i < this->ntask; i++) {
		if (this->task[i]->st)
			ntrip_log(this->task[i]->st, LOG_DEBUG, "syncer %d queueing %s", i, json);
		else
			logfmt(&this->caster->flog, LOG_DEBUG, "syncer %d queueing %s (not running)", i, json);
		ntrip_task_queue(this->task[i], packet);
	}
	packet_decref(packet);
}

/*
 * Convert and send a Json object
 */
void syncer_queue_json(struct caster_state *caster, json_object *j) {
	if (j == NULL)
		return;

	struct config *config = caster_config_getref(caster);
	if (config->dyn->syncers_count >= 1) {
		char *s = mystrdup(json_object_to_json_string(j));
		if (s != NULL) {
			logfmt(&caster->flog, LOG_DEBUG, "livesource_send_json syncer %s", s);
			syncer_queue(config->dyn->syncers[0], s);
			strfree(s);
		}
	}
	config_decref(config);

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
		queue_full(a, a->task[n]);
}

/*
 * Compare whether a current task applies to the provided node.
 */
static int compare_node_task(struct config_node *node, struct ntrip_task *task) {
	return (strcasecmp(node->host, task->host)
		|| node->port != task->port
		|| node->tls != task->tls);
}

/*
 * Create a syncer task
 */
static struct ntrip_task *syncer_task_new(struct caster_state *caster, struct syncer *syncer,
	int i, struct config_node *node, const char *uri, int bulk_max_size) {
	struct ntrip_task *task;
	int err = 0;

	int authkeylen = strlen(node->authorization) + 10;
	char *authkey = (char *)malloc(authkeylen);
	if (authkey == NULL)
		return NULL;

	snprintf(authkey, authkeylen, "internal %s", node->authorization);

	task = ntrip_task_new(caster, node->host, node->port, uri,
		node->tls, node->retry_delay, bulk_max_size, node->queue_max_size, "syncer", NULL);
	if (task == NULL)
		return NULL;

	if (evhttp_add_header(&task->headers, "Authorization", authkey) < 0)
		err = 1;
	strfree(authkey);

	if (err) {
		ntrip_task_decref(task);
		return NULL;
	}

	task->method = "POST";
	task->status_cb = status_cb;
	task->status_cb_arg = syncer;
	task->end_cb = end_cb;
	task->end_cb_arg = syncer;
	task->restart_cb = syncer_start;
	task->restart_cb_arg = syncer;
	task->cb_arg2 = i;
	task->connection_keepalive = 1;
	task->bulk_content_type = "application/json";
	task->bulk_max_size = bulk_max_size;
	task->use_mimeq = 1;
	return task;
}

/*
 * Reload a syncer, reusing existing tasks, creating new tasks if necessary, and dropping unused tasks.
 */
int syncer_reload(struct syncer *this,
	struct config_node *node, int node_count, const char *uri,
	int bulk_max_size) {
	struct ntrip_task **tasks = (struct ntrip_task **)calloc(sizeof(struct ntrip_task *)*node_count, 1);
	int ntask = node_count;
	int err = 0;
	if (tasks == NULL)
		return -1;

	for (int i = 0; i < node_count; i++) {
		struct ntrip_task *nt = NULL;
		if (this->task != NULL) {
			for (int j = 0; j < this->ntask; j++) {
				if (!compare_node_task(&node[i], this->task[j])) {
					nt = this->task[j];
					ntrip_task_incref(nt);
					break;
				}
			}
		}
		if (nt == NULL) {
				nt = syncer_task_new(this->caster, this, i, &node[i], uri, bulk_max_size);
				if (nt == NULL) {
					err = 1;
					break;
				}
				queue_full(this, nt);
		}
		tasks[i] = nt;
	}

	if (err) {
		for (int i = 0; i < ntask; i++)
			if (tasks[i] != NULL)
				ntrip_task_decref(tasks[i]);
		free(tasks);
		return -1;
	}

	/* Drop former task references */
	for (int i = 0; i < this->ntask; i++)
		ntrip_task_decref(this->task[i]);
	free(this->task);
	this->task = tasks;
	this->ntask = ntask;
	return 0;
}

/*
 * Initialize a sender task.
 */
struct syncer *syncer_new(struct caster_state *caster,
	struct config_node *node, int node_count, const char *uri,
	int bulk_max_size) {

	if (bulk_max_size != 0)
		/* Not yet implemented on the API side */
		return NULL;

	if (node_count == 0)
		return NULL;

	struct syncer *this = (struct syncer *)malloc(sizeof(struct syncer));
	if (this == NULL)
		return NULL;

	this->caster = caster;
	this->task = NULL;
	this->ntask = 0;

	if (syncer_reload(this, node, node_count, uri, bulk_max_size) < 0) {
		free(this);
		return NULL;
	}
	return this;
}

void syncer_free(struct syncer *this) {
	for (int i = 0; i < this->ntask; i++) {
		ntrip_task_decref(this->task[i]);
		this->task[i] = NULL;
	}
	free(this->task);
	free(this);
}

/*
 * Start a syncer.
 */
static void
syncer_start(void *arg_cb, int n) {
	struct syncer *a = (struct syncer *)arg_cb;
	struct ntrip_task *task = a->task[n];

	ntrip_task_start(task, a, NULL, 0);
}

void
syncer_start_all(struct syncer *this) {
	for (int i = 0; i < this->ntask; i++)
		if (atomic_load(&this->task[i]->state) == TASK_INIT)
			syncer_start(this, i);
}
