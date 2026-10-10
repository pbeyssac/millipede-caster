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
 * The task for node n, with a reference, or NULL if a reload left fewer nodes.
 *
 * task/ntask are swapped by syncer_reload(). The lock is held for this read only, never while
 * taking another lock: the task callbacks run with the connection's locks held, and a thread
 * holding this lock while waiting for one of those would deadlock against them as soon as a
 * reload queued for the write lock.
 */
static struct ntrip_task *syncer_task_ref(struct syncer *this, int n) {
	struct ntrip_task *task = NULL;
	P_RWLOCK_RDLOCK(&this->lock);
	if (n >= 0 && n < this->ntask && this->task[n] != NULL) {
		task = this->task[n];
		ntrip_task_incref(task);
	}
	P_RWLOCK_UNLOCK(&this->lock);
	return task;
}


/*
 * Queue a serial check to 1 node.
 */
static void queue_checkserial(struct syncer *this, struct ntrip_task *task, int n) {
	json_object *j = livesource_checkserial_json(task->caster->livesources);
	logfmt(&task->caster->flog, LOG_DEBUG, "syncer queue %d checkserial, serial %lld", n, task->caster->livesources->serial);
	queue_json(this, task, j);
}

/*
 * Take the tasks with a reference under the lock
 */
static struct ntrip_task **get_task_array(struct syncer *this, int *pntask) {
	P_RWLOCK_RDLOCK(&this->lock);
	int ntask = this->ntask;
	*pntask = ntask;
	struct ntrip_task **tasks = ntask ? (struct ntrip_task **)malloc(sizeof(struct ntrip_task *)*ntask) : NULL;
	if (tasks != NULL)
		for (int i = 0; i < ntask; i++) {
			tasks[i] = this->task[i];
			ntrip_task_incref(tasks[i]);
		}
	P_RWLOCK_UNLOCK(&this->lock);
	return tasks;
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

	/* Take the tasks with a reference under the lock, then queue without it */
	int ntask;
	struct ntrip_task **tasks = get_task_array(this, &ntask);
	if (ntask && tasks == NULL) {
		logfmt(&this->caster->flog, LOG_CRIT, "Out of memory when allocating syncer output, dropping");
		packet_decref(packet);
		return;
	}

	for (int i = 0; i < ntask; i++) {
		struct ntrip_state *st = ntrip_task_get_st_ref(tasks[i]);
		if (st) {
			ntrip_log(st, LOG_DEBUG, "syncer %d queueing %.80s", i, json);
			ntrip_decref(st, "syncer_queue");
		} else
			logfmt(&this->caster->flog, LOG_DEBUG, "syncer %d queueing %.80s (not running)", i, json);
		ntrip_task_queue(tasks[i], packet);
		ntrip_task_decref(tasks[i]);
	}
	free(tasks);
	packet_decref(packet);
}

/*
 * Convert and send a Json object
 */
void syncer_queue_json(struct caster_state *caster, json_object *j) {
	if (j == NULL)
		return;

	struct config *config = caster_config_getref(caster);

	/*
	 * Read the syncer pointer once, and test what was read.
	 *
	 * A reload hands the syncer over to the new dynconfig and nulls the entry in the old
	 * one (caster_reload_syncers()), while the old configuration is still the current one.
	 * A worker thread holding it therefore sees syncers_count at 1 with syncers[0] already
	 * NULL. Testing config->dyn->syncers[0] and then passing it would only narrow the
	 * window, not close it: the reload can null it in between.
	 *
	 * The syncer itself is moved, never freed, by a reload, so a pointer read before the
	 * handover stays valid for the call.
	 */
	struct syncer *syncer = NULL;
	if (config->dyn->syncers != NULL && config->dyn->syncers_count >= 1)
		syncer = config->dyn->syncers[0];

	if (syncer != NULL) {
		char *s = mystrdup(json_object_to_json_string(j));
		if (s != NULL) {
			logfmt(&caster->flog, LOG_DEBUG, "syncer_queue_json %.80s", s);
			syncer_queue(syncer, s);
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
	struct ntrip_task *task = syncer_task_ref(a, n);
	if (task == NULL)
		return;
	ntrip_task_clear_st(task);

	/*
	 * Queue a serial check for the next connection, to handle
	 * cases where the node has been rebooted/restarted.
	 */
	queue_checkserial(a, task, n);

	ntrip_task_reschedule(task, a);
	ntrip_task_decref(task);
}

/*
 * Handle status code in server reply.
 */
static void
status_cb(void *arg, int status, int n) {
	struct syncer *a = (struct syncer *)arg;
	struct ntrip_task *task = syncer_task_ref(a, n);
	if (task == NULL)
		return;
	ntrip_log(task->st, LOG_EDEBUG, "syncer status %d", task->st->status_code);

	/* acknowledge/purge pending data anyway */
	ntrip_task_ack_pending(task);

	/* If the call failed, requeue a full table */
	if (task->st->status_code != 200)
		queue_full(a, task);
	ntrip_task_decref(task);
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

	/*
	 * Swap under the lock: a worker thread may be walking the former array in syncer_queue().
	 * Drop the former task references once nobody can be reading it.
	 */
	P_RWLOCK_WRLOCK(&this->lock);
	struct ntrip_task **oldtasks = this->task;
	int noldtask = this->ntask;
	this->task = tasks;
	this->ntask = ntask;
	P_RWLOCK_UNLOCK(&this->lock);

	for (int i = 0; i < noldtask; i++)
		ntrip_task_decref(oldtasks[i]);
	free(oldtasks);
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
	REFCNT_INIT(this);
	P_RWLOCK_INIT(&this->lock, NULL);

	if (syncer_reload(this, node, node_count, uri, bulk_max_size) < 0) {
		P_RWLOCK_DESTROY(&this->lock);
		free(this);
		return NULL;
	}
	return this;
}

REFCNT_INCREF_BODY(syncer_incref, struct syncer);
REFCNT_DECREF_BODY(syncer_decref, struct syncer, syncer_free);

void syncer_free(struct syncer *this) {
	P_RWLOCK_WRLOCK(&this->lock);
	struct ntrip_task **tasks = this->task;
	int ntask = this->ntask;
	this->task = NULL;
	this->ntask = 0;
	P_RWLOCK_UNLOCK(&this->lock);

	for (int i = 0; i < ntask; i++) {
		ntrip_task_stop(tasks[i]);
		ntrip_task_decref(tasks[i]);
	}
	free(tasks);
	P_RWLOCK_DESTROY(&this->lock);
	free(this);
}

/*
 * Start a syncer.
 */
static void
syncer_start_config(void *arg_cb, int n, struct config *new_config) {
	struct syncer *a = (struct syncer *)arg_cb;
	struct ntrip_task *task = syncer_task_ref(a, n);
	if (task == NULL)
		return;
	queue_full(a, task);
	ntrip_task_start(task, a, NULL, 0, new_config);
	ntrip_task_decref(task);
}

static void
syncer_start(void *arg_cb, int n) {
	syncer_start_config(arg_cb, n, NULL);
}

void
syncer_start_all(struct syncer *this, struct config *new_config) {
	P_RWLOCK_RDLOCK(&this->lock);
	int ntask = this->ntask;
	P_RWLOCK_UNLOCK(&this->lock);
	for (int i = 0; i < ntask; i++) {
		struct ntrip_task *task = syncer_task_ref(this, i);
		if (task == NULL)
			continue;
		int init = atomic_load(&task->state) == TASK_INIT;
		ntrip_task_decref(task);
		if (init)
			syncer_start_config(this, i, new_config);
	}
}
