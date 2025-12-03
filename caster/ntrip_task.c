#include <assert.h>

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <event2/http.h>
#include <event2/buffer.h>

#include "conf.h"
#include "ntripcli.h"
#include "ntrip_task.h"
#include "util.h"

static void
_ntrip_task_restart_cb(int fd, short what, void *arg) {
	struct ntrip_task *a = (struct ntrip_task *)arg;
	P_RWLOCK_WRLOCK(&a->mimeq_lock);
	if (a->ev)
		event_free(a->ev);
	a->ev = NULL;
	P_RWLOCK_UNLOCK(&a->mimeq_lock);
	a->restart_cb(a->restart_cb_arg, a->cb_arg2);
}

/*
 * Called on a successful connection.
 */
static void connect_cb(struct ntrip_state *st){
	/* Reinitialize exponential backoff */
	st->task->current_retry_delay = st->task->refresh_delay;

	if (st->task->use_mimeq) {
		st->state = NTRIP_IDLE_CLIENT;
		ntrip_task_send_next_request(st);
	} else
		ntripcli_send_request(st, NULL, 0);
}

/*
 * Create a new task, with periodic rescheduling if refresh_delay is not 0.
 * Don't start it.
 */
struct ntrip_task *ntrip_task_new(struct caster_state *caster,
	const char *host, unsigned short port, const char *uri, int tls, int refresh_delay,
	size_t bulk_max_size, size_t queue_max_size, const char *type, const char *drainfilename) {

	struct ntrip_task *this = (struct ntrip_task *)malloc(sizeof(struct ntrip_task));
	if (this == NULL)
		return NULL;
	this->host = host?mystrdup(host):NULL;
	this->uri = uri?mystrdup(uri):NULL;
	if ((host && this->host == NULL) || (uri && this->uri == NULL)) {
		strfree(this->host);
		strfree((char *)this->uri);
		free(this);
		return NULL;
	}
	memset(&this->start, 0, sizeof(this->start));
	atomic_init(&this->refcnt, 1);
	this->port = port;
	this->status_timeout = 0;		// only used with mimeq/task_send_next_request()
	this->refresh_delay = refresh_delay;
	this->max_retry_delay = refresh_delay;
	this->current_retry_delay = refresh_delay;
	this->end_cb = NULL;
	this->line_cb = NULL;
	this->status_cb = NULL;
	this->connect_cb = connect_cb;
	this->st = NULL;
	this->caster = caster;
	this->ev = NULL;
	this->type = type;
	this->tls = tls;
	this->method = "GET";
	this->connection_keepalive = 0;
	this->use_mimeq = 0;
	this->pending = 0;
	this->read_timeout = 0;
	this->write_timeout = 0;
	TAILQ_INIT(&this->headers);
	STAILQ_INIT(&this->mimeq);
	P_RWLOCK_INIT(&this->mimeq_lock, NULL);
	P_RWLOCK_INIT(&this->st_lock, NULL);
	atomic_init(&this->state, TASK_INIT);
	atomic_init(&this->restart_sending, 0);
	this->bulk_max_size = bulk_max_size;
	this->queue_max_size = queue_max_size;
	this->queue_size = 0;
	this->nograylog = 0;
	this->drainfilename = drainfilename?mystrdup(drainfilename):NULL;
	return this;
}

/*
 * Protected access to clear the st pointer and
 * return a counted reference to its previous value, if not NULL.
 */
struct ntrip_state *ntrip_task_clear_get_st(struct ntrip_task *this, int getref) {
	struct ntrip_state *rst;
	P_RWLOCK_WRLOCK(&this->st_lock);
	rst = getref ? this->st : NULL;
	if (this->st != NULL) {
		this->st->task = NULL;
		if (!rst)
			ntrip_decref(this->st, "ntrip_task_clear_st");
	}
	this->st = NULL;
	P_RWLOCK_UNLOCK(&this->st_lock);
	return rst;
}

void ntrip_task_clear_st(struct ntrip_task *this) {
	ntrip_task_clear_get_st(this, 0);
}

/*
 * Return a counted reference to the ntrip_state, or NULL.
 */
static struct ntrip_state *ntrip_task_get_st_ref(struct ntrip_task *this) {
	P_RWLOCK_RDLOCK(&this->st_lock);
	struct ntrip_state *st = this->st;
	if (st != NULL)
		ntrip_incref(st, "ntrip_task_get_st_ref");
	P_RWLOCK_UNLOCK(&this->st_lock);
	return st;
}

enum task_state ntrip_task_get_state(struct ntrip_task *this) {
	return atomic_load_explicit(&this->state, memory_order_relaxed);
}

static inline void ntrip_task_set_st(struct ntrip_task *this, struct ntrip_state *st) {
	P_RWLOCK_WRLOCK(&this->st_lock);
	ntrip_incref(st, "ntrip_task_set_st");
	this->st = st;
	P_RWLOCK_UNLOCK(&this->st_lock);
}

int ntrip_task_start(struct ntrip_task *this, void *reschedule_arg, struct livesource *livesource, int persistent) {
	int r = -1;
	assert(this->st == NULL);
	atomic_store_explicit(&this->state, TASK_RUNNING, memory_order_relaxed);
	struct ntrip_state *st =
		ntripcli_new(this->caster, this->host, this->port, this->tls, this->uri, this->type, this,
		livesource, persistent);

	if (st == NULL) {
		r = -1;
	} else {
		ntrip_task_set_st(this, st);
		r = ntripcli_start(st);
	}

	if (r < 0) {
		ntrip_task_clear_st(this);
		if (reschedule_arg != NULL)
			ntrip_task_reschedule(this, reschedule_arg);
	}
	return r;
}

/*
 * Clear associated rescheduling event for a task.
 * Kill any associated TCP session.
 */
void ntrip_task_stop(struct ntrip_task *this) {
	if (atomic_load_explicit(&this->state, memory_order_relaxed) == TASK_END)
		return;
	atomic_store_explicit(&this->state, TASK_END, memory_order_relaxed);

	P_RWLOCK_WRLOCK(&this->mimeq_lock);
	this->pending = 0;
	if (this->ev) {
		event_free(this->ev);
		this->ev = NULL;
	}
	P_RWLOCK_UNLOCK(&this->mimeq_lock);

	struct ntrip_state *st = ntrip_task_clear_get_st(this, 1);

	if (st) {
		logfmt(&this->caster->flog, LOG_INFO, "Stopping %s (%p) from %s:%d", this->type, this, this->host, this->port);
		bufferevent_lock(st->bev);
		ntrip_decref_end(st, "ntrip_task_stop");
		bufferevent_unlock(st->bev);
		ntrip_decref(st, "ntrip_task_stop 2");
	} else
		logfmt(&this->caster->flog, LOG_INFO, "Stopping %s (%p) from %s:%d: not running", this->type, this, this->host, this->port);
}

void ntrip_task_reschedule(struct ntrip_task *this, void *arg_cb) {
	if (atomic_load_explicit(&this->state, memory_order_relaxed) == TASK_END)
		return;
	P_RWLOCK_WRLOCK(&this->mimeq_lock);
	this->pending = 0;
	if (this->refresh_delay) {
		struct timeval timeout_interval = { this->current_retry_delay, 0 };
		if (this->ev != NULL)
			event_free(this->ev);
		this->ev = event_new(caster_get_eventbase(this->caster), -1, 0, _ntrip_task_restart_cb, this);
		if (this->ev) {
			event_add(this->ev, &timeout_interval);
			this->current_retry_delay = (this->current_retry_delay?this->current_retry_delay:1)*2;
			if (this->current_retry_delay > this->max_retry_delay) this->current_retry_delay = this->max_retry_delay;

			P_RWLOCK_UNLOCK(&this->mimeq_lock);
			logfmt(&this->caster->flog, LOG_INFO, "Starting refresh callback for %s %s:%d in %d seconds", this->type, this->host, this->port, this->current_retry_delay);
		} else {
			P_RWLOCK_UNLOCK(&this->mimeq_lock);
			logfmt(&this->caster->flog, LOG_CRIT, "Can't schedule refresh callback for %s %s:%d, canceling", this->type, this->host, this->port);
		}
	} else
		P_RWLOCK_UNLOCK(&this->mimeq_lock);
}

/*
 * Drain the queue, possibly storing the content in a file.
 * Keep the items currently being sent.
 */
static size_t ntrip_task_drain_queue(struct ntrip_task *this) {
	struct mimeq tmp_mimeq;
	struct mime_content *m;

	STAILQ_INIT(&tmp_mimeq);

	P_RWLOCK_WRLOCK(&this->mimeq_lock);

	STAILQ_SWAP(&this->mimeq, &tmp_mimeq, mime_content);

	size_t r = this->queue_size;
	size_t len_moved = 0;

	/*
	 * We need to keep this->pending items at the head
	 * to avoid use-after-free of sent data.
	 */
	int pending = this->pending;
	while (pending && (m = STAILQ_FIRST(&tmp_mimeq))) {
		STAILQ_REMOVE_HEAD(&tmp_mimeq, next);
		len_moved += m->len;
		STAILQ_INSERT_TAIL(&this->mimeq, m, next);
		pending--;
	}
	assert(pending == 0);
	r -= len_moved;
	this->queue_size = len_moved;
	P_RWLOCK_UNLOCK(&this->mimeq_lock);

	if (!r)
		return r;

	FILE *f = NULL;
	if (this->drainfilename) {
		char filename[PATH_MAX];
		filedate(filename, sizeof filename, this->drainfilename);
		f = fopen_absolute(this->caster->config_dir, filename, "a+");
	}
	while ((m = STAILQ_FIRST(&tmp_mimeq))) {
		STAILQ_REMOVE_HEAD(&tmp_mimeq, next);
		if (f != NULL) {
			fwrite(m->packet->data, m->packet->datalen, 1, f);
			fputs("\n", f);
		}
		mime_free(m);
	}
	if (f != NULL)
		fclose(f);
	return r;
}

/*
 * Insert a new item in the queue, checking accepted size.
 */
void ntrip_task_queue(struct ntrip_task *this, struct packet *packet) {
	if (atomic_load_explicit(&this->state, memory_order_relaxed) == TASK_END)
		return;
	struct mime_content *m = mime_new_from_packet("application/json", packet);
	if (m == NULL) {
		logfmt(&this->caster->flog, LOG_CRIT, "Out of memory when allocating log output, dropping");
		return;
	}
	size_t len = m->len;

	P_RWLOCK_WRLOCK(&this->mimeq_lock);
	if (len + this->queue_size > this->queue_max_size) {
		P_RWLOCK_UNLOCK(&this->mimeq_lock);
		size_t len = ntrip_task_drain_queue(this);
		logfmt(&this->caster->flog, LOG_CRIT, "Backlog queue was %d bytes, drained", len);
	} else
		P_RWLOCK_UNLOCK(&this->mimeq_lock);

	if (this->bulk_max_size && len > this->bulk_max_size - 1) {
		logfmt(&this->caster->flog, LOG_ERR, "Log message %d bytes, bigger than max %d bytes, dropping",
				m->len, this->bulk_max_size-1);
		mime_free(m);
	} else {
		P_RWLOCK_WRLOCK(&this->mimeq_lock);
		STAILQ_INSERT_TAIL(&this->mimeq, m, next);
		this->queue_size += len;
		P_RWLOCK_UNLOCK(&this->mimeq_lock);
	}

	int first_sending = atomic_fetch_add_explicit(&this->restart_sending, 1, memory_order_relaxed) == 0;
	if (first_sending) {
		struct ntrip_state *st = ntrip_task_get_st_ref(this);
		if (st != NULL) {
			struct bufferevent *bev = st->bev;
			assert(bev != NULL);
			bufferevent_lock(bev);
			if (st->state == NTRIP_IDLE_CLIENT)
				ntrip_task_send_next_request(st);
			ntrip_decref(st, "ntrip_task_queue");
			bufferevent_unlock(bev);
		}
	}
	atomic_fetch_sub_explicit(&this->restart_sending, 1, memory_order_relaxed);
}

/*
 * Send the next request to the server, if any data is in the queue.
 * Should only be called when in NTRIP_IDLE_CLIENT state.
 *
 * Required lock: ntrip_state
 */
void ntrip_task_send_next_request(struct ntrip_state *st) {
	struct evbuffer *output = bufferevent_get_output(st->bev);
	struct mime_content *m;
	struct ntrip_task *task = st->task;
	assert(st->state == NTRIP_IDLE_CLIENT);
	assert(task->pending == 0);
	size_t size = 0;

	P_RWLOCK_WRLOCK(&task->mimeq_lock);
	if (task->bulk_max_size) {
		/*
		 * Bulk mode
		 */

		/*
		 * Count how many elements we can send under the max size
		 */
		int n = 0;
		STAILQ_FOREACH(m, &task->mimeq, next) {
			if (size + m->len + 1 > task->bulk_max_size)
				break;
			// count 1 more for the added newline
			size += m->len + 1;
			n++;
		}

		if (n == 0) {
			P_RWLOCK_UNLOCK(&task->mimeq_lock);
			return;
		}

		/* Dummy MIME content to pass MIME type and size */
		struct mime_content mc;
		mc.len = size;
		mc.mime_type = task->bulk_content_type;

		/* Send the HTTP request followed by the MIME items joined by '\n' */
		ntripcli_send_request(st, &mc, 0);
		STAILQ_FOREACH(m, &task->mimeq, next) {
			if (n == 0)
				break;
			if (packet_send(m->packet, st, time(NULL)) < 0
			 || evbuffer_add_reference(output, "\n", 1, NULL, NULL) < 0) {
				P_RWLOCK_UNLOCK(&task->mimeq_lock);
				ntrip_log(st, LOG_CRIT, "Not enough memory, dropping connection to %s:%d", st->host, st->port);
				ntrip_task_clear_st(task);
				ntrip_decref_end(st, "ntrip_task_send_next_request");
				return;
			}
			st->task->pending++;
			n--;
		}
	} else {
		/* Regular mode: 1 request per MIME item */
		m = STAILQ_FIRST(&task->mimeq);
		if (m) {
			ntripcli_send_request(st, m, 0);
			if (packet_send(m->packet, st, time(NULL)) < 0) {
				P_RWLOCK_UNLOCK(&task->mimeq_lock);
				ntrip_log(st, LOG_CRIT, "Not enough memory, dropping connection to %s:%d", st->host, st->port);
				ntrip_task_clear_st(task);
				ntrip_decref_end(st, "ntrip_task_send_next_request");
				return;
			}
			task->pending = 1;
		}
	}
	P_RWLOCK_UNLOCK(&task->mimeq_lock);

	/*
	 * Only expect a reply from the server if we sent a HTTP request.
	 * Will close if it times out.
	 * In other cases, just keep the connection idle.
	 */
	struct timeval read_timeout = { st->task->pending ? st->task->status_timeout : 0 };
	bufferevent_set_timeouts(st->bev, &read_timeout, NULL);
}

/*
 * Acknowledge pending data.
 *
 * Required lock: ntrip_state
 */
void ntrip_task_ack_pending(struct ntrip_task *this) {
	if (atomic_load_explicit(&this->state, memory_order_relaxed) == TASK_END)
		return;
	struct mime_content *m;
	P_RWLOCK_WRLOCK(&this->mimeq_lock);
	while (this->pending && (m = STAILQ_FIRST(&this->mimeq))) {
		STAILQ_REMOVE_HEAD(&this->mimeq, next);
		this->queue_size -= m->len;
		this->pending--;
		mime_free(m);
	}
	assert(this->pending == 0);
	P_RWLOCK_UNLOCK(&this->mimeq_lock);
}

static void ntrip_task_free(struct ntrip_task *this) {
	ntrip_task_stop(this);
	ntrip_task_drain_queue(this);

	ntrip_task_clear_st(this);

	P_RWLOCK_WRLOCK(&this->mimeq_lock);
	evhttp_clear_headers(&this->headers);
	strfree(this->host);
	strfree((char *)this->uri);
	strfree((char *)this->drainfilename);
	if (this->ev)
		event_free(this->ev);
	P_RWLOCK_UNLOCK(&this->mimeq_lock);
	P_RWLOCK_DESTROY(&this->mimeq_lock);
	P_RWLOCK_DESTROY(&this->st_lock);
	free(this);
}

void ntrip_task_incref(struct ntrip_task *this) {
	atomic_fetch_add(&this->refcnt, 1);
}

void ntrip_task_decref(struct ntrip_task *this) {
	if (atomic_fetch_add_explicit(&this->refcnt, -1, memory_order_relaxed) == 1)
		ntrip_task_free(this);
}

void ntrip_task_reload(struct ntrip_task *this,
	const char *host, unsigned short port, const char *uri, int tls,
	int refresh_delay, int bulk_max_size, int queue_max_size, const char *drainfilename) {

	ntrip_task_stop(this);
	this->refresh_delay = refresh_delay;
	this->bulk_max_size = bulk_max_size;
	this->queue_max_size = queue_max_size;
	strfree((char *)this->uri);
	this->uri = mystrdup(uri);
	if (this->drainfilename)
		strfree((char *)this->drainfilename);
	this->drainfilename = mystrdup(drainfilename);
}
