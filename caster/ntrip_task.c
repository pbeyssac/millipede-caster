#include <assert.h>

#include <stdio.h>
#include <event2/http.h>
#include <event2/buffer.h>

#include "conf.h"
#include "ntripcli.h"
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
	const char *host, unsigned short port, const char *uri, int tls, int refresh_delay,
	size_t bulk_max_size, size_t queue_max_size, const char *type, const char *drainfilename) {

	struct ntrip_task *this = (struct ntrip_task *)malloc(sizeof(struct ntrip_task));
	if (this == NULL)
		return NULL;
	this->host = mystrdup(host);
	this->uri = mystrdup(uri);
	if (this->host == NULL || this->uri == NULL) {
		strfree(this->host);
		strfree((char *)this->uri);
		free(this);
		return NULL;
	}
	this->port = port;
	this->refresh_delay = refresh_delay;
	this->end_cb = NULL;
	this->line_cb = NULL;
	this->status_cb = NULL;
	this->st = NULL;
	this->caster = caster;
	this->ev = NULL;
	this->type = type;
	this->tls = tls;
	this->method = "GET";
	this->connection_keepalive = 0;
	this->use_mimeq = 0;
	this->read_timeout = 0;
	this->write_timeout = 0;
	TAILQ_INIT(&this->headers);
	STAILQ_INIT(&this->mimeq);
	this->bulk_max_size = bulk_max_size;
	this->queue_max_size = queue_max_size;
	this->queue_size = 0;
	this->nograylog = 0;
	this->drainfilename = drainfilename?mystrdup(drainfilename):NULL;
	return this;
}

/*
 * Clear associated rescheduling event for a task.
 * Kill any associated TCP session.
 */
void ntrip_task_stop(struct ntrip_task *this) {
	logfmt(&this->caster->flog, LOG_INFO, "Stopping %s from %s:%d", this->type, this->host, this->port);
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
		logfmt(&this->caster->flog, LOG_INFO, "Starting refresh callback for %s %s:%d in %d seconds", this->type, this->host, this->port, this->refresh_delay);
		this->ev = event_new(this->caster->base, -1, 0, _ntrip_task_restart_cb, this);
		event_add(this->ev, &timeout_interval);
	}
}

/*
 * Drain the queue, possibly storing the content in a file.
 */
static size_t ntrip_task_drain_queue(struct ntrip_task *this) {
	size_t r;
	struct mimeq tmp_mimeq;
	struct mime_content *m;

	STAILQ_INIT(&tmp_mimeq);
	if (this->st != NULL)
		bufferevent_lock(this->st->bev);
	STAILQ_SWAP(&this->mimeq, &tmp_mimeq, mime_content);
	r = this->queue_size;
	this->queue_size = 0;
	if (this->st != NULL)
		bufferevent_unlock(this->st->bev);

	if (!this->drainfilename || !r)
		return r;

	char filename[PATH_MAX];
	filedate(filename, sizeof filename, this->drainfilename);
	FILE *f = fopen(filename, "a+");
	if (f == NULL)
		return -1;
	while ((m = STAILQ_FIRST(&tmp_mimeq))) {
		STAILQ_REMOVE_HEAD(&tmp_mimeq, next);
		fputs(m->s, f);
		fputs("\n", f);
		mime_free(m);
	}
	fclose(f);
	return r;
}

/*
 * Insert a new item in the queue, checking accepted size.
 */
void ntrip_task_queue(struct ntrip_task *this, char *json) {
	char *s = mystrdup(json);
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	if (m == NULL) {
		logfmt(&this->caster->flog, LOG_CRIT, "Out of memory when allocating log output, dropping");
		return;
	}
	size_t len = m->len;

	if (len + this->queue_size > this->queue_max_size) {
		size_t len = ntrip_task_drain_queue(this);
		logfmt(&this->caster->flog, LOG_CRIT, "Backlog queue was %d bytes, drained", len);
	}

	if (this->st != NULL)
		bufferevent_lock(this->st->bev);

	if (this->bulk_max_size && len > this->bulk_max_size - 1) {
		if (this->st)
			ntrip_log(this->st, LOG_ERR, "Log message %d bytes, bigger than max %d bytes, dropping",
				m->len, this->bulk_max_size-1);
		else
			logfmt(&this->caster->flog, LOG_ERR, "Log message %d bytes, bigger than max %d bytes, dropping",
				m->len, this->bulk_max_size-1);
		mime_free(m);
	} else
		STAILQ_INSERT_TAIL(&this->mimeq, m, next);

	this->queue_size += len;

	if (this->st != NULL) {
		if (this->st->state == NTRIP_IDLE_CLIENT)
			ntrip_task_send_next_request(this->st);
		bufferevent_unlock(this->st->bev);
	}
}

/*
 * Send the next request to the server, if any data is in the queue.
 * Should only be called when in NTRIP_IDLE_CLIENT state.
 */
void ntrip_task_send_next_request(struct ntrip_state *st) {
	struct mime_content *m;
	assert(st->state == NTRIP_IDLE_CLIENT);
	size_t size = 0;
	if (st->task->bulk_max_size) {
		/*
		 * Bulk mode
		 */
		struct evbuffer *output = bufferevent_get_output(st->bev);

		/*
		 * Count how many elements we can send under the max size
		 */
		int n = 0;
		STAILQ_FOREACH(m, &st->task->mimeq, next) {
			if (size + m->len + 1 > st->task->bulk_max_size)
				break;
			// count 1 more for the added newline
			size += m->len + 1;
			n++;
		}

		if (n == 0)
			return;

		/* Dummy MIME content to pass MIME type and size */
		struct mime_content mc;
		mc.len = size;
		mc.mime_type = st->task->bulk_content_type;

		/* Send the HTTP request followed by the MIME items joined by '\n' */
		ntripcli_send_request(st, &mc, 0);
		while (n--) {
			m = STAILQ_FIRST(&st->task->mimeq);
			STAILQ_REMOVE_HEAD(&st->task->mimeq, next);
			st->task->queue_size -= m->len;
			if (evbuffer_add_reference(output, m->s, m->len, mime_free_callback, m) < 0
			 || evbuffer_add_reference(output, "\n", 1, NULL, NULL) < 0) {
				ntrip_log(st, LOG_CRIT, "Not enough memory, dropping connection to %s:%d", st->host, st->port);
				ntrip_deferred_free(st, "ntripcli_send_next_request");
				return;
			}
		}
	} else {
		/* Regular mode: 1 request per MIME item */
		m = STAILQ_FIRST(&st->task->mimeq);
		if (m) {
			STAILQ_REMOVE_HEAD(&st->task->mimeq, next);
			st->sent_bytes += m->len;
			st->task->queue_size -= m->len;
			ntripcli_send_request(st, m, 1);
		}
	}
}

void ntrip_task_free(struct ntrip_task *this) {
	evhttp_clear_headers(&this->headers);
	ntrip_task_drain_queue(this);
	strfree(this->host);
	strfree((char *)this->uri);
	free(this);
}

void ntrip_task_reload(struct ntrip_task *this,
	const char *host, unsigned short port, const char *uri, int tls,
	int retry_delay, int bulk_max_size, int queue_max_size, const char *drainfilename) {

	ntrip_task_stop(this);
	this->refresh_delay = retry_delay;
	this->bulk_max_size = bulk_max_size;
	this->queue_max_size = queue_max_size;
	strfree((char *)this->uri);
	this->uri = mystrdup(uri);
	if (this->drainfilename)
		strfree((char *)this->drainfilename);
	this->drainfilename = mystrdup(drainfilename);
}
