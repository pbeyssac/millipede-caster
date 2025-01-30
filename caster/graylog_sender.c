#include <event2/http.h>

#include "conf.h"
#include "ntrip_task.h"
#include "ntripcli.h"
#include "graylog_sender.h"

/*
 * Module to export GELF log data to Graylog, using its HTTP/POST API.
 */

/*
 * Queue a GELF/JSON log entry.
 */
void graylog_sender_queue(struct graylog_sender *this, char *json) {
	ntrip_task_queue(this->task, json);
}

/*
 * Callback called at the end of the ntrip session.
 */
static void
end_cb(int ok, void *arg) {
	struct graylog_sender *a = (struct graylog_sender *)arg;
	a->task->st = NULL;
	ntrip_task_reschedule(a->task, a);
}

/*
 * Handle status code in server reply.
 */
static void
status_cb(void *arg, int status) {
	/* Graylog replies with status=202, force 200 instead */
	struct graylog_sender *a = (struct graylog_sender *)arg;
	if (status == 202)
		a->task->st->status_code = 200;
}

/*
 * Initialize a graylog sender task.
 */
struct graylog_sender *graylog_sender_new(struct caster_state *caster,
	const char *host, unsigned short port, const char *uri, int tls,
	int retry_delay, int bulk_max_size, int queue_max_size, const char *authkey, const char *drainfilename) {

	struct graylog_sender *this = (struct graylog_sender *)malloc(sizeof(struct graylog_sender));
	if (this == NULL)
		return NULL;
	this->task = ntrip_task_new(caster, host, port, uri, tls, retry_delay, bulk_max_size, queue_max_size, "graylog_sender", drainfilename);
	this->task->method = "POST";
	this->task->status_cb = status_cb;
	this->task->status_cb_arg = this;
	this->task->end_cb = end_cb;
	this->task->end_cb_arg = this;
	this->task->restart_cb = graylog_sender_start;
	this->task->restart_cb_arg = this;
	this->task->connection_keepalive = 1;
	this->task->bulk_content_type = "application/json";
	this->task->bulk_max_size = bulk_max_size;
	this->task->use_mimeq = 1;
	this->task->nograylog = 1;

	if (this->task == NULL) {
		free(this);
		return NULL;
	}
	if (evhttp_add_header(&this->task->headers, "Authorization", authkey) < 0) {
		ntrip_task_free(this->task);
		free(this);
		return NULL;
	}
	STAILQ_INIT(&this->mimeq);
	return this;
}

void graylog_sender_free(struct graylog_sender *this) {
	ntrip_task_stop(this->task);
	ntrip_task_free(this->task);
	free(this);
}

/*
 * Reload fetcher, possibly modifying the refresh_delay and priority.
 *
 * Same as a stop/start, except we keep the sourcetable during the reload.
 */
int graylog_sender_reload(struct graylog_sender *this,
	const char *host, unsigned short port, const char *uri, int tls,
	int retry_delay, int bulk_max_size, int queue_max_size, const char *authkey, const char *drainfilename) {

	ntrip_task_reload(this->task, host, port, uri, tls, retry_delay, bulk_max_size, queue_max_size, drainfilename);

	evhttp_clear_headers(&this->task->headers);
	evhttp_add_header(&this->task->headers, "Authorization", authkey);

	graylog_sender_start(this);
	return 0;
}

/*
 * Start a graylog sender.
 */
void
graylog_sender_start(void *arg_cb) {
	struct graylog_sender *a = (struct graylog_sender *)arg_cb;

	if (ntripcli_start(a->task->caster, a->task->host, a->task->port, a->task->tls, a->task->uri, a->task->type, a->task, NULL, 0) < 0) {
		a->task->st = NULL;
		ntrip_task_reschedule(a->task, a);
	}
}
