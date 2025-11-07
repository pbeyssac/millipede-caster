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
	struct packet *packet = packet_new_from_string(json);
	if (packet == NULL){
		logfmt(&this->task->caster->flog, LOG_CRIT, "No configured ports to listen to, aborting.");
		return;
	}
	ntrip_task_queue(this->task, packet);
	packet_decref(packet);
}

/*
 * Callback called at the end of the http session.
 *
 * Required lock: ntrip_state
 */
static void
end_cb(int ok, void *arg, int n) {
	struct graylog_sender *a = (struct graylog_sender *)arg;
	ntrip_task_clear_st(a->task);
	ntrip_task_reschedule(a->task, a);
}

/*
 * Handle status code in server reply.
 */
static void
status_cb(void *arg, int status, int n) {
	/* Graylog replies with status=202, force 200 instead */
	struct graylog_sender *a = (struct graylog_sender *)arg;
	if (status == 202)
		a->task->st->status_code = 200;
	if (a->task->st->status_code == 200)
		/* acknowledge pending data so it can be purged */
		ntrip_task_ack_pending(a->task);
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
	this->task->cb_arg2 = 0;
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
		ntrip_task_decref(this->task);
		free(this);
		return NULL;
	}
	return this;
}

void graylog_sender_free(struct graylog_sender *this) {
	ntrip_task_stop(this->task);
	ntrip_task_decref(this->task);
	free(this);
}

/*
 * Start a graylog sender.
 */
void
graylog_sender_start(void *arg_cb, int n) {
	struct graylog_sender *a = (struct graylog_sender *)arg_cb;

	ntrip_task_start(a->task, arg_cb, NULL, 0);
}
