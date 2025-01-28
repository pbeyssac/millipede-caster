#ifndef __NTRIP_TASK_H__
#define __NTRIP_TASK_H__

#include <event2/event_struct.h>

#include "ntrip_common.h"

/*
 * Descriptor for a regularly scheduled outgoing connection task.
 */
struct ntrip_task {
	/* Host, port, whether to use TLS */
	char *host;
	unsigned short port;
	int tls;
	/* Task type string */
	const char *type;

	/* HTTP method to use */
	const char *method;

	/* HTTP URI */
	const char *uri;

	/* How often to runs, in seconds. 0 = one shot. */
	int refresh_delay;

	struct caster_state *caster;

	/* Additional headers */
	struct evkeyvalq headers;

	/*
	 * Callbacks
	 */

	/* Called line by line */
	int (*line_cb)(struct ntrip_state *st, void *, const char *);
	void *line_cb_arg;
	/* End of connection */
	void (*end_cb)(int, void *);
	void *end_cb_arg;
	/* Restart callback and arg called when the reschedule event is triggered */
	void (*restart_cb)(void *arg);
	void *restart_cb_arg;

	/* HTTP status callback, called as soon as it is received */
	void (*status_cb)(void *arg, int status);
	void *status_cb_arg;

	/* Current ntrip_state, if any */
	struct ntrip_state *st;

	/* event structure for libevent */
	struct event *ev;

	/* try to negotiate Connection: keep-alive with the server */
	char connection_keepalive;

	/* MIME request queue */
	struct mimeq mimeq;

	/* Current and maximum MIME queue size */
	size_t queue_size;
	size_t queue_max_size;

	/* Use the above queue instead of hardcoded requests */
	char use_mimeq;

	/*
	 * Maximum content size for aggregating messages in bulk requests,
	 * 0 = no bulk mode.
	 */
	size_t bulk_max_size;

	/* MIME type for bulk requests */
	const char *bulk_content_type;

	/* Flag: don't send logs for this task to graylog, to avoid loops */
	char nograylog;

	/* strftime(3) format file name for overflow files */
	const char *drainfilename;
};

struct ntrip_task *ntrip_task_new(struct caster_state *caster,
	const char *host, unsigned short port, const char *uri, int tls, int retry_delay,
	size_t bulk_max_size, size_t queue_max_size, const char *type, const char *drainfilename);
void ntrip_task_free(struct ntrip_task *this);
void ntrip_task_stop(struct ntrip_task *this);
void ntrip_task_reschedule(struct ntrip_task *this, void *arg_cb);
void ntrip_task_queue(struct ntrip_task *this, char *json);
void ntrip_task_send_next_request(struct ntrip_state *st);

void ntrip_task_reload(struct ntrip_task *this,
	const char *host, unsigned short port, const char *uri, int tls,
	int retry_delay, int bulk_max_size, int queue_max_size, const char *drainfilename);

#endif
