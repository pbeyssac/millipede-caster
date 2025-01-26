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

	/* Current ntrip_state, if any */
	struct ntrip_state *st;

	/* event structure for libevent */
	struct event *ev;
};

struct ntrip_task *ntrip_task_new(struct caster_state *caster,
	const char *host, unsigned short port, int tls, int refresh_delay, const char *type);
void ntrip_task_free(struct ntrip_task *this);
void ntrip_task_stop(struct ntrip_task *this);
void ntrip_task_reschedule(struct ntrip_task *this, void *arg_cb);

#endif
