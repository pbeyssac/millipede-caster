#ifndef __GRAYLOG_SENDER_H__
#define __GRAYLOG_SENDER_H__

#include <sys/queue.h>

#include "ntrip_task.h"
#include "util.h"

struct graylog_sender {
	struct ntrip_task *task;
};

void graylog_sender_queue(struct graylog_sender *this, char *json);
struct graylog_sender *graylog_sender_new(struct caster_state *caster,
	const char *host, unsigned short port, const char *uri, int tls,
	int retry_delay, int bulk_max_size, int queue_max_size, const char *authkey, const char *drainfilename);
void graylog_sender_free(struct graylog_sender *this);
void graylog_sender_stop(struct graylog_sender *this);
void graylog_sender_start(void *arg_cb, int n);

#endif
