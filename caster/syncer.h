#ifndef __SYNCER_H__
#define __SYNCER_H__

#include "config.h"
#include "ntrip_task.h"
#include "util.h"

struct syncer {
	struct ntrip_task **task;
	int ntask;
	struct caster_state *caster;
};

void syncer_queue(struct syncer *this, char *json);
void syncer_queue_json(struct caster_state *caster, json_object *j);
struct syncer *syncer_new(struct caster_state *caster,
	struct config_node *node, int node_count, const char *uri,
	int retry_delay, int bulk_max_size);
void syncer_free(struct syncer *this);
void syncer_stop(struct syncer *this);
void syncer_start(void *arg_cb, int n);

#endif
