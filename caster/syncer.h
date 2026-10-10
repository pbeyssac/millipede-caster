#ifndef __SYNCER_H__
#define __SYNCER_H__

#include "config.h"
#include "ntrip_task.h"
#include "util.h"

struct syncer {
	/*
	 * task/ntask are replaced by syncer_reload() on a configuration reload while worker
	 * threads walk them in syncer_queue(): both are protected by lock.
	 */
	P_RWLOCK_T lock;

	struct ntrip_task **task;
	int ntask;
	struct caster_state *caster;

	// Reference counter
	REFCNT;
};

void syncer_queue(struct syncer *this, char *json);
void syncer_queue_json(struct caster_state *caster, json_object *j);
int syncer_reload(struct syncer *this,
	struct config_node *node, int node_count, const char *uri,
	int bulk_max_size);
struct syncer *syncer_new(struct caster_state *caster,
	struct config_node *node, int node_count, const char *uri,
	int bulk_max_size);
void syncer_free(struct syncer *this);
void syncer_stop(struct syncer *this);
void syncer_start_all(struct syncer *this, struct config *new_config);
REFCNT_INCREF_DECL(syncer_incref, struct syncer);
REFCNT_DECREF_DECL(syncer_decref, struct syncer);

#endif
