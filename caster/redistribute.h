#ifndef __REDISTRIBUTE_H__
#define __REDISTRIBUTE_H__

#include <sys/time.h>

#include "endpoints.h"
#include "livesource.h"
#include "util.h"

/*
 * Parameters for a call to a on-demand source.
 */
struct redistribute_cb_args {
	struct caster_state *caster;
	struct endpoint endpoint;
	struct timeval t0;			// time started
	char *uri, *mountpoint;
	pos_t mountpoint_pos;			// position from the STR line
	char persistent;			// restart after failure?
	struct livesource *livesource;
	struct ntrip_task *task;
};

int redistribute_switch_source(struct ntrip_state *this, char *new_mountpoint, pos_t *mountpoint_pos, struct livesource *livesource);
struct redistribute_cb_args *redistribute_args_new(struct caster_state *caster, struct livesource *livesource,
	struct endpoint *e,
	char *mountpoint, pos_t *mountpoint_pos, int reconnect_delay, int persistent);
void redistribute_args_free(struct redistribute_cb_args *this);
int redistribute_schedule(struct caster_state *caster, struct ntrip_state *st, struct redistribute_cb_args *redis_args);
void redistribute_cb(evutil_socket_t fd, short what, void *cbarg);
void redistribute_source_stream(struct redistribute_cb_args *redis_args);
#endif
