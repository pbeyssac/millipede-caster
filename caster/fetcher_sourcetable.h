#ifndef __FETCHER_SOURCETABLE_H__
#define __FETCHER_SOURCETABLE_H__

#include "caster.h"
#include "sourcetable.h"

struct sourcetable_fetch_args {
	_Atomic int refcnt;
	struct sourcetable *sourcetable;
	int priority;			// priority in a sourcetable stack
	struct ntrip_task *task;
};

struct sourcetable_fetch_args *fetcher_sourcetable_new(struct caster_state *caster,
	const char *host, unsigned short port, int tls, int refresh_delay, int priority,
	struct config *config);
void fetcher_sourcetable_incref(struct sourcetable_fetch_args *this);
void fetcher_sourcetable_decref(struct sourcetable_fetch_args *this);
void fetcher_sourcetable_stop(struct sourcetable_fetch_args *this);
void fetcher_sourcetable_reload(struct sourcetable_fetch_args *this, int refresh_delay, int sourcetable_priority);
void fetcher_sourcetable_start(void *arg_cb, int n);
void fetcher_sourcetable_start_with_config(void *arg_cb, int n, struct config *new_config);

#endif
