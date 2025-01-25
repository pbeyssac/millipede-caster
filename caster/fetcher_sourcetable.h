#ifndef __FETCHER_SOURCETABLE_H__
#define __FETCHER_SOURCETABLE_H__

#include "caster.h"
#include "sourcetable.h"

struct sourcetable_fetch_args {
	struct sourcetable *sourcetable;
	struct caster_state *caster;
	char *host;
	unsigned short port;
	int refresh_delay;
	int priority;			// priority in a sourcetable stack
	void (*sourcetable_cb)(int, short, void *);
	struct event *ev;
	struct ntrip_state *st;
};

struct sourcetable_fetch_args *fetcher_sourcetable_new(struct caster_state *caster,
        const char *host, unsigned short port, int refresh_delay, int priority);
void fetcher_sourcetable_free(struct sourcetable_fetch_args *this);
void fetcher_sourcetable_stop(struct sourcetable_fetch_args *this);
void fetcher_sourcetable_reload(struct sourcetable_fetch_args *this, int refresh_delay, int priority);
void fetcher_sourcetable_start(struct sourcetable_fetch_args *arg_cb);

#endif
