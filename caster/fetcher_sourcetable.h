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
	struct timeval t0;
	void (*sourcetable_cb)(int, short, void *);
};

void
fetcher_sourcetable_get(struct sourcetable_fetch_args *arg_cb);

#endif
