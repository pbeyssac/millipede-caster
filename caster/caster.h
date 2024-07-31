#ifndef __CASTER_H__
#define __CASTER_H__

#include <sys/types.h>

#include "conf.h"
#include "config.h"
#include "jobs.h"
#include "livesource.h"
#include "log.h"
#include "queue.h"
#include "sourcetable.h"
#include "util.h"

union sock {
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

/*
 * State for a caster
 */
struct caster_state {
	struct {
		struct general_ntripq queue;
		P_RWLOCK_T lock;
		int next_id;
	} ntrips;
	struct config *config;
	const char *config_file;
#ifdef THREADS
	struct joblist *joblist;
#endif
	struct event_base *base;
	struct evdns_base *dns_base;

	// Array of listening addresses
	union sock *socks;
	// Array of pointers to libevent listeners, same size
        struct evconnlistener **listeners;

	P_RWLOCK_T authlock;
	struct auth_entry *host_auth;
	struct auth_entry *source_auth;

	/*
	 * Live sources (currently received) related to this caster
	 */
	struct {
		struct livesourceq queue;
		P_RWLOCK_T lock;
	} livesources;

	sourcetable_stack_t sourcetablestack;

	/* Logs */
	struct log flog, alog;

	/* Signal handling */
	struct event *signalint_event;
	struct event *signalpipe_event;
	struct event *signalhup_event;

	/*
	 * Sourcetable fetcher configuration.
	 */
	struct sourcetable_fetch_args *sourcetable_fetchers;
};

void my_bufferevent_free(struct ntrip_state *this, struct bufferevent *bev);
void caster_del_livesource(struct caster_state *this, struct livesource *livesource);
int caster_main(char *config_file);
void free_callback(const void *data, size_t datalen, void *extra);

#endif
