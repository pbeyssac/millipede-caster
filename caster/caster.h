#ifndef __CASTER_H__
#define __CASTER_H__

#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>

#include <openssl/ssl.h>

#include "conf.h"
#include "config.h"
#include "hash.h"
#include "ip.h"
#include "jobs.h"
#include "livesource.h"
#include "log.h"
#include "queue.h"
#include "sourcetable.h"
#include "util.h"

/*
 * Descriptor for a listener
 */
struct listener {
	union sock sockaddr;			// Listening address
	struct evconnlistener *listener;	// libevent structure
	struct caster_state *caster;

	int tls;			// is TLS activated?
	SSL_CTX *ssl_server_ctx;	// TLS context, certs etc.
};

/*
 * State for a caster
 */
struct caster_state {
	struct {
		struct general_ntripq queue;
		P_RWLOCK_T lock;
		struct general_ntripq free_queue;
		P_RWLOCK_T free_lock;
		long long next_id;	// must never wrap
		int n;		// number of items in queue
		int nfree;	// number of items in free_queue
		struct hash_table *ipcount;	// count by IP
	} ntrips;
	struct config *config;
	const char *config_file;
	char *config_dir;
	struct joblist *joblist;
	struct event_base *base;
	struct evdns_base *dns_base;

	// Array of pointers to listener configurations
	struct listener **listeners;
	int listeners_count;

	P_RWLOCK_T configlock;
	struct auth_entry *host_auth;
	struct auth_entry *source_auth;

	struct prefix_table *blocklist;

	/*
	 * Live sources (currently received) related to this caster
	 */
	struct {
		struct livesourceq queue;
		P_RWLOCK_T lock;
		P_MUTEX_T delete_lock;
	} livesources;

	sourcetable_stack_t sourcetablestack;

	/* Logs */
	struct log flog, alog;

	/* Thread id (thread-specific variable) for logs */
	pthread_key_t thread_id;

	/* Signal handling */
	struct event *signalint_event;
	struct event *signalpipe_event;
	struct event *signalhup_event;

	/*
	 * Sourcetable fetcher configuration.
	 */
	struct sourcetable_fetch_args **sourcetable_fetchers;
	int sourcetable_fetchers_count;
};

void caster_log_error(struct caster_state *this, char *orig);
void caster_del_livesource(struct caster_state *this, struct livesource *livesource);
int caster_main(char *config_file);
void free_callback(const void *data, size_t datalen, void *extra);
int caster_reload(struct caster_state *this);

#endif
