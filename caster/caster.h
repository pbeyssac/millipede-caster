#ifndef __CASTER_H__
#define __CASTER_H__

#include <netinet/in.h>
#include <sys/time.h>
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
#include "rtcm.h"
#include "sourcetable.h"
#include "syncer.h"
#include "util.h"
#include "graylog_sender.h"

/*
 * Descriptor for a listener
 */
struct listener {
	union sock sockaddr;			// Listening address
	struct evconnlistener *listener;	// libevent structure
	struct caster_state *caster;

	int tls;			// is TLS activated?
	SSL_CTX *ssl_server_ctx;	// TLS context, certs etc.
	char *hostname;			// hostname for TLS/SNI
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
	// Configured endpoints, pre-processed in JSON format.
	json_object *endpoints_json;

	const char *config_file;
	char *config_dir;
	struct joblist *joblist;
	struct event_base *base;
	struct evdns_base *dns_base;
	struct hash_table *rtcm_cache;
	P_RWLOCK_T rtcm_lock;

	// Array of pointers to listener configurations
	struct listener **listeners;
	int listeners_count;

	P_RWLOCK_T configlock;
	struct auth_entry *host_auth;
	struct auth_entry *source_auth;

	struct prefix_table *blocklist;

	SSL_CTX *ssl_client_ctx;	// TLS context for fetchers

	struct timeval start_date;

	/*
	 * Live sources, local and remote
	 */
	struct livesources *livesources;

	sourcetable_stack_t sourcetablestack;

	/* RTCM filtering */
	struct rtcm_filter *rtcm_filter;	// filters (max 1 currently)
	struct hash_table *rtcm_filter_dict;	// mountpoint => filter dictionary

	/* Logs */
	struct log flog, alog;
	char hostname[128];
	struct graylog_sender **graylog;
	int graylog_count;	/* 0 or 1 */

	/* Table synchronization */
	struct syncer **syncers;
	int syncers_count;

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
int caster_tls_log_cb(const char *str, size_t len, void *u);
int caster_main(char *config_file);
void free_callback(const void *data, size_t datalen, void *extra);
json_object *caster_endpoints_json(struct caster_state *caster);
int caster_reload(struct caster_state *this);

#endif
