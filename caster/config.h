#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdatomic.h>
#include <stdio.h>

#include <json-c/json_object.h>

#include "auth.h"
#include "ip.h"
#include "log.h"
#include "rtcm.h"

/*
 * Caster configuration structures.
 */

struct config_bind {
	const char *ip;
	unsigned short port;
	/*
	 * Size of listen queue
	 * Set to -1 to use system default.
	 */
	int queue_size;
	int tls;
	const char *tls_full_certificate_chain;
	const char *tls_private_key;
	const char *hostname;
};

struct config_proxy {
	/*
	 * Destination host and port to proxy.
	 */
	const char *host;
	unsigned short port;

	/*
	 * Delay to refresh a proxied sourcetable.
	 */
	int table_refresh_delay;

	/*
	 * Priority when in a stack.
	 *
	 * Higher = better priority
	 */
	int priority;
	int tls;
};

// IP prefix (IP address + prefix length)
struct config_trusted_http_proxy_prefixes {
	struct prefix prefix;
};

struct config_node {
	/*
	 * Destination host and port
	 */
	const char *host;
	unsigned short port;
	const char *authorization;
	int tls;

	/* Maximum queue size for memory backlog */
	size_t queue_max_size;

	/* How many seconds to wait for a HTTP status in a reply */
	int status_timeout;

	int retry_delay, max_retry_delay;
};

struct config_endpoint {
	const char *ip;
	const char *host;
	unsigned short port;
	int tls;
};

struct config_graylog {
	/*
	 * Configuration for a graylog server
	 */
	const char *host;
	unsigned short port;

	/* URI on the server */
	const char *uri;

	int tls;
	int log_level;

	/* Token for Authorization: HTTP header */
	const char *authorization;

	/* How many seconds to wait for a HTTP status in a reply */
	int status_timeout;

	/* How many seconds to initially wait before restarting a failed connection */
	int retry_delay;

	/* How many maximum seconds to wait beteen retries (exponential backoff from retry_delay) */
	int max_retry_delay;

	/* Maximum size for bulk mode, 0 to disable bulk mode */
	size_t bulk_max_size;

	/* Maximum queue size for memory backlog */
	size_t queue_max_size;

	/* File template (see strftime(3)) for overflow files */
	const char *drainfilename;
};

struct config_syslog {
	int log_level;
	int facility;
};

struct config_threads {
	/* Thread stack size */
	size_t	stacksize;
};

struct config_webroots {
	const char *path;
	const char *uri;
};

struct config_rtcm_convert {
	const char *types;			// ','-separated list of RTCM types to convert
	enum rtcm_conversion conversion;	// conversion to apply
};

struct config_rtcm_filter {
	const char *apply;	// ','-separated list of mountpoints
	const char *pass;	// ','-separated list of RTCM types
	struct config_rtcm_convert *convert;
	int convert_count;
};

struct config {
	/*
	 * Hysteresis distance in meters for virtual source switch.
	 */
	float hysteresis_m;

	/*
	 * Max distance to prune the sourcetable when computing the
	 * nearest bases.
	 */
	float max_nearest_lookup_distance_m;

	/*
	 * Number of bases to aim for (by adjusting the lookup distance)
	 * for nearest base computation.
	 */
	int nearest_base_count_target;

	/*
	 * Min & max recompute interval for nearest base, in seconds.
	 */
	int			min_nearest_recompute_interval;
	int			max_nearest_recompute_interval;

	/* Minimal delta in meters for nearest base recompute */
	float			min_nearest_recompute_pos_delta;

	/*
	 * Proxy definition
	 */
	struct config_proxy	*proxy;
	int			proxy_count;

	/*
	 * Optional handling of X-Forwarded-For.
	 */
	const char		**trusted_http_proxy;
	int			trusted_http_proxy_count;
	struct prefix		*trusted_http_proxy_prefixes;
	const char		*trusted_http_ip_header;

	/*
	 * Node list definition
	 */
	struct config_node	*node;
	int			node_count;

	struct config_endpoint	*endpoint;
	int			endpoint_count;
	// Configured endpoints, pre-processed in JSON format.
	json_object		*endpoints_json;

	/*
	 * Graylog server definition
	 */
	struct config_graylog	*graylog;
	int			graylog_count;

	/*
	 * Syslog configuration
	 */
	struct config_syslog	*syslog;
	int			syslog_count;

	/*
	 * Sizes of accepted backlogs before we drop a client.
	 */
	size_t			backlog_socket;		// used to set the socket buffer size
	size_t			backlog_evbuffer;

	/*
	 * Read timeout for sources
	 */
	int			source_read_timeout;

	/*
	 * Default timeouts for ntripcli and ntripsrv,
	 * unless otherwise specified by specific tasks.
	 */
	int			ntripcli_default_read_timeout;
	int			ntripcli_default_write_timeout;
	int			ntripsrv_default_read_timeout;
	int			ntripsrv_default_write_timeout;

	/*
	 * Read/write timeout for sourcetable fetcher
	 */
	int			sourcetable_fetch_timeout;

	/*
	 * Read/write timeout for on-demand source
	 */
	int			on_demand_source_timeout;

	/*
	 * Array of listen addresses to bind to
	 */
	struct config_bind	*bind;
	int 			bind_count;

	/* Maximal size of received HTTP header line */
	size_t http_header_max_size;
	/* Maximal size of received content length */
	size_t http_content_length_max;

	/*
	 * Threads configuration
	 */
	struct config_threads	*threads;
	int			threads_count;

	/*
	 * Delay in seconds to close a source without a subscriber.
	 * Only applies to sources we pull (GET) ourselves.
	 */
	int idle_max_delay;

	/*
	 * Delay to retry connection to a on-demand source.
	 */
	int reconnect_delay;

	/*
	 * Min packet size to acquire before retransmiting
	 */
	int min_raw_packet;

	/*
	 * Max packet size when retransmitng a stream
	 */
	int max_raw_packet;

	/*
	 * Host, blocklist and sources filenames
	 */
	const char *host_auth_filename;
	const char *source_auth_filename;
	const char *blocklist_filename;
	const char *sourcetable_filename;
	int sourcetable_priority;

	int test_default;

	/*
	 * Log files and log level
	 */
	const char *access_log;
	const char *log;
	int log_level;

	/*
	 * Username access to the /adm section (account from source.auth)
	 */
	const char *admin_user;

	/*
	 * Web root file paths.
	 */
	struct config_webroots *webroots;
	int webroots_count;

	/*
	 * RTCM filter
	 */
	struct config_rtcm_filter *rtcm_filter;
	int rtcm_filter_count;

	/* Auth key for incoming syncer API connections */
	const char *syncer_auth;

	_Atomic int refcnt;

	/* Auth file entries */
	struct auth_entry *host_auth;
	struct auth_entry *source_auth;

	/* Quota/block list by IP prefix */
	struct prefix_table *blocklist;

	/* Pointer to caster-specific structures derived from config */
	struct caster_dynconfig *dyn;

	/* Pointer to callback function for housekeeping tasks at config_free() */
	void (*free_callback)(struct config *config);

	long long gen;
};

extern int backlog_delay;
extern size_t backlog_socket;
extern size_t backlog_evbuffer;

struct config *config_parse(const char *filename, long long config_gen);
void config_free(struct config *this);

static inline void config_incref(struct config *this) {
	atomic_fetch_add_explicit(&this->refcnt, 1, memory_order_relaxed);
}

static inline void config_decref(struct config *this) {
	if (atomic_fetch_sub_explicit(&this->refcnt, 1, memory_order_relaxed) == 1)
		config_free(this);
}

#endif
