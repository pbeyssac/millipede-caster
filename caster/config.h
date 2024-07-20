#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdio.h>

#include "log.h"

/*
 * Caster configuration structures.
 */

struct config_bind {
	char *ip;
	unsigned short port;
	/*
	 * Size of listen queue
	 * Set to -1 to use system default.
	 */
	int queue_size;
};

struct config_proxy {
	/*
	 * Destination host and port to proxy.
	 */
	char *host;
	unsigned short port;

	/*
	 * Delay to refresh a proxied sourcetable.
	 */
	int table_refresh_delay;
};

struct config {
	/*
	 * Hysteresis distance in meters for virtual source switch.
	 */
	float hysteresis_m;

	/*
	 * Proxy definition
	 */
	struct config_proxy	*proxy;
	int			proxy_count;

	/*
	 * Read timeout for sources
	 */
	int			source_read_timeout;
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
	 * Host and sources filenames
	 */
	const char *host_auth_filename;
	const char *source_auth_filename;
	const char *sourcetable_filename;

	int test_default;

	/*
	 * Log files and log level
	 */
	const char *access_log;
	const char *log;
	int log_level;

	/*
	 * Zero copy mode shares outgoing queued RTCM packets, saving memory, but incurring
	 * some overhead.
	 *
	 * Useful if there are many subscribers per source, or a lot of backlog.
	 */
	int zero_copy;

	/* Used only for YAML config reading as the CYAML default is 0 */
	int disable_zero_copy;
};

extern int backlog_delay;
extern size_t backlog_socket;
extern size_t backlog_evbuffer;

struct config *config_new();
struct config *config_parse(struct config **this, const char *filename);

#endif
