#ifndef __NTRIP_COMMON_H__
#define __NTRIP_COMMON_H__

#include <netinet/in.h>

#include "conf.h"
#include "caster.h"
#include "livesource.h"
#include "redistribute.h"
#include "util.h"


enum ntrip_session_state {
	NTRIP_WAIT_HTTP_METHOD,		// Wait for HTTP method (first request line)
	NTRIP_WAIT_HTTP_STATUS,		// Wait for HTTP status (first reply line)
	NTRIP_WAIT_HTTP_HEADER,		// Wait for HTTP header or empty line
	NTRIP_REGISTER_SOURCE,		// Register new source as live.
					// Ephemeral, immediately followed by NTRIP_WAIT_STREAM_GET
	NTRIP_WAIT_STREAM_GET,		// Source connected, get data (client)
	NTRIP_WAIT_STREAM_SOURCE,	// Source connected, receive data (server)
	NTRIP_WAIT_SOURCETABLE_LINE,	// Client waiting for the next sourcetable line
	NTRIP_WAIT_CLIENT_INPUT,	// Server waiting for GGA lines from client
	NTRIP_WAIT_CLOSE,		// End of connection, close
	NTRIP_END			// Ready for ntrip_free
};

/*
 * States for Transfer-Encoding: chunked
 */
enum ntrip_chunk_state {
	CHUNK_NONE,		// no chunk encoding
	CHUNK_WAIT_LEN,		// waiting for chunk len (hex digits + "\r\n")
	CHUNK_IN_PROGRESS,	// in chunk
	CHUNK_WAITING_TRAILER	// waiting for "\r\n" trailer
};

/* Log levels, same as syslog and GEF + LOG_EDEBUG */

#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */
#define	LOG_EDEBUG	8	/* extended debug messages */

/*
 * Number of HTTP args.
 * This works both for a NTRIP request:
 *		GET /CT HTTP/1.1
 *		SOURCE passwd /CT
 * or a reply:
 *		ICY 200 OK
 *		HTTP/1.1 200 OK
 */
#define SIZE_HTTP_ARGS	3

/*
 * State for a connection (client or server)
 */

struct ntrip_state {
	/*
	 * The ntrip_state structure is locked by way of its
	 * corresponding bufferevent (below in bev). libevent
	 * does its own locking on it. It's a recursive mutex.
	 */

	struct caster_state *caster;
	enum ntrip_session_state state;
	int id;		// Unique id for external reference
	const char *type;
	time_t start;	// time the connection was established

	/* linked-list pointers for main job queue */
	STAILQ_ENTRY(ntrip_state) next;
	/* job list for this particular session */
	struct jobq jobq;

	/*
	 * ntrip_state lifecycle on the caster "ntrips" queues:
	 *
	 * ntrip_new() -> inserted on caster->ntrips.queue
	 * ... useful lifecycle ...
	 * Death: state set to NTRIP_END
	 * - removed from caster->ntrips.queue
	 * - if threading activated:
	 *   - added to caster->ntrips.free_queue for deferred free
	 *   else:
	 *   - ntrip_free
	 */

	// Linked-list entry for the caster->ntrips.queue
	TAILQ_ENTRY(ntrip_state) nextg;
	// Linked-list entry for the caster->ntrips.free_queue
	TAILQ_ENTRY(ntrip_state) nextf;

	/*
	 * State for a NTRIP client or server
	 */

	struct bufferevent *bev;		// main bufferevent associated with the session
	char bev_freed;				// has it been freed already?

	/*
	 * HTTP chunk handling
	 */
	struct evbuffer *chunk_buf;		// HTTP chunk reassembling
	size_t chunk_len;			// remaining chunk len to receive
	enum ntrip_chunk_state chunk_state;	// current state in chunk reassembly

	char remote;				// Flag: remote address is filled in peeraddr
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
		struct sockaddr generic;
	} peeraddr;
	char remote_addr[40];		// Conversion of the IP address part to an ASCII string

	char *http_args[SIZE_HTTP_ARGS];

	// Set if this session is itself a source
	struct livesource *own_livesource;

	/* packet feed (RTCM or other) redistribution */
	time_t last_send;			// last time a packet was resent to someone
	char redistribute;			// Flag: register as a live source
	char registered;			// Flag: registered as a live source
	char persistent;			// Flag: don't unregister & close even after idle_max_delay

	/*
	 * NTRIP client state
	 */
	short status_code;			// HTTP status code received (client)
	short client_version;			// NTRIP version in use
	char *host;				// host to connect to
	unsigned short port;			// port to connect to
	struct sourcetable *tmp_sourcetable;	// sourcetable we are currently downloading
	struct sourcetable_fetch_args *sourcetable_cb_arg;	// sourcetable download callback
	struct subscriber *subscription;	// current source subscription

	/*
	 * NTRIP server state
	 */
	char *user, *password;
	char *mountpoint;
	pos_t mountpoint_pos;			// geographical position of the current source
	char user_agent_ntrip;			// Flag: set if the User-Agent header
						// contains "ntrip" (case-insensitive)
	const char *user_agent;			// User-Agent header, if present

	/*
	 * Relevant sourceline if the connection is from a source.
	 */
	struct sourceline *sourceline;

	/*
	 * Values set if the connection is from a client to a source.
	 *
	 * cached values from sourceline->virtual and sourceline->on_demand,
	 * needed in case the source table goes away/is reloaded etc.
	 */
	char source_virtual;				// source is virtual
	char source_on_demand;				// source is on-demand

	short server_version;				// NTRIP version

	// Position gathered from GGA lines sent by a NTRIP client
	char last_pos_valid;			// last_pos and max_min_dist are valid
	pos_t last_pos;				// last known position
	float last_dist;			// last known base distance (for hysteresis)
	float max_min_dist;			// maximum distance to the closest base

	/*
	 * Virtual mountpoint handling
	 */
	char *virtual_mountpoint;

	/* Callback and argugments for source switching on a virtual or on-demand source */
	void (*callback_subscribe)(struct redistribute_cb_args *, int);

	/* Pointer to callback arguments, used both by the requesting connection and the source stream */
	struct redistribute_cb_args *callback_subscribe_arg;
};

struct ntrip_state *ntrip_new(struct caster_state *caster, char *host, unsigned short port, char *mountpoint);
void ntrip_free(struct ntrip_state *this, char *orig);
void ntrip_deferred_free(struct ntrip_state *this, char *orig);
void ntrip_deferred_run(struct caster_state *this, char *orig);
const char *ntrip_list_json(struct caster_state *caster, struct ntrip_state *st);
struct livesource *ntrip_add_livesource(struct ntrip_state *this, char *mountpoint, pos_t *mountpoint_pos, int on_demand);
void ntrip_unregister_livesource(struct ntrip_state *this, char *mountpoint);
char *ntrip_peer_ipstr(struct ntrip_state *this);
unsigned short ntrip_peer_port(struct ntrip_state *this);
void ntrip_alog(void *arg, const char *fmt, ...);
void ntrip_log(void *arg, int level, const char *fmt, ...);
int ntrip_handle_raw(struct ntrip_state *st, struct bufferevent *bev);
int ntrip_handle_raw_chunk(struct ntrip_state *st, struct bufferevent *bev);

#endif
