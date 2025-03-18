#ifndef __NTRIP_COMMON_H__
#define __NTRIP_COMMON_H__

#include <netinet/in.h>

#include <event2/event.h>
#include <openssl/ssl.h>

#include "conf.h"
#include "caster.h"
#include "hash.h"
#include "ip.h"
#include "livesource.h"
#include "redistribute.h"
#include "request.h"
#include "util.h"


enum ntrip_session_state {
	NTRIP_INIT,			// Only set by ntrip_new
	NTRIP_WAIT_HTTP_METHOD,		// Wait for HTTP method (first request line)
	NTRIP_WAIT_HTTP_STATUS,		// Wait for HTTP status (first reply line)
	NTRIP_WAIT_HTTP_HEADER,		// Wait for HTTP header or empty line
	NTRIP_REGISTER_SOURCE,		// Register new source as live.
					// Ephemeral, immediately followed by NTRIP_WAIT_STREAM_GET
	NTRIP_WAIT_STREAM_GET,		// Source connected, get data (client)
	NTRIP_WAIT_STREAM_SOURCE,	// Source connected, receive data (server)
	NTRIP_WAIT_CALLBACK_LINE,	// Client waiting for the next callback line
	NTRIP_WAIT_CLIENT_INPUT,	// Server waiting for GGA lines from client
	NTRIP_WAIT_CLIENT_CONTENT,	// Server waiting for content
	NTRIP_WAIT_SERVER_CONTENT,	// Client waiting for content
	NTRIP_WAIT_CLOSE,		// End of connection, drain output then close
	NTRIP_FORCE_CLOSE,		// End of connection, force close now
	NTRIP_IDLE_CLIENT,		// client connection, waiting for something to send
	NTRIP_END			// Ready for ntrip_free
};

/*
 * States for Transfer-Encoding: chunked
 */
enum ntrip_chunk_state {
	CHUNK_NONE,		// no chunk encoding
	CHUNK_INIT,		// chunk encoding detected, waiting for init
	CHUNK_WAIT_LEN,		// waiting for chunk len (hex digits + "\r\n")
	CHUNK_IN_PROGRESS,	// in chunk
	CHUNK_WAITING_TRAILER,	// waiting for "\r\n" trailer
	CHUNK_LAST,		// like CHUNK_WAITING_TRAILER, but last chunk
	CHUNK_END		// finished, ready to be freed
};

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

struct rtcm_info;

struct ntrip_state {
	/*
	 * The ntrip_state structure is locked by way of its
	 * corresponding bufferevent (below in bev). libevent
	 * does its own locking on it. It's a recursive mutex.
	 */

	struct caster_state *caster;
	enum ntrip_session_state state;
	long long id;		// Unique id for external reference; must not wrap
	const char *type;
	struct timeval start;	// time the connection was established
	unsigned long long received_bytes, sent_bytes;

	/* linked-list pointers for main job queue */
	STAILQ_ENTRY(ntrip_state) next;
	/* job list for this particular session */
	struct jobq jobq;
	/* number of jobs in the queue */
	int njobs;
	/*
	 * Number of jobs added after the ntrip_state was removed from the main job queue
	 * or -1 if the ntrip_state is in the main job queue.
	 */
	int newjobs;

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

	// Flag: is this a client (outgoing) or a server (incoming) connection?
	char client;

	/*
	 * State for a NTRIP client or server
	 */

	struct bufferevent *bev;		// main bufferevent associated with the session
	char bev_freed;				// has it been freed already?
	char bev_close_on_free;			// do we have to close() the file descriptor
						// at bufferevent_free()? libevent can't do it
						// for accept()'ed sockets.
	struct evbuffer *input;
	int fd;					// file descriptor for the bufferevent
	SSL *ssl;				// TLS state

	char connection_keepalive;		// Flag: request that the connection stays open
	char received_keepalive;		// Flag: received a keep-alive header from the other end
	unsigned long content_length;		// Content-Length received from the other end, if any
	unsigned long content_done;		// How many content bytes have been received
	char *content;				// Received content
	char *content_type;			// MIME type

	struct rtcm_info *rtcm_info;

	struct {
		struct evbuffer *raw_input;
		bufferevent_filter_cb in_filter;
	} filter;

	/*
	 * HTTP chunk handling
	 */
	struct evbuffer *chunk_buf;		// HTTP chunk reassembling
	size_t chunk_len;			// remaining chunk len to receive
	enum ntrip_chunk_state chunk_state;	// current state in chunk reassembly

	char remote;				// Flag: remote address is filled in peeraddr
	char counted;				// Flag: counted in IP quotas
	union sock peeraddr;
	char remote_addr[40];		// Conversion of the IP address part to an ASCII string
	char local;			// Flag: local address is filled in localaddr
	union sock myaddr;
	char local_addr[40];		// Conversion of the IP address part to an ASCII string

	char *http_args[SIZE_HTTP_ARGS];

	// Set if this session is itself a source
	struct livesource *own_livesource;

	/* packet feed (RTCM or other) redistribution */
	time_t last_send;			// last time a packet was resent to someone
	char persistent;			// Flag: don't unregister & close the livesource even after idle_max_delay

	/*
	 * NTRIP client state
	 */
	short status_code;			// HTTP status code received (client)
	short client_version;			// NTRIP version in use: 0=plain HTTP, 1=NTRIP 1, 2=NTRIP 2
	char *host;				// host to connect to
	unsigned short port;			// port to connect to
	struct ntrip_task *task;		// descriptor and callbacks for the current task
	struct subscriber *subscription;	// current source subscription
	char *uri;				// URI for requests

	/*
	 * NTRIP server state
	 */
	int scheme_basic;			// Flag: "Basic" or "internal" auth scheme
	char *user, *password;
	char *mountpoint;
	pos_t mountpoint_pos;			// geographical position of the current source
	char user_agent_ntrip;			// Flag: set if the User-Agent header
						// contains "ntrip" (case-insensitive)
	const char *user_agent;			// User-Agent header, if present
	char wildcard;				// Flag: set for a source if the mountpoint is unregistered (wildcard entry)

	char *query_string;			// HTTP GET query string, if any.

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
	// date and position last used for recomputing the nearest base
	struct timeval last_recompute_date;
	pos_t last_recompute_pos;

	/*
	 * Virtual mountpoint handling
	 */
	char *virtual_mountpoint;
};

struct ntrip_state *ntrip_new(struct caster_state *caster, struct bufferevent *bev,
	char *host, unsigned short port, const char *uri, char *mountpoint);
void ntrip_register(struct ntrip_state *this);
int ntrip_register_check(struct ntrip_state *this);
void ntrip_set_fd(struct ntrip_state *this);
void ntrip_set_peeraddr(struct ntrip_state *this, struct sockaddr *sa, size_t socklen);
void ntrip_set_localaddr(struct ntrip_state *this);
void ntrip_clear_request(struct ntrip_state *this);
void ntrip_free(struct ntrip_state *this, char *orig);
void ntrip_deferred_free(struct ntrip_state *this, char *orig);
void ntrip_deferred_run(struct caster_state *this);
int ntrip_drop_by_id(struct caster_state *caster, long long id);
void ntrip_unregister_livesource(struct ntrip_state *this);
void ntrip_notify_close(struct ntrip_state *st);
unsigned short ntrip_peer_port(struct ntrip_state *this);
void ntrip_alog(void *arg, const char *fmt, ...);
void ntrip_log(void *arg, int level, const char *fmt, ...);
int ntrip_handle_raw(struct ntrip_state *st);
int ntrip_filter_run_input(struct ntrip_state *st);
int ntrip_handle_raw_chunk(struct ntrip_state *st);
int ntrip_chunk_decode_init(struct ntrip_state *st);
void ntrip_set_rtcm_cache(struct ntrip_state *st);

#endif
