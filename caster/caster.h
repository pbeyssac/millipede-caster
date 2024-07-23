#ifndef __CASTER_H__
#define __CASTER_H__

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>

#include "conf.h"
#include "config.h"
#include "jobs.h"
#include "livesource.h"
#include "log.h"
#include "redistribute.h"
#include "sourcetable.h"
#include "util.h"

enum ntrip_session_state {
	NTRIP_WAIT_HTTP_METHOD,		// Wait for HTTP method (first request line)
	NTRIP_WAIT_HTTP_STATUS,		// Wait for HTTP status (first reply line)
	NTRIP_WAIT_HTTP_HEADER,		// Wait for HTTP header or empty line
	NTRIP_REGISTER_SOURCE,
	NTRIP_WAIT_STREAM_GET,
	NTRIP_WAIT_STREAM_SOURCE,
	NTRIP_WAIT_SOURCETABLE_LINE,
	NTRIP_WAIT_CLIENT_INPUT,
	NTRIP_WAIT_CLOSE,
	NTRIP_END
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

/*
 * State for a caster
 */
struct caster_state {
	struct config *config;
#ifdef THREADS
	struct joblist *joblist;
#endif
	struct event_base *base;
	struct evdns_base *dns_base;

	P_RWLOCK_T authlock;
	struct auth_entry *host_auth;
	struct auth_entry *source_auth;

	/*
	 * Live sources (currently received) related to this caster
	 */
	struct {
		struct livesourceq queue;
		pthread_rwlock_t lock;
	} livesources;

	sourcetable_stack_t sourcetablestack;

	/* Logs */
	struct log flog, alog;
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

struct ntrip_state {
	P_RWLOCK_T lock;
	int refcnt;
	struct caster_state *caster;
	enum ntrip_session_state state;

#ifdef THREADS
	/* linked-list pointers for main job queue */
	STAILQ_ENTRY(ntrip_state) next;
	/* job list for this particular session */
	struct jobq jobq;
#endif

	/*
	 * State for a NTRIP client or server
	 */

	struct evbuffer *chunk_buf;
	size_t chunk_len;
	enum ntrip_chunk_state chunk_state;

	struct bufferevent *bev;	// associated bufferevent
	char bev_freed;
	//struct event_base *base;	// libevent event base

	char remote;				// Flag: remote address is filled in peeraddr
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
		struct sockaddr generic;
	} peeraddr;

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
	char *host;
	unsigned short port;
	struct sourcetable *tmp_sourcetable;	// sourcetable we are currently downloading
	struct subscriber *subscription;	// current source subscription

	/*
	 * NTRIP server state
	 */
	char *user, *password;
	char *mountpoint;
	pos_t mountpoint_pos;
	char user_agent_ntrip;			// set if the User-Agent header contraints "ntrip" (case-insensitive)

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
	struct sourcetable_fetch_args *sourcetable_cb_arg;

	// Position gathered from GGA lines sent by a NTRIP client
	char last_pos_valid;			// last_pos and max_min_dist are valid
	pos_t last_pos;				// last known position
	float last_dist;			// last known base distance (for hysteresis)
	float max_min_dist;

	/*
	 * Virtual mountpoint handling
	 */
	char *virtual_mountpoint;

	/* Callback and argugments for source switching on a virtual or on-demand source */
	void (*callback_subscribe)(struct redistribute_cb_args *, int);
	struct redistribute_cb_args *callback_subscribe_arg;
};

int ntripsrv_redo_virtual_pos(struct ntrip_state *st);
void my_bufferevent_free(struct ntrip_state *this, struct bufferevent *bev);
void caster_del_livesource(struct caster_state *this, struct livesource *livesource);
int caster_main(char *config_file);
void free_callback(const void *data, size_t datalen, void *extra);

#endif
