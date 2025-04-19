#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/time.h>

#include <openssl/ssl.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "caster.h"
#include "log.h"
#include "livesource.h"
#include "ntrip_common.h"
#include "rtcm.h"

static void ntrip_deferred_free(struct ntrip_state *this, char *orig);

/*
 * Create a NTRIP session state for a client or a server connection.
 */
struct ntrip_state *ntrip_new(struct caster_state *caster, struct bufferevent *bev,
		char *host, unsigned short port, const char *uri, char *mountpoint) {
	struct ntrip_state *this = (struct ntrip_state *)malloc(sizeof(struct ntrip_state));
	if (this == NULL) {
		logfmt(&caster->flog, LOG_CRIT, "ntrip_new failed: out of memory");
		return NULL;
	}
	this->mountpoint = mystrdup(mountpoint?mountpoint:"");
	this->uri = uri ? mystrdup(uri) : NULL;
	this->host = host ? mystrdup(host) : NULL;
	if ((host && this->host == NULL) || this->mountpoint == NULL || (uri && this->uri == NULL)) {
		strfree(this->mountpoint);
		strfree(this->uri);
		strfree(this->host);
		free(this);
		return NULL;
	}

	gettimeofday(&this->start, NULL);
	this->received_bytes = 0;
	this->sent_bytes = 0;

	this->caster = caster;
	this->state = NTRIP_INIT;
	this->chunk_state = CHUNK_NONE;
	this->chunk_buf = NULL;
	this->port = port;
	this->last_send = time(NULL);
	this->subscription = NULL;
	this->server_version = 2;
	this->client_version = 0;
	this->connection_keepalive = 0;
	this->received_keepalive = 0;
	this->source_virtual = 0;
	this->source_on_demand = 0;
	this->last_pos_valid = 0;
	memset(&this->last_recompute_date, 0, sizeof(this->last_recompute_date));
	this->max_min_dist = 0;
	this->lookup_dist = caster->config->max_nearest_lookup_distance_m;
	this->user = NULL;
	this->password = NULL;
	this->scheme_basic = 0;
	this->type = "starting";
	this->user_agent = NULL;
	this->user_agent_ntrip = 0;
	this->wildcard = 0;
	this->rtcm_info = NULL;
	this->own_livesource = NULL;
	if (threads)
		STAILQ_INIT(&this->jobq);
	this->njobs = 0;
	this->newjobs = 0;
	this->refcnt = 1;
	this->bev_freed = 0;
	this->bev_close_on_free = 0;
	this->bev = bev;

	// Explicitly copied to avoid locking issues later with bufferevent_getfd()
	this->fd = bufferevent_getfd(bev);

	this->input = bufferevent_get_input(bev);
	this->filter.in_filter = NULL;
	this->filter.raw_input = this->input;
	this->persistent = 0;
	this->task = NULL;
	this->subscription = NULL;
	this->sourceline = NULL;
	this->virtual_mountpoint = NULL;
	this->status_code = 0;
	this->id = 0;
	memset(&this->http_args, 0, sizeof(this->http_args));

	this->remote_addr[0] = '\0';
	this->remote = 0;
	memset(&this->peeraddr, 0, sizeof(this->peeraddr));

	this->local_addr[0] = '\0';
	this->local = 0;
	memset(&this->myaddr, 0, sizeof(this->myaddr));

	this->counted = 0;
	this->ssl = NULL;
	this->content_length = 0;
	this->content_done = 0;
	this->content = NULL;
	this->query_string = NULL;
	this->content_type = NULL;
	this->client = 0;
	this->rtcm_filter = 0;
	return this;
}

/*
 *
 * Increment counter for this IP.
 *
 * Required lock: ntrips.lock
 */
static int ntrip_quota_incr(struct ntrip_state *this) {
	this->counted = 1;
	return hash_table_incr(this->caster->ntrips.ipcount, this->remote_addr);
}

/*
 * Decrement counter for this IP.
 *
 * Required lock: ntrips.lock
 */
static void ntrip_quota_decr(struct ntrip_state *this) {
	if (!this->counted)
		return;
	hash_table_decr(this->caster->ntrips.ipcount, this->remote_addr);
}

/*
 * Insert ntrip_state in the main connection queue.
 * Check IP quotas.
 */
static int _ntrip_register(struct ntrip_state *this, int quota_check) {
	int r = 0;
	int ipcount = -1, quota = -1;

	P_RWLOCK_WRLOCK(&this->caster->ntrips.lock);

	if (quota_check)
		ipcount = ntrip_quota_incr(this);

	this->id = this->caster->ntrips.next_id++;
	TAILQ_INSERT_TAIL(&this->caster->ntrips.queue, this, nextg);
	this->caster->ntrips.n++;

	P_RWLOCK_UNLOCK(&this->caster->ntrips.lock);

	if (this->task)
		this->task->st_id = this->id;

	if (quota_check) {
		P_RWLOCK_RDLOCK(&this->caster->configlock);
		if (this->caster->config->blocklist)
			quota = prefix_table_get_quota(this->caster->config->blocklist, &this->peeraddr);
		P_RWLOCK_UNLOCK(&this->caster->configlock);
	}

	if (quota >= 0 && ipcount > quota) {
		ntrip_log(this, LOG_WARNING, "over quota (%d connections, max %d), dropping", ipcount, quota);
		r = -1;
		// ntrip_quota_decr(this) will be called later, when we remove the state from ntrips.queue
	}

	return r;
}

/*
 * Insert ntrip_state in the main connection queue.
 */
void ntrip_register(struct ntrip_state *this) {
	_ntrip_register(this, 0);
}
int ntrip_register_check(struct ntrip_state *this) {
	return _ntrip_register(this, 1);
}

/*
 * Cache the socket fd for easier access later.
 */
void ntrip_set_fd(struct ntrip_state *this) {
	this->fd = bufferevent_getfd(this->bev);
}

/*
 * Set peer address, either from a provided sockaddr (sa != NULL) or
 * from getpeername() if sa == NULL.
 */
void ntrip_set_peeraddr(struct ntrip_state *this, struct sockaddr *sa, size_t socklen) {
	if (sa == NULL) {
		socklen_t psocklen = sizeof(this->peeraddr);
		if (getpeername(this->fd, &this->peeraddr.generic, &psocklen) < 0) {
			ntrip_log(this, LOG_NOTICE, "getpeername failed: %s", strerror(errno));
			return;
		}
	} else
		memcpy(&this->peeraddr, sa, socklen < sizeof this->peeraddr ? socklen:sizeof this->peeraddr);
	this->remote = 1;
	ip_str(&this->peeraddr, this->remote_addr, sizeof this->remote_addr);
}

void ntrip_set_localaddr(struct ntrip_state *this) {
	socklen_t psocklen = sizeof(this->myaddr);
	if (getsockname(this->fd, &this->myaddr.generic, &psocklen) < 0) {
		ntrip_log(this, LOG_NOTICE, "getsockname failed: %s", strerror(errno));
		return;
	}
	this->local = 1;
	ip_str(&this->myaddr, this->local_addr, sizeof this->local_addr);
}

static void my_bufferevent_free(struct ntrip_state *this, struct bufferevent *bev) {
	if (!this->bev_freed) {
		ntrip_log(this, LOG_EDEBUG, "bufferevent_free %p", bev);
		if (this->bev_close_on_free) {
			/*
			 * We have to cleanup this bufferevent "by hand" in cases
			 * where BEV_OPT_CLOSE_ON_FREE doesn't apply.
			 */
			int r = bufferevent_flush(this->bev, EV_WRITE, BEV_FINISHED);
			if (r < 0)
				ntrip_log(this, LOG_DEBUG, "bufferevent_flush err");
			bufferevent_disable(this->bev, EV_READ|EV_WRITE);
			bufferevent_set_timeouts(this->bev, NULL, NULL);
			bufferevent_setcb(this->bev, NULL, NULL, NULL, NULL);

			/*
			 * The following is crucial to work around a libevent bug
			 * with pending timeouts applying on the next use of the
			 * file descriptor, closing innocent random connections
			 * reusing the fd.
			 *
			 * Setting it to -1 ensures this doesn't happen.
			 *
			 * Clearing the timeouts and callbacks as done above doesn't
			 * seem to be enough.
			 */
			bufferevent_setfd(this->bev, -1);

			/*
			 * Log close() failures (typically EBADF), which are an early sign
			 * of something amiss.
			 */
			if (close(this->fd) < 0)
				ntrip_log(this, LOG_NOTICE, "CLOSE fd %d err %d", this->fd, errno);
		}
		bufferevent_free(bev);
		this->bev_freed = 1;
	} else
		ntrip_log(this, LOG_DEBUG, "double free for bufferevent %p", bev);
}

/*
 * Common free routine for ntrip_free() and keep-alive mode.
 */
static void _ntrip_common_free(struct ntrip_state *this) {
	if (this->chunk_buf)
		evbuffer_free(this->chunk_buf);

	for (char **arg = &this->http_args[0]; arg < &this->http_args[SIZE_HTTP_ARGS] && *arg; arg++)
		strfree(*arg);
	memset(&this->http_args, 0, sizeof(this->http_args));

	strfree(this->user);
	/*
	 * Don't need to explicitly free this->password as it's in the
	 * same allocation as this->user
	 */

	strfree(this->content);
	strfree(this->content_type);
	strfree((char *)this->user_agent);
	strfree(this->query_string);
}

/*
 * Clear for the next request, necessary for the keep-alive mode.
 */
void ntrip_clear_request(struct ntrip_state *this) {
	_ntrip_common_free(this);
	// Cancel chunk encoding from client by default
	this->chunk_state = CHUNK_NONE;
	this->chunk_buf = NULL;
	this->content = NULL;
	this->content_type = NULL;
	this->user_agent = NULL;
	this->user = NULL;
	this->password = NULL;
	this->query_string = NULL;
	this->received_keepalive = 0;
	this->content_length = 0;
	this->content_done = 0;
}

/*
 * Free a ntrip_state record.
 *
 * Required lock: ntrip_state
 */
static void _ntrip_free(struct ntrip_state *this, char *orig, int unlink) {
	ntrip_log(this, LOG_EDEBUG, "FREE %s", orig);

	strfree(this->mountpoint);
	strfree(this->uri);
	strfree(this->virtual_mountpoint);
	strfree(this->host);

	_ntrip_common_free(this);

	// this->ssl is freed by the bufferevent.

	if (this->subscription)
		livesource_del_subscriber(this);

	if (unlink) {
		P_RWLOCK_WRLOCK(&this->caster->ntrips.lock);
		TAILQ_REMOVE(&this->caster->ntrips.queue, this, nextg);
		this->caster->ntrips.n--;
		ntrip_quota_decr(this);
		P_RWLOCK_UNLOCK(&this->caster->ntrips.lock);
	}

	/*
	 * This will prevent any further locking on the ntrip_state, so we do
	 * it only once it is removed from ntrips.queue.
	 */
	ntrip_log(this, LOG_EDEBUG, "freeing bev %p", this->bev);
	my_bufferevent_free(this, this->bev);
	free(this);
}

void ntrip_free(struct ntrip_state *this, char *orig) {
	_ntrip_free(this, orig, 1);
}

static void ntrip_deferred_free2(struct ntrip_state *this) {
	struct caster_state *caster = this->caster;
	ntrip_log(this, LOG_EDEBUG, "ntrip_deferred_free2");
	P_RWLOCK_WRLOCK(&this->caster->ntrips.lock);
	P_RWLOCK_WRLOCK(&this->caster->ntrips.free_lock);
	bufferevent_lock(this->bev);

	ntrip_quota_decr(this);
	TAILQ_REMOVE(&this->caster->ntrips.queue, this, nextg);
	this->caster->ntrips.n--;
	TAILQ_INSERT_TAIL(&this->caster->ntrips.free_queue, this, nextf);
	this->caster->ntrips.nfree++;
	P_RWLOCK_UNLOCK(&this->caster->ntrips.free_lock);
	P_RWLOCK_UNLOCK(&this->caster->ntrips.lock);
	bufferevent_unlock(this->bev);

	/* Certainly some work to do now */
	ntrip_deferred_run(caster);
}

/*
 * Increment reference counter.
 * No lock needed.
 */
void ntrip_incref(struct ntrip_state *this, char *orig) {
	atomic_fetch_add(&this->refcnt, 1);
}

/*
 * Decrement reference counter.
 * Required lock: ntrip_state
 */
void ntrip_decref(struct ntrip_state *this, char *orig) {
	if (atomic_fetch_sub(&this->refcnt, 1) == 1) {
		assert(this->state == NTRIP_END);
		ntrip_deferred_free(this, orig);
	}
}

/*
 * Set ntrip_state in the NTRIP_END state (end of connection).
 * Decrement reference counter.
 * Required lock: ntrip_state
 */
void ntrip_decref_end(struct ntrip_state *this, char *orig) {
	if (this->state == NTRIP_END) {
		ntrip_log(this, LOG_EDEBUG, "double call to ntrip_deferred_free from %s", orig);
		return;
	}
	this->state = NTRIP_END;

	/*
	 * Unregister all we can right now.
	 *
	 * TBD: might move some relevant things from _ntrip_free() down here.
	 */

	if (this->own_livesource)
		ntrip_unregister_livesource(this);
	if (this->chunk_buf) {
		evbuffer_free(this->chunk_buf);
		this->chunk_buf = NULL;
		this->chunk_state = CHUNK_NONE;
	}
	struct bufferevent *bev = this->bev;

	size_t remain = evbuffer_get_length(bufferevent_get_output(bev));
	if (remain) {
		ntrip_log(this, LOG_DEBUG, "Warning: potentiel evbuffer leak, %ld bytes remaining", remain);
		evbuffer_drain(bufferevent_get_output(bev), remain);
	}
	ntrip_decref(this, orig);
}

/*
 * Required lock: ntrip_state
 */
static void ntrip_deferred_free(struct ntrip_state *this, char *orig) {
	struct bufferevent *bev = this->bev;

	bufferevent_disable(bev, EV_READ|EV_WRITE);
	bufferevent_set_timeouts(bev, NULL, NULL);
	bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

	/*
	 * In unthreaded mode, no locking issue: do the rest at once.
	 */
	if (!threads) {
		_ntrip_free(this, orig, 1);
		return;
	}

	joblist_drain(this);

	ntrip_log(this, LOG_EDEBUG, "ntrip_deferred_free njobs %d newjobs %d", this->njobs, this->newjobs);
	joblist_append_ntrip_unlocked(this->caster->joblist, &ntrip_deferred_free2, this);
}

/*
 * Run deferred frees
 *
 * Used in threaded mode to avoid locking issues.
 */
void ntrip_deferred_run(struct caster_state *this) {
	int n = 0;
	struct ntrip_state *st;
	P_RWLOCK_WRLOCK(&this->ntrips.free_lock);

	while ((st = TAILQ_FIRST(&this->ntrips.free_queue))) {
		TAILQ_REMOVE_HEAD(&this->ntrips.free_queue, nextf);
		this->ntrips.nfree--;
		P_RWLOCK_UNLOCK(&this->ntrips.free_lock);

		/* Keep a copy of the pointer because it will be lost after _ntrip_free */
		struct bufferevent *bev = st->bev;

		bufferevent_lock(bev);

		assert(STAILQ_EMPTY(&st->jobq));

		if (st->newjobs == -1) {
			/*
			 * Still in one of the main job queues.
			 *
			 * Since removing the ntrip_state from the job queue would be expensive,
			 * just give up for the moment.
			 */
			P_RWLOCK_WRLOCK(&this->ntrips.free_lock);
			ntrip_log(st, LOG_DEBUG, "ntrip_deferred_run njobs %d newjobs %d, deferring more", st->njobs, st->newjobs);
			TAILQ_INSERT_TAIL(&this->ntrips.free_queue, st, nextf);
			this->ntrips.nfree++;
			bufferevent_unlock(bev);
			/* Exit the loop to avoid an infinite loop */
			break;
		}

		assert(st->newjobs != -1);
		ntrip_log(st, LOG_EDEBUG, "ntrip_deferred_run njobs %d newjobs %d", st->njobs, st->newjobs);

		assert(st->njobs == 0);

		struct subscriber *sub = st->subscription;
		if (sub) {
			/*
			 * Done here instead of _ntrip_free() to avoid lock ordering problems.
			 */
			bufferevent_unlock(bev);
			livesource_del_subscriber(st);
			bufferevent_lock(bev);
		}

		_ntrip_free(st, "ntrip_deferred_run", 0);
		bufferevent_unlock(bev);

		P_RWLOCK_WRLOCK(&this->ntrips.free_lock);
		n++;
	}
	P_RWLOCK_UNLOCK(&this->ntrips.free_lock);
	if (n)
		logfmt(&this->flog, LOG_INFO, "ntrip_deferred_run did %d ntrip_free", n);
}

/*
 * Drop a connection by ID
 */
int ntrip_drop_by_id(struct caster_state *caster, long long id) {
	int r = 0;

	struct ntrip_state *st;
	P_RWLOCK_RDLOCK(&caster->ntrips.lock);
	TAILQ_FOREACH(st, &caster->ntrips.queue, nextg) {
		struct bufferevent *bev = st->bev;
		bufferevent_lock(bev);
		if (st->id > id) {
			bufferevent_unlock(bev);
			break;
		}
		if (st->id == id) {
			ntrip_notify_close(st);
			ntrip_decref_end(st, "ntrip_drop_by_id");
			bufferevent_unlock(bev);
			r = 1;
			break;
		}
		bufferevent_unlock(bev);
	}
	P_RWLOCK_UNLOCK(&caster->ntrips.lock);
	return r;
}

/*
 * Required lock: ntrip_state
 */
void ntrip_unregister_livesource(struct ntrip_state *this) {
	if (!this->own_livesource)
		return;
	livesource_del(this->own_livesource, this, this->caster);
	this->own_livesource = NULL;
}

/*
 * Notify users of a connection that it is closing.
 *
 * Required lock: ntrip_state
 */
void ntrip_notify_close(struct ntrip_state *st) {

	/*
	 * Superfluous check, might be needed later in case some fields
	 * of ntrip_state are placed in a union to save space.
	 */
	if (!st->client)
		return;

	if (st->task != NULL) {
		/* Notify the callback the transfer is over, and failed. */
		st->task->end_cb(0, st->task->end_cb_arg, st->task->cb_arg2);
		st->task = NULL;
	}
}

unsigned short ntrip_peer_port(struct ntrip_state *this) {
	struct sockaddr *sa = &this->peeraddr.generic;
	switch(sa->sa_family) {
	case AF_INET:
		return ntohs(this->peeraddr.v4.sin_port);
	case AF_INET6:
		return ntohs(this->peeraddr.v6.sin6_port);
	default:
		return 0;
	}
}

static void
_ntrip_log(struct log *log, struct ntrip_state *this, int level, const char *fmt, va_list ap) {
	struct gelf_entry g;
	int thread_id;
	char addrport[64];
	char addr[40];

	thread_id = threads?(long)pthread_getspecific(this->caster->thread_id):-1;
	gelf_init(&g, level, this->caster->hostname, thread_id);
	g.connection_id = this->id;

	if (this->caster->graylog && this->caster->graylog[0] && this->task && this->task->nograylog)
		g.nograylog = 1;

	if (this->remote) {
		unsigned port = ntrip_peer_port(this);
		struct sockaddr *sa = &this->peeraddr.generic;
		g.remote_ip = addr;
		g.remote_port = port;
		ip_str((union sock *)sa, addr, sizeof addr);
		switch(sa->sa_family) {
		case AF_INET:
			snprintf(addrport, sizeof addrport, "%s:%hu", this->remote_addr, port);
			break;
		case AF_INET6:
			snprintf(addrport, sizeof addrport, "%s.%hu", this->remote_addr, port);
			break;
		default:
			g.remote_ip = NULL;
			snprintf(addrport, sizeof addrport, "[???]");
		}
	} else {
		g.remote_ip = NULL;
		strcpy(addrport, "-");
	}

	vasprintf(&g.short_message, fmt, ap);

	logfmt_g(log, &g, level, "%s %lld %s", addrport, this->id, g.short_message);

	free(g.short_message);
}

void ntrip_alog(void *arg, const char *fmt, ...) {
	struct ntrip_state *this = (struct ntrip_state *)arg;
	va_list ap;
	va_start(ap, fmt);
	_ntrip_log(&this->caster->alog, this, -1, fmt, ap);
	va_end(ap);
}

void ntrip_log(void *arg, int level, const char *fmt, ...) {
	struct ntrip_state *this = (struct ntrip_state *)arg;
	if (level > this->caster->config->log_level && (!this->caster->config->graylog || level > this->caster->config->graylog[0].log_level))
		return;
	va_list ap;
	va_start(ap, fmt);
	_ntrip_log(&this->caster->flog, this, level, fmt, ap);
	va_end(ap);
}

int ntrip_filter_run_input(struct ntrip_state *st) {
	if (st->filter.in_filter != NULL) {
		enum bufferevent_filter_result r;
		r = st->filter.in_filter(st->filter.raw_input, st->input, -1, BEV_NORMAL, st);

		if (r == BEV_NEED_MORE)
			return -1;

		if (r != BEV_OK) {
			ntrip_decref_end(st, "after chunk_decoder");
			return -1;
		}
	}
	return 0;
}

/*
 * Filter to decapsulate HTTP chunks.
 *
 * Compatible with the libevent bufferevent_filter API, just in case.
 *
 * flags: BEV_NORMAL, BEV_FLUSH, BEV_FINISHED
 * returns: BEV_OK, BEV_NEED_MORE, BEV_ERROR
 */
static enum bufferevent_filter_result ntrip_chunk_decode(struct evbuffer *input, struct evbuffer *dst, ev_ssize_t dst_limit, enum bufferevent_flush_mode mode, void *ctx) {
	struct ntrip_state *st = (struct ntrip_state *)ctx;
	size_t len;
	size_t chunk_len;
	unsigned long len_raw;
	int len_done = 0;

	ntrip_log(st, LOG_EDEBUG, "ntrip_chunk_decode len %d limit %d flush_mode %d", evbuffer_get_length(input), dst_limit, mode);
	while (1) {
		len_raw = evbuffer_get_length(input);
		if (len_raw <= 0) {
			ntrip_log(st, LOG_EDEBUG, "ntrip_chunk_decode OK/MORE done %d", len_done);
			return len_done?BEV_OK:BEV_NEED_MORE;
		}

		if (st->chunk_state == CHUNK_WAIT_LEN) {
			char *line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF_STRICT);
			if (line == NULL) {
				ntrip_log(st, LOG_EDEBUG, "ntrip_chunk_decode readln failed, OK/MORE done %d", len_done);
				return len_done?BEV_OK:BEV_NEED_MORE;
			}

			char *p = line;
			while (*p && *p != ';' && *p != '\n' && *p != '\r') p++;
			*p = '\0';

			if (sscanf(line, "%zx", &chunk_len) != 1) {
				ntrip_log(st, LOG_INFO, "failed chunk_len: \"%s\"", line);
				free(line);
				st->state = NTRIP_FORCE_CLOSE;
				st->chunk_state = CHUNK_NONE;
				ntrip_log(st, LOG_EDEBUG, "ntrip_chunk_decode OK/ERROR done %d", len_done);
				return len_done?BEV_OK:BEV_ERROR;
			}
			free(line);

			if (chunk_len == 0) {
				st->chunk_state = CHUNK_LAST;
			} else
				st->chunk_state = CHUNK_IN_PROGRESS;
			st->chunk_len = chunk_len;
		} else if (st->chunk_state == CHUNK_IN_PROGRESS) {
			int len_used;
			if (len_raw <= st->chunk_len) {
				len_used = len_raw;
				evbuffer_add_buffer(dst, input);
				st->chunk_len -= len_used;
			} else {
				len_used = st->chunk_len;
				unsigned char *data = evbuffer_pullup(input, len_used);
				evbuffer_add(dst, data, len_used);
				evbuffer_drain(input, len_used);
				st->chunk_len = 0;
			}
			len_done += len_used;
			if (st->chunk_len == 0)
				st->chunk_state = CHUNK_WAITING_TRAILER;
			st->received_bytes += len_used;
		} else if (st->chunk_state == CHUNK_WAITING_TRAILER || st->chunk_state == CHUNK_LAST) {
			char data[2];
			if (len_raw < 2) {
				ntrip_log(st, LOG_EDEBUG, "ntrip_chunk_decode OK/MORE done %d", len_done);
				return len_done?BEV_OK:BEV_NEED_MORE;
			}
			// skip trailing CR LF
			evbuffer_remove(input, data, 2);
			if (data[0] != '\r' || data[1] != '\n')
				ntrip_log(st, LOG_INFO, "Wrong chunk trailer 0x%02x 0x%02x", data[0], data[1]);

			if (st->chunk_state == CHUNK_LAST) {
				st->chunk_state = CHUNK_END;
				st->filter.in_filter = NULL;
				evbuffer_free(st->chunk_buf);
				st->chunk_buf = NULL;
				st->input = st->filter.raw_input;
				ntrip_log(st, LOG_EDEBUG, "ntrip_chunk_decode 0-length done %d, closing", len_done);
				return BEV_OK;
			}
			st->chunk_state = CHUNK_WAIT_LEN;
		} else if (st->chunk_state == CHUNK_END)
			return BEV_ERROR;
	}
}

int ntrip_chunk_decode_init(struct ntrip_state *st) {
	if (st->chunk_buf == NULL)
		st->chunk_buf = evbuffer_new();
	if (st->chunk_buf == NULL)
		return -1;
	st->filter.in_filter = ntrip_chunk_decode;
	st->chunk_state = CHUNK_WAIT_LEN;

	st->input = st->chunk_buf;
	if (evbuffer_get_length(st->filter.raw_input) > 0) {
		ntrip_log(st, LOG_EDEBUG, "ntrip_chunk_decode_init for %d bytes", evbuffer_get_length(st->filter.raw_input));
		ntrip_chunk_decode(st->filter.raw_input, st->input, -1, BEV_NORMAL, st);
	}
	return 0;
}

/*
 * Find or create the RTCM cache entry for the current source.
 */
void ntrip_set_rtcm_cache(struct ntrip_state *st) {
	if (st->caster->rtcm_cache == NULL)
		return;

	P_RWLOCK_WRLOCK(&st->caster->rtcm_lock);
	struct rtcm_info *rp = NULL;
	rp = hash_table_get(st->caster->rtcm_cache, st->mountpoint);
	if (rp == NULL) {
		rp = rtcm_info_new();
		hash_table_add(st->caster->rtcm_cache, st->mountpoint, rp);
	}
	st->rtcm_info = rp;
	P_RWLOCK_UNLOCK(&st->caster->rtcm_lock);
}
