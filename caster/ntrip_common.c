#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <openssl/ssl.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <json-c/json.h>

#include "conf.h"
#include "caster.h"
#include "log.h"
#include "livesource.h"
#include "ntrip_common.h"
#include "util.h"

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
	if ((host && (this->host = mystrdup(host)) == NULL) || this->mountpoint == NULL || (uri && this->uri == NULL)) {
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
	this->max_min_dist = 0;
	this->user = NULL;
	this->password = NULL;
	this->type = "starting";
	this->user_agent = NULL;
	this->user_agent_ntrip = 0;
	this->wildcard = 0;
	this->own_livesource = NULL;
	if (threads)
		STAILQ_INIT(&this->jobq);
	this->njobs = 0;
	this->newjobs = 0;
	this->bev_freed = 0;
	this->bev = bev;

	// Explicitly copied to avoid locking issues later with bufferevent_getfd()
	this->fd = bufferevent_getfd(bev);

	this->input = bufferevent_get_input(bev);
	this->filter.in_filter = NULL;
	this->filter.raw_input = this->input;
	this->redistribute = 0;
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
	this->counted = 0;
	this->ssl = NULL;
	this->content_length = 0;
	this->content_done = 0;
	this->content = NULL;
	this->query_string = NULL;
	this->content_type = NULL;
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

	if (quota_check) {
		P_RWLOCK_RDLOCK(&this->caster->configlock);
		if (this->caster->blocklist)
			quota = prefix_table_get_quota(this->caster->blocklist, &this->peeraddr);
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

static void my_bufferevent_free(struct ntrip_state *this, struct bufferevent *bev) {
	if (!this->bev_freed) {
		ntrip_log(this, LOG_EDEBUG, "bufferevent_free %p", bev);
		bufferevent_free(bev);
		this->bev_freed = 1;
	} else
		ntrip_log(this, LOG_DEBUG, "double free for bufferevent %p", bev);
}

/*
 * Free a ntrip_state record.
 *
 * Required lock: ntrip_state
 */
static void _ntrip_free(struct ntrip_state *this, char *orig, int unlink) {
	ntrip_log(this, LOG_DEBUG, "FREE %s", orig);

	strfree(this->mountpoint);
	strfree(this->uri);
	strfree(this->virtual_mountpoint);
	strfree(this->host);
	strfree(this->content);
	strfree(this->content_type);
	strfree(this->query_string);

	// this->ssl is freed by the bufferevent.

	for (int i = 0; i < SIZE_HTTP_ARGS; i++) {
		if (this->http_args[i])
			strfree(this->http_args[i]);
	}

	if (this->user)
		strfree(this->user);
	/*
	 * Don't need to explicitly free this->password as it's in the
	 * same allocation as this->user
	 */

	strfree((char *)this->user_agent);

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
 * Required locks: bufferevent, ntrip_state
 */
void ntrip_deferred_free(struct ntrip_state *this, char *orig) {
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

static json_object *ntrip_json(struct ntrip_state *st) {
        bufferevent_lock(st->bev);

	char *ipstr = st->remote_addr;
	json_object *jsonip;
	unsigned port = ip_port(&st->peeraddr);
	jsonip = ipstr[0] ? json_object_new_string(ipstr) : json_object_new_null();
	json_object *new_obj = json_object_new_object();
	json_object *jsonid = json_object_new_int64(st->id);
	json_object *received_bytes = json_object_new_int64(st->received_bytes);
	json_object *sent_bytes = json_object_new_int64(st->sent_bytes);
	json_object *jsonport = json_object_new_int(port);
	json_object_object_add(new_obj, "id", jsonid);
	json_object_object_add(new_obj, "received_bytes", received_bytes);
	json_object_object_add(new_obj, "sent_bytes", sent_bytes);
	json_object_object_add(new_obj, "ip", jsonip);
	json_object_object_add(new_obj, "port", jsonport);
	json_object_object_add(new_obj, "type", json_object_new_string(st->type));
	json_object_object_add(new_obj, "wildcard", json_object_new_boolean(st->wildcard));
	if (!strcmp(st->type, "source") || !strcmp(st->type, "source_fetcher"))
		json_object_object_add(new_obj, "mountpoint", json_object_new_string(st->mountpoint));
	else if (!strcmp(st->type, "client"))
		json_object_object_add(new_obj, "mountpoint", json_object_new_string(st->http_args[1]+1));

	if (st->user_agent)
		json_object_object_add(new_obj, "user-agent", json_object_new_string(st->user_agent));

	struct tcp_info ti;
	socklen_t ti_len = sizeof ti;
	if (getsockopt(st->fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len) >= 0) {
		json_object *tcpi_obj = json_object_new_object();
		json_object_object_add(tcpi_obj, "rtt", json_object_new_int64(ti.tcpi_rtt));
		json_object_object_add(tcpi_obj, "rttvar", json_object_new_int64(ti.tcpi_rttvar));
		json_object_object_add(tcpi_obj, "snd_mss", json_object_new_int64(ti.tcpi_snd_mss));
		json_object_object_add(tcpi_obj, "rcv_mss", json_object_new_int64(ti.tcpi_rcv_mss));
		json_object_object_add(tcpi_obj, "last_data_recv", json_object_new_int64(ti.tcpi_last_data_recv));
		json_object_object_add(tcpi_obj, "rcv_wnd", json_object_new_int64(ti.tcpi_rcv_space));
#ifdef __FreeBSD__
		// FreeBSD-specific
		json_object_object_add(tcpi_obj, "snd_wnd", json_object_new_int64(ti.tcpi_snd_wnd));
		json_object_object_add(tcpi_obj, "snd_rexmitpack", json_object_new_int64(ti.tcpi_snd_rexmitpack));
#endif
		json_object_object_add(new_obj, "tcp_info", tcpi_obj);
	}

	char iso_date[30];
	iso_date_from_timeval(iso_date, sizeof iso_date, &st->start);
	json_object_object_add(new_obj, "start", json_object_new_string(iso_date));

        bufferevent_unlock(st->bev);
	return new_obj;
}

/*
 * Return a list of ntrip_state as a JSON object.
 */
struct mime_content *ntrip_list_json(struct caster_state *caster) {
	char *s;
	json_object *new_list = json_object_new_object();
	struct ntrip_state *sst;

	P_RWLOCK_RDLOCK(&caster->ntrips.lock);
	TAILQ_FOREACH(sst, &caster->ntrips.queue, nextg) {
		char idstr[40];
		json_object *nj = ntrip_json(sst);
		snprintf(idstr, sizeof idstr, "%lld", sst->id);
		json_object_object_add(new_list, idstr, nj);
	}
	P_RWLOCK_UNLOCK(&caster->ntrips.lock);

	s = mystrdup(json_object_to_json_string(new_list));
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	json_object_put(new_list);
	if (m == NULL)
		strfree((char *)s);
	return m;
}

/*
 * Return memory stats.
 */
struct mime_content *ntrip_mem_json(struct caster_state *caster) {
	struct mime_content *m = malloc_stats_dump(1);
	return m;
}

/*
 * Reload the configuration and return a status code.
 */
struct mime_content *ntrip_reload_json(struct caster_state *caster) {
	char result[40];
	int r = caster_reload(caster);
	snprintf(result, sizeof result, "{\"result\": %d}\n", r);
	char *s = mystrdup(result);
	struct mime_content *m = mime_new(s, -1, "application/json", 1);
	return m;
}

/*
 * Required lock: ntrip_state
 * Acquires lock: livesources
 *
 */
struct livesource *ntrip_add_livesource(struct ntrip_state *this, char *mountpoint, struct livesource **existing) {
	struct livesource *existing_livesource;

	assert(this->own_livesource == NULL && this->subscription == NULL);

	/*
	 * A deadlock by lock order reversal (livesources then ntrip_state) is not possible here
	 * since we are not a source subscriber.
	 */
	P_RWLOCK_WRLOCK(&this->caster->livesources.lock);
	existing_livesource = livesource_find_unlocked(this->caster, this, mountpoint, NULL, 0, NULL);
	if (existing)
		*existing = existing_livesource;
	if (existing_livesource) {
		/* Here, we should perphaps destroy & replace any existing source fetcher. */
		P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
		return NULL;
	}
	struct livesource *np = livesource_new(mountpoint, LIVESOURCE_RUNNING);
	if (np == NULL) {
		P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
		this->own_livesource = NULL;
		return NULL;
	}
	TAILQ_INSERT_TAIL(&this->caster->livesources.queue, np, next);
	this->own_livesource = np;
	P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
	ntrip_log(this, LOG_INFO, "livesource %s created RUNNING", mountpoint);
	return np;
}

/*
 * Required lock: ntrip_state
 */
void ntrip_unregister_livesource(struct ntrip_state *this) {
	if (!this->own_livesource)
		return;
	ntrip_log(this, LOG_INFO, "Unregister livesource %s", this->mountpoint);
	caster_del_livesource(this->caster, this->own_livesource);
	this->own_livesource = NULL;
}

char *ntrip_peer_ipstr(struct ntrip_state *this) {
	char *r;
	char inetaddr[64];
	r = ip_str(&this->peeraddr, inetaddr, sizeof inetaddr);
	return r?mystrdup(r):NULL;
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

	thread_id = threads?(long)pthread_getspecific(this->caster->thread_id):-1;
	gelf_init(&g, level, this->caster->hostname, thread_id);
	g.connection_id = this->id;

	if (this->caster->graylog && this->caster->graylog[0] && this->task && this->task->nograylog)
		g.nograylog = 1;

	if (this->remote) {
		unsigned port = ntrip_peer_port(this);
		struct sockaddr *sa = &this->peeraddr.generic;
		g.addrport = addrport;
		switch(sa->sa_family) {
		case AF_INET:
			snprintf(addrport, sizeof addrport, "%s:%hu", this->remote_addr, port);
			break;
		case AF_INET6:
			snprintf(addrport, sizeof addrport, "%s.%hu", this->remote_addr, port);
			break;
		default:
			g.addrport = NULL;
			snprintf(addrport, sizeof addrport, "[???]");
		}
	} else {
		g.addrport = NULL;
		strcpy(addrport, "-");
	}

	vasprintf(&g.short_message, fmt, ap);

	if (threads)
		logfmt_g(log, &g, level, "%s %lld [%lu] %s", addrport, this->id, (long)thread_id, g.short_message);
	else
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
	if (level > this->caster->config->log_level && level > this->caster->config->graylog[0].log_level)
		return;
	va_list ap;
	va_start(ap, fmt);
	_ntrip_log(&this->caster->flog, this, level, fmt, ap);
	va_end(ap);
}

int ntrip_handle_raw(struct ntrip_state *st) {
	struct evbuffer *input = st->input;

	while (1) {

		unsigned long len_raw = evbuffer_get_length(input);
		ntrip_log(st, LOG_EDEBUG, "ntrip_handle_raw ready to get %d bytes", len_raw);
		if (len_raw < st->caster->config->min_raw_packet)
			return 0;
		if (len_raw > st->caster->config->max_raw_packet)
			len_raw = st->caster->config->max_raw_packet;
		struct packet *rawp = packet_new(len_raw, st->caster);
		st->received_bytes += len_raw;
		if (rawp == NULL) {
			evbuffer_drain(input, len_raw);
			ntrip_log(st, LOG_CRIT, "Raw: Not enough memory, dropping %d bytes", len_raw);
			return 1;
		}
		evbuffer_remove(input, &rawp->data[0], len_raw);

		//ntrip_log(st, LOG_DEBUG, "Raw: packet source %s size %d", st->mountpoint, len_raw);
		if (livesource_send_subscribers(st->own_livesource, rawp, st->caster))
			st->last_send = time(NULL);
		packet_free(rawp);
		return 1;
	}
}

int ntrip_filter_run_input(struct ntrip_state *st) {
	if (st->filter.in_filter != NULL) {
		enum bufferevent_filter_result r;
		r = st->filter.in_filter(st->filter.raw_input, st->input, -1, BEV_NORMAL, st);

		if (r == BEV_NEED_MORE)
			return -1;

		if (r != BEV_OK) {
			ntrip_deferred_free(st, "after chunk_decoder");
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
			ntrip_log(st, LOG_DEBUG, "ntrip_chunk_decode OK/MORE done %d", len_done);
			return len_done?BEV_OK:BEV_NEED_MORE;
		}

		if (st->chunk_state == CHUNK_WAIT_LEN) {
			char *line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF_STRICT);
			if (line == NULL) {
				ntrip_log(st, LOG_DEBUG, "ntrip_chunk_decode readln failed, OK/MORE done %d", len_done);
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
				ntrip_log(st, LOG_DEBUG, "ntrip_chunk_decode OK/ERROR done %d", len_done);
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
				ntrip_log(st, LOG_DEBUG, "ntrip_chunk_decode OK/MORE done %d", len_done);
				return len_done?BEV_OK:BEV_NEED_MORE;
			}
			// skip trailing CR LF
			evbuffer_remove(input, data, 2);
			if (data[0] != '\r' || data[1] != '\n')
				ntrip_log(st, LOG_INFO, "Wrong chunk trailer 0x%02x 0x%02x", data[0], data[1]);

			if (st->chunk_state == CHUNK_LAST) {
				st->state = NTRIP_FORCE_CLOSE;
				st->chunk_state = CHUNK_END;
				ntrip_log(st, LOG_DEBUG, "ntrip_chunk_decode 0-length done %d, closing", len_done);
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
 * Handle receipt and retransmission of 1 RTCM packet.
 * Return 0 if more data is needed.
 */
static int ntrip_handle_rtcm(struct ntrip_state *st) {
	unsigned short len_rtcm;
	struct evbuffer_ptr p;
	struct evbuffer *input = bufferevent_get_input(st->bev);
	/*
	 * Look for 0xd3 header byte
	 */
	evbuffer_ptr_set(input, &p, 0, EVBUFFER_PTR_SET);
	p = evbuffer_search(input, "\xd3", 1, &p);
	if (p.pos < 0) {
		unsigned long len = evbuffer_get_length(input);
#if 0
		char *drain = (char *)strmalloc(len+1);
		if (drain != NULL) {
			evbuffer_remove(input, drain, len);
			drain[len] = '\0';
			ntrip_log(st, LOG_INFO, "RTCM: draining %zd bytes: \"%s\"", len, drain);
			free(drain);
		} else
#endif
		{
			ntrip_log(st, LOG_INFO, "draining %zd bytes", len);
			evbuffer_drain(input, len);
		}
		return 0;
	}
	if (p.pos > 0) {
		ntrip_log(st, LOG_DEBUG, "RTCM: found packet start, draining %zd bytes", p.pos);
		evbuffer_drain(input, p.pos);
	}

	unsigned char *mem = evbuffer_pullup(input, 3);
	if (mem == NULL) {
		ntrip_log(st, LOG_DEBUG, "RTCM: not enough data, waiting");
		return 0;
	}

	/*
	 * Compute RTCM length from packet header
	 */
	len_rtcm = (mem[1] & 3)*256 + mem[2] + 6;
	if (len_rtcm > evbuffer_get_length(input)) {
		return 0;
	}

	struct packet *rtcmp = packet_new(len_rtcm, st->caster);
	if (rtcmp == NULL) {
		evbuffer_drain(input, len_rtcm);
		ntrip_log(st, LOG_CRIT, "RTCM: Not enough memory, dropping packet");
		return 1;
	}

	evbuffer_remove(input, &rtcmp->data[0], len_rtcm);
	unsigned long crc = crc24q_hash(&rtcmp->data[0], len_rtcm-3);
	if (crc == (rtcmp->data[len_rtcm-3]<<16)+(rtcmp->data[len_rtcm-2]<<8)+rtcmp->data[len_rtcm-1]) {
		unsigned short type = rtcmp->data[3]*16 + rtcmp->data[4]/16;
		ntrip_log(st, LOG_DEBUG, "RTCM source %s size %d type %d", st->mountpoint, len_rtcm, type);
	} else {
		ntrip_log(st, LOG_INFO, "RTCM: bad checksum! %08lx %08x", crc, (rtcmp->data[len_rtcm-3]<<16)+(rtcmp->data[len_rtcm-2]<<8)+rtcmp->data[len_rtcm-1]);
	}

	if (livesource_send_subscribers(st->own_livesource, rtcmp, st->caster))
		st->last_send = time(NULL);
	packet_free(rtcmp);
	return 1;
}
