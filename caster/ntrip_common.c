#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
struct ntrip_state *ntrip_new(struct caster_state *caster, char *host, unsigned short port, char *mountpoint) {
	struct ntrip_state *this = (struct ntrip_state *)calloc(1, sizeof(struct ntrip_state));
	if (this == NULL) {
		logfmt(&caster->flog, "ntrip_new failed: out of memory\n");
		return NULL;
	}
	this->mountpoint = mystrdup(mountpoint?mountpoint:"");
	if (this->mountpoint == NULL) {
		strfree(this);
		return NULL;
	}

	this->caster = caster;
	this->state = NTRIP_WAIT_HTTP_STATUS;
	this->chunk_state = CHUNK_NONE;
	this->chunk_buf = NULL;
	this->host = host;
	this->port = port;
	this->remote_addr[0] = '\0';
	this->start = 0;
	this->last_send = time(NULL);
	this->subscription = NULL;
	this->server_version = 1;
	this->client_version = 1;
	this->callback_subscribe = NULL;
	this->callback_subscribe_arg = NULL;
	this->max_min_dist = 0;
	this->user = NULL;
	this->password = NULL;
	this->type = "starting";
	this->user_agent = NULL;
	if (threads)
		STAILQ_INIT(&this->jobq);
	this->njobs = 0;
	this->newjobs = 0;
	P_RWLOCK_WRLOCK(&this->caster->ntrips.lock);
	this->id = this->caster->ntrips.next_id++;
	TAILQ_INSERT_TAIL(&this->caster->ntrips.queue, this, nextg);
	P_RWLOCK_UNLOCK(&this->caster->ntrips.lock);
	return this;
}

static void my_bufferevent_free(struct ntrip_state *this, struct bufferevent *bev) {
	if (!this->bev_freed) {
		ntrip_log(this, LOG_EDEBUG, "bufferevent_free %p for %p\n", bev, this);
		bufferevent_free(bev);
		this->bev_freed = 1;
	} else
		ntrip_log(this, LOG_DEBUG, "double free for bufferevent %p\n", bev);
}

/*
 * Free a ntrip_state record.
 *
 * Required lock: ntrip_state
 */
static void _ntrip_free(struct ntrip_state *this, char *orig, int unlink) {
	ntrip_log(this, LOG_DEBUG, "FREE %p %s\n", this, orig);

	if (this->mountpoint)
		strfree(this->mountpoint);
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

	if (this->chunk_buf)
		evbuffer_free(this->chunk_buf);

	if (this->subscription)
		livesource_del_subscriber(this->subscription, this);

	if (this->tmp_sourcetable)
		sourcetable_free(this->tmp_sourcetable);

	if (unlink) {
		P_RWLOCK_WRLOCK(&this->caster->ntrips.lock);
		TAILQ_REMOVE(&this->caster->ntrips.queue, this, nextg);
		P_RWLOCK_UNLOCK(&this->caster->ntrips.lock);
	}

	/*
	 * This will prevent any further locking on the ntrip_state, so we do
	 * it only once it is removed from ntrips.queue.
	 */
	ntrip_log(this, LOG_EDEBUG, "freeing bev %p for %p\n", this->bev, this);
	my_bufferevent_free(this, this->bev);
	free(this);
}

void ntrip_free(struct ntrip_state *this, char *orig) {
	_ntrip_free(this, orig, 1);
}

void ntrip_deferred_free(struct ntrip_state *this, char *orig) {
	if (this->state == NTRIP_END) {
		ntrip_log(this, LOG_EDEBUG, "double call to ntrip_deferred_free %p from %s\n", this, orig);
		return;
	}

	this->state = NTRIP_END;

	/*
	 * Unregister all we can right now.
	 *
	 * TBD: might move some relevant things from _ntrip_free() down here.
	 */

	if (this->callback_subscribe_arg && this->callback_subscribe_arg->requesting_st == this) {
		ntrip_log(this, LOG_EDEBUG, "removing callback reference as requesting_st %p\n", this);
		this->callback_subscribe_arg->requesting_st = NULL;
		this->callback_subscribe_arg = NULL;
	}
	bufferevent_disable(this->bev, EV_READ|EV_WRITE);
	bufferevent_set_timeouts(this->bev, NULL, NULL);
	bufferevent_setcb(this->bev, NULL, NULL, NULL, NULL);

	/*
	 * In unthreaded mode, no locking issue: do the rest at once.
	 */
	if (!threads) {
		_ntrip_free(this, orig, 1);
		return;
	}

	joblist_drain(this);

	ntrip_log(this, LOG_EDEBUG, "ntrip_deferred_free %p njobs %d newjobs %d\n", this, this->njobs, this->newjobs);

	P_RWLOCK_WRLOCK(&this->caster->ntrips.lock);
	TAILQ_REMOVE(&this->caster->ntrips.queue, this, nextg);
	P_RWLOCK_UNLOCK(&this->caster->ntrips.lock);

	P_RWLOCK_WRLOCK(&this->caster->ntrips.free_lock);
	TAILQ_INSERT_TAIL(&this->caster->ntrips.free_queue, this, nextf);
	P_RWLOCK_UNLOCK(&this->caster->ntrips.free_lock);
}

void ntrip_deferred_run(struct caster_state *this, char *orig) {
	int n = 0;
	struct ntrip_state *st;
	P_RWLOCK_WRLOCK(&this->ntrips.free_lock);

	while ((st = TAILQ_FIRST(&this->ntrips.free_queue))) {
		TAILQ_REMOVE_HEAD(&this->ntrips.free_queue, nextf);
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
			ntrip_log(st, LOG_DEBUG, "ntrip_deferred_run %p njobs %d newjobs %d, deferring more\n", st, st->njobs, st->newjobs);
			TAILQ_INSERT_TAIL(&this->ntrips.free_queue, st, nextf);
			bufferevent_unlock(bev);
			/* Exit the loop to avoid an infinite loop */
			break;
		}

		assert(st->newjobs != -1);
		ntrip_log(st, LOG_EDEBUG, "ntrip_deferred_run %p njobs %d newjobs %d\n", st, st->njobs, st->newjobs);

		assert(st->njobs == 0);

		struct subscriber *sub = st->subscription;
		if (sub) {
			/*
			 * Done here instead of _ntrip_free() to avoid lock ordering problems.
			 */
			bufferevent_unlock(bev);
			livesource_del_subscriber(sub, st);
			bufferevent_lock(bev);
		}

		_ntrip_free(st, "ntrip_deferred_run", 0);
		bufferevent_unlock(bev);

		P_RWLOCK_WRLOCK(&this->ntrips.free_lock);
		n++;
	}
	P_RWLOCK_UNLOCK(&this->ntrips.free_lock);
	if (n)
		logfmt(&this->flog, "ntrip_deferred_run did %d ntrip_free\n", n);
}

static json_object *ntrip_json(struct ntrip_state *st, int lock) {
        bufferevent_lock(st->bev);

	char *ipstr = st->remote_addr;
	json_object *jsonip;
	unsigned port = sockaddr_port(&st->peeraddr.generic);
	jsonip = ipstr[0] ? json_object_new_string(ipstr) : json_object_new_null();
	json_object *new_obj = json_object_new_object();
	json_object *jsonid = json_object_new_int(st->id);
	json_object *jsonport = json_object_new_int(port);
	json_object_object_add(new_obj, "id", jsonid);
	json_object_object_add(new_obj, "ip", jsonip);
	json_object_object_add(new_obj, "port", jsonport);
	json_object_object_add(new_obj, "type", json_object_new_string(st->type));
	if (!strcmp(st->type, "source") || !strcmp(st->type, "source_fetcher"))
		json_object_object_add(new_obj, "mountpoint", json_object_new_string(st->mountpoint));
	else if (!strcmp(st->type, "client"))
		json_object_object_add(new_obj, "mountpoint", json_object_new_string(st->http_args[1]+1));

	if (st->user_agent)
		json_object_object_add(new_obj, "user-agent", json_object_new_string(st->user_agent));

	struct tm date;
	gmtime_r(&st->start, &date);
	char iso_date[22];
	strftime(iso_date, sizeof iso_date, "%Y-%m-%dT%H:%M:%SZ", &date);
	json_object_object_add(new_obj, "start", json_object_new_string(iso_date));

        bufferevent_unlock(st->bev);
	return new_obj;
}

/*
 * Return a list of ntrip_state as a JSON object.
 */
const char *ntrip_list_json(struct caster_state *caster, struct ntrip_state *st) {
	const char *s;
	json_object *new_list = json_object_new_object();
	struct ntrip_state *sst;
	P_RWLOCK_RDLOCK(&caster->ntrips.lock);
	TAILQ_FOREACH(sst, &caster->ntrips.queue, nextg) {
		char idstr[40];
		/*
		 * Don't require a lock from ntrip_json on the current connection
		 */
		json_object *nj = ntrip_json(sst, st != sst);
		snprintf(idstr, sizeof idstr, "%d", sst->id);
		json_object_object_add(new_list, idstr, nj);
	}
	P_RWLOCK_UNLOCK(&caster->ntrips.lock);
	s = mystrdup(json_object_to_json_string(new_list));
	json_object_put(new_list);
	return s;
}

struct livesource *ntrip_add_livesource(struct ntrip_state *this, char *mountpoint, pos_t *mountpoint_pos, int on_demand) {
	struct livesource *existing_livesource;
	enum livesource_state existing_state;

	P_RWLOCK_WRLOCK(&this->caster->livesources.lock);
	existing_livesource = livesource_find_unlocked(this->caster, this, mountpoint, mountpoint_pos, on_demand, &existing_state);
	if (existing_livesource) {
		P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
		if (on_demand && existing_state == LIVESOURCE_FETCH_PENDING) {
			ntrip_log(this, LOG_INFO, "%p livesource %s PENDING -> RUNNING\n", this, mountpoint);
			P_RWLOCK_WRLOCK(&existing_livesource->lock);
			existing_livesource->state = LIVESOURCE_RUNNING;
			P_RWLOCK_UNLOCK(&existing_livesource->lock);
			this->registered = 1;
		} else if (existing_state == LIVESOURCE_RUNNING)
			ntrip_log(this, LOG_INFO, "%p livesource %s already RUNNING\n", this, mountpoint);
		else
			existing_livesource = NULL;
		return existing_livesource;
	}
	struct livesource *np = livesource_new(mountpoint, LIVESOURCE_RUNNING);
	if (np == NULL) {
		P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
		return NULL;
	}
	TAILQ_INSERT_TAIL(&this->caster->livesources.queue, np, next);
	this->registered = 1;
	P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
	ntrip_log(this, LOG_INFO, "%p livesource %s created RUNNING\n", this, mountpoint);
	return np;
}

void ntrip_unregister_livesource(struct ntrip_state *this, char *mountpoint) {
	ntrip_log(this, LOG_INFO, "Unregister livesource %s\n", mountpoint);
	struct livesource *l = livesource_find(this->caster, this, mountpoint, NULL);
	if (l)
		caster_del_livesource(this->caster, l);
}

char *ntrip_peer_ipstr(struct ntrip_state *this) {
	char *r;
	char inetaddr[64];
	r = sockaddr_ipstr(&this->peeraddr.generic, inetaddr, sizeof inetaddr);
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
_ntrip_log(struct log *log, struct ntrip_state *this, const char *fmt, va_list ap) {
	char date[36];
	logdate(date, sizeof date);

	P_RWLOCK_WRLOCK(&log->lock);
	fputs(date, log->logfile);

	if (this->remote) {
		unsigned port = ntrip_peer_port(this);
		struct sockaddr *sa = &this->peeraddr.generic;
		switch(sa->sa_family) {
		case AF_INET:
			fprintf(log->logfile, "%s:%hu ", this->remote_addr, port);
			break;
		case AF_INET6:
			fprintf(log->logfile, "%s.%hu ", this->remote_addr, port);
			break;
		default:
			fprintf(log->logfile, "[???] ");
		}
	}

	if (threads)
		fprintf(log->logfile, "[%lu] ", (long)pthread_getspecific(this->caster->thread_id));

	vfprintf(log->logfile, fmt, ap);
	P_RWLOCK_UNLOCK(&log->lock);
}

void ntrip_alog(void *arg, const char *fmt, ...) {
	struct ntrip_state *this = (struct ntrip_state *)arg;
	va_list ap;
	va_start(ap, fmt);
	_ntrip_log(&this->caster->alog, this, fmt, ap);
	va_end(ap);
}

void ntrip_log(void *arg, int level, const char *fmt, ...) {
	struct ntrip_state *this = (struct ntrip_state *)arg;
	if (level > this->caster->config->log_level)
		return;
	va_list ap;
	va_start(ap, fmt);
	_ntrip_log(&this->caster->flog, this, fmt, ap);
	va_end(ap);
}

int ntrip_handle_raw(struct ntrip_state *st, struct bufferevent *bev) {
	struct evbuffer *input = bufferevent_get_input(bev);

	if (st->chunk_state != CHUNK_NONE)
		return ntrip_handle_raw_chunk(st, bev);

	while (1) {

		unsigned long len_raw = evbuffer_get_length(input);
		if (len_raw < st->caster->config->min_raw_packet)
			return 0;
		if (len_raw > st->caster->config->max_raw_packet)
			len_raw = st->caster->config->max_raw_packet;
		struct packet *rawp = packet_new(len_raw, st->caster);
		if (rawp == NULL) {
			evbuffer_drain(input, len_raw);
			ntrip_log(st, LOG_CRIT, "Raw: Not enough memory, dropping %d bytes\n", len_raw);
			return 1;
		}
		evbuffer_remove(input, &rawp->data[0], len_raw);
		//ntrip_log(st, LOG_DEBUG, "Raw: packet source %s size %d\n", st->mountpoint, len_raw);
		if (livesource_send_subscribers(st->own_livesource, rawp, st->caster))
			st->last_send = time(NULL);
		packet_free(rawp);
		return 1;
	}
}

/*
 * Extract raw data in HTTP chunks
 */
int ntrip_handle_raw_chunk(struct ntrip_state *st, struct bufferevent *bev) {
	size_t len;
	size_t chunk_len;
	struct evbuffer *input = bufferevent_get_input(bev);
	unsigned long len_raw;

	while (1) {
		if (st->chunk_state == CHUNK_WAIT_LEN) {
			char *line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF_STRICT);
			if (line == NULL)
				return 0;

			char *p = line;
			while (*p && *p != ';' && *p != '\n' && *p != '\r') p++;
			*p = '\0';

			if (sscanf(line, "%zx", &chunk_len) == 1) {
				// ntrip_log(st, LOG_DEBUG, "ok chunk_len: \"%s\" (%zu)\n", line, chunk_len);
			} else {
				ntrip_log(st, LOG_INFO, "failed chunk_len: \"%s\"\n", line);
				return 0;
			}
			st->chunk_state = CHUNK_IN_PROGRESS;
			st->chunk_len = chunk_len;
		} else if (st->chunk_state == CHUNK_IN_PROGRESS) {
			len_raw = evbuffer_get_length(input);
			if (len_raw <= 0)
				return 0;
			if (len_raw <= st->chunk_len) {
				evbuffer_add_buffer(st->chunk_buf, input);
				st->chunk_len -= len_raw;
			} else {
				len_raw = st->chunk_len;
				unsigned char *data = evbuffer_pullup(input, len_raw);
				evbuffer_add(st->chunk_buf, data, len_raw);
				evbuffer_drain(input, len_raw);
				st->chunk_len = 0;
			}
			if (st->chunk_len == 0)
				st->chunk_state = CHUNK_WAITING_TRAILER;

			len_raw = evbuffer_get_length(st->chunk_buf);
			struct packet *packet = packet_new(len_raw, st->caster);
			if (packet == NULL) {
				ntrip_log(st, LOG_CRIT, "Not enough memory, dropping packet\n");
				return 1;
			}
			evbuffer_remove(st->chunk_buf, &packet->data[0], len_raw);
			if (livesource_send_subscribers(st->own_livesource, packet, st->caster))
				st->last_send = time(NULL);
			packet_free(packet);
			return 1;
		} else if (st->chunk_state == CHUNK_WAITING_TRAILER) {
			char data[2];
			long len_raw = evbuffer_get_length(input);
			if (len_raw < 2)
				return 0;
			// skip trailing CR LF
			evbuffer_remove(input, data, 2);
			if (data[0] != '\r' || data[1] != '\n')
				ntrip_log(st, LOG_INFO, "Wrong chunk trailer\n");
			st->chunk_state = CHUNK_WAIT_LEN;
		}
	}
}

/*
 * Handle receipt and retransmission of 1 RTCM packet.
 * Return 0 if more data is needed.
 */
static int ntrip_handle_rtcm(struct ntrip_state *st, struct bufferevent *bev) {
	unsigned short len_rtcm;
	struct evbuffer_ptr p;
	struct evbuffer *input = bufferevent_get_input(bev);
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
			ntrip_log(st, LOG_INFO, "RTCM: draining %zd bytes: \"%s\"\n", len, drain);
			free(drain);
		} else
#endif
		{
			ntrip_log(st, LOG_INFO, "draining %zd bytes\n", len);
			evbuffer_drain(input, len);
		}
		return 0;
	}
	if (p.pos > 0) {
		ntrip_log(st, LOG_DEBUG, "RTCM: found packet start, draining %zd bytes\n", p.pos);
		evbuffer_drain(input, p.pos);
	}

	unsigned char *mem = evbuffer_pullup(input, 3);
	if (mem == NULL) {
		ntrip_log(st, LOG_DEBUG, "RTCM: not enough data, waiting\n");
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
		ntrip_log(st, LOG_CRIT, "RTCM: Not enough memory, dropping packet\n");
		return 1;
	}

	evbuffer_remove(input, &rtcmp->data[0], len_rtcm);
	unsigned long crc = crc24q_hash(&rtcmp->data[0], len_rtcm-3);
	if (crc == (rtcmp->data[len_rtcm-3]<<16)+(rtcmp->data[len_rtcm-2]<<8)+rtcmp->data[len_rtcm-1]) {
		unsigned short type = rtcmp->data[3]*16 + rtcmp->data[4]/16;
		ntrip_log(st, LOG_DEBUG, "RTCM source %s size %d type %d\n", st->mountpoint, len_rtcm, type);
	} else {
		ntrip_log(st, LOG_INFO, "RTCM: bad checksum! %08lx %08x\n", crc, (rtcmp->data[len_rtcm-3]<<16)+(rtcmp->data[len_rtcm-2]<<8)+rtcmp->data[len_rtcm-1]);
	}

	if (livesource_send_subscribers(st->own_livesource, rtcmp, st->caster))
		st->last_send = time(NULL);
	packet_free(rtcmp);
	return 1;
}
