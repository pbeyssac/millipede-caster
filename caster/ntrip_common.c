#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "conf.h"
#include "caster.h"
#include "log.h"
#include "livesource.h"
#include "ntrip_common.h"

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
		free(this);
		return NULL;
	}

	P_RWLOCK_INIT(&this->lock, NULL);
	this->caster = caster;
	this->state = NTRIP_WAIT_HTTP_STATUS;
	this->chunk_state = CHUNK_NONE;
	this->chunk_buf = NULL;
	this->host = host;
	this->port = port;
	this->refcnt = 1;
	this->last_send = time(NULL);
	this->subscription = NULL;
	this->server_version = 1;
	this->client_version = 1;
	this->callback_subscribe = NULL;
	this->max_min_dist = 0;
	this->user = NULL;
	this->password = NULL;
#ifdef THREADS
	STAILQ_INIT(&this->jobq);
#endif
	return this;
}

/*
 * Free a ntrip_state record.
 *
 * Required lock: ntrip_state
 */
void ntrip_free(struct ntrip_state *this, char *orig) {
	ntrip_log(this, LOG_DEBUG, "FREE %p %s\n", this, orig);

	if (!this->bev_freed) {
		ntrip_log(this, LOG_EDEBUG, "force-freeing bev %p for %p\n", this->bev, this);
		my_bufferevent_free(this, this->bev);
	}
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

	if (this->chunk_buf)
		evbuffer_free(this->chunk_buf);

	if (this->subscription)
		livesource_del_subscriber(this->subscription, this->caster);

	if (this->tmp_sourcetable)
		sourcetable_free(this->tmp_sourcetable);

	P_RWLOCK_DESTROY(&this->lock);
	free(this);
}

struct livesource *ntrip_add_livesource(struct ntrip_state *this, char *mountpoint) {
	ntrip_log(this, LOG_INFO, "Registering livesource %s\n", mountpoint);

	P_RWLOCK_WRLOCK(&this->caster->livesources.lock);
	if (livesource_find_unlocked(this->caster, mountpoint)) {
		P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
		return NULL;
	}
	struct livesource *np = livesource_new(mountpoint);
	if (np == NULL) {
		P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
		return NULL;
	}
	TAILQ_INSERT_TAIL(&this->caster->livesources.queue, np, next);
	this->registered = 1;
	P_RWLOCK_UNLOCK(&this->caster->livesources.lock);
	return np;
}

void ntrip_unregister_livesource(struct ntrip_state *this, char *mountpoint) {
	ntrip_log(this, LOG_INFO, "Unregister livesource %s\n", mountpoint);
	struct livesource *l = livesource_find(this->caster, mountpoint);
	if (l)
		caster_del_livesource(this->caster, l);
}

static void
_ntrip_log(struct log *log, struct ntrip_state *this, const char *fmt, va_list ap) {
	char date[36];
	logdate(date, sizeof date);

	P_RWLOCK_WRLOCK(&log->lock);
	fputs(date, log->logfile);

	if (this->remote) {
		char inetaddr[64];
		struct sockaddr *sa = &this->peeraddr.generic;
		switch(sa->sa_family) {
		case AF_INET:
			inet_ntop(sa->sa_family, &this->peeraddr.v4.sin_addr, inetaddr, sizeof inetaddr);
			fprintf(log->logfile, "%s:%hu ", inetaddr, ntohs(this->peeraddr.v4.sin_port));
			break;
		case AF_INET6:
			inet_ntop(sa->sa_family, &this->peeraddr.v6.sin6_addr, inetaddr, sizeof inetaddr);
			fprintf(log->logfile, "%s.%hu ", inetaddr, ntohs(this->peeraddr.v6.sin6_port));
			break;
		default:
			fprintf(log->logfile, "[???] ");
		}
	}
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

	//struct livesource *l = livesource_find(st->caster, st->mountpoint);
	if (livesource_send_subscribers(st->own_livesource, rtcmp, st->caster))
		st->last_send = time(NULL);
	packet_free(rtcmp);
	return 1;
}
