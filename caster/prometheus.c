#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "caster.h"
#include "hash.h"
#include "livesource.h"
#include "ntrip_common.h"
#include "prometheus.h"
#include "rtcm_freq.h"
#include "util.h"

/*
 * Prometheus text exposition format exporter.
 *
 * See: https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md
 *
 * We deliberately avoid any external Prometheus C library: the format is
 * simple enough to hand-roll, and the only thing we need is a snapshot of
 * the caster's internal counters/gauges at scrape time.
 *
 * Threading: the handler runs on a libevent worker thread (via
 * joblist_append_ntrip_unlocked_content -> ntripsrv_deferred_output).
 * It takes the appropriate locks (ntrips.lock, livesources->lock,
 * log_stream->lock, rtcm_freq->lock) while walking each structure.
 *
 * Output: a single heap-allocated string, returned as a mime_content
 * with mime type "text/plain; version=0.0.4; charset=utf-8".
 */

/*
 * Growable buffer used to assemble the metrics output.
 */
struct mbuf {
	char *data;
	size_t len;
	size_t cap;
};

static int mbuf_init(struct mbuf *b, size_t cap) {
	b->data = (char *)malloc(cap);
	if (b->data == NULL) {
		b->len = b->cap = 0;
		return -1;
	}
	b->len = 0;
	b->cap = cap;
	return 0;
}

static int mbuf_ensure(struct mbuf *b, size_t extra) {
	if (b->len + extra + 1 <= b->cap)
		return 0;
	size_t new_cap = b->cap;
	while (new_cap < b->len + extra + 1)
		new_cap *= 2;
	char *nd = (char *)realloc(b->data, new_cap);
	if (nd == NULL)
		return -1;
	b->data = nd;
	b->cap = new_cap;
	return 0;
}

static int mbuf_append(struct mbuf *b, const char *s, size_t n) {
	if (mbuf_ensure(b, n) < 0)
		return -1;
	memcpy(b->data + b->len, s, n);
	b->len += n;
	b->data[b->len] = '\0';
	return 0;
}

static int mbuf_printf(struct mbuf *b, const char *fmt, ...) {
	char stack[256];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(stack, sizeof stack, fmt, ap);
	va_end(ap);
	if (n < 0)
		return -1;
	if ((size_t)n < sizeof stack)
		return mbuf_append(b, stack, (size_t)n);

	/* Didn't fit in stack — retry with a heap buffer. */
	char *heap = (char *)malloc((size_t)n + 1);
	if (heap == NULL)
		return -1;
	va_start(ap, fmt);
	int n2 = vsnprintf(heap, (size_t)n + 1, fmt, ap);
	va_end(ap);
	if (n2 < 0) {
		free(heap);
		return -1;
	}
	int r = mbuf_append(b, heap, (size_t)n2);
	free(heap);
	return r;
}

/*
 * Escape a label value for Prometheus: backslash, double-quote, newline.
 * Returns a newly allocated string (caller frees).
 */
static char *prom_escape_label(const char *s) {
	if (s == NULL)
		s = "";
	size_t cap = strlen(s) * 2 + 1;
	char *out = (char *)malloc(cap);
	if (out == NULL)
		return NULL;
	char *p = out;
	for (; *s; s++) {
		if (*s == '\\' || *s == '"' || *s == '\n') {
			*p++ = '\\';
			if (*s == '\n')
				*p++ = 'n';
			else
				*p++ = *s;
		} else
			*p++ = *s;
	}
	*p = '\0';
	return out;
}

static int prom_metric_header(struct mbuf *b, const char *name,
			      const char *help, const char *type) {
	if (help && *help && mbuf_printf(b, "# HELP %s %s\n", name, help) < 0)
		return -1;
	if (mbuf_printf(b, "# TYPE %s %s\n", name, type) < 0)
		return -1;
	return 0;
}

static int prom_labeled(struct mbuf *b, const char *name,
			const char *label_name, const char *label_value,
			double value) {
	char *esc = prom_escape_label(label_value);
	if (esc == NULL)
		return -1;
	int r = mbuf_printf(b, "%s{%s=\"%s\"} %.6f\n",
			    name, label_name, esc, value);
	free(esc);
	return r;
}

static int prom_unlabeled(struct mbuf *b, const char *name, double value) {
	return mbuf_printf(b, "%s %.6f\n", name, value);
}

/*
 * Walk the rtcm_freq tracker's per-mountpoint entries and emit:
 *   millipede_rtcm_packets_total{mountpoint,type} <total_count>
 *   millipede_rtcm_rate_hz{mountpoint,type} <rate>
 * for each active type slot.
 */
static void prom_emit_rtcm_metrics(struct mbuf *b, struct caster_state *caster, time_t now_sec) {
	if (caster->rtcm_freq == NULL || caster->rtcm_freq->table == NULL)
		return;

	struct hash_iterator hi;
	struct element *e;
	P_RWLOCK_RDLOCK(&caster->rtcm_freq->lock);
	HASH_FOREACH(e, caster->rtcm_freq->table, hi) {
		struct rtcm_freq_mountpoint *m = (struct rtcm_freq_mountpoint *)e->value;
		if (m == NULL)
			continue;
		P_MUTEX_LOCK(&m->lock);
		for (int slot = 0; slot < RTCM_FREQ_TOTAL_SLOTS; slot++) {
			struct rtcm_freq_per_type *t = &m->types[slot];
			if (t->total_count == 0)
				continue;
			unsigned short type = rtcm_freq_type(slot);
			double rate = rtcm_freq_rate(t, now_sec);
			char *esc_mp = prom_escape_label(e->key);
			char type_str[8];
			snprintf(type_str, sizeof type_str, "%u", type);
			char *esc_type = prom_escape_label(type_str);
			if (esc_mp && esc_type) {
				mbuf_printf(b,
				    "millipede_rtcm_packets_total{mountpoint=\"%s\",type=\"%s\"} %llu\n",
				    esc_mp, esc_type, (unsigned long long)t->total_count);
				mbuf_printf(b,
				    "millipede_rtcm_rate_hz{mountpoint=\"%s\",type=\"%s\"} %.6f\n",
				    esc_mp, esc_type, rate);
			}
			free(esc_mp);
			free(esc_type);
		}
		P_MUTEX_UNLOCK(&m->lock);
	}
	P_RWLOCK_UNLOCK(&caster->rtcm_freq->lock);
}

struct mime_content *prometheus_metrics_text(struct caster_state *caster, struct request *req) {
	(void)req;  /* reserved for future use (e.g. content negotiation) */
	struct mbuf b;
	if (mbuf_init(&b, 8192) < 0) {
		char *s = mystrdup("");
		return mime_new(s, -1, "text/plain; version=0.0.4; charset=utf-8", 1);
	}

	/* uptime_seconds */
	struct timeval now;
	gettimeofday(&now, NULL);
	double uptime = (double)(now.tv_sec - caster->start_date.tv_sec)
		      + (double)(now.tv_usec - caster->start_date.tv_usec) / 1e6;
	prom_metric_header(&b, "millipede_uptime_seconds",
		"Seconds since the caster process started.", "gauge");
	prom_unlabeled(&b, "millipede_uptime_seconds", uptime);

	/* Walk the ntrips queue to count connections and sum bytes. */
	unsigned long long recv_total = 0, sent_total = 0;
	int n_source = 0, n_client = 0, n_other = 0;
	struct ntrip_state *st;
	P_RWLOCK_RDLOCK(&caster->ntrips.lock);
	TAILQ_FOREACH(st, &caster->ntrips.queue, nextg) {
		recv_total += st->received_bytes;
		sent_total += st->sent_bytes;
		if (st->type) {
			if (!strcmp(st->type, "source") || !strcmp(st->type, "source_fetcher"))
				n_source++;
			else if (!strcmp(st->type, "client"))
				n_client++;
			else
				n_other++;
		} else
			n_other++;
	}
	P_RWLOCK_UNLOCK(&caster->ntrips.lock);

	prom_metric_header(&b, "millipede_connections_total",
		"Number of currently active connections by type.", "gauge");
	prom_labeled(&b, "millipede_connections_total", "type", "source", (double)n_source);
	prom_labeled(&b, "millipede_connections_total", "type", "client", (double)n_client);
	if (n_other > 0)
		prom_labeled(&b, "millipede_connections_total", "type", "other", (double)n_other);

	prom_metric_header(&b, "millipede_received_bytes_total",
		"Total bytes received from all connections since process start.", "counter");
	mbuf_printf(&b, "millipede_received_bytes_total %llu\n", recv_total);

	prom_metric_header(&b, "millipede_sent_bytes_total",
		"Total bytes sent to all connections since process start.", "counter");
	mbuf_printf(&b, "millipede_sent_bytes_total %llu\n", sent_total);

	/* Mountpoints: count active livesources. */
	int n_mountpoints = 0;
	if (caster->livesources && caster->livesources->hash) {
		struct hash_iterator hi;
		struct element *e;
		P_RWLOCK_RDLOCK(&caster->livesources->lock);
		HASH_FOREACH(e, caster->livesources->hash, hi) {
			(void)e;
			n_mountpoints++;
		}
		P_RWLOCK_UNLOCK(&caster->livesources->lock);
	}
	prom_metric_header(&b, "millipede_mountpoints",
		"Number of currently active local mountpoints (livesources).", "gauge");
	prom_unlabeled(&b, "millipede_mountpoints", (double)n_mountpoints);

	/* SSE log stream subscriber count. */
	int n_subscribers = 0;
	if (caster->log_stream) {
		P_MUTEX_LOCK(&caster->log_stream->lock);
		n_subscribers = caster->log_stream->subs_count;
		P_MUTEX_UNLOCK(&caster->log_stream->lock);
	}
	prom_metric_header(&b, "millipede_log_stream_subscribers",
		"Number of currently connected SSE log stream subscribers.", "gauge");
	prom_unlabeled(&b, "millipede_log_stream_subscribers", (double)n_subscribers);

	/* Per-mountpoint, per-RTCM-type counters and rates. */
	prom_metric_header(&b, "millipede_rtcm_packets_total",
		"Total RTCM packets received per mountpoint and message type.", "counter");
	prom_metric_header(&b, "millipede_rtcm_rate_hz",
		"Sliding-window (60s) RTCM packet rate per mountpoint and message type, in Hz.", "gauge");
	prom_emit_rtcm_metrics(&b, caster, now.tv_sec);

	/* Final newline for cleanliness. */
	if (b.len == 0)
		mbuf_append(&b, "\n", 1);

	char *s = b.data;
	struct mime_content *m = mime_new(s, -1,
		"text/plain; version=0.0.4; charset=utf-8", 1);
	return m;
}
