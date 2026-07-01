#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "log_stream.h"
#include "util.h"

/*
 * Log stream implementation.
 *
 * See log_stream.h for the design overview.
 */

#define LOG_STREAM_INITIAL_SUBS_CAPACITY  8

struct log_stream *log_stream_new(void) {
        struct log_stream *this = (struct log_stream *)calloc(1, sizeof(*this));
        if (this == NULL)
                return NULL;
        P_MUTEX_INIT(&this->lock, NULL);
        this->subs = (struct log_stream_sub **)calloc(
                LOG_STREAM_INITIAL_SUBS_CAPACITY, sizeof(*this->subs));
        if (this->subs == NULL) {
                P_MUTEX_DESTROY(&this->lock);
                free(this);
                return NULL;
        }
        this->subs_capacity = LOG_STREAM_INITIAL_SUBS_CAPACITY;
        this->subs_count = 0;
        atomic_store(&this->next_seq, 1);
        return this;
}

static void log_stream_entry_free(struct log_stream_entry *e) {
        if (e->hostname) {
                strfree(e->hostname);
                e->hostname = NULL;
        }
        if (e->message) {
                strfree(e->message);
                e->message = NULL;
        }
}

void log_stream_free(struct log_stream *this) {
        if (this == NULL)
                return;
        P_MUTEX_LOCK(&this->lock);
        for (int i = 0; i < LOG_STREAM_BUFFER_SIZE; i++)
                log_stream_entry_free(&this->buffer[i]);
        for (int i = 0; i < this->subs_count; i++) {
                if (this->subs[i])
                        free(this->subs[i]);
        }
        free(this->subs);
        P_MUTEX_UNLOCK(&this->lock);
        P_MUTEX_DESTROY(&this->lock);
        free(this);
}

/*
 * Helper: escape a string for inclusion in a JSON string literal.
 * Returns a newly allocated string (caller frees), or NULL on OOM.
 */
static char *json_escape(const char *s) {
        if (s == NULL)
                s = "";
        size_t cap = strlen(s) * 6 + 1;
        char *out = (char *)malloc(cap);
        if (out == NULL)
                return NULL;
        char *p = out;
        for (; *s; s++) {
                unsigned char c = (unsigned char)*s;
                if (c == '\\' || c == '"') { *p++ = '\\'; *p++ = c; }
                else if (c == '\n') { *p++ = '\\'; *p++ = 'n'; }
                else if (c == '\r') { *p++ = '\\'; *p++ = 'r'; }
                else if (c == '\t') { *p++ = '\\'; *p++ = 't'; }
                else if (c < 0x20) {
                        snprintf(p, 7, "\\u%04x", c);
                        p += 6;
                } else
                        *p++ = c;
        }
        *p = '\0';
        return out;
}

static const char *level_name(int level) {
        switch (level) {
                case 0: return "EMERG";
                case 1: return "ALERT";
                case 2: return "CRIT";
                case 3: return "ERR";
                case 4: return "WARNING";
                case 5: return "NOTICE";
                case 6: return "INFO";
                case 7: return "DEBUG";
                case 8: return "EDEBUG";
                default: return "UNKNOWN";
        }
}

/*
 * Format a log entry as an SSE event.
 * Returns a newly allocated string (caller frees), or NULL on OOM.
 *
 * The SSE format is:
 *   event: log
 *   data: {"ts":"2024-01-01T00:00:00Z","level":"INFO","level_num":6,"thread_id":0,"hostname":"caster1","message":"..."}
 *   <blank line>
 */
static char *log_stream_format_sse(struct log_stream_entry *e, unsigned long seq) {
        char ts[32];
        time_t t = e->ts.tv_sec;
        struct tm tm;
        gmtime_r(&t, &tm);
        strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm);

        char *esc_host = json_escape(e->hostname);
        char *esc_msg = json_escape(e->message);
        if (esc_host == NULL || esc_msg == NULL) {
                free(esc_host); free(esc_msg);
                return NULL;
        }

        /* Worst case: ts(20) + level(7) + ints(~12 each) + escaped strings + fixed overhead */
        size_t cap = strlen(esc_host) + strlen(esc_msg) + 256;
        char *out = (char *)malloc(cap);
        if (out == NULL) {
                free(esc_host); free(esc_msg);
                return NULL;
        }
        snprintf(out, cap,
                "event: log\n"
                "data: {\"seq\":%lu,\"ts\":\"%s\",\"level\":\"%s\",\"level_num\":%d,"
                "\"thread_id\":%d,\"hostname\":\"%s\",\"message\":\"%s\"}\n\n",
                seq, ts, level_name(e->level), e->level,
                e->thread_id, esc_host, esc_msg);
        free(esc_host);
        free(esc_msg);
        return out;
}

void log_stream_publish(struct log_stream *this,
                        struct timeval *ts, int level,
                        const char *hostname, int thread_id,
                        const char *msg) {
        if (this == NULL)
                return;
        /* Don't store EDEBUG by default — it would flood the buffer.
         * Future: make this configurable. */
        if (level > LOG_DEBUG)
                return;

        P_MUTEX_LOCK(&this->lock);

        /* Free the entry currently at buffer_head, then write the new entry. */
        struct log_stream_entry *e = &this->buffer[this->buffer_head];
        log_stream_entry_free(e);

        e->ts = *ts;
        e->level = level;
        e->thread_id = thread_id;
        e->hostname = mystrdup(hostname ? hostname : "");
        e->message = mystrdup(msg ? msg : "");
        if (e->hostname == NULL || e->message == NULL) {
                /* OOM: clear the slot */
                log_stream_entry_free(e);
                P_MUTEX_UNLOCK(&this->lock);
                return;
        }
        this->buffer_head = (this->buffer_head + 1) % LOG_STREAM_BUFFER_SIZE;
        unsigned long seq = atomic_fetch_add(&this->next_seq, 1);

        P_MUTEX_UNLOCK(&this->lock);
        /* Note: seq is not stored in the entry itself; the timer computes
         * it by walking the buffer from the oldest entry. We use next_seq
         * only as a monotonic counter for "have we sent this entry yet?"
         * comparisons. The actual mapping from buffer slot to seq is done
         * by the timer. */
        (void)seq;
}

void *log_stream_subscribe(struct log_stream *this, struct bufferevent *bev) {
        if (this == NULL || bev == NULL)
                return NULL;
        struct log_stream_sub *sub = (struct log_stream_sub *)calloc(1, sizeof(*sub));
        if (sub == NULL)
                return NULL;
        sub->bev = bev;
        /* Set last_seq to the current next_seq so the subscriber doesn't
         * get the entire buffer on connect (the buffer is for catch-up
         * after a brief disconnect, not for initial history). Set to
         * (next_seq - LOG_STREAM_BUFFER_SIZE) to send the recent history. */
        unsigned long next = atomic_load(&this->next_seq);
        sub->last_seq = (next > LOG_STREAM_BUFFER_SIZE) ? next - LOG_STREAM_BUFFER_SIZE : 0;

        P_MUTEX_LOCK(&this->lock);
        if (this->subs_count == this->subs_capacity) {
                int new_cap = this->subs_capacity * 2;
                struct log_stream_sub **new_subs = (struct log_stream_sub **)realloc(
                        this->subs, new_cap * sizeof(*new_subs));
                if (new_subs == NULL) {
                        P_MUTEX_UNLOCK(&this->lock);
                        free(sub);
                        return NULL;
                }
                this->subs = new_subs;
                this->subs_capacity = new_cap;
        }
        this->subs[this->subs_count++] = sub;
        P_MUTEX_UNLOCK(&this->lock);
        return sub;
}

void log_stream_unsubscribe(struct log_stream *this, void *handle) {
        if (this == NULL || handle == NULL)
                return;
        P_MUTEX_LOCK(&this->lock);
        for (int i = 0; i < this->subs_count; i++) {
                if (this->subs[i] == handle) {
                        /* Swap with last and shrink */
                        this->subs[i] = this->subs[this->subs_count - 1];
                        this->subs[this->subs_count - 1] = NULL;
                        this->subs_count--;
                        free(handle);
                        break;
                }
        }
        P_MUTEX_UNLOCK(&this->lock);
}

/*
 * Walk the circular buffer in order from oldest to newest and call
 * `cb` for each entry. Stop when `cb` returns non-zero.
 * `cb` is called with the entry pointer and its sequence number.
 * Caller holds the log_stream lock.
 */
static void log_stream_walk(struct log_stream *this,
        int (*cb)(struct log_stream_entry *, unsigned long, void *),
        void *cb_arg) {

        unsigned long next = atomic_load(&this->next_seq);
        /* The buffer holds entries [next - count, next) where count is
         * the number of entries currently stored (up to LOG_STREAM_BUFFER_SIZE). */
        unsigned long count = (next > LOG_STREAM_BUFFER_SIZE) ? LOG_STREAM_BUFFER_SIZE : next;
        if (count == 0)
                return;
        unsigned long start_seq = next - count;
        for (unsigned long i = 0; i < count; i++) {
                int idx = (this->buffer_head - count + i + LOG_STREAM_BUFFER_SIZE) % LOG_STREAM_BUFFER_SIZE;
                unsigned long seq = start_seq + i;
                if (cb(&this->buffer[idx], seq, cb_arg))
                        break;
        }
}

/*
 * Per-subscriber callback: if the entry's seq > sub->last_seq,
 * format it as SSE and append to the bev's output buffer.
 * Returns 0 to continue iteration, 1 to stop (on error).
 */
struct send_ctx {
        struct log_stream_sub *sub;
        int error;
};

static int send_cb(struct log_stream_entry *e, unsigned long seq, void *arg) {
        struct send_ctx *ctx = (struct send_ctx *)arg;
        if (ctx->error)
                return 1;
        if (seq <= ctx->sub->last_seq)
                return 0;
        char *sse = log_stream_format_sse(e, seq);
        if (sse == NULL) {
                ctx->error = 1;
                return 1;
        }
        struct evbuffer *out = bufferevent_get_output(ctx->sub->bev);
        if (evbuffer_add(out, sse, strlen(sse)) != 0) {
                free(sse);
                ctx->error = 1;
                return 1;
        }
        free(sse);
        ctx->sub->last_seq = seq;
        return 0;
}

void log_stream_timer(int fd, short event, void *arg) {
        struct log_stream *this = (struct log_stream *)arg;
        if (this == NULL)
                return;
        P_MUTEX_LOCK(&this->lock);

        /* For each subscriber, walk the buffer and send new entries. */
        for (int i = 0; i < this->subs_count; ) {
                struct log_stream_sub *sub = this->subs[i];
                struct send_ctx ctx = { .sub = sub, .error = 0 };
                log_stream_walk(this, send_cb, &ctx);
                if (ctx.error) {
                        /* Subscriber is dead: remove by swap-with-last. */
                        this->subs[i] = this->subs[this->subs_count - 1];
                        this->subs[this->subs_count - 1] = NULL;
                        this->subs_count--;
                        free(sub);
                        /* Don't increment i: re-check the new entry at this slot. */
                } else {
                        i++;
                }
        }
        P_MUTEX_UNLOCK(&this->lock);
}
