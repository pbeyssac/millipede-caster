#ifndef __LOG_STREAM_H__
#define __LOG_STREAM_H__

#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"

/*
 * Real-time log streaming via Server-Sent Events (SSE).
 *
 * Architecture:
 *  - A circular buffer holds the last LOG_STREAM_BUFFER_SIZE log entries.
 *  - Each entry has a monotonically increasing sequence number (seq).
 *  - SSE subscribers register their bufferevent + last_seq sent.
 *  - A periodic timer (1 Hz) pushes new entries to each subscriber.
 *  - Subscribers whose bufferevent has errored/closed are removed.
 *
 * Threading:
 *  - The subscriber list and the circular buffer are protected by a mutex.
 *  - log_stream_publish() is called from vlogall() (any thread).
 *  - log_stream_timer() runs on a libevent timer (single thread).
 *  - log_stream_subscribe()/unsubscribe() can be called from any thread.
 *
 * Per-subscriber cleanup: each ntrip_state that subscribes stores the
 * subscriber pointer in `st->log_stream_sub`. ntrip_free() calls
 * log_stream_unsubscribe() to clean up.
 */

#define LOG_STREAM_BUFFER_SIZE   500    /* keep the last 500 log entries */

/*
 * One log entry in the circular buffer.
 */
struct log_stream_entry {
        struct timeval ts;
        int level;             /* LOG_* (syslog severity) */
        int thread_id;
        char *hostname;
        char *message;         /* formatted message, no trailing newline */
};

/*
 * One SSE subscriber.
 */
struct log_stream_sub {
        struct bufferevent *bev;
        unsigned long last_seq;        /* seq of the last entry sent */
};

/*
 * Top-level log stream state.
 */
struct log_stream {
        P_MUTEX_T lock;
        struct log_stream_entry buffer[LOG_STREAM_BUFFER_SIZE];
        int buffer_head;               /* index of next slot to write */
        _Atomic unsigned long next_seq; /* next sequence number to assign */

        /* Subscribers (linked list) */
        struct log_stream_sub **subs;
        int subs_count;
        int subs_capacity;
};

struct log_stream *log_stream_new(void);
void log_stream_free(struct log_stream *this);

/*
 * Publish a new log entry to the stream.
 * Safe to call from any thread.
 * `msg` is the formatted message (no trailing newline); the caller
 * retains ownership. `hostname` and `thread_id` come from the gelf_entry.
 */
void log_stream_publish(struct log_stream *this,
                        struct timeval *ts, int level,
                        const char *hostname, int thread_id,
                        const char *msg);

/*
 * Subscribe a bufferevent to the stream.
 * Returns a non-NULL opaque handle on success, NULL on failure.
 * The handle is owned by the caller and must be passed to
 * log_stream_unsubscribe() when the connection closes (typically
 * from ntrip_free()).
 *
 * On subscribe, the last LOG_STREAM_BUFFER_SIZE entries (or fewer)
 * are NOT immediately sent — they will be sent on the next timer tick.
 */
void *log_stream_subscribe(struct log_stream *this, struct bufferevent *bev);

/*
 * Unsubscribe a previously-registered subscriber.
 * Safe to call with a NULL handle (no-op).
 */
void log_stream_unsubscribe(struct log_stream *this, void *handle);

/*
 * Periodic timer callback. Sends any new log entries to each subscriber
 * and removes dead subscribers. Must be called from a libevent event
 * loop thread.
 */
void log_stream_timer(int fd, short event, void *arg);

#endif /* __LOG_STREAM_H__ */
