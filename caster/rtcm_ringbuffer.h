#ifndef __RTCM_RINGBUFFER_H__
#define __RTCM_RINGBUFFER_H__

#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>

#include <json-c/json_object.h>

#include "conf.h"
#include "hash.h"
#include "packet.h"

/*
 * RTCM Ring Buffer
 *
 * Stores raw RTCM packets per mountpoint in a sliding time window with a
 * per-mountpoint memory cap. Designed to back the future
 *   GET /api/v1/rinex?mountpoint=...&from=...&to=...
 * endpoint: PPK post-processing software can pull a RINEX file generated
 * from the caster's recent RTCM history without the rover having to be
 * online during the survey.
 *
 * Architecture (mirrors rtcm_freq):
 *   - Top-level: hash_table mountpoint -> rtcm_rb_mountpoint
 *   - Per-mountpoint mutex (different mountpoints update concurrently)
 *   - Per-mountpoint dynamic ring buffer (head/tail indices into a
 *     growable array of slots)
 *
 * Eviction policy (checked on every insert):
 *   1. Time-based: drop slots whose timestamp is older than
 *      retention_seconds.
 *   2. Memory-based: drop oldest slots while total_bytes >
 *      max_bytes_per_mountpoint.
 *
 * Memory ownership:
 *   - The ring buffer holds its own reference on each stored packet
 *     (packet_incref on insert, packet_decref on eviction).
 *   - The caller of rtcm_ringbuffer_record() still owns its reference
 *     and must decref it as usual.
 *
 * Threading:
 *   - rtcm_ringbuffer_record() is safe to call from any thread
 *     (typically a libevent worker thread).
 *   - rtcm_ringbuffer_extract_range() takes the per-mountpoint mutex
 *     for the duration of the copy and incref's each returned packet
 *     so the caller can iterate without holding the lock.
 */

/*
 * Default retention window for the RTCM ring buffer (in minutes).
 * Tuned so that a typical PPK survey of <30 min can be reconstructed
 * even if the user notices a problem only after the fact.
 */
#define RTCM_RB_DEFAULT_RETENTION_MIN   30

/*
 * Default per-mountpoint memory cap (in bytes).
 * 64 MiB covers ~30 min of MSM7 observations at 1 Hz for a multi-GNSS
 * base (~3.5 KB per epoch * 1800 epochs = ~6 MB; the headroom absorbs
 * bursts and the 1005/107x/108x/109x housekeeping messages).
 */
#define RTCM_RB_DEFAULT_MAX_BYTES       (64ULL * 1024 * 1024)

/*
 * Initial slot capacity for a freshly-seen mountpoint.
 * Grows by doubling when full, up to RTCM_RB_MAX_SLOTS.
 */
#define RTCM_RB_INITIAL_SLOTS           64
#define RTCM_RB_MAX_SLOTS               65536

/*
 * One slot in the ring buffer.
 * `packet` is NULL for an empty slot (only happens transiently during
 * eviction; the ring is always densely packed from `tail` to `head`).
 */
struct rtcm_rb_slot {
	struct packet *packet;
	struct timeval ts;
	size_t bytes;       /* cached packet->datalen for fast sum */
};

/*
 * Per-mountpoint state.
 */
struct rtcm_rb_mountpoint {
	P_MUTEX_T lock;
	char *mountpoint;

	/* Dynamic ring buffer */
	struct rtcm_rb_slot *slots;
	size_t capacity;        /* allocated slot count */
	size_t head;            /* index of next write position */
	size_t count;           /* number of valid entries in [head-count, head) */
	size_t total_bytes;     /* sum of slot[i].bytes for valid entries */

	/* Stats (since first packet ever for this mountpoint) */
	struct timeval first_seen;
	struct timeval last_seen;
	unsigned long long total_packets;
	unsigned long long evicted_packets;   /* count of evictions (time or memory) */
};

/*
 * Top-level tracker.
 */
struct rtcm_ringbuffer_tracker {
	struct hash_table *table;
	P_RWLOCK_T lock;

	/* Configuration (immutable after tracker_new) */
	time_t retention_seconds;
	size_t max_bytes_per_mountpoint;
};

/*
 * Entry returned by rtcm_ringbuffer_extract_range().
 * Caller owns the array and must:
 *   1. packet_decref() each .packet
 *   2. free() the array itself
 */
struct rtcm_rb_entry {
	struct packet *packet;
	struct timeval ts;
};

/*
 * Lifecycle.
 *
 * retention_minutes: how long to keep each packet (default 30).
 * max_bytes_per_mountpoint: per-mountpoint memory cap (default 64 MiB).
 */
struct rtcm_ringbuffer_tracker *rtcm_ringbuffer_tracker_new(
	int retention_minutes,
	size_t max_bytes_per_mountpoint);
void rtcm_ringbuffer_tracker_free(struct rtcm_ringbuffer_tracker *this);

/*
 * Record one RTCM packet for a mountpoint.
 * Safe to call from any thread. Takes a new reference on `packet`
 * (caller still owns its reference and must decref as usual).
 *
 * If `now` is NULL, gettimeofday() is called internally.
 */
void rtcm_ringbuffer_record(struct rtcm_ringbuffer_tracker *this,
			    const char *mountpoint,
			    struct packet *packet,
			    struct timeval *now);

/*
 * Remove a mountpoint entirely from the tracker.
 * Drops all stored packets (decref each) and frees the per-mountpoint
 * state. Safe to call from any thread. No-op if mountpoint is unknown.
 *
 * Called from livesource_del() so the buffer does not leak when a
 * source disconnects. (Note: rtcm_freq currently does NOT do this and
 * its table grows monotonically — that is a separate bug to fix later.)
 */
void rtcm_ringbuffer_remove(struct rtcm_ringbuffer_tracker *this,
			    const char *mountpoint);

/*
 * Extract all packets whose timestamp falls in [from, to] (inclusive
 * on both ends). If `from` is NULL, extracts from the oldest available
 * packet. If `to` is NULL, extracts up to the newest packet.
 *
 * Returns a heap-allocated array of rtcm_rb_entry (each packet is
 * incref'd) and stores its length in *count_out. Returns NULL if:
 *   - the mountpoint is unknown
 *   - the time range matches no packets
 *   - out of memory
 *
 * The caller must decref each packet and free() the array.
 */
struct rtcm_rb_entry *rtcm_ringbuffer_extract_range(
	struct rtcm_ringbuffer_tracker *this,
	const char *mountpoint,
	const struct timeval *from,
	const struct timeval *to,
	size_t *count_out);

/*
 * Serialize per-mountpoint stats as JSON:
 *   {
 *     "packets": <int>,           // current count in buffer
 *     "bytes": <int>,             // current bytes in buffer
 *     "capacity_slots": <int>,    // allocated slot count
 *     "first_seen": <iso8601>,
 *     "last_seen": <iso8601>,
 *     "total_packets": <int>,     // since first packet ever
 *     "evicted_packets": <int>    // count of evictions
 *   }
 * Returns NULL if the mountpoint is unknown.
 */
json_object *rtcm_ringbuffer_mountpoint_json(
	struct rtcm_ringbuffer_tracker *this,
	const char *mountpoint);

/*
 * Serialize the whole tracker as JSON:
 *   {
 *     "<mountpoint>": { ...per-mountpoint stats... },
 *     ...
 *   }
 */
json_object *rtcm_ringbuffer_tracker_json(
	struct rtcm_ringbuffer_tracker *this);

#endif /* __RTCM_RINGBUFFER_H__ */
