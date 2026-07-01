#ifndef __RTCM_FREQ_H__
#define __RTCM_FREQ_H__

#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>

#include <json-c/json_object.h>

#include "conf.h"
#include "hash.h"
#include "rtcm.h"   /* for RTCM_1K_MIN/MAX, RTCM_4K_MIN/MAX */

/*
 * RTCM Frequency Tracker
 *
 * Tracks per-mountpoint, per-RTCM-message-type packet rates over a sliding
 * window of RTCM_FREQ_WINDOW_SEC seconds. The window is divided into
 * RTCM_FREQ_BUCKETS buckets (one per second).
 *
 * Designed to detect abnormal sources (e.g. a base that should emit 1074
 * at 1 Hz but actually emits at 0.1 Hz).
 *
 * Concurrency: the tracker has its own mutex. Each per-mountpoint entry
 * has its own mutex, so different mountpoints can be updated concurrently.
 */

#define RTCM_FREQ_WINDOW_SEC   60
#define RTCM_FREQ_BUCKETS      60    // 1 bucket per second

/*
 * Per-type statistics
 */
struct rtcm_freq_per_type {
	unsigned int buckets[RTCM_FREQ_BUCKETS];
	int current_idx;             // 0..RTCM_FREQ_BUCKETS-1
	time_t current_sec;          // second value of current bucket
	time_t first_bucket_sec;     // second value of oldest non-zero bucket in window (0 if none)
	unsigned long total_count;   // since first packet
	struct timeval first_seen;
	struct timeval last_seen;
};

/*
 * Per-mountpoint statistics
 * Tracks all RTCM types observed (1k range and 4k range).
 * We use a flat array indexed by (type - RTCM_1K_MIN) for 1000-1230
 * and (type - RTCM_4K_MIN + 231) for 4000-4095.
 * That gives a 327-slot array (~16KB per mountpoint).
 */
#define RTCM_FREQ_1K_SLOTS   (RTCM_1K_MAX - RTCM_1K_MIN + 1)   // 231
#define RTCM_FREQ_4K_SLOTS   (RTCM_4K_MAX - RTCM_4K_MIN + 1)   // 96
#define RTCM_FREQ_TOTAL_SLOTS (RTCM_FREQ_1K_SLOTS + RTCM_FREQ_4K_SLOTS)

struct rtcm_freq_mountpoint {
	P_MUTEX_T lock;
	char *mountpoint;
	struct rtcm_freq_per_type types[RTCM_FREQ_TOTAL_SLOTS];
};

/*
 * Top-level tracker: a hash table mountpoint -> rtcm_freq_mountpoint
 */
struct rtcm_freq_tracker {
	struct hash_table *table;
	P_RWLOCK_T lock;
};

struct rtcm_freq_tracker *rtcm_freq_tracker_new(void);
void rtcm_freq_tracker_free(struct rtcm_freq_tracker *this);

/*
 * Record one RTCM packet for a mountpoint.
 * Safe to call from any thread.
 */
void rtcm_freq_record(struct rtcm_freq_tracker *this,
		      const char *mountpoint,
		      unsigned short rtcm_type,
		      struct timeval *now);

/*
 * Remove a mountpoint from the tracker (e.g. when its livesource is freed).
 */
void rtcm_freq_remove(struct rtcm_freq_tracker *this, const char *mountpoint);

/*
 * Compute the current sliding-window rate (Hz) for a per-type entry.
 * Walks the 60-bucket circular buffer and divides by the active window.
 * Safe to call from any thread; caller must hold the per-mountpoint mutex.
 */
double rtcm_freq_rate(struct rtcm_freq_per_type *t, time_t now_sec);

/*
 * Serialize the whole tracker as a JSON object:
 *   {
 *     "<mountpoint>": {
 *       "<type>": {
 *         "rate_hz": <double>,         // sliding-window rate
 *         "total": <int>,
 *         "first_seen": <iso8601>,
 *         "last_seen": <iso8601>
 *       },
 *       ...
 *     },
 *     ...
 *   }
 */
json_object *rtcm_freq_tracker_json(struct rtcm_freq_tracker *this);

/*
 * Serialize a single mountpoint as a JSON object (or NULL if unknown).
 */
json_object *rtcm_freq_mountpoint_json(struct rtcm_freq_tracker *this,
				       const char *mountpoint);

/*
 * Helper: map an RTCM type to a slot index, or -1 if out of range.
 */
static inline int rtcm_freq_slot(unsigned short type) {
	if (type >= RTCM_1K_MIN && type <= RTCM_1K_MAX)
		return type - RTCM_1K_MIN;
	if (type >= RTCM_4K_MIN && type <= RTCM_4K_MAX)
		return type - RTCM_4K_MIN + RTCM_FREQ_1K_SLOTS;
	return -1;
}

/*
 * Helper: reverse mapping (slot index -> RTCM type).
 */
static inline unsigned short rtcm_freq_type(int slot) {
	if (slot < RTCM_FREQ_1K_SLOTS)
		return (unsigned short)(slot + RTCM_1K_MIN);
	return (unsigned short)(slot - RTCM_FREQ_1K_SLOTS + RTCM_4K_MIN);
}

#endif /* __RTCM_FREQ_H__ */
