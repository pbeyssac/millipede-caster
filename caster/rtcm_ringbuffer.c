#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rtcm_ringbuffer.h"
#include "util.h"

/*
 * RTCM Ring Buffer implementation.
 *
 * Design notes:
 *  - One top-level hash table: mountpoint -> rtcm_rb_mountpoint
 *  - Each rtcm_rb_mountpoint has its own mutex (per-mountpoint locking)
 *  - Per-mountpoint storage is a dynamic circular buffer of
 *    rtcm_rb_slot entries (packet pointer + timestamp + cached size).
 *  - On insert: grow if full, then lazily evict stale (time-based)
 *    and over-cap (memory-based) slots from the tail.
 *  - Extract-range is a locked linear scan; returned entries are
 *    incref'd so the caller can iterate without holding the lock.
 *
 * Ownership:
 *  - The hash table owns both the key (a strdup'd mountpoint) and the
 *    value (the rtcm_rb_mountpoint struct).
 *  - Each stored packet is incref'd on insert and decref'd on eviction
 *    or tracker free.
 */

/*
 * Per-mountpoint destructor (registered as the hash table free callback).
 * Drops all stored packets, frees the slot array, destroys the mutex.
 */
static void rtcm_rb_mountpoint_free(void *p) {
	struct rtcm_rb_mountpoint *m = (struct rtcm_rb_mountpoint *)p;
	if (m == NULL)
		return;
	/* Drop references on all stored packets. */
	for (size_t i = 0; i < m->count; i++) {
		size_t idx = (m->head - m->count + i + m->capacity) % m->capacity;
		if (m->slots[idx].packet)
			packet_decref(m->slots[idx].packet);
	}
	free(m->slots);
	P_MUTEX_DESTROY(&m->lock);
	free(m);
}

struct rtcm_ringbuffer_tracker *rtcm_ringbuffer_tracker_new(
		int retention_minutes, size_t max_bytes_per_mountpoint) {
	struct rtcm_ringbuffer_tracker *this = (struct rtcm_ringbuffer_tracker *)malloc(sizeof(*this));
	if (this == NULL)
		return NULL;
	this->table = hash_table_new(64, rtcm_rb_mountpoint_free);
	if (this->table == NULL) {
		free(this);
		return NULL;
	}
	P_RWLOCK_INIT(&this->lock, NULL);
	this->retention_seconds = (retention_minutes > 0 ? retention_minutes : RTCM_RB_DEFAULT_RETENTION_MIN) * 60;
	this->max_bytes_per_mountpoint = (max_bytes_per_mountpoint > 0 ? max_bytes_per_mountpoint : RTCM_RB_DEFAULT_MAX_BYTES);
	return this;
}

void rtcm_ringbuffer_tracker_free(struct rtcm_ringbuffer_tracker *this) {
	if (this == NULL)
		return;
	/* hash_table_free() invokes rtcm_rb_mountpoint_free on each
	 * value, which decrefs all stored packets. */
	if (this->table)
		hash_table_free(this->table);
	P_RWLOCK_DESTROY(&this->lock);
	free(this);
}

/*
 * Look up (or create) the per-mountpoint entry.
 * Returns the entry with its mutex LOCKED, or NULL on OOM / not found.
 *
 * Mirrors rtcm_freq_get_or_create_locked() in rtcm_freq.c.
 */
static struct rtcm_rb_mountpoint *rtcm_rb_get_or_create_locked(
		struct rtcm_ringbuffer_tracker *this,
		const char *mountpoint, int create) {
	struct rtcm_rb_mountpoint *m = NULL;

	P_RWLOCK_RDLOCK(&this->lock);
	m = (struct rtcm_rb_mountpoint *)hash_table_get(this->table, mountpoint);
	P_RWLOCK_UNLOCK(&this->lock);

	if (m == NULL && create) {
		P_RWLOCK_WRLOCK(&this->lock);
		/* Re-check under the write lock — another thread may
		 * have just inserted it. */
		m = (struct rtcm_rb_mountpoint *)hash_table_get(this->table, mountpoint);
		if (m == NULL) {
			m = (struct rtcm_rb_mountpoint *)calloc(1, sizeof(*m));
			if (m == NULL) {
				P_RWLOCK_UNLOCK(&this->lock);
				return NULL;
			}
			P_MUTEX_INIT(&m->lock, NULL);
			m->capacity = RTCM_RB_INITIAL_SLOTS;
			m->slots = (struct rtcm_rb_slot *)calloc(m->capacity, sizeof(*m->slots));
			if (m->slots == NULL) {
				P_MUTEX_DESTROY(&m->lock);
				free(m);
				P_RWLOCK_UNLOCK(&this->lock);
				return NULL;
			}
			if (hash_table_add(this->table, mountpoint, m) != 0) {
				free(m->slots);
				P_MUTEX_DESTROY(&m->lock);
				free(m);
				P_RWLOCK_UNLOCK(&this->lock);
				return NULL;
			}
		}
		P_RWLOCK_UNLOCK(&this->lock);
	}

	if (m)
		P_MUTEX_LOCK(&m->lock);
	return m;
}

/*
 * Double the slot array capacity, linearizing the circular buffer.
 * Returns 0 on success, -1 on OOM or capacity cap reached.
 *
 * Caller must hold m->lock.
 */
static int rtcm_rb_grow(struct rtcm_rb_mountpoint *m) {
	if (m->capacity >= RTCM_RB_MAX_SLOTS)
		return -1;
	size_t new_cap = m->capacity * 2;
	if (new_cap > RTCM_RB_MAX_SLOTS)
		new_cap = RTCM_RB_MAX_SLOTS;
	struct rtcm_rb_slot *new_slots = (struct rtcm_rb_slot *)calloc(new_cap, sizeof(*new_slots));
	if (new_slots == NULL)
		return -1;
	/* Linearize: copy entries from oldest to newest into new_slots[0..count-1]. */
	for (size_t i = 0; i < m->count; i++) {
		size_t old_idx = (m->head - m->count + i + m->capacity) % m->capacity;
		new_slots[i] = m->slots[old_idx];
	}
	free(m->slots);
	m->slots = new_slots;
	m->capacity = new_cap;
	m->head = m->count;  /* next write goes right after the last valid entry */
	return 0;
}

/*
 * Drop the oldest slot (at the tail of the ring).
 * Caller must hold m->lock and ensure m->count > 0.
 */
static void rtcm_rb_drop_oldest(struct rtcm_rb_mountpoint *m) {
	size_t oldest_idx = (m->head - m->count + m->capacity) % m->capacity;
	struct rtcm_rb_slot *s = &m->slots[oldest_idx];
	if (s->packet)
		packet_decref(s->packet);
	m->total_bytes -= s->bytes;
	s->packet = NULL;
	s->bytes = 0;
	timerclear(&s->ts);
	m->count--;
	m->evicted_packets++;
}

void rtcm_ringbuffer_record(struct rtcm_ringbuffer_tracker *this,
			    const char *mountpoint,
			    struct packet *packet,
			    struct timeval *now) {
	if (this == NULL || mountpoint == NULL || packet == NULL)
		return;

	struct timeval tv;
	if (now == NULL) {
		gettimeofday(&tv, NULL);
		now = &tv;
	}

	struct rtcm_rb_mountpoint *m =
		rtcm_rb_get_or_create_locked(this, mountpoint, 1);
	if (m == NULL)
		return;

	/* 1. Evict packets older than the retention window. */
	time_t cutoff = now->tv_sec - this->retention_seconds;
	while (m->count > 0) {
		size_t oldest_idx = (m->head - m->count + m->capacity) % m->capacity;
		if (m->slots[oldest_idx].ts.tv_sec < cutoff)
			rtcm_rb_drop_oldest(m);
		else
			break;
	}

	/* 2. Evict from the tail while the memory cap would be exceeded
	 *    after inserting this packet. Always keep at least one slot
	 *    free for the new packet (so a single oversized packet does
	 *    not wedge the ring). */
	while (m->count > 0 &&
	       m->total_bytes + packet->datalen > this->max_bytes_per_mountpoint) {
		rtcm_rb_drop_oldest(m);
	}

	/* 3. Grow the slot array if full. */
	if (m->count == m->capacity) {
		if (rtcm_rb_grow(m) != 0) {
			/* Can't grow further — drop the oldest entry to
			 * make room for the new one. */
			rtcm_rb_drop_oldest(m);
		}
	}

	/* 4. Insert. */
	struct rtcm_rb_slot *s = &m->slots[m->head];
	s->packet = packet;
	packet_incref(packet);
	s->ts = *now;
	s->bytes = packet->datalen;
	m->total_bytes += s->bytes;
	m->head = (m->head + 1) % m->capacity;
	m->count++;

	/* 5. Update stats. */
	if (!timerisset(&m->first_seen))
		m->first_seen = *now;
	m->last_seen = *now;
	m->total_packets++;

	P_MUTEX_UNLOCK(&m->lock);
}

void rtcm_ringbuffer_remove(struct rtcm_ringbuffer_tracker *this,
			    const char *mountpoint) {
	if (this == NULL || mountpoint == NULL)
		return;
	P_RWLOCK_WRLOCK(&this->lock);
	/* hash_table_del() invokes rtcm_rb_mountpoint_free() on the
	 * value, which decrefs all stored packets and frees the struct. */
	hash_table_del(this->table, mountpoint);
	P_RWLOCK_UNLOCK(&this->lock);
}

struct rtcm_rb_entry *rtcm_ringbuffer_extract_range(
		struct rtcm_ringbuffer_tracker *this,
		const char *mountpoint,
		const struct timeval *from,
		const struct timeval *to,
		size_t *count_out) {
	if (count_out)
		*count_out = 0;
	if (this == NULL || mountpoint == NULL)
		return NULL;

	struct rtcm_rb_mountpoint *m =
		rtcm_rb_get_or_create_locked(this, mountpoint, 0);
	if (m == NULL)
		return NULL;

	/* First pass: count matching entries so we can allocate once. */
	size_t match = 0;
	for (size_t i = 0; i < m->count; i++) {
		size_t idx = (m->head - m->count + i + m->capacity) % m->capacity;
		const struct timeval *ts = &m->slots[idx].ts;
		if (from && timercmp(ts, from, <))
			continue;
		if (to && timercmp(ts, to, >))
			continue;
		match++;
	}

	if (match == 0) {
		P_MUTEX_UNLOCK(&m->lock);
		return NULL;
	}

	struct rtcm_rb_entry *out = (struct rtcm_rb_entry *)calloc(match, sizeof(*out));
	if (out == NULL) {
		P_MUTEX_UNLOCK(&m->lock);
		return NULL;
	}

	/* Second pass: copy + incref. */
	size_t j = 0;
	for (size_t i = 0; i < m->count; i++) {
		size_t idx = (m->head - m->count + i + m->capacity) % m->capacity;
		const struct timeval *ts = &m->slots[idx].ts;
		if (from && timercmp(ts, from, <))
			continue;
		if (to && timercmp(ts, to, >))
			continue;
		out[j].packet = m->slots[idx].packet;
		out[j].ts = m->slots[idx].ts;
		if (out[j].packet)
			packet_incref(out[j].packet);
		j++;
	}

	P_MUTEX_UNLOCK(&m->lock);

	if (count_out)
		*count_out = match;
	return out;
}

/*
 * Format a timeval as an ISO8601 string ("YYYY-MM-DDThh:mm:ssZ").
 * Returns a static buffer; caller must copy if it needs persistence.
 */
static const char *rtcm_rb_iso(const struct timeval *tv) {
	static char buf[32];
	if (!timerisset(tv))
		return "";
	time_t t = tv->tv_sec;
	struct tm tm;
	gmtime_r(&t, &tm);
	strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
	return buf;
}

/*
 * Build the per-mountpoint JSON stats object.
 * Caller must hold m->lock.
 */
static json_object *rtcm_rb_mountpoint_to_json_locked(struct rtcm_rb_mountpoint *m) {
	json_object *j = json_object_new_object();
	json_object_object_add_ex(j, "packets",
		json_object_new_int64((int64_t)m->count), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(j, "bytes",
		json_object_new_int64((int64_t)m->total_bytes), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(j, "capacity_slots",
		json_object_new_int64((int64_t)m->capacity), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(j, "first_seen",
		json_object_new_string(rtcm_rb_iso(&m->first_seen)), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(j, "last_seen",
		json_object_new_string(rtcm_rb_iso(&m->last_seen)), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(j, "total_packets",
		json_object_new_uint64(m->total_packets), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(j, "evicted_packets",
		json_object_new_uint64(m->evicted_packets), JSON_C_CONSTANT_NEW);
	return j;
}

json_object *rtcm_ringbuffer_mountpoint_json(
		struct rtcm_ringbuffer_tracker *this,
		const char *mountpoint) {
	if (this == NULL || mountpoint == NULL)
		return NULL;
	struct rtcm_rb_mountpoint *m =
		rtcm_rb_get_or_create_locked(this, mountpoint, 0);
	if (m == NULL)
		return NULL;
	json_object *j = rtcm_rb_mountpoint_to_json_locked(m);
	P_MUTEX_UNLOCK(&m->lock);
	return j;
}

json_object *rtcm_ringbuffer_tracker_json(struct rtcm_ringbuffer_tracker *this) {
	if (this == NULL)
		return json_object_new_object();
	json_object *root = json_object_new_object();

	P_RWLOCK_RDLOCK(&this->lock);
	struct hash_iterator hi;
	struct element *e;
	HASH_FOREACH(e, this->table, hi) {
		struct rtcm_rb_mountpoint *m = (struct rtcm_rb_mountpoint *)e->value;
		if (m == NULL)
			continue;
		P_MUTEX_LOCK(&m->lock);
		json_object *jm = rtcm_rb_mountpoint_to_json_locked(m);
		P_MUTEX_UNLOCK(&m->lock);
		json_object_object_add_ex(root, e->key, jm, JSON_C_CONSTANT_NEW);
	}
	P_RWLOCK_UNLOCK(&this->lock);
	return root;
}
