#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rtcm_freq.h"
#include "util.h"

/*
 * RTCM Frequency Tracker implementation.
 *
 * Design notes:
 *  - One top-level hash table: mountpoint -> rtcm_freq_mountpoint
 *  - Each rtcm_freq_mountpoint has its own mutex (per-mountpoint locking)
 *  - For each type slot, a fixed-size circular buffer of 60 second-buckets
 *  - On record(): rotate buckets forward as time passes, zeroing stale buckets
 *  - Rate is computed by summing all buckets and dividing by the window size
 *
 * Ownership: the hash table owns both the key (a strdup'd copy of the
 * mountpoint name) and the value (the rtcm_freq_mountpoint struct).
 * rtcm_freq_mountpoint_free() is registered as the hash table's value
 * destructor so that hash_table_del() / hash_table_free() clean up
 * properly (mutex + struct + key).
 */

/*
 * Destructor for a rtcm_freq_mountpoint entry.
 * Used as the hash table's free_callback.
 */
static void rtcm_freq_mountpoint_free(void *p) {
        struct rtcm_freq_mountpoint *m = (struct rtcm_freq_mountpoint *)p;
        if (m == NULL)
                return;
        P_MUTEX_DESTROY(&m->lock);
        free(m);
}

struct rtcm_freq_tracker *rtcm_freq_tracker_new(void) {
        struct rtcm_freq_tracker *this = (struct rtcm_freq_tracker *)malloc(sizeof(*this));
        if (this == NULL)
                return NULL;
        this->table = hash_table_new(64, rtcm_freq_mountpoint_free);
        if (this->table == NULL) {
                free(this);
                return NULL;
        }
        P_RWLOCK_INIT(&this->lock, NULL);
        return this;
}

void rtcm_freq_tracker_free(struct rtcm_freq_tracker *this) {
        if (this == NULL)
                return;
        /* hash_table_free() will invoke rtcm_freq_mountpoint_free on each
         * value, and strfree() on each key. */
        if (this->table)
                hash_table_free(this->table);
        P_RWLOCK_DESTROY(&this->lock);
        free(this);
}

/*
 * Look up (or create) the per-mountpoint entry.
 * Returns a pointer with the entry's mutex LOCKED, or NULL on OOM / not found.
 */
static struct rtcm_freq_mountpoint *rtcm_freq_get_or_create_locked(
                struct rtcm_freq_tracker *this, const char *mountpoint,
                int create) {

        struct rtcm_freq_mountpoint *m = NULL;

        P_RWLOCK_RDLOCK(&this->lock);
        m = (struct rtcm_freq_mountpoint *)hash_table_get(this->table, mountpoint);
        P_RWLOCK_UNLOCK(&this->lock);

        if (m == NULL && create) {
                /* Try to insert under the write lock. */
                P_RWLOCK_WRLOCK(&this->lock);
                /* Re-check, another thread may have just inserted it. */
                m = (struct rtcm_freq_mountpoint *)hash_table_get(this->table, mountpoint);
                if (m == NULL) {
                        m = (struct rtcm_freq_mountpoint *)calloc(1, sizeof(*m));
                        if (m == NULL) {
                                P_RWLOCK_UNLOCK(&this->lock);
                                return NULL;
                        }
                        P_MUTEX_INIT(&m->lock, NULL);
                        /* All fields (types[], current_idx, current_sec, etc.)
                         * are already zero thanks to calloc. */
                        if (hash_table_add(this->table, mountpoint, m) != 0) {
                                P_MUTEX_DESTROY(&m->lock);
                                free(m);
                                P_RWLOCK_UNLOCK(&this->lock);
                                return NULL;
                        }
                }
                P_RWLOCK_UNLOCK(&this->lock);
        }

        if (m) {
                P_MUTEX_LOCK(&m->lock);
        }
        return m;
}

/*
 * Advance the bucket cursor for a per-type entry so that
 * m->types[slot].current_sec == now_sec, zeroing any skipped buckets.
 */
static void rtcm_freq_advance_buckets(struct rtcm_freq_per_type *t, time_t now_sec) {
        if (t->current_sec == 0) {
                /* First packet ever for this type. */
                t->current_sec = now_sec;
                t->current_idx = 0;
                memset(t->buckets, 0, sizeof t->buckets);
                t->first_bucket_sec = 0;  /* will be set by caller */
                return;
        }
        time_t delta = now_sec - t->current_sec;
        if (delta <= 0) {
                /* Same second or clock skew backwards; nothing to do. */
                return;
        }
        if (delta >= RTCM_FREQ_BUCKETS) {
                /* The whole window is stale: zero everything. */
                memset(t->buckets, 0, sizeof t->buckets);
                t->current_idx = 0;
                t->current_sec = now_sec;
                t->first_bucket_sec = 0;  /* window is empty */
                return;
        }
        for (time_t i = 0; i < delta; i++) {
                t->current_idx = (t->current_idx + 1) % RTCM_FREQ_BUCKETS;
                t->buckets[t->current_idx] = 0;
        }
        t->current_sec = now_sec;
        /* If first_bucket_sec is now outside the window, reset it.
         * The caller will set it to now_sec if no other non-zero bucket
         * remains in the window. */
        if (t->first_bucket_sec && now_sec - t->first_bucket_sec >= RTCM_FREQ_BUCKETS)
                t->first_bucket_sec = 0;
}

void rtcm_freq_record(struct rtcm_freq_tracker *this,
                      const char *mountpoint,
                      unsigned short rtcm_type,
                      struct timeval *now) {
        if (this == NULL || mountpoint == NULL)
                return;

        int slot = rtcm_freq_slot(rtcm_type);
        if (slot < 0)
                return;

        struct timeval tv;
        if (now == NULL) {
                gettimeofday(&tv, NULL);
                now = &tv;
        }

        struct rtcm_freq_mountpoint *m =
                rtcm_freq_get_or_create_locked(this, mountpoint, 1);
        if (m == NULL)
                return;

        struct rtcm_freq_per_type *t = &m->types[slot];
        rtcm_freq_advance_buckets(t, now->tv_sec);
        t->buckets[t->current_idx]++;
        if (t->first_bucket_sec == 0)
                t->first_bucket_sec = now->tv_sec;
        t->total_count++;
        if (!timerisset(&t->first_seen))
                t->first_seen = *now;
        t->last_seen = *now;

        P_MUTEX_UNLOCK(&m->lock);
}

void rtcm_freq_remove(struct rtcm_freq_tracker *this, const char *mountpoint) {
        if (this == NULL || mountpoint == NULL)
                return;
        P_RWLOCK_WRLOCK(&this->lock);
        /* hash_table_del() will call rtcm_freq_mountpoint_free() on the
         * value, which destroys the mutex and frees the struct. */
        hash_table_del(this->table, mountpoint);
        P_RWLOCK_UNLOCK(&this->lock);
}

/*
 * Compute the rate over the last RTCM_FREQ_WINDOW_SEC seconds.
 *
 * For an active source (recent traffic): rate = sum / active_seconds
 *   where active_seconds = max(1, min(WINDOW, current_sec - first_bucket_sec + 1))
 * For an idle source (no traffic in the last WINDOW seconds): rate = 0
 */
static double rtcm_freq_rate(struct rtcm_freq_per_type *t, time_t now_sec) {
        if (t->current_sec == 0 || t->total_count == 0)
                return 0.0;
        /* If the window is fully stale, the rate is 0. */
        if (now_sec - t->current_sec >= RTCM_FREQ_BUCKETS)
                return 0.0;
        /* If first_bucket_sec is zero, all buckets in the window are zero
         * (shouldn't happen if total_count > 0, but be defensive). */
        if (t->first_bucket_sec == 0)
                return 0.0;
        unsigned long sum = 0;
        for (int i = 0; i < RTCM_FREQ_BUCKETS; i++)
                sum += t->buckets[i];
        /* Active window: from the oldest non-zero bucket to the current one.
         * Cap at RTCM_FREQ_WINDOW_SEC. */
        time_t active = t->current_sec - t->first_bucket_sec + 1;
        if (active < 1)
                active = 1;
        if (active > RTCM_FREQ_WINDOW_SEC)
                active = RTCM_FREQ_WINDOW_SEC;
        return (double)sum / (double)active;
}

/*
 * Format a timeval as an ISO8601 string ("YYYY-MM-DDThh:mm:ssZ").
 * Returns a static buffer; caller must copy if it needs persistence.
 */
static const char *rtcm_freq_iso(struct timeval *tv) {
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
 * Add one type's stats to a JSON object.
 * Caller holds the per-mountpoint mutex.
 *
 * Note: we use json_object_object_add (not _ex) for the type key because
 * the key is a stack buffer that would be reused on the next iteration;
 * the _ex variant with JSON_C_OBJECT_ADD_CONSTANT_KEY would store the
 * pointer without copying it.
 */
static void rtcm_freq_type_to_json(struct rtcm_freq_mountpoint *m,
                                   int slot, json_object *parent, time_t now_sec) {
        struct rtcm_freq_per_type *t = &m->types[slot];
        if (t->total_count == 0)
                return;
        char key[8];
        snprintf(key, sizeof key, "%u", rtcm_freq_type(slot));
        json_object *j = json_object_new_object();
        json_object_object_add_ex(j, "rate_hz",
                json_object_new_double(rtcm_freq_rate(t, now_sec)),
                JSON_C_CONSTANT_NEW);
        json_object_object_add_ex(j, "total",
                json_object_new_int64((int64_t)t->total_count),
                JSON_C_CONSTANT_NEW);
        json_object_object_add_ex(j, "first_seen",
                json_object_new_string(rtcm_freq_iso(&t->first_seen)),
                JSON_C_CONSTANT_NEW);
        json_object_object_add_ex(j, "last_seen",
                json_object_new_string(rtcm_freq_iso(&t->last_seen)),
                JSON_C_CONSTANT_NEW);
        json_object_object_add(parent, key, j);
}

json_object *rtcm_freq_mountpoint_json(struct rtcm_freq_tracker *this,
                                       const char *mountpoint) {
        if (this == NULL || mountpoint == NULL)
                return NULL;
        struct rtcm_freq_mountpoint *m =
                rtcm_freq_get_or_create_locked(this, mountpoint, 0);
        if (m == NULL)
                return NULL;
        json_object *j = json_object_new_object();
        time_t now_sec = time(NULL);
        for (int slot = 0; slot < RTCM_FREQ_TOTAL_SLOTS; slot++)
                rtcm_freq_type_to_json(m, slot, j, now_sec);
        P_MUTEX_UNLOCK(&m->lock);
        return j;
}

json_object *rtcm_freq_tracker_json(struct rtcm_freq_tracker *this) {
        if (this == NULL)
                return json_object_new_object();
        json_object *root = json_object_new_object();
        time_t now_sec = time(NULL);

        P_RWLOCK_RDLOCK(&this->lock);
        struct hash_iterator hi;
        struct element *e;
        HASH_FOREACH(e, this->table, hi) {
                struct rtcm_freq_mountpoint *m =
                        (struct rtcm_freq_mountpoint *)e->value;
                if (m == NULL)
                        continue;
                P_MUTEX_LOCK(&m->lock);
                json_object *jm = json_object_new_object();
                for (int slot = 0; slot < RTCM_FREQ_TOTAL_SLOTS; slot++)
                        rtcm_freq_type_to_json(m, slot, jm, now_sec);
                P_MUTEX_UNLOCK(&m->lock);
                json_object_object_add_ex(root, e->key, jm, JSON_C_CONSTANT_NEW);
        }
        P_RWLOCK_UNLOCK(&this->lock);
        return root;
}
