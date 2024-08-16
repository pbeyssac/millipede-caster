#ifndef __JOBS_H__
#define __JOBS_H__

#include <event2/bufferevent.h>
#include "queue.h"

enum job_type {
	JOB_LIBEVENT_RW,
	JOB_LIBEVENT_EVENT
};

/*
 * Job entry for the FIFO list, to dispatch tasks to workers.
 * Only used when threads are activated.
 */
struct job {
	STAILQ_ENTRY(job) next;

	enum job_type type;

	union {
		/* type == JOB_LIBEVENT_RW: read or write callback job */
		struct {
			void (*cb)(struct bufferevent *bev, void *arg);
		} rw;

		/* type == JOB_LIBEVENT_EVENT: event callback job */
		struct {
			void (*cb)(struct bufferevent *bev, short events, void *arg);
			/* Event flags */
			short events;
		} event;
	};
};

STAILQ_HEAD (jobq, job);
STAILQ_HEAD (ntripq, ntrip_state);
TAILQ_HEAD (general_ntripq, ntrip_state);

/*
 *  FIFO list for worker threads to get new jobs.
 */
struct joblist {
	/* The work queue itself */
	struct ntripq ntrip_queue;
	/* Append-only queue, separated to simplify locking */
	struct ntripq append_queue;

	/* Mutexes protecting access to the queues */
	P_MUTEX_T mutex;
	P_MUTEX_T append_mutex;

	/*
	 * Used to signal workers a new job has been appended
	 * or the work queue has been refilled.
	 */
	pthread_cond_t condjob;

	/* The associated caster */
	struct caster_state *caster;
};

struct joblist *joblist_new(struct caster_state *caster);
void joblist_free(struct joblist *this);
void joblist_run(struct joblist *this);
void joblist_append(struct joblist *this, void (*cb)(struct bufferevent *bev, void *arg), void (*cbe)(struct bufferevent *bev, short events, void *arg), struct bufferevent *bev, void *arg, short events);
void joblist_drain(struct ntrip_state *st);
void *jobs_start_routine(void *arg);
int jobs_start_threads(struct caster_state *caster, int nthreads);

#endif
