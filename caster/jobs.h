#ifndef __JOBS_H__
#define __JOBS_H__

#include <event2/bufferevent.h>
#include "queue.h"

enum job_type {
	JOB_LIBEVENT_RW,
	JOB_LIBEVENT_EVENT,
	JOB_NTRIP_LOCK,
	JOB_NTRIP_UNLOCKED,
	JOB_REDISTRIBUTE
};

struct ntrip_state;
struct redistribute_cb_args;

/*
 * Job entry for FIFO lists, to dispatch tasks to workers.
 * Only used when threads are activated.
 */
struct job {
	STAILQ_ENTRY(job) next;

	enum job_type type;

	union {
		/* type == JOB_LIBEVENT_RW: libevent read or write callback job */
		struct {
			void (*cb)(struct bufferevent *bev, void *arg);
		} rw;

		/* type == JOB_LIBEVENT_EVENT: libevent callback job */
		struct {
			void (*cb)(struct bufferevent *bev, short events, void *arg);
			/* Event flags */
			short events;
		} event;

		/*
		 * type == JOB_NTRIP_LOCK: job associated with a ntrip_state,
		 *	requires a lock on ntrip_state.
		 */
		struct {
			void (*cb)(struct ntrip_state *st);
		} ntrip_locked;

		/*
		 * type == JOB_REDISTRIBUTE:
		 *	livesource redistribute job
		 */
		struct {
			void (*cb)(struct redistribute_cb_args *arg);
			struct redistribute_cb_args *arg;
		} redistribute;

		/*
		 * type == JOB_NTRIP_UNLOCKED: job associated with a ntrip_state,
		 *	requires no lock on ntrip_state.
		 */
		struct {
			void (*cb)(struct ntrip_state *st);
			struct ntrip_state *st;
		} ntrip_unlocked;
	};
};

STAILQ_HEAD (jobq, job);
STAILQ_HEAD (ntripq, ntrip_state);
TAILQ_HEAD (general_ntripq, ntrip_state);

/*
 *  FIFO lists for worker threads to get new jobs.
 */
struct joblist {
	/* The work queue for ntrip_states with a lock */
	struct ntripq ntrip_queue;
	/* Main work queue for jobs without a lock */
	struct jobq jobq;

	/* Number of jobs in ntrip_queue and jobq */
	int ntrip_njobs, njobs;

	/* Append-only queues, separated to simplify locking */

	/* Append work queue for ntrip_states with a lock */
	struct ntripq append_queue;
	/* Append work queue for jobs without a lock */
	struct jobq append_jobq;

	/* Number of jobs in append_queue and append_jobq */
	int append_ntrip_njobs, append_njobs;

	/* Mutexes protecting access to the queues */
	P_MUTEX_T mutex;		// ntrip_queue and jobq
	P_MUTEX_T append_mutex;		// append_queue and append_jobq

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
void joblist_append_ntrip_locked(struct joblist *this, struct ntrip_state *st, void (*cb)(struct ntrip_state *arg));
void joblist_append_redistribute(struct joblist *this, void (*cb)(struct redistribute_cb_args *redis_args), struct redistribute_cb_args *redis_args);
void joblist_append_ntrip_unlocked(struct joblist *this, void (*cb)(struct ntrip_state *st), struct ntrip_state *st);
void joblist_drain(struct ntrip_state *st);
void *jobs_start_routine(void *arg);
int jobs_start_threads(struct caster_state *caster, int nthreads);

#endif
