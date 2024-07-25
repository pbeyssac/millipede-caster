#ifndef __JOBS_H__
#define __JOBS_H__

#include <pthread_np.h>
#include <event2/bufferevent.h>
#include "queue.h"

/*
 * Job entry for the FIFO list, to dispatch tasks to workers.
 * Only used when threads are activated.
 */
struct job {
	STAILQ_ENTRY(job) next;

	/* If not NULL, this is a read or write callback job */
	void (*cb)(struct bufferevent *bev, void *arg);

	/* If not NULL, this is an event callback job */
	void (*cbe)(struct bufferevent *bev, short events, void *arg);

	/* Parameter for all jobs */
	void *arg;

	/* Event flags for event jobs only */
	short events;
};
STAILQ_HEAD (jobq, job);
STAILQ_HEAD (ntripq, ntrip_state);
/*
 *  FIFO list for worker threads to get new jobs.
 */
struct joblist {
	/* The queue itself */
	struct ntripq ntrip_queue;

	/* Protect access to the queue */
	P_MUTEX_T mutex;

	/* Used to signal workers a new job has been appended */
	pthread_cond_t condjob;

	/* The associated caster */
	struct caster_state *caster;
};

struct joblist *joblist_new(struct caster_state *caster);
void joblist_free(struct joblist *this);
void joblist_run(struct joblist *this);
void joblist_append(struct joblist *this, void (*cb)(struct bufferevent *bev, void *arg), void (*cbe)(struct bufferevent *bev, short events, void *arg), struct bufferevent *bev, void *arg, short events);
void *jobs_start_routine(void *arg);
int jobs_start_threads(struct caster_state *caster, int nthreads);

#endif
