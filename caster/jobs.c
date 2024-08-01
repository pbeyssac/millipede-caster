#include <assert.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <pthread.h>

#include "conf.h"
#include "caster.h"
#include "jobs.h"
#include "ntrip_common.h"


static void _log_error(struct joblist *this, char *orig) {
	char s[256];
	strerror_r(errno, s, sizeof s);
	logfmt(&this->caster->flog, "%s: %s (%d)\n", orig, s, errno);
}

/*
 * Create a job list.
 */
#ifdef THREADS
struct joblist *joblist_new(struct caster_state *caster) {
	struct joblist *this = (struct joblist *)malloc(sizeof(struct joblist));
	if (this != NULL) {
		this->caster = caster;
		STAILQ_INIT(&this->ntrip_queue);
		P_MUTEX_INIT(&this->mutex, NULL);
		if (pthread_cond_init(&this->condjob, NULL) < 0)
			_log_error(this, "pthread_cond_init");
	}
	return this;
}

/*
 * Free a job list.
 */
void joblist_free(struct joblist *this) {
	struct job *j;
	struct ntrip_state *st;
	P_MUTEX_LOCK(&this->mutex);
	while ((st = STAILQ_FIRST(&this->ntrip_queue))) {
		STAILQ_REMOVE_HEAD(&this->ntrip_queue, next);
		while ((j = STAILQ_FIRST(&st->jobq))) {
			STAILQ_REMOVE_HEAD(&st->jobq, next);
			free(j);
		}
	}
	if (pthread_cond_destroy(&this->condjob) < 0)
		_log_error(this, "pthread_cond_signal");
	P_MUTEX_DESTROY(&this->mutex);
}

/*
 * Run jobs in a job list, on a FIFO basis.
 *
 * Simultaneously run by all workers.
 */
void joblist_run(struct joblist *this) {
	struct job *j;
	struct ntrip_state *st;

	/*
	 * Initial lock acquisition on the job list
	 */
	P_MUTEX_LOCK(&this->mutex);

	/*
	 * Now run jobs forever.
	 */
	while(1) {
		int nst;
		st = STAILQ_FIRST(&this->ntrip_queue);
		if (st == NULL) {

			/*
			 * Empty queue.
			 */
			if (pthread_cond_wait(&this->condjob, &this->mutex) < 0)
				_log_error(this, "pthread_cond_wait");
			continue;
		}

		/*
		 * We have the first ready session in the queue, remove it
		 * so we can release the lock on the list.
		 */

		STAILQ_REMOVE_HEAD(&this->ntrip_queue, next);

		P_MUTEX_UNLOCK(&this->mutex);

		/*
		 * libevent locks the bufferevent during callbacks if threading is activated,
		 * so in the following callbacks we need to get our own locks beginning
		 * with bufferevent to avoid deadlocks due to lock order reversal.
                 *
                 * The buffervent is associated with the ntrip_state, it's the same for all jobs in the queue.
		 */
		struct bufferevent *bev = st->bev;
		bufferevent_lock(bev);

		/*
		 * Run the jobs.
		 */

		nst = 0;

		while ((j = STAILQ_FIRST(&st->jobq))) {
			STAILQ_REMOVE_HEAD(&st->jobq, next);
			if (st->state != NTRIP_END) {
				if (j->cb) {
					j->cb(bev, j->arg);
				} else {
					j->cbe(bev, j->events, j->arg);
				}
			}

			nst++;
			free(j);
		}

		ntrip_log(st, LOG_EDEBUG, "thread %p ran %d jobs for ntrip state %p\n", pthread_self(), nst, st);

		bufferevent_unlock(bev);

		/*
		 * Unreference the buffervent
		 */
		int r = bufferevent_decref(bev);

		/*
		 * Free the ntrip state if adequate, and log bufferevent freeing problems.
		 */
		if (st->state == NTRIP_END) {
			if (r == 0)
				ntrip_log(st, LOG_EDEBUG, "bufferevent %p not freed, ntrip state %p\n", bev, st);
			else
				ntrip_log(st, LOG_EDEBUG, "bufferevent %p freed, ntrip state %p\n", bev, st);
			ntrip_free(st, "joblist_run");
		}

		/*
		 * Lock the list again for the next job.
		 */
		P_MUTEX_LOCK(&this->mutex);
	}
}

/*
 * Add a new job at the end of the list.
 */
void joblist_append(struct joblist *this, void (*cb)(struct bufferevent *bev, void *arg), void (*cbe)(struct bufferevent *bev, short events, void *arg), struct bufferevent *bev, void *arg, short events) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	/*
	 * Check the bufferevent has not been freed.
	 * If it was, we shouldn't be called here.
	 */
	assert(!st->bev_freed);

	P_MUTEX_LOCK(&this->mutex);

	/*
	 * Check whether the ntrip_state queue is empty.
	 * If it is, we will need to insert the ntrip_state in the main job queue.
	 *
	 * In other words:
	 *	!jobq_was_empty <=> ntrip_state is in the main job queue
	 */
	int jobq_was_empty = STAILQ_EMPTY(&st->jobq);
	struct job *lastj = STAILQ_LAST(&st->jobq, job, next);

	/*
	 * Check the last recorded callback, if any. Skip if identical to the new one.
	 */
	if (lastj == NULL || lastj->events != events || lastj->cb != cb  || lastj->cbe != cbe) {
		struct job *j = (struct job *)malloc(sizeof(struct job));
		if (j == NULL) {
			ntrip_log(st, LOG_CRIT, "Out of memory, cannot allocate job.");
			P_MUTEX_UNLOCK(&this->mutex);
			return;
		}

		/*
		 * Create and insert a new job record in the queue for this ntrip_state.
		 */
		j->cb = cb;
		j->cbe = cbe;
		j->arg = arg;
		j->events = events;
		STAILQ_INSERT_TAIL(&st->jobq, j, next);
	}

	if (jobq_was_empty) {
		/*
		 * Insertion needed in the main job queue.
		 */
		ntrip_log(st, LOG_EDEBUG, "inserting in joblist ntrip_queue %p\n", st);
		STAILQ_INSERT_TAIL(&this->ntrip_queue, st, next);
		/*
		 * Make sure the bufferevent is not freed in our back
		 * before we have a chance to use it.
		 */
		bufferevent_incref(bev);
	} else
		ntrip_log(st, LOG_EDEBUG, "ntrip_state %p already in job list\n", st);

	/*
	 * Signal "some" waiting workers there is a new job.
	 */
	if (pthread_cond_signal(&this->condjob) < 0)
		_log_error(this, "pthread_cond_signal");
	P_MUTEX_UNLOCK(&this->mutex);
}

void *jobs_start_routine(void *arg) {
	struct caster_state *caster = (struct caster_state *)arg;
	printf("started thread %p\n", pthread_self());
	joblist_run(caster->joblist);
	return NULL;
}

int jobs_start_threads(struct caster_state *caster, int nthreads) {
	pthread_t *p = (pthread_t *)malloc(sizeof(pthread_t)*nthreads);
	if (p == NULL) {
		return -1;
	}

	pthread_attr_t attr;
	size_t stacksize;
	pthread_attr_init(&attr);

	// Get stack size
	pthread_attr_getstacksize(&attr, &stacksize);
	printf("Default stack size: %zu bytes\n", stacksize);

	// Set stack size to 500k
	pthread_attr_setstacksize(&attr, 500*1024);

	for (int i = 0; i < nthreads; i++) {
		int r = pthread_create(&p[i], &attr, jobs_start_routine, caster);
		if (r < 0) {
			return -1;
		}
	}
	pthread_attr_destroy(&attr);
	return 0;
}

#endif
