#include <assert.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "caster.h"
#include "jobs.h"
#include "ntrip_common.h"

/*
 * Create a job list.
 */
#ifdef THREADS
struct joblist *joblist_new(struct caster_state *caster) {
	struct joblist *this = (struct joblist *)malloc(sizeof(struct joblist));
	if (this != NULL) {
		this->caster = caster;
		STAILQ_INIT(&this->queue);
		P_MUTEX_INIT(&this->mutex, NULL);
		pthread_cond_init(&this->condjob, NULL);
	}
	return this;
}

/*
 * Free a job list.
 */
void joblist_free(struct joblist *this) {
	struct job *j;
	P_MUTEX_LOCK(&this->mutex);
	while ((j = STAILQ_FIRST(&this->queue))) {
		STAILQ_REMOVE_HEAD(&this->queue, next);
		free(j);
	}
	P_MUTEX_DESTROY(&this->mutex);
}

/*
 * Run jobs in a job list, on a FIFO basis.
 *
 * Simultaneously run by all workers.
 */
void joblist_run(struct joblist *this) {
	struct job *j;
	int n = 0;

	/*
	 * Initial lock acquisition on the job list
	 */
	P_MUTEX_LOCK(&this->mutex);

	/*
	 * Now run jobs forever.
	 */
	while(1) {
		j = STAILQ_FIRST(&this->queue);
		if (j == NULL) {

			/*
			 * Empty queue.
			 */
			if (n != 1)
				fprintf(stderr, "%p sleeping after running %d job(s)\n", pthread_self(), n);
			pthread_cond_wait(&this->condjob, &this->mutex);
			n = 0;
			continue;
		}

		/*
		 * We have the first job in the queue, remove it
		 * so we can release the lock on the list.
		 */

		STAILQ_REMOVE_HEAD(&this->queue, next);
		P_MUTEX_UNLOCK(&this->mutex);

		/*
		 * Run the job.
		 */
		struct ntrip_state *st = (struct ntrip_state *)j->arg;
		if (j->cb) {
			j->cb(j->bev, j->arg);
		} else {
			j->cbe(j->bev, j->events, j->arg);
		}
		n++;

		/*
		 * Unreferefence the buffervent so it can be freed.
		 */
		bufferevent_decref(j->bev);

		/*
		 * Free the job record and unref the ntrip state.
		 */
		free(j);

		P_RWLOCK_WRLOCK(&st->lock);
		st->refcnt--;
		ntrip_free(st, "joblist_run");
		//ntrip_decref(st, "joblist_run");

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
	struct job *j = (struct job *)malloc(sizeof(struct job));

	if (j == NULL) {
		ntrip_log(st, LOG_CRIT, "Out of memory, cannot allocate job.");
		return;
	}

	/*
	 * Create the job record.
	 */
	j->cb = cb;
	j->cbe = cbe;
	j->bev = bev;
	j->arg = arg;
	j->events = events;

	/*
	 * Check the bufferevent has not been freed.
	 * If it was, we shouldn't be called here.
	 */
	assert(!st->bev_freed);

	/*
	 * Make sure the bufferevent is not freed in our back
	 * before we have a chance to use it.
	 *
	 * libevent does its own locking on the buffer if threading is activated,
	 * so keep it out of our locks.
	 */
	bufferevent_incref(bev);

	ntrip_incref(st);

	/*
	 * Insert in the queue.
	 */
	P_MUTEX_LOCK(&this->mutex);
	STAILQ_INSERT_TAIL(&this->queue, j, next);

	/*
	 * Signal "some" waiting workers there is a new job.
	 */
	pthread_cond_signal(&this->condjob);
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

#if 0
static int joblist_count_bev(struct joblist *this, struct bufferevent *bev, struct caster_state *caster) {
	struct job *j;
	int ref = 0;
	P_MUTEX_LOCK(&this->mutex);
	STAILQ_FOREACH(j, &this->queue, next) {
		if (j->bev == bev) {
			logfmt(&caster->flog, "bev %p for job %p %p %p %d\n", j->bev, j->cb, j->cbe, j->arg, j->events);
			ref++;
		}
	}
	P_MUTEX_UNLOCK(&this->mutex);
	return ref;
}
#endif

#endif
