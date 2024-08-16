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
struct joblist *joblist_new(struct caster_state *caster) {
	struct joblist *this = (struct joblist *)malloc(sizeof(struct joblist));
	if (this != NULL) {
		this->caster = caster;
		STAILQ_INIT(&this->ntrip_queue);
		STAILQ_INIT(&this->append_queue);
		P_MUTEX_INIT(&this->mutex, NULL);
		P_MUTEX_INIT(&this->append_mutex, NULL);
		if (pthread_cond_init(&this->condjob, NULL) < 0)
			_log_error(this, "pthread_cond_init");
	}
	return this;
}

/*
 * Free a job list.
 */
void joblist_free(struct joblist *this) {
	struct ntrip_state *st;
	P_MUTEX_LOCK(&this->mutex);
	while ((st = STAILQ_FIRST(&this->ntrip_queue))) {
		STAILQ_REMOVE_HEAD(&this->ntrip_queue, next);
		joblist_drain(st);
	}
	P_MUTEX_UNLOCK(&this->mutex);
	P_MUTEX_LOCK(&this->append_mutex);
	while ((st = STAILQ_FIRST(&this->append_queue))) {
		STAILQ_REMOVE_HEAD(&this->append_queue, next);
		joblist_drain(st);
	}
	P_MUTEX_UNLOCK(&this->append_mutex);
	P_MUTEX_DESTROY(&this->mutex);
	P_MUTEX_DESTROY(&this->append_mutex);
	if (pthread_cond_destroy(&this->condjob) < 0)
		_log_error(this, "pthread_cond_signal");
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
			 * Work queue is empty, check the append queue for a refill.
			 */
			P_MUTEX_LOCK(&this->append_mutex);
			st = STAILQ_FIRST(&this->append_queue);
			if (st == NULL) {
				P_MUTEX_UNLOCK(&this->append_mutex);
				/*
				 * Both queues empty => wait.
				 */
				if (pthread_cond_wait(&this->condjob, &this->mutex) < 0)
					_log_error(this, "pthread_cond_wait");
				continue;
			}
			/*
			 * Fill the work queue, empty the append queue.
			 */
			STAILQ_SWAP(&this->ntrip_queue, &this->append_queue, ntrip_state);
			pthread_cond_broadcast(&this->condjob);
			P_MUTEX_UNLOCK(&this->append_mutex);
		}

		/*
		 * We have the first ready session in the queue, remove it
		 * so we can release the lock on the list.
		 */

		STAILQ_REMOVE_HEAD(&this->ntrip_queue, next);

		struct bufferevent *bev = st->bev;

		/*
		 * Get a lock on bev before unlocking the queue, to avoid having st freed in our back.
		 *
		 * libevent locks the bufferevent during joblist_append() if threading is activated,
		 * so in the following callbacks we need to get our own locks beginning
		 * with bufferevent to avoid deadlocks due to lock order reversal.
                 *
                 * The bufferevent is associated with the ntrip_state, it's the same for all jobs in the queue,
		 * so we only need to lock it once.
		 */
		bufferevent_lock(bev);
		st->newjobs = 0;

		P_MUTEX_UNLOCK(&this->mutex);

		/*
		 * Run the jobs.
		 */

		nst = 0;

		ntrip_log(st, LOG_EDEBUG, "starting jobs for ntrip state %p\n", st);

		while ((j = STAILQ_FIRST(&st->jobq))) {
			STAILQ_REMOVE_HEAD(&st->jobq, next);
			st->njobs--;
			if (st->newjobs > 0)
				st->newjobs--;
			if (st->state != NTRIP_END) {
				switch (j->type) {
				case JOB_LIBEVENT_RW:
					j->rw.cb(bev, (void *)st);
					break;
				case JOB_LIBEVENT_EVENT:
					j->event.cb(bev, j->event.events, (void *)st);
					break;
				}
			}
			nst++;
			free(j);
		}

		ntrip_log(st, LOG_EDEBUG, "ran %d jobs for ntrip state %p\n", nst, st);

		bufferevent_unlock(bev);

		ntrip_deferred_run(this->caster, "joblist_run");
		/*
		 * Lock the list again for the next job.
		 */
		P_MUTEX_LOCK(&this->mutex);
	}
}

static int job_equal(struct job *j1, struct job *j2) {
	if (j1->type != j2->type)
		return 0;
	if (j1->type == JOB_LIBEVENT_RW)
		return j1->rw.cb == j2->rw.cb;
	if (j1->type == JOB_LIBEVENT_EVENT)
		return j1->event.events == j2->event.events && j1->event.cb == j2->event.cb;
	return 0;
}

static void _joblist_append_generic(struct joblist *this, struct ntrip_state *st, struct job *tmpj) {
	/*
	 * Check the bufferevent has not been freed
	 */
	assert(!st->bev_freed);

	P_MUTEX_LOCK(&this->append_mutex);

	/* Drop callback if ntrip_state is waiting for deletion */
	if (st->state == NTRIP_END) {
		P_MUTEX_UNLOCK(&this->append_mutex);
		return;
	}

	ntrip_log(st, LOG_EDEBUG, "appending job for %p njobs %d newjobs %d\n", st, st->njobs, st->newjobs);

	/*
	 * Check whether the ntrip_state queue is empty.
	 * If it is, we will need to insert the ntrip_state in the main job queue.
	 *
	 * In other words:
	 *	!jobq_was_empty <=> ntrip_state is in the main job queue
	 */
	int jobq_was_empty = STAILQ_EMPTY(&st->jobq);

	/*
	 * Deactivate callback deduplication for systems lacking STAILQ_LAST.
	 */
	struct job *lastj = STAILQ_LAST(&st->jobq, job, next);

	if (jobq_was_empty)
		assert(!st->njobs && !st->newjobs);
	else
		assert(st->njobs && st->newjobs == -1);

	/*
	 * Check the last recorded callback, if any. Skip if identical to the new one.
	 */
	struct job *j = NULL;
	if (lastj == NULL || !job_equal(lastj, tmpj)) {
		j = (struct job *)malloc(sizeof(struct job));
		if (j == NULL) {
			ntrip_log(st, LOG_CRIT, "Out of memory, cannot allocate job.\n");
			P_MUTEX_UNLOCK(&this->append_mutex);
			return;
		}

		/*
		 * Create and insert a new job record in the queue for this ntrip_state.
		 */
		*j = *tmpj;
		STAILQ_INSERT_TAIL(&st->jobq, j, next);
		st->njobs++;
		if (st->newjobs >= 0)
			st->newjobs++;
	}
	if (j == NULL) {
		P_MUTEX_UNLOCK(&this->append_mutex);
		return;
	}

	assert(jobq_was_empty ? st->newjobs == 1 : st->newjobs == -1);
	if (st->newjobs == 1) {
		/*
		 * Insertion needed in the main job queue.
		 */
		assert(st->newjobs != -1);
		ntrip_log(st, LOG_EDEBUG, "inserting in joblist ntrip_queue %p njobs %d newjobs %d\n", st, st->njobs, st->newjobs);
		STAILQ_INSERT_TAIL(&this->append_queue, st, next);
		st->newjobs = -1;
	} else {
		assert(st->newjobs == -1);
		ntrip_log(st, LOG_EDEBUG, "ntrip_state %p already in job list, njobs %d newjobs %d\n", st, st->njobs, st->newjobs);
	}

	/*
	 * Signal waiting workers there is a new job.
	 */
	if (pthread_cond_signal(&this->condjob) < 0)
		_log_error(this, "pthread_cond_signal");
	P_MUTEX_UNLOCK(&this->append_mutex);
}

/*
 * Add a new job at the end of the list.
 *
 * The bufferevent is already locked by libevent.
 */
void joblist_append(struct joblist *this, void (*cb)(struct bufferevent *bev, void *arg), void (*cbe)(struct bufferevent *bev, short events, void *arg), struct bufferevent *bev, void *arg, short events) {
	struct job tmpj;
	if (cb) {
		tmpj.type = JOB_LIBEVENT_RW;
		tmpj.rw.cb = cb;
	} else {
		tmpj.type = JOB_LIBEVENT_EVENT;
		tmpj.event.cb = cbe;
		tmpj.event.events = events;
	}
	_joblist_append_generic(this, (struct ntrip_state *)arg, &tmpj);
}

/*
 * Drain the job queue for a ntrip_state
 */
void joblist_drain(struct ntrip_state *st) {
	struct job *j;
	while ((j = STAILQ_FIRST(&st->jobq))) {
		STAILQ_REMOVE_HEAD(&st->jobq, next);
		st->njobs--;
		if (st->newjobs > 0) st->newjobs--;
		free(j);
	}
}

/*
 * Temporary structure to provide threads with the id
 * we have assigned them.
 */
struct thread_start_args {
	long thread_id;
	struct caster_state *caster;
};

void *jobs_start_routine(void *arg) {
	struct thread_start_args *start_args = (struct thread_start_args *)arg;
	struct caster_state *caster = start_args->caster;
	pthread_setspecific(caster->thread_id, (void *)(start_args->thread_id));
	printf("started thread %lu\n", start_args->thread_id);
	free(start_args);
	joblist_run(caster->joblist);
	return NULL;
}

int jobs_start_threads(struct caster_state *caster, int nthreads) {
	pthread_t *p = (pthread_t *)malloc(sizeof(pthread_t)*nthreads);
	if (p == NULL) {
		return -1;
	}

	pthread_key_create(&caster->thread_id, NULL);
	pthread_setspecific(caster->thread_id, 0);

	// Set stack size to the configured value
	size_t stacksize = caster->config->threads[0].stacksize;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, stacksize);
	printf("Setting thread stack size to %zu bytes\n", stacksize);

	for (int i = 0; i < nthreads; i++) {
		struct thread_start_args *args = (struct thread_start_args *)malloc(sizeof(struct thread_start_args));
		args->thread_id = i+1;
		args->caster = caster;
		int r = pthread_create(&p[i], &attr, jobs_start_routine, args);
		if (r < 0) {
			return -1;
		}
	}
	pthread_attr_destroy(&attr);
	return 0;
}
