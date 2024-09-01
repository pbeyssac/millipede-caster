#include <assert.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "conf.h"
#include "caster.h"
#include "jobs.h"
#include "ntrip_common.h"


/*
 * Create a job list.
 */
struct joblist *joblist_new(struct caster_state *caster) {
	struct joblist *this = (struct joblist *)malloc(sizeof(struct joblist));
	if (this != NULL) {
		this->ntrip_njobs = 0;
		this->append_ntrip_njobs = 0;
		this->njobs = 0;
		this->append_njobs = 0;
		this->caster = caster;
		this->nthreads = 0;
		this->threads = NULL;
		STAILQ_INIT(&this->ntrip_queue);
		STAILQ_INIT(&this->append_queue);
		STAILQ_INIT(&this->jobq);
		STAILQ_INIT(&this->append_jobq);
		P_MUTEX_INIT(&this->mutex, NULL);
		P_MUTEX_INIT(&this->append_mutex, NULL);
		if (pthread_cond_init(&this->condjob, NULL) < 0)
			caster_log_error(this->caster, "pthread_cond_init");
	}
	return this;
}

/*
 * Required lock: ntrip_state
 */
static int _joblist_drain(struct jobq *jobq) {
	struct job *j;
	int n = 0;
	while ((j = STAILQ_FIRST(jobq))) {
		STAILQ_REMOVE_HEAD(jobq, next);
		n++;
		free(j);
	}
	return n;
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
	_joblist_drain(&this->jobq);
	P_MUTEX_UNLOCK(&this->mutex);
	P_MUTEX_LOCK(&this->append_mutex);
	while ((st = STAILQ_FIRST(&this->append_queue))) {
		STAILQ_REMOVE_HEAD(&this->append_queue, next);
		joblist_drain(st);
	}
	_joblist_drain(&this->append_jobq);
	P_MUTEX_UNLOCK(&this->append_mutex);
	P_MUTEX_UNLOCK(&this->mutex);
	P_MUTEX_DESTROY(&this->mutex);
	P_MUTEX_DESTROY(&this->append_mutex);
	if (pthread_cond_destroy(&this->condjob) < 0)
		caster_log_error(this->caster, "pthread_cond_signal");
	free(this);
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
	 * Initial lock acquisition on the job lists
	 */
	P_MUTEX_LOCK(&this->mutex);

	/*
	 * Now run jobs forever.
	 */
	while(1) {
		/*
		 * Check the independent/unlocked queues
		 */
		j = STAILQ_FIRST(&this->jobq);
		if (j == NULL) {
			assert(this->njobs == 0);
			/* Empty queue, check the corresponding append queue */
			P_MUTEX_LOCK(&this->append_mutex);
			STAILQ_SWAP(&this->jobq, &this->append_jobq, job);
			assert(this->append_njobs >= 0);
			int tmpn = this->njobs;
			this->njobs = this->append_njobs;
			this->append_njobs = tmpn;
			P_MUTEX_UNLOCK(&this->append_mutex);
			j = STAILQ_FIRST(&this->jobq);
		}
		assert(this->njobs >= 0);
		if (j) {
			assert(this->njobs > 0);
			STAILQ_REMOVE_HEAD(&this->jobq, next);
			this->njobs--;
			P_MUTEX_UNLOCK(&this->mutex);
			if (j->type == JOB_REDISTRIBUTE)
				j->redistribute.cb(j->redistribute.arg);
			else if (j->type == JOB_NTRIP_UNLOCKED)
				j->ntrip_unlocked.cb(j->ntrip_unlocked.st);
			else if (j->type == JOB_NTRIP_UNLOCKED_CONTENT)
				j->ntrip_unlocked_content.cb(j->ntrip_unlocked_content.st, j->ntrip_unlocked_content.content_cb);
			else if (j->type == JOB_STOP_THREAD)
				pthread_exit(NULL);
			free(j);
			P_MUTEX_LOCK(&this->mutex);
		}

		/*
		 * Check the locked ntrip_state work queues
		 */
		st = STAILQ_FIRST(&this->ntrip_queue);
		if (st == NULL) {
			/*
			 * Work queue is empty, check the append queue for a refill.
			 */
			P_MUTEX_LOCK(&this->append_mutex);
			st = STAILQ_FIRST(&this->append_queue);
			if (st == NULL) {
				P_MUTEX_UNLOCK(&this->append_mutex);
				if (j != NULL)
					/* jobq wasn't empty last time we checked, restart */
					continue;
				/*
				 * All queues empty => wait.
				 */
				if (pthread_cond_wait(&this->condjob, &this->mutex) < 0)
					caster_log_error(this->caster, "pthread_cond_wait");
				continue;
			}
			/*
			 * Fill the work queue, empty the append queue.
			 */
			STAILQ_SWAP(&this->ntrip_queue, &this->append_queue, ntrip_state);
			int tmpn = this->ntrip_njobs;
			this->ntrip_njobs = this->append_ntrip_njobs;
			this->append_ntrip_njobs = tmpn;
			pthread_cond_broadcast(&this->condjob);
			P_MUTEX_UNLOCK(&this->append_mutex);
		}

		/*
		 * We have the first ready session in the queue, remove it
		 * so we can release the lock on the list.
		 */

		STAILQ_REMOVE_HEAD(&this->ntrip_queue, next);
		this->ntrip_njobs--;

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
				case JOB_NTRIP_LOCK:
					j->ntrip_locked.cb(st);
					break;
				default:
					abort();
					break;
				}
			}
			free(j);
		}

		bufferevent_unlock(bev);

		ntrip_deferred_run(this->caster);
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
	if (j1->type == JOB_NTRIP_LOCK)
		return j1->ntrip_locked.cb == j2->ntrip_locked.cb;
	return 0;
}

/*
 * Append a new job.
 *
 * If st != NULL:
 *	append to this ntrip_state's job queue.
 *	required lock: ntrip_state.
 *
 * If st == NULL:
 *	append to the main job queue.
 *	no required lock.
 */
static void _joblist_append_generic(struct joblist *this, struct ntrip_state *st, struct job *tmpj) {
	struct job *j = NULL;
	if (st == NULL) {
		P_MUTEX_LOCK(&this->append_mutex);
		j = (struct job *)malloc(sizeof(struct job));
		if (j == NULL) {
			//ntrip_log(st, LOG_CRIT, "Out of memory, cannot allocate job.\n");
			return;
		}
		memcpy(j, tmpj, sizeof(*j));
		assert(this->append_njobs >= 0);
		STAILQ_INSERT_TAIL(&this->append_jobq, j, next);
		this->append_njobs++;
		P_MUTEX_UNLOCK(&this->append_mutex);
		return;
	}

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

	/*
	 * Check whether the ntrip_state queue is empty.
	 * If it is, we will need to insert the ntrip_state in the main job queue.
	 *
	 * In other words:
	 *	!jobq_was_empty <=> ntrip_state is in the main job queue
	 */
	int jobq_was_empty = STAILQ_EMPTY(&st->jobq);

	struct job *lastj = STAILQ_LAST(&st->jobq, job, next);

	if (jobq_was_empty)
		assert(!st->njobs && st->newjobs <= 0);
	else
		assert(st->njobs /* && st->newjobs == -1 */);

	/*
	 * Check the last recorded callback, if any. Skip if identical to the new one.
	 */
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

	assert(jobq_was_empty ? (st->newjobs == 1 || st->newjobs == -1) : 1);
	if (st->newjobs == 1) {
		/*
		 * Insertion needed in the main job queue.
		 */
		assert(st->newjobs != -1);
		ntrip_log(st, LOG_EDEBUG, "job appended, inserting in joblist ntrip_queue njobs %d newjobs %d\n", st->njobs, st->newjobs);
		STAILQ_INSERT_TAIL(&this->append_queue, st, next);
		this->append_ntrip_njobs++;
		st->newjobs = -1;
	} else {
		assert(st->newjobs == -1);
		ntrip_log(st, LOG_EDEBUG, "job appended, ntrip already in job list, njobs %d newjobs %d\n", st->njobs, st->newjobs);
	}

	/*
	 * Signal waiting workers there is a new job.
	 */
	if (pthread_cond_signal(&this->condjob) < 0)
		caster_log_error(this->caster, "pthread_cond_signal");
	P_MUTEX_UNLOCK(&this->append_mutex);
}

/*
 * Add a new job at the end of the list for this ntrip_state.
 *
 * The bufferevent/ntrip_state is already locked by libevent.
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
 * Queue a new job for a ntrip_state at the end of its list, or directly execute in unthreaded mode.
 * Required lock: ntrip_state
 */
void joblist_append_ntrip_locked(struct joblist *this, struct ntrip_state *st, void (*cb)(struct ntrip_state *arg)) {
	if (threads) {
		struct job tmpj;
		tmpj.type = JOB_NTRIP_LOCK;
		tmpj.ntrip_locked.cb = cb;
		_joblist_append_generic(this, st, &tmpj);
	} else
		cb(st);
}

/*
 * Queue a new redistribute job, or directly execute in unthreaded mode.
 */
void joblist_append_redistribute(struct joblist *this, void (*cb)(struct redistribute_cb_args *redis_args), struct redistribute_cb_args *redis_args) {
	if (threads) {
		struct job tmpj;
		tmpj.type = JOB_REDISTRIBUTE;
		tmpj.redistribute.cb = cb;
		tmpj.redistribute.arg = redis_args;
		_joblist_append_generic(this, NULL, &tmpj);
	} else
		cb(redis_args);
}

/*
 * Queue a new unlocked ntrip job, or directly execute in unthreaded mode.
 */
void joblist_append_ntrip_unlocked(struct joblist *this, void (*cb)(struct ntrip_state *st), struct ntrip_state *st) {
	if (threads) {
		struct job tmpj;
		tmpj.type = JOB_NTRIP_UNLOCKED;
		tmpj.ntrip_unlocked.cb = cb;
		tmpj.ntrip_unlocked.st = st;
		_joblist_append_generic(this, NULL, &tmpj);
	} else
		cb(st);
}

/*
 * Queue a new unlocked ntrip job, or directly execute in unthreaded mode.
 */
void joblist_append_ntrip_unlocked_content(struct joblist *this, void (*cb)(struct ntrip_state *st, struct mime_content *(*content_cb)(struct caster_state *caster
)), struct ntrip_state *st, struct mime_content *(*content_cb)(struct caster_state *caster)) {
	if (threads) {
		struct job tmpj;
		tmpj.type = JOB_NTRIP_UNLOCKED_CONTENT;
		tmpj.ntrip_unlocked_content.cb = cb;
		tmpj.ntrip_unlocked_content.st = st;
		tmpj.ntrip_unlocked_content.content_cb = content_cb;
		_joblist_append_generic(this, NULL, &tmpj);
	} else
		cb(st, content_cb);
}

void joblist_append_stop(struct joblist *this) {
	struct job tmpj;
	tmpj.type = JOB_STOP_THREAD;
	_joblist_append_generic(this, NULL, &tmpj);
}

/*
 * Drain the job queue for a ntrip_state
 *
 * Required lock: ntrip_state
 */
void joblist_drain(struct ntrip_state *st) {
	int old_newjobs = st->newjobs;
	int n = _joblist_drain(&st->jobq);
	st->njobs -= n;
	if (old_newjobs > 0)
		st->newjobs = st->newjobs > n ? st->newjobs-n : 0;
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

int jobs_start_threads(struct joblist *this, int nthreads) {
	int err = 0;
	pthread_t *p = (pthread_t *)malloc(sizeof(pthread_t)*nthreads);
	if (p == NULL) {
		return -1;
	}

	pthread_key_create(&this->caster->thread_id, NULL);
	pthread_setspecific(this->caster->thread_id, 0);

	// Set stack size to the configured value
	size_t stacksize = this->caster->config->threads[0].stacksize;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, stacksize);
	printf("Setting thread stack size to %zu bytes\n", stacksize);

	int i;
	for (i = 0; i < nthreads; i++) {
		struct thread_start_args *args = (struct thread_start_args *)malloc(sizeof(struct thread_start_args));
		args->thread_id = i+1;
		args->caster = this->caster;
		int r = pthread_create(&p[i], &attr, jobs_start_routine, args);
		if (r != 0) {
			err = 1;
			free(args);
			break;
		}
	}
	pthread_attr_destroy(&attr);

	if (err) {
		this->nthreads = i;
		jobs_stop_threads(this);
		return -1;
	}

	this->threads = p;
	this->nthreads = nthreads;
	return 0;
}

void jobs_stop_threads(struct joblist *this) {
	for (int i = 0; i < this->nthreads; i++) {
		joblist_append_stop(this);
		pthread_yield();
	}

	int r, nlive;

	do {
		nlive = 0;
		for (int i = 0; i < this->nthreads; i++) {
			r = pthread_kill(this->threads[i], 0);
			if (r == 0)
				nlive++;
		}
		if (nlive != 0) {
			logfmt(&this->caster->flog, "%d thread(s) still active, waiting\n", nlive);
			sleep(1);
		}
	} while (nlive);
	free(this->threads);
	this->threads = NULL;
	this->nthreads = 0;
}
