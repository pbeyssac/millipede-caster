#ifndef __CONF_H__
#define __CONF_H__

#define NTHREADS	3
#define	DEBUG		1
#define	DEBUG_EVENT	0

#ifdef THREADS
#include <pthread.h>

#define	P_RWLOCK_T			pthread_rwlock_t
#define	P_RWLOCK_INIT(arg, attr)	pthread_rwlock_init((arg),(attr))
#define	P_RWLOCK_WRLOCK(arg)		pthread_rwlock_wrlock(arg)
#define	P_RWLOCK_RDLOCK(arg)		pthread_rwlock_rdlock(arg)
#define	P_RWLOCK_UNLOCK(arg)		pthread_rwlock_unlock(arg)
#define	P_RWLOCK_DESTROY(arg)		pthread_rwlock_destroy(arg)
#define	P_MUTEX_T			pthread_mutex_t
#define	P_MUTEX_INIT(arg, attr)		pthread_mutex_init((arg),(attr))
#define	P_MUTEX_LOCK(arg)		pthread_mutex_lock(arg)
#define	P_MUTEX_UNLOCK(arg)		pthread_mutex_unlock(arg)
#define	P_MUTEX_DESTROY(arg)		pthread_mutex_destroy(arg)
#else
#define	P_RWLOCK_T			char
#define	P_RWLOCK_INIT(arg, attr)
#define	P_RWLOCK_WRLOCK(arg)
#define	P_RWLOCK_RDLOCK(arg)
#define	P_RWLOCK_UNLOCK(arg)
#define	P_RWLOCK_DESTROY(arg)
#define P_MUTEX_T			char
#define	P_MUTEX_INIT(arg, attr)
#define	P_MUTEX_LOCK(arg)
#define	P_MUTEX_UNLOCK(arg)
#define	P_MUTEX_DESTROY(arg)
#endif

#define	SERVER_VERSION_STRING	"pbs/0"
#define	CLIENT_VERSION_STRING	"pbc/0"

#endif
