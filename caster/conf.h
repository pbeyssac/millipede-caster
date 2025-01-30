#ifndef __CONF_H__
#define __CONF_H__

#define	DEBUG		1
#define	DEBUG_EVENT	0

#include <pthread.h>

#define	P_RWLOCK_T			pthread_rwlock_t
#define	P_RWLOCK_INIT(arg, attr)	{if (threads) pthread_rwlock_init((arg),(attr));}
#define	P_RWLOCK_WRLOCK(arg)		{if (threads) pthread_rwlock_wrlock(arg);}
#define	P_RWLOCK_RDLOCK(arg)		{if (threads) pthread_rwlock_rdlock(arg);}
#define	P_RWLOCK_UNLOCK(arg)		{if (threads) pthread_rwlock_unlock(arg);}
#define	P_RWLOCK_DESTROY(arg)		{if (threads) pthread_rwlock_destroy(arg);}
#define	P_MUTEX_T			pthread_mutex_t
#define	P_MUTEX_INIT(arg, attr)		{if (threads) pthread_mutex_init((arg),(attr));}
#define	P_MUTEX_LOCK(arg)		{if (threads) pthread_mutex_lock(arg);}
#define	P_MUTEX_UNLOCK(arg)		{if (threads) pthread_mutex_unlock(arg);}
#define	P_MUTEX_DESTROY(arg)		{if (threads) pthread_mutex_destroy(arg);}

/*
 * Server and client version strings for HTTP
 */
#define	SERVER_VERSION_STRING	"Millipede Server 0.7"		// For Server: header
#define	CLIENT_VERSION_STRING	"Millipede Client 0.7"		// User-Agent header, prepended with "NTRIP "

extern int threads;
extern int nthreads;

#endif
