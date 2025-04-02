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

// General constant for shorter calls to json-c's API json_object_object_add_ex()
#define JSON_C_CONSTANT_NEW	(JSON_C_OBJECT_ADD_CONSTANT_KEY|JSON_C_OBJECT_ADD_KEY_IS_NEW)

/*
 * Server and client version strings for HTTP
 */
#define	SERVER_VERSION_STRING	"Millipede Server 0.8"		// For Server: header
#define	CLIENT_VERSION_STRING	"Millipede Client 0.8"		// User-Agent header, prepended with "NTRIP "

extern int threads;
extern int nthreads;

#endif
