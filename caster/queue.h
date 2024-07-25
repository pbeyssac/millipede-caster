#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <sys/queue.h>

/*
 * Linux-compatibility.
 *
 * Code taken from FreeBSD <sys/queue.h>
 */

#ifndef TAILQ_REMOVE_HEAD
#define TAILQ_REMOVE_HEAD(head, field)					\
	TAILQ_REMOVE(head, TAILQ_FIRST(head), field)
#endif

#ifndef TAILQ_FOREACH_SAFE
#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#endif
