#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#include "conf.h"
#include "gelf.h"

typedef void (*log_cb_t)(void *, struct gelf_entry *, int, const char *, va_list);

struct log {
	FILE *logfile;
	void *state;
	log_cb_t log_cb;
	P_RWLOCK_T lock;
};

/* Log levels, same as syslog and GEF + LOG_EDEBUG */

#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */
#define	LOG_EDEBUG	8	/* extended debug messages */

int log_init(struct log *this, const char *filename, log_cb_t log_cb, void *arg);
int log_reopen(struct log *this, const char *filename);
void logfmt_direct(struct log *this, struct gelf_entry *g, int level, const char *fmt, ...);
void logfmt_g(struct log *this, struct gelf_entry *g, int level, const char *fmt, ...);
void logfmt(struct log *this, int level, const char *fmt, ...);
void log_free(struct log *this);

#endif
