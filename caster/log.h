#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#include "conf.h"
#include "gelf.h"

typedef void (*log_cb_t)(void *, struct gelf_entry *, int, const char *, va_list);

struct log {
	FILE *logfile;		// NULL causes use of stderr instead
	void *state;
	_Atomic int syslog_facility;
	_Atomic int max_log_level;
	_Atomic int syslog_level, graylog_level, log_level;
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

struct caster_state;

int log_init(struct log *this, const char *filename, log_cb_t log_cb, int graylog_level, int log_level, int syslog_level, int syslog_facility, void *arg);
int log_reopen(struct log *this, const char *filename, int log_level, int graylog_level, int syslog_level, int syslog_facility);
void logfmt_g(struct log *this, struct gelf_entry *g, int level, const char *fmt, ...);
void logfmt(struct log *this, int level, const char *fmt, ...);
void log_free(struct log *this);
void vlogall(struct caster_state *caster, struct gelf_entry *g, struct log *log, int level, const char *fmt, va_list ap);

#endif
