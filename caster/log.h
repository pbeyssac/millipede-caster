#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

typedef void (*log_cb_t)(void *, const char *, va_list);

struct log {
	FILE *logfile;
	void *state;
	log_cb_t log_cb;
};

int log_init(struct log *this, const char *filename, log_cb_t log_cb, void *arg);
void logfmt(struct log *this, const char *fmt, ...);
void log_free(struct log *this);

#endif
