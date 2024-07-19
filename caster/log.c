#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int log_init(struct log *this, const char *filename, log_cb_t log_cb, void *arg) {
	this->logfile = fopen(filename, "a+");
	if (!this->logfile) {
		fprintf(stderr, "Can't open log file %s: %s\n", filename, strerror(errno));
		exit(1);
	}
	this->log_cb = log_cb;
	this->state = arg;
	setlinebuf(this->logfile);
	return this->logfile == NULL ? -1:0;
}

void log_free(struct log *this) {
	fclose(this->logfile);
}

/*
static void
_log(struct log *this, const char *fmt, va_list ap) {
	char date[36];
	logdate(date, sizeof date);
	fputs(date, this->logfile);
	vfprintf(this->logfile, fmt, ap);
}
*/

void
logfmt(struct log *this, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	this->log_cb(this->state, fmt, ap);
	va_end(ap);
}
