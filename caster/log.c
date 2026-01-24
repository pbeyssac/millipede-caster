#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include "graylog_sender.h"
#include "log.h"

#define max(a,b)	((a)>=(b)?(a):(b))

int log_init(struct log *this, const char *filename, log_cb_t log_cb,
	int log_level, int graylog_level,  int syslog_level, int syslog_facility, void *arg) {
	P_RWLOCK_INIT(&this->lock, NULL);
	this->log_cb = log_cb;
	this->state = arg;
	this->syslog_facility = syslog_facility;
	this->syslog_level = syslog_level;
	this->graylog_level = graylog_level;
	this->log_level = log_level;
	this->max_log_level = max(max(syslog_level, graylog_level), log_level);

	// If filename is NULL, can't assign stderr to this->logfile as this causes weird side effects
	// Use NULL instead.

	this->logfile = NULL;
	if (filename) {
		this->logfile = fopen(filename, "a+");
		if (!this->logfile) {
			fprintf(stderr, "Can't open log file %s: %s\n", filename, strerror(errno));
			return -1;
		}
	}
	if (this->logfile)
		setlinebuf(this->logfile);
	return 0;
}

int log_reopen(struct log *this, const char *filename,
	int log_level, int graylog_level, int syslog_level, int syslog_facility) {
	FILE *newfile =	fopen(filename, "a+");
	if (!newfile) {
		fprintf(stderr, "Can't reopen log file %s: %s\n", filename, strerror(errno));
		return -1;
	}
	setlinebuf(newfile);
	P_RWLOCK_WRLOCK(&this->lock);
	atomic_store(&this->syslog_facility, syslog_facility);
	atomic_store(&this->syslog_level, syslog_level);
	atomic_store(&this->graylog_level, graylog_level);
	atomic_store(&this->log_level, log_level);
	atomic_store(&this->max_log_level, max(max(syslog_level, graylog_level), log_level));
	if (this->logfile)
		fclose(this->logfile);
	this->logfile = newfile;
	P_RWLOCK_UNLOCK(&this->lock);
	return 0;
}

void log_free(struct log *this) {
	P_RWLOCK_WRLOCK(&this->lock);
	if (this->logfile)
		fclose(this->logfile);
	P_RWLOCK_UNLOCK(&this->lock);
	P_RWLOCK_DESTROY(&this->lock);
}

static void logfmt_file(struct log *this, struct gelf_entry *g, int level, const char *fmt, ...) {
	va_list ap;
	char date[36];
	logdate(date, sizeof date, &g->ts);
	va_start(ap, fmt);
	P_RWLOCK_WRLOCK(&this->lock);
	FILE *out = this->logfile?this->logfile:stderr;
	fputs(date, out);
	fputc(' ', out);
	vfprintf(out, fmt, ap);
	P_RWLOCK_UNLOCK(&this->lock);
	va_end(ap);
}

static void logfmt_syslog(struct log *this, struct gelf_entry *g, int level, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vsyslog((level>LOG_DEBUG?LOG_DEBUG:level)|atomic_load(&this->syslog_facility), fmt, ap);
	va_end(ap);
}

static void logfmt_graylog(struct log *this, struct caster_state *caster, struct gelf_entry *g) {
	if (atomic_load(&caster->graylog_log_level) == -1)
		return;
	json_object *j = gelf_json(g);
	const char *s = json_object_to_json_string(j);
	graylog_sender_queue(caster->config->dyn->graylog[0], s);
	json_object_put(j);
}

void
logfmt_g(struct log *this, struct gelf_entry *g, int level, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	this->log_cb(this->state, g, level, fmt, ap);
	va_end(ap);
}

void
logfmt(struct log *this, int level, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	this->log_cb(this->state, NULL, level, fmt, ap);
	va_end(ap);
}

void
vlogall(struct caster_state *caster, struct gelf_entry *g, struct log *log, int level, const char *fmt, va_list ap) {
	struct gelf_entry localg;

	if (level < 0)
		return;

	int thread_id = threads?(long)pthread_getspecific(caster->thread_id):-1;

	if (g == NULL) {
		g = &localg;
		gelf_init(g, level, caster->hostname, thread_id);
	} else {
		g->hostname = caster->hostname;
		g->thread_id = thread_id;
	}

	char *msg;
	vasprintf(&msg, fmt, ap);

	if (level <= atomic_load(&log->log_level)) {
		if (threads)
			logfmt_file(log, g, level, "[%lu] %s\n", (long)thread_id, msg);
		else
			logfmt_file(log, g, level, "%s\n", msg);
	}

	if (level <= atomic_load(&log->syslog_level)) {
		if (threads)
			logfmt_syslog(log, g, level, "[%lu] %s\n", (long)thread_id, msg);
		else
			logfmt_syslog(log, g, level, "%s\n", msg);
	}

	if (!g->nograylog && atomic_load(&caster->graylog_log_level) != -1 && caster->config
	    && level <= atomic_load(&log->graylog_level)) {
		if (g->short_message == NULL) {
			g->short_message = msg;
			msg = NULL;
		}
		logfmt_graylog(log, caster, g);
	}
	free(g->short_message);
	g->short_message = NULL;
	free(msg);
}
