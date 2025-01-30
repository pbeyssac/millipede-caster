#ifndef _GELF_ENTRY_H
#define _GELF_ENTRY_H

#include <sys/time.h>

#include <json-c/json.h>

/* Structure to store date for the GELF log format */

struct gelf_entry {
	struct timeval ts;				// date
	int level;					// log level
	const char *remote_ip;				// remote host IP
	int remote_port;				// remote port
	const char *hostname;				// local hostname
	char *short_message;				// Message itself
	int thread_id;					// Thread id or -1
	unsigned long long connection_id;		// IP connection id
	char nograylog;					// Skip sending to graylog
};

void gelf_init(struct gelf_entry *g, int level, const char *hostname, int thread_id);
json_object *gelf_json(struct gelf_entry *g);

#endif
