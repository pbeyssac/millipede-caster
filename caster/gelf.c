#include <json-c/json.h>

#include "gelf.h"
#include "util.h"

/*
 * GELF format handling.
 */

/*
 * Initialize a GELF structure.
 */
void gelf_init(struct gelf_entry *g, int level, const char *hostname, int thread_id) {
	g->level = level;
	g->short_message = NULL;
	g->remote_ip = NULL;
	g->remote_port = 0;
	g->hostname = hostname;
	g->thread_id = thread_id;
	g->connection_id = 0;
	g->nograylog = 0;
	gettimeofday(&g->ts, NULL);
}

/*
 * Convert a GELF structure to JSON.
 */
json_object *gelf_json(struct gelf_entry *g) {
	json_object *new_obj = json_object_new_object();
	if (g->thread_id >= 0)
		json_object_object_add(new_obj, "_thread_id", json_object_new_int(g->thread_id));
	if (g->remote_ip) {
		json_object_object_add(new_obj, "_remote_ip", json_object_new_string(g->remote_ip));
		json_object_object_add(new_obj, "_remote_port", json_object_new_int(g->remote_port));
	}
	json_object_object_add(new_obj, "level", json_object_new_int(g->level));
	json_object_object_add(new_obj, "short_message", json_object_new_string(g->short_message));
	json_object_object_add(new_obj, "host", json_object_new_string(g->hostname));
	json_object_object_add(new_obj, "version", json_object_new_string("1.1"));
	if (g->connection_id)
		json_object_object_add(new_obj, "_connection_id", json_object_new_int64(g->connection_id));
	json_object_object_add(new_obj, "timestamp", json_object_new_double((double)g->ts.tv_sec + g->ts.tv_usec/1000000.));
	return new_obj;
}
