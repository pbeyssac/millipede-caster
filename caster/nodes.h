#ifndef __NODES_H__
#define __NODES_H__

#include <time.h>

#include <json-c/json_object.h>

#include "hash.h"

enum node_state {
	NODE_INIT,
	NODE_DOWN,
	NODE_UP
};

struct node {
	json_object *j;
	struct timeval last_update;
	enum node_state state;
};

struct nodes {
	struct hash_table *nodes;
	P_RWLOCK_T lock;
};

struct nodes *nodes_new();
void nodes_free(struct nodes *this);
void node_set_state(struct nodes *this, const char *hostname, enum node_state state);
void nodes_add_node(struct nodes *this, const char *hostname, json_object *j);
int node_update_execute(struct caster_state *caster, struct json_object *json);
json_object *nodes_json(struct nodes *this);

#endif