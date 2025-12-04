#include <assert.h>
#include <stdio.h>

#include <json-c/json_object.h>

#include "caster.h"
#include "nodes.h"

/*
 * Node table handling functions.
 */
const char *node_status[3] = {"INIT", "DOWN", "UP"};

static void node_free(void *arg) {
	struct node *this = (struct node *)arg;
	if (this->j)
		json_object_put(this->j);
	free(this);
}

struct nodes *nodes_new() {
	struct nodes *this = (struct nodes *)malloc(sizeof(struct nodes));
	if (this == NULL)
		return NULL;
	this->nodes = hash_table_new(509, node_free);
	if (this->nodes == NULL) {
		free(this);
		return NULL;
	}
	P_RWLOCK_INIT(&this->lock, NULL);
	return this;
}

void nodes_free(struct nodes *this) {
	P_RWLOCK_DESTROY(&this->lock);
	hash_table_free(this->nodes);
	free(this);
}

void node_set_state(struct nodes *this, const char *hostname, enum node_state state) {
	P_RWLOCK_WRLOCK(&this->lock);
	struct node *n = (struct node *)hash_table_get(this->nodes, hostname);
	if (n != NULL) {
		gettimeofday(&n->last_update, NULL);
		n->state = state;
	}
	P_RWLOCK_UNLOCK(&this->lock);
}

void nodes_add_node(struct nodes *this, const char *hostname, json_object *j) {
	P_RWLOCK_WRLOCK(&this->lock);
	struct node *n = (struct node *)hash_table_get(this->nodes, hostname);
	if (n != NULL) {
		if (j != NULL) {
			if (n->j != NULL)
				json_object_put(n->j);
			n->j = j;
		}
		gettimeofday(&n->last_update, NULL);
	} else {
		n = (struct node *)malloc(sizeof(struct node));
		if (n != NULL) {
			gettimeofday(&n->last_update, NULL);
			n->j = j;
			n->state = NODE_UP;
			int e = hash_table_add(this->nodes, hostname, n);
			assert(e != -1);
			if (e == -2) {
				/* Out of memory */
				free(n);
				n = NULL;
			}
		}
		if (n == NULL)
			json_object_put(j);
	}
	P_RWLOCK_UNLOCK(&this->lock);
}

int node_update_execute(struct caster_state *caster, struct json_object *json) {
	fprintf(stderr, "nodes: %s\n", json_object_get_string(json));
	return 200;
}

json_object *node_json(struct caster_state *caster) {
	json_object *j = json_object_new_object();
	json_object_object_add_ex(j, "hostname", json_object_new_string(caster->hostname), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(j, "endpoints", json_object_get(caster->config->endpoints_json), JSON_C_CONSTANT_NEW);
	return j;
}

json_object *nodes_json(struct nodes *this) {
	json_object *jlist = json_object_new_object();
	struct hash_iterator hi;
	struct element *e;
	P_RWLOCK_RDLOCK(&this->lock);
	HASH_FOREACH(e, this->nodes, hi) {
		struct node *n = (struct node *)e->value;
		json_object *j = json_object_new_object();
		json_object_object_add_ex(j, "endpoints", json_object_get(n->j), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(j, "status", json_object_new_string(node_status[n->state]), JSON_C_CONSTANT_NEW);
		json_object_object_add(jlist, e->key, j);
		timeval_to_json(&n->last_update, j, "last_update");
	}
	P_RWLOCK_UNLOCK(&this->lock);
	return jlist;
}
