#include <stdlib.h>

#include <json-c/json_object.h>

#include "endpoints.h"
#include "util.h"

/*
 * Handle endpoint arrays and structures
 */

void endpoint_init(struct endpoint *this, const char *host, unsigned short port, int tls) {
	if (host)
		this->host = mystrdup(host);
	else
		this->host = host;
	this->tls = tls;
	this->port = port;
}

void endpoint_copy(struct endpoint *this, struct endpoint *orig) {
	endpoint_init(this, orig->host, orig->port, orig->tls);
}

void endpoint_free(struct endpoint *this) {
	strfree((char *)this->host);
}

void endpoints_free(struct endpoint *pe, int n) {
	for (int i = 0; i < n; i++)
		strfree((char *)pe[i].host);
	free(pe);
}

struct endpoint *endpoints_from_json(json_object *j, int *pn) {
	int i;
	int n = json_object_array_length(j);
	struct endpoint *pe = (struct endpoint *)malloc(sizeof(struct endpoint)*n);
	for (i = 0; i < n; i++) {
		json_object *ji = json_object_array_get_idx(j, i);
		const char *host = json_object_get_string(json_object_object_get(ji, "host"));
		json_object *jtls = json_object_object_get(ji, "tls");
		json_object *jport = json_object_object_get(ji, "port");
		if (jport == NULL || host == NULL || jtls == NULL) {
			endpoints_free(pe, i-1);
			pe = NULL;
			break;
		}
		endpoint_init(pe+i, host, json_object_get_int(jport), json_object_get_boolean(jtls));
	}
	*pn = n;
	return pe;
}

json_object *endpoints_to_json(struct endpoint *pe, int n) {
	json_object *j = json_object_new_array_ext(n);
	for (int i = 0; i < n; i++) {
		json_object *ji = json_object_new_object();
		json_object_object_add_ex(ji, "host", json_object_new_string(pe[i].host), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(ji, "tls", json_object_new_boolean(pe[i].tls), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(ji, "port", json_object_new_int(pe[i].port), JSON_C_CONSTANT_NEW);
		json_object_array_add(j, ji);
	}
	return j;
}
