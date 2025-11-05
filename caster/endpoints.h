#ifndef __ENDPOINTS_H__
#define __ENDPOINTS_H__

#include <json-c/json_object.h>

struct endpoint {
	const char *host;
	unsigned short port;
	int tls;
};

void endpoint_init(struct endpoint *this, const char *host, unsigned short port, int tls);
void endpoint_copy(struct endpoint *this, struct endpoint *orig);
void endpoint_free(struct endpoint *this);
void endpoints_free(struct endpoint *pe, int n);
struct endpoint *endpoints_from_json(json_object *j, int *pn);
json_object *endpoints_to_json(struct endpoint *pe, int n);

#endif
