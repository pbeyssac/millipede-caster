#ifndef _ENDPOINTS_H_
#define _ENDPOINTS_H_

struct endpoint {
	char *host;
	unsigned short port;
	int tls;
};

void endpoints_free(struct endpoint *pe, int n);
struct endpoint *endpoints_from_json(json_object *j, int *pn);
json_object *endpoints_to_json(struct endpoint *pe, int n);

#endif
