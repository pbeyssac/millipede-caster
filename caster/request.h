#ifndef __REQUEST_H__
#define __REQUEST_H__

struct caster_state;
struct json_object;

struct request {
	struct hash_table *hash;
	struct json_object *json;
	unsigned short status;
};

struct request *request_new();
void request_free(struct request *this);

#endif
