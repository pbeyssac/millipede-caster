#ifndef _REQUEST_H_
#define _REQUEST_H_

struct caster_state;
struct json_object;

struct request {
	struct hash_table *hash;
	unsigned short status;
};

struct request *request_new();
void request_free(struct request *this);

#endif
