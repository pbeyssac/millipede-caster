#include "conf.h"

#include <stdlib.h>

#include "sourceline.h"
#include "util.h"


struct sourceline *sourceline_new(const char *host, unsigned short port, const char *key, const char *value) {
	struct sourceline *this = (struct sourceline *)malloc(sizeof(struct sourceline));
	char *duphost = mystrdup(host);
	char *dupkey = mystrdup(key);
	char *dupvalue = mystrdup(value);
	if (!duphost || !dupkey || !dupvalue || !this) {
		strfree(duphost);
		strfree(dupkey);
		strfree(dupvalue);
		free(this);
		return NULL;
	}
	this->host = duphost;
	this->key = dupkey;
	this->value = dupvalue;
	this->port = port;
	return this;
}

/*
 * Return a deep copy of a struct sourceline
 */
struct sourceline *sourceline_copy(struct sourceline *orig) {
	struct sourceline *this = sourceline_new(orig->host, orig->port, orig->key, orig->value);
	if (this == NULL)
		return NULL;
	this->pos = orig->pos;
	this->on_demand = orig->on_demand;
	this->virtual = orig->virtual;
	return this;
}

void sourceline_free(struct sourceline *this) {
	strfree(this->host);
	strfree(this->key);
	strfree(this->value);
	free(this);
}
