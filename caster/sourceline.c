#include "conf.h"

#include <stdlib.h>

#include "sourceline.h"
#include "util.h"


struct sourceline *sourceline_new() {
	struct sourceline *this = (struct sourceline *)malloc(sizeof(struct sourceline));
	return this;
}

/*
 * Return a deep copy of a struct sourceline
 */
struct sourceline *sourceline_copy(struct sourceline *orig) {
	struct sourceline *this = (struct sourceline *)malloc(sizeof(struct sourceline));
	this->host = mystrdup(orig->host);
	this->key = mystrdup(orig->key);
	this->value = mystrdup(orig->value);
	this->port = orig->port;
	this->pos = orig->pos;
	this->on_demand = orig->on_demand;
	this->virtual = orig->virtual;

	if (this->host == NULL || this->key == NULL || this->value == NULL) {
		strfree(this->host);
		strfree(this->key);
		strfree(this->value);
		return NULL;
	}
	return this;
}

void sourceline_free(struct sourceline *this) {
	strfree(this->host);
	strfree(this->key);
	strfree(this->value);
	free(this);
}
