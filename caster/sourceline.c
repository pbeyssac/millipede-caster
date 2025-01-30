#include "conf.h"

#include <stdlib.h>
#include <string.h>

#include "sourceline.h"
#include "util.h"


struct sourceline *sourceline_new(const char *host, unsigned short port, int tls, const char *key, const char *value, int priority) {
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
	this->tls = tls;
	this->priority = priority;
	return this;
}

/*
 * Return a new struct sourceline * parsed from the provided entry, a "STR;..." line.
 */
struct sourceline *sourceline_new_parse(const char *entry, const char *caster, unsigned short port, int tls, int priority, int on_demand) {
	struct sourceline *r = NULL;

	if (memcmp("STR;", entry, 4))
		return NULL;

	char *valueparse = mystrdup(entry);
	if (valueparse == NULL)
		return NULL;

	char *p1 = valueparse + 4;
	char *p2 = p1;
	char *token;

	while (*p2 && *p2 != ';') p2++;
	if (!*p2) {
		strfree(valueparse);
		return NULL;
	}

	char *key = (char *)strmalloc(p2 - p1 + 1);
	if (key == NULL) {
		strfree(valueparse);
		return NULL;
	}
	key[p2-p1] = '\0';
	memcpy(key, p1, p2-p1);
	struct sourceline *n1 = sourceline_new(caster, port, tls, key, entry, priority);
	strfree(key);
	if (n1 == NULL) {
		strfree(valueparse);
		return NULL;
	}
	n1->virtual = 0;
	n1->on_demand = on_demand;
	int err = 0, n = 0;
	pos_t pos;
	char *septmp = valueparse;
	while ((token = strsep(&septmp, ";")) != NULL) {
		if (n == 9) {
			if (sscanf(token, "%f", &pos.lat) != 1) {
				err = 1;
			}
		} else if (n == 10) {
			if (sscanf(token, "%f", &pos.lon) != 1) {
				err = 1;
			}
		} else if (n == 11) {
			int virtual;
			if (sscanf(token, "%d", &virtual) == 1)
				n1->virtual = virtual;
		} else if (n == 17) {
			int bps = 9600;
			if (sscanf(token, "%d", &bps) == 1)
				n1->bps = bps;
		}
		n++;
	}
	if (n != 19) err = 1;
	if (err) {
		sourceline_free(n1);
		r = NULL;
	} else {
		n1->pos = pos;
		r = n1;
	}
	strfree(valueparse);
	return r;
}

/*
 * Return a deep copy of a struct sourceline
 */
struct sourceline *sourceline_copy(struct sourceline *orig) {
	struct sourceline *this = sourceline_new(orig->host, orig->port, orig->tls, orig->key, orig->value, orig->priority);
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
