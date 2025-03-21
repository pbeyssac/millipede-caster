#include "conf.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>

#include "livesource.h"
#include "log.h"
#include "ntrip_common.h"
#include "sourcetable.h"

/*
 * Read a sourcetable file
 */
struct sourcetable *sourcetable_read(struct caster_state *caster, const char *filename, int priority) {
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen;
	int nlines = 0;

	FILE *fp = fopen(filename, "r+");
	if (fp == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Can't open %s", filename);
		return NULL;
	}

	struct sourcetable *tmp_sourcetable = sourcetable_new("LOCAL", 0, 0);
	tmp_sourcetable->local = 1;
	tmp_sourcetable->filename = mystrdup(filename);
	while ((linelen = getline(&line, &linecap, fp)) > 0) {
		nlines++;
		for (; line[linelen-1] == '\n' || line[linelen-1] == '\r'; linelen--)
			line[linelen-1] = '\0';
		if (linelen == 0)
			/* Skip empty line */
			continue;
		char *p;
		for (p = line; *p && isspace(*p); p++);
		if (*p == '#')
			/* Skip comment line */
			continue;
		if (sourcetable_add(tmp_sourcetable, line, 0, caster) < 0) {
			logfmt(&caster->flog, LOG_ERR, "Can't parse line %d in sourcetable", nlines);
			sourcetable_free(tmp_sourcetable);
			return NULL;
		}
	}
	tmp_sourcetable->priority = priority;
	strfree(line);
	return tmp_sourcetable;
}

/*
 * Parse a sourcetable from a JSON object.
 */
static struct sourcetable *sourcetable_from_json(json_object *j, struct caster_state *caster) {
	struct sourcetable *tmp_sourcetable;

	json_object *jhost = json_object_object_get(j, "host");
	json_object *jport = json_object_object_get(j, "port");
	json_object *jtls = json_object_object_get(j, "tls");
	json_object *jpull = json_object_object_get(j, "pullable");
	json_object *jprio = json_object_object_get(j, "priority");
	json_object *jdate = json_object_object_get(j, "fetch_time");
	json_object *tlist = json_object_object_get(j, "mountpoints");

	if (!jhost || !jport || !jdate || !jpull || !tlist)
		return NULL;

	const char *host = json_object_get_string(jhost);
	const char *date = json_object_get_string(jdate);
	unsigned short port = json_object_get_int(jport);
	unsigned short tls = jtls?json_object_get_boolean(jtls):0;

	tmp_sourcetable = sourcetable_new(host, port, tls);
	if (tmp_sourcetable == NULL)
		return NULL;

	tmp_sourcetable->pullable = json_object_get_boolean(jpull);
	tmp_sourcetable->priority = jprio?json_object_get_int(jprio):0;

	struct json_object_iterator it;
	struct json_object_iterator itEnd;

	timeval_from_iso_date(&tmp_sourcetable->fetch_time, date);

	it = json_object_iter_begin(tlist);
	itEnd = json_object_iter_end(tlist);

	while (!json_object_iter_equal(&it, &itEnd)) {
		//const char *mountpoint = json_object_iter_peek_name(&it);
		struct json_object *source = json_object_iter_peek_value(&it);
		const char *str = json_object_get_string(json_object_object_get(source, "str"));

		if (str == NULL || sourcetable_add(tmp_sourcetable, str, tmp_sourcetable->pullable, caster) < 0) {
			sourcetable_free(tmp_sourcetable);
			tmp_sourcetable = NULL;
			break;
		}
		json_object_iter_next(&it);
	}
	return tmp_sourcetable;
}

struct sourcetable *sourcetable_new(const char *host, unsigned short port, int tls) {
	struct sourcetable *this = (struct sourcetable *)malloc(sizeof(struct sourcetable));
	char *duphost = (host == NULL) ? NULL : mystrdup(host);
	char *header = mystrdup("");
	struct hash_table *kv = hash_table_new(509, (void (*)(void *))sourceline_free);
	if ((host != NULL && duphost == NULL) || header == NULL || this == NULL || kv == NULL) {
		strfree(duphost);
		strfree(header);
		free(this);
		if (kv) hash_table_free(kv);
		return NULL;
	}

	P_RWLOCK_INIT(&this->lock, NULL);
	this->caster = duphost;
	this->port = port;
	this->filename = NULL;
	this->header = header;
	this->pullable = 0;
	this->local = 0;
	this->priority = 0;
	this->key_val = kv;
	struct timeval t = { 0, 0 };
	this->fetch_time = t;
	this->nvirtual = 0;
	this->tls = tls;
	return this;
}

void sourcetable_free_unlocked(struct sourcetable *this) {
	strfree(this->header);
	strfree(this->caster);
	strfree((char *)this->filename);

	hash_table_free(this->key_val);

	P_RWLOCK_UNLOCK(&this->lock);
	P_RWLOCK_DESTROY(&this->lock);
	free(this);
}

void sourcetable_free(struct sourcetable *this) {
	P_RWLOCK_WRLOCK(&this->lock);
	sourcetable_free_unlocked(this);
}

/*
 * Return sourcetable as a string.
 */
struct mime_content *sourcetable_get(struct sourcetable *this) {
	struct sourceline *n;
	P_RWLOCK_RDLOCK(&this->lock);

	/*
	 * Compute string size for the final sourcetable.
	 */

	int len = strlen(this->header)+17;

	struct element *e;
	struct hash_iterator hi;
	HASH_FOREACH(e, this->key_val, hi) {
		n = (struct sourceline *)e->value;
		len += strlen(n->value) + 2;
	}

	char *s = (char *)strmalloc(len);

	/*
	 * Build the result per se
	 */
	if (s != NULL) {
		struct element **ep;
		int ne;
		ep = hash_array(this->key_val, &ne);

		strcpy(s, this->header);
		for (int i = 0; i < ne; i++) {
			e = ep[i];
			n = (struct sourceline *)e->value;
			strcat(s, n->value);
			strcat(s, "\r\n");
		}
		strcat(s, "ENDSOURCETABLE\r\n");
		hash_array_free(ep);
	}
	P_RWLOCK_UNLOCK(&this->lock);
	if (s == NULL)
		return NULL;
	struct mime_content *m = mime_new(s, len-1, "gnss/sourcetable", 1);
	return m;
}

/*
 * Return sourcetable as a Json object.
 */
json_object *sourcetable_json(struct sourcetable *this) {
	struct sourceline *n;
	json_object *jmain = json_object_new_object();


	json_object_object_add(jmain, "host", json_object_new_string(this->caster));
	json_object_object_add(jmain, "port", json_object_new_int(this->port));
	json_object_object_add(jmain, "tls", json_object_new_boolean(this->tls));
	json_object_object_add(jmain, "pullable", json_object_new_boolean(this->pullable));
	json_object_object_add(jmain, "priority", json_object_new_int(this->priority));

	if (strcmp(this->caster, "LOCAL")) {
		char iso_date[40];
		iso_date_from_timeval(iso_date, sizeof iso_date, &this->fetch_time);
		json_object_object_add(jmain, "fetch_time", json_object_new_string(iso_date));
	}

	json_object *jmnt = json_object_new_object();

	struct element *e;
	struct hash_iterator hi;

	P_RWLOCK_RDLOCK(&this->lock);
	HASH_FOREACH(e, this->key_val, hi) {
		n = (struct sourceline *)e->value;
		json_object *j = json_object_new_object();
		json_object_object_add(j, "str", json_object_new_string(n->value));
		json_object_object_add(j, "lat", json_object_new_double(n->pos.lat));
		json_object_object_add(j, "lon", json_object_new_double(n->pos.lon));
		json_object_object_add(j, "virtual", json_object_new_boolean(n->virtual));
		json_object_object_add(jmnt, n->key, j);

	}
	P_RWLOCK_UNLOCK(&this->lock);

	json_object_object_add(jmain, "mountpoints", jmnt);

	return jmain;
}

static int _sourcetable_add_direct(struct sourcetable *this, struct sourceline *s) {
	int r;
	P_RWLOCK_WRLOCK(&this->lock);
	r = hash_table_add(this->key_val, s->key, s);
	if (s->virtual)
		this->nvirtual++;
	P_RWLOCK_UNLOCK(&this->lock);
	return r;
}

int sourcetable_add(struct sourcetable *this, const char *sourcetable_entry, int on_demand, struct caster_state *caster) {
	int r = 0;
	if (!strncmp(sourcetable_entry, "STR;", 4)) {
		struct sourceline *n1 = sourceline_new_parse(sourcetable_entry,
			this->caster, this->port, this->tls,
			this->priority, on_demand);
		if (n1 == NULL) {
			logfmt(&caster->flog, LOG_ERR, "Can't parse sourcetable line or out of memory: %s", sourcetable_entry);
			return -1;
		}
		r = _sourcetable_add_direct(this, n1);
		if (r < 0) {
			logfmt(&caster->flog, LOG_ERR, "Can't add sourcetable line (possibly duplicate key): %s", sourcetable_entry);
			sourceline_free(n1);
		}
	} else {
		P_RWLOCK_WRLOCK(&this->lock);
		int new_len = strlen(this->header) + strlen(sourcetable_entry) + 3;
		char *s = (char *)strrealloc(this->header, new_len);
		if (s == NULL) {
			P_RWLOCK_UNLOCK(&this->lock);
			return -1;
		}
		strcat(s, sourcetable_entry);
		strcat(s, "\r\n");
		this->header = s;
		P_RWLOCK_UNLOCK(&this->lock);
	}
	return r;
}

/*
 * Return the number of entries in a sourcetable, unlocked
 */
static int _sourcetable_nentries_unlocked(struct sourcetable *this, int omit_virtual) {
	return hash_len(this->key_val) - (omit_virtual ? this->nvirtual : 0);
}

/*
 * Return the number of entries in a sourcetable
 */
int sourcetable_nentries(struct sourcetable *this, int omit_virtual) {
	P_RWLOCK_RDLOCK(&this->lock);
	int r = _sourcetable_nentries_unlocked(this, omit_virtual);
	P_RWLOCK_UNLOCK(&this->lock);
	return r;
}

void sourcetable_diff(struct caster_state *caster, struct sourcetable *t1, struct sourcetable *t2) {
	struct element **keys1, **keys2;
	int n1, n2;
	int i1, i2;

	P_RWLOCK_RDLOCK(&t1->lock);
	keys1 = hash_array(t1->key_val, &n1);
	P_RWLOCK_UNLOCK(&t1->lock);
	if (!keys1)
		return;
	P_RWLOCK_RDLOCK(&t2->lock);
	keys2 = hash_array(t2->key_val, &n2);
	P_RWLOCK_UNLOCK(&t2->lock);
	if (!keys2) {
		hash_array_free(keys1);
		return;
	}

	i1 = 0;
	i2 = 0;
	int c;
	while (i1 < n1 && i2 < n2) {
		c = strcmp(keys1[i1]->key, keys2[i2]->key);
		if (c < 0) {
			logfmt(&caster->flog, LOG_INFO, "%s:%d Removed source %s", t1->caster, t1->port, keys1[i1]->key);
			i1++;
			continue;
		}
		if (c > 0) {
			logfmt(&caster->flog, LOG_INFO, "%s:%d Added source %s", t2->caster, t2->port, keys2[i2]->key);
			i2++;
			continue;
		}
		i1++;
		i2++;
	}
	while (i1 < n1) {
		logfmt(&caster->flog, LOG_INFO, "%s:%d Removed source %s", t1->caster, t1->port, keys1[i1]->key);
		i1++;
	}
	while (i2 < n2) {
		logfmt(&caster->flog, LOG_INFO, "%s:%d Added source %s", t2->caster, t2->port, keys2[i2]->key);
		i2++;
	}
	hash_array_free(keys1);
	hash_array_free(keys2);
}

static int _cmp_dist(const void *pos1, const void *pos2) {
	struct spos *p1 = (struct spos *)pos1;
	struct spos *p2 = (struct spos *)pos2;
	if (p1->dist > p2->dist) {
		return 1;
	}
	if (p1->dist < p2->dist) {
		return -1;
	}
	return 0;
}

/*
 * Return a distance table for all mountpoints in sourcetable relative to the given position.
 */
struct dist_table *sourcetable_find_pos(struct sourcetable *this, pos_t *pos) {
	int n = 0;
	struct sourceline *np;
	if (this == NULL)
		return NULL;

	P_RWLOCK_RDLOCK(&this->lock);

	/*
	 * Count how many entries we need to reserve.
	 */
	n = _sourcetable_nentries_unlocked(this, 1);

	if (n == 0) {
		P_RWLOCK_UNLOCK(&this->lock);
		return NULL;
	}

	/*
	 * Allocate the table structures.
	 */
	struct dist_table *d = (struct dist_table *)malloc(sizeof(struct dist_table));
	if (d == NULL) {
		P_RWLOCK_UNLOCK(&this->lock);
		return NULL;
	}
	struct spos *dist_array = (struct spos *)malloc(sizeof(struct spos)*n);
	if (dist_array == NULL) {
		P_RWLOCK_UNLOCK(&this->lock);
		free(d);
		return NULL;
	}

	/*
	 * Prepare the table to be sorted.
	 */
	int i = 0;

	struct hash_iterator hi;
	struct element *e;
	HASH_FOREACH(e, this->key_val, hi) {
		np = (struct sourceline *)e->value;
		// printf("%d: %s pos (%f, %f)\n", i, np->key, np->pos.lat, np->pos.lon);
		if (!np->virtual) {
			dist_array[i].dist = distance(&np->pos, pos);
			dist_array[i].pos = np->pos;
			dist_array[i].mountpoint = np->key;
			dist_array[i].on_demand = np->on_demand;
			i++;
		}
	}

	P_RWLOCK_UNLOCK(&this->lock);

	/*
	 * Keep some useful additional info
	 *
	 * Use i instead of n as the table size, in case they differ.
	 */
	d->dist_array = dist_array;
	d->size_dist_array = i;
	d->pos = *pos;
	d->sourcetable = this;

	/*
	 * Sort the distance array
	 */
	qsort(dist_array, i, sizeof(struct spos), _cmp_dist);
	return d;
}

/*
 * Find a mountpoint in a sourcetable.
 */
struct sourceline *sourcetable_find_mountpoint(struct sourcetable *this, char *mountpoint) {
	struct sourceline *result;

	P_RWLOCK_RDLOCK(&this->lock);
	result = (struct sourceline *)hash_table_get(this->key_val, mountpoint);
	P_RWLOCK_UNLOCK(&this->lock);

	return result;
}

void dist_table_free(struct dist_table *this) {
	free(this->dist_array);
	free(this);
}

void dist_table_display(struct ntrip_state *st, struct dist_table *this, int max) {
	float max_dist = this->size_dist_array ? this->dist_array[this->size_dist_array-1].dist : 40000;

	ntrip_log(st, LOG_INFO, "dist_table from (%f, %f) %s:%d, furthest base dist %.2f:", this->pos.lat, this->pos.lon, this->sourcetable->caster, this->sourcetable->port, max_dist);
	for (int i = 0; i < max && i < this->size_dist_array; i++) {
		ntrip_log(st, LOG_INFO, "%.2f: %s", this->dist_array[i].dist, this->dist_array[i].mountpoint);
	}
}

/*
 * Find a mountpoint in a sourcetable stack.
 */
static struct sourceline *_stack_find_mountpoint(struct caster_state *caster, sourcetable_stack_t *stack, char *mountpoint, int local) {
	struct sourceline *np = NULL;

	/*
	 * catch empty mountpoint name
	 */
	if (!strcmp(mountpoint, ""))
		return NULL;

	struct sourceline *r = NULL;
	struct sourcetable *s;
	int priority = -10000;

	P_RWLOCK_RDLOCK(&stack->lock);

	TAILQ_FOREACH(s, &stack->list, next) {
		if (local && strcmp(s->caster, "LOCAL"))
			continue;
		np = sourcetable_find_mountpoint(s, mountpoint);
		/*
		 * If the mountpoint is from our local table, and other non-local tables are to
		 * be looked-up, skip if not live.
		 */
		if (!local && np && !strcmp(s->caster, "LOCAL") && (!np->virtual && !livesource_find(caster, NULL, np->key, &np->pos)))
			continue;
		if (np && s->priority > priority) {
			priority = s->priority;
			r = np;
		}
	}

	P_RWLOCK_UNLOCK(&stack->lock);
	return r;
}

/*
 * Find a mountpoint in a sourcetable stack.
 * Used for clients.
 */
struct sourceline *stack_find_mountpoint(struct caster_state *caster, sourcetable_stack_t *stack, char *mountpoint) {
	return _stack_find_mountpoint(caster, stack, mountpoint, 0);
}

/*
 * Find a mountpoint in a local sourcetable from the stack.
 * Used to check for legitimate incoming sources.
 */
struct sourceline *stack_find_local_mountpoint(struct caster_state *caster, sourcetable_stack_t *stack, char *mountpoint) {
	return _stack_find_mountpoint(caster, stack, mountpoint, 1);
}

struct sourceline *stack_find_pullable(sourcetable_stack_t *stack, char *mountpoint, struct sourcetable **sourcetable) {
	struct sourcetable *s;
	struct sourceline *r = NULL;

	P_RWLOCK_RDLOCK(&stack->lock);

	TAILQ_FOREACH(s, &stack->list, next) {
		if (s->pullable) {
			struct sourceline *np = sourcetable_find_mountpoint(s, mountpoint);
			if (np) {
				if (sourcetable) *sourcetable = s;
				r = np;
				break;
			}
		}
	}

	P_RWLOCK_UNLOCK(&stack->lock);
	return r;
}

/*
 * Remove a sourcetable identified by host+port in the sourcetable stack.
 * Insert a new one instead, if new_sourcetable is not NULL.
 */
static void _stack_replace_host(struct caster_state *caster, sourcetable_stack_t *stack, const char *host, unsigned port, struct sourcetable *new_sourcetable, int compare_tv) {
	struct sourcetable *s;
	struct sourcetable *r = NULL;

	P_RWLOCK_WRLOCK(&stack->lock);

	TAILQ_FOREACH(s, &stack->list, next) {
		P_RWLOCK_WRLOCK(&s->lock);
		if (!strcmp(s->caster, host) && s->port == port) {
			r = s;
			break;
		}
		P_RWLOCK_UNLOCK(&s->lock);
	}

	if (r) {
		if (new_sourcetable == NULL || !compare_tv || timercmp(&r->fetch_time, &new_sourcetable->fetch_time, <)) {
			TAILQ_REMOVE(&stack->list, r, next);
			if (new_sourcetable != NULL) {
				P_RWLOCK_UNLOCK(&r->lock);
				sourcetable_diff(caster, r, new_sourcetable);
				P_RWLOCK_WRLOCK(&r->lock);
			}
			sourcetable_free_unlocked(r);
		} else {
			P_RWLOCK_UNLOCK(&r->lock);
			if (new_sourcetable != NULL) {
				sourcetable_free_unlocked(new_sourcetable);
				new_sourcetable = NULL;
			}
		}
	}
	if (new_sourcetable != NULL)
		TAILQ_INSERT_TAIL(&stack->list, new_sourcetable, next);

	P_RWLOCK_UNLOCK(&stack->lock);
}

void stack_replace_host(struct caster_state *caster, sourcetable_stack_t *stack, const char *host, unsigned port, struct sourcetable *new_sourcetable) {
	_stack_replace_host(caster, stack, host, port, new_sourcetable, 0);
}

/*
 * Return an aggregated sourcetable as computed from our sourcetable stack.
 */
struct sourcetable *stack_flatten(struct caster_state *caster, sourcetable_stack_t *this) {
	struct sourcetable *s;
	char *header = mystrdup("");
	struct hash_iterator hi;
	struct element *e;
	struct sourcetable *r = sourcetable_new(NULL, 0, 0);

	if (header == NULL || r == NULL)
		goto cancel;

	/*
	 * Directly build the returned sourcetable
	 */
	strfree(r->header);
	r->header = header;

	P_RWLOCK_RDLOCK(&this->lock);

	TAILQ_FOREACH(s, &this->list, next) {
		int local_table;

		P_RWLOCK_RDLOCK(&s->lock);

		/* Use the header from a local table */

		if (!strcmp(s->caster, "LOCAL")) {
			char *header_tmp = mystrdup(s->header);
			if (header_tmp == NULL) {
				P_RWLOCK_UNLOCK(&s->lock);
				P_RWLOCK_UNLOCK(&this->lock);
				goto cancel;
			}
			strfree(r->header);
			r->header = header_tmp;
			local_table = 1;
		} else
			local_table = 0;

		HASH_FOREACH(e, s->key_val, hi) {
			struct sourceline *sp = (struct sourceline *)e->value;
			/*
			 * If the mountpoint is from our local table, skip if not live.
			 */
			if (local_table && (!sp->virtual && !livesource_find(caster, NULL, sp->key, &sp->pos)))
				continue;

			struct element *e = hash_table_get_element(r->key_val, sp->key);
			struct sourceline *mp;

			if (e) {
				mp = (struct sourceline *)e->value;
				/*
				 * Mountpoint already in table, keep the highest priority entry
				 */
				if (mp->priority < sp->priority) {
					mp = sourceline_copy(sp);
					if (mp == NULL) {
						P_RWLOCK_UNLOCK(&s->lock);
						P_RWLOCK_UNLOCK(&this->lock);
						goto cancel;
					}
					hash_table_replace(r->key_val, e, mp);
				}
			} else {
				/*
				 * Entry not found, add.
				 */
				mp = sourceline_copy(sp);
				if (mp == NULL) {
					P_RWLOCK_UNLOCK(&s->lock);
					P_RWLOCK_UNLOCK(&this->lock);
					goto cancel;
				}
				_sourcetable_add_direct(r, mp);
			}
		}

		P_RWLOCK_UNLOCK(&s->lock);
	}

	P_RWLOCK_UNLOCK(&this->lock);
	return r;

cancel:
	strfree(header);
	if (r) sourcetable_free(r);
	return NULL;
}

/*
 * Return all the sourcetables as a JSON array
 */
struct mime_content *sourcetable_list_json(struct caster_state *caster, struct request *req) {
	sourcetable_stack_t *this = &caster->sourcetablestack;
	struct sourcetable *s;

	int n = 0;
	P_RWLOCK_RDLOCK(&this->lock);
	TAILQ_FOREACH(s, &this->list, next)
		n++;

	json_object *jmain = json_object_new_array_ext(n);

	TAILQ_FOREACH(s, &this->list, next) {
		json_object *stj = sourcetable_json(s);
		json_object_array_add(jmain, stj);
	}
	P_RWLOCK_UNLOCK(&this->lock);

	char *rs = mystrdup(json_object_to_json_string(jmain));
	struct mime_content *m = mime_new(rs, -1, "application/json", 1);
	json_object_put(jmain);
	return m;
}

/*
 * Handle and insert a received sourcetable.
 */
int sourcetable_update_execute(struct caster_state *caster, json_object *j) {
	struct sourcetable *s = sourcetable_from_json(j, caster);

	if (s != NULL) {
		logfmt(&caster->flog, LOG_DEBUG, "received sourcetable for %s", s->caster);
		_stack_replace_host(caster, &caster->sourcetablestack, s->caster, s->port, s, 1);
	}
	return 200;
}
