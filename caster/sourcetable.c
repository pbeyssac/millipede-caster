#include "conf.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>

#include "livesource.h"
#include "log.h"
#include "ntrip_common.h"
#include "sourcetable.h"
#include "util.h"

static int _sourcetable_add_unlocked(struct sourcetable *this, const char *sourcetable_entry, int on_demand, struct caster_state *caster);

/*
 * Read a sourcetable file
 */
struct sourcetable *sourcetable_read(struct caster_state *caster, const char *filename, int priority) {
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen;
	int nlines = 0;

	FILE *fp = fopen_absolute(caster->config_dir, filename, "r");
	if (fp == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Can't open %s", filename);
		return NULL;
	}

	struct sourcetable *tmp_sourcetable = sourcetable_new("LOCAL", 0, 0);
	if (tmp_sourcetable == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Can't read %s: out of memory", filename);
		fclose(fp);
		return NULL;
	}

	tmp_sourcetable->local = 1;
	tmp_sourcetable->filename = mystrdup(filename);
	tmp_sourcetable->priority = priority;
	while ((linelen = getline(&line, &linecap, fp)) > 0) {
		nlines++;
		for (; linelen && (line[linelen-1] == '\n' || line[linelen-1] == '\r'); linelen--)
			line[linelen-1] = '\0';
		if (linelen == 0)
			/* Skip empty line */
			continue;
		char *p;
		for (p = line; *p && isspace(*p); p++);
		if (*p == '#')
			/* Skip comment line */
			continue;
		if (_sourcetable_add_unlocked(tmp_sourcetable, line, 0, caster) < 0) {
			logfmt(&caster->flog, LOG_ERR, "Can't parse line %d in sourcetable", nlines);
			strfree(line);
			sourcetable_decref(tmp_sourcetable);
			fclose(fp);
			return NULL;
		}
	}
	fclose(fp);
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

		if (str == NULL || _sourcetable_add_unlocked(tmp_sourcetable, str, tmp_sourcetable->pullable, caster) < 0) {
			sourcetable_decref(tmp_sourcetable);
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
	struct hash_table *kv = hash_table_new(509, (void (*)(void *))sourceline_decref);
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
	atomic_store(&this->refcnt, 1);
	return this;
}

static void sourcetable_free(struct sourcetable *this) {
	strfree(this->header);
	strfree(this->caster);
	strfree((char *)this->filename);

	hash_table_free(this->key_val);

	P_RWLOCK_DESTROY(&this->lock);
	free(this);
}

void sourcetable_incref(struct sourcetable *this) {
	atomic_fetch_add(&this->refcnt, 1);
}

void sourcetable_decref(struct sourcetable *this) {
	if (atomic_fetch_add_explicit(&this->refcnt, -1, memory_order_relaxed) == 1)
		sourcetable_free(this);
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


	json_object_object_add_ex(jmain, "host", json_object_new_string(this->caster), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(jmain, "port", json_object_new_int(this->port), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(jmain, "tls", json_object_new_boolean(this->tls), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(jmain, "pullable", json_object_new_boolean(this->pullable), JSON_C_CONSTANT_NEW);
	json_object_object_add_ex(jmain, "priority", json_object_new_int(this->priority), JSON_C_CONSTANT_NEW);

	if (strcmp(this->caster, "LOCAL"))
		timeval_to_json(&this->fetch_time, jmain, "fetch_time");

	json_object *jmnt = json_object_new_object();

	struct element *e;
	struct hash_iterator hi;

	P_RWLOCK_RDLOCK(&this->lock);
	HASH_FOREACH(e, this->key_val, hi) {
		n = (struct sourceline *)e->value;
		json_object *j = json_object_new_object();
		json_object_object_add_ex(j, "str", json_object_new_string(n->value), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(j, "lat", json_object_new_double(n->pos.lat), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(j, "lon", json_object_new_double(n->pos.lon), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(j, "virtual", json_object_new_boolean(n->virtual), JSON_C_CONSTANT_NEW);
		json_object_object_add(jmnt, n->key, j);

	}
	P_RWLOCK_UNLOCK(&this->lock);

	json_object_object_add_ex(jmain, "mountpoints", jmnt, JSON_C_CONSTANT_NEW);

	return jmain;
}

static int _sourcetable_add_direct(struct sourcetable *this, struct sourceline *s) {
	int r;
	r = hash_table_add(this->key_val, s->key, s);
	if (r >= 0) {
		sourceline_incref(s);
		if (s->virtual)
			this->nvirtual++;
	}
	return r;
}

static int _sourcetable_add_unlocked(struct sourcetable *this, const char *sourcetable_entry, int on_demand, struct caster_state *caster) {
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
		sourceline_decref(n1);
		if (r < 0) {
			logfmt(&caster->flog, LOG_ERR, "Can't add sourcetable line (%s): %s",
				(r == -1)?"duplicate key":"out of memory",
				sourcetable_entry);
		}
	} else {
		int new_len = strlen(this->header) + strlen(sourcetable_entry) + 3;
		char *s = (char *)strrealloc(this->header, new_len);
		if (s == NULL)
			return -1;
		strcat(s, sourcetable_entry);
		strcat(s, "\r\n");
		this->header = s;
	}
	return r;
}

int sourcetable_add(struct sourcetable *this, const char *sourcetable_entry, int on_demand, struct caster_state *caster) {
	P_RWLOCK_WRLOCK(&this->lock);
	int result = _sourcetable_add_unlocked(this, sourcetable_entry, on_demand, caster);
	P_RWLOCK_UNLOCK(&this->lock);
	return result;
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

static struct dist_table *dist_table_new(int n, const char *host, unsigned short port) {
	struct dist_table *this = (struct dist_table *)malloc(sizeof(struct dist_table));
	if (this == NULL)
		return NULL;

	struct spos *dist_array = (struct spos *)malloc(sizeof(struct spos)*n);
	if (dist_array == NULL) {
		free(this);
		return NULL;
	}
	this->dist_array = dist_array;

	this->size_dist_array = 0;
	this->port = port;
	this->host = host?mystrdup(host):NULL;
	return this;
}

static void dist_table_add(struct dist_table *this, double dist, pos_t *pos, char *mountpoint, int on_demand) {
	int i = this->size_dist_array++;
	this->dist_array[i].dist = dist;
	this->dist_array[i].pos = *pos;
	this->dist_array[i].mountpoint = mountpoint;
	this->dist_array[i].on_demand = on_demand;
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

	/*
	 * Allocate the table structures.
	 */
	struct dist_table *d = dist_table_new(n, this->caster, this->port);
	if (d == NULL) {
		P_RWLOCK_UNLOCK(&this->lock);
		return NULL;
	}

	/*
	 * Prepare the table to be sorted.
	 */

	struct hash_iterator hi;
	struct element *e;
	HASH_FOREACH(e, this->key_val, hi) {
		np = (struct sourceline *)e->value;
		// printf("%d: %s pos (%f, %f)\n", i, np->key, np->pos.lat, np->pos.lon);
		if (!np->virtual)
			dist_table_add(d, distance(&np->pos, pos), &np->pos, np->key, np->on_demand);
	}

	P_RWLOCK_UNLOCK(&this->lock);

	/*
	 * Keep some useful additional info
	 */
	d->pos = *pos;

	/*
	 * Sort the distance array
	 * Use i instead of n as the table size, in case they differ.
	 */
	qsort(d->dist_array, d->size_dist_array, sizeof(struct spos), _cmp_dist);
	return d;
}

/*
 * Find a mountpoint in a sourcetable.
 */
struct sourceline *sourcetable_find_mountpoint(struct sourcetable *this, char *mountpoint) {
	struct sourceline *result;

	P_RWLOCK_RDLOCK(&this->lock);
	result = (struct sourceline *)hash_table_get(this->key_val, mountpoint);
	if (result != NULL)
		sourceline_incref(result);
	P_RWLOCK_UNLOCK(&this->lock);

	return result;
}

void dist_table_free(struct dist_table *this) {
	free(this->dist_array);
	strfree((char *)this->host);
	free(this);
}

void dist_table_display(struct ntrip_state *st, struct dist_table *this, int max) {
	const char *mp[2];
	float min_dist[2];
	min_dist[0] = -1;
	min_dist[1] = -1;
	mp[0] = "-";
	mp[1] = "-";
	for (int i = 0; i < 2 && i < this->size_dist_array; i++) {
		mp[i] = (i < this->size_dist_array) ? this->dist_array[i].mountpoint : NULL;
		min_dist[i] = (i < this->size_dist_array) ? this->dist_array[i].dist : -1;
	}

	ntrip_log(st, LOG_INFO, "dist_table from (%f, %f) %s:%d, closest bases %s dist %.2f, %s dist %.2f", this->pos.lat, this->pos.lon, this->host, this->port, mp[0], min_dist[0], mp[1], min_dist[1]);
	for (int i = 0; i < max && i < this->size_dist_array; i++) {
		ntrip_log(st, LOG_DEBUG, "%.2f: %s", this->dist_array[i].dist, this->dist_array[i].mountpoint);
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

	P_RWLOCK_RDLOCK(&stack->lock);

	TAILQ_FOREACH(s, &stack->list, next) {
		if (local && strcmp(s->caster, "LOCAL"))
			continue;
		np = sourcetable_find_mountpoint(s, mountpoint);
		if (!np)
			continue;
		/*
		 * If the mountpoint is from our local table, and other non-local tables are to
		 * be looked-up (local == 0), skip if not live.
		 */
		if (local || strcmp(s->caster, "LOCAL") || np->virtual || livesource_exists(caster, np->key, &np->pos)) {
			r = np;
			break;
		}
		sourceline_decref(np);
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
				if (sourcetable) {
					sourcetable_incref(s);
					*sourcetable = s;
				}
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
static void _stack_replace(struct caster_state *caster, sourcetable_stack_t *stack, const char *host, unsigned port, struct sourcetable *new_sourcetable, int compare_tv, int local) {
	struct sourcetable *s;
	struct sourcetable *r = NULL;

	P_RWLOCK_WRLOCK(&stack->lock);

	TAILQ_FOREACH(s, &stack->list, next) {
		P_RWLOCK_WRLOCK(&s->lock);
		if ((local && s->local && s->filename)
			||
		    (host && !strcmp(s->caster, host) && s->port == port)) {
			r = s;
			break;
		}
		P_RWLOCK_UNLOCK(&s->lock);
	}

	if (r) {
		if (new_sourcetable == NULL || !compare_tv || timercmp(&r->fetch_time, &new_sourcetable->fetch_time, <)) {
			if (local)
				logfmt(&caster->flog, LOG_INFO, "Removing %s", s->filename);
			TAILQ_REMOVE(&stack->list, r, next);
			P_RWLOCK_UNLOCK(&r->lock);
			if (new_sourcetable != NULL)
				sourcetable_diff(caster, r, new_sourcetable);
			sourcetable_decref(r);
		} else {
			P_RWLOCK_UNLOCK(&r->lock);
			if (new_sourcetable != NULL)
				new_sourcetable = NULL;
		}
	}
	if (new_sourcetable != NULL) {
		/*
		 * Insert at the right place to keep the stack sorted by decreasing priority.
		 */
		if (local)
			logfmt(&caster->flog, LOG_INFO, "Reloading %s", new_sourcetable->filename);
		sourcetable_incref(new_sourcetable);
		TAILQ_FOREACH(s, &stack->list, next) {
			if (new_sourcetable->priority >= s->priority) {
				TAILQ_INSERT_BEFORE(s, new_sourcetable, next);
				new_sourcetable = NULL;
				break;
			}
		}
		if (new_sourcetable)
			TAILQ_INSERT_TAIL(&stack->list, new_sourcetable, next);
	}

	P_RWLOCK_UNLOCK(&stack->lock);
}

void stack_replace_host(struct caster_state *caster, sourcetable_stack_t *stack, const char *host, unsigned port, struct sourcetable *new_sourcetable) {
	_stack_replace(caster, stack, host, port, new_sourcetable, 0, 0);
}

void stack_replace_local(struct caster_state *caster, sourcetable_stack_t *stack, struct sourcetable *new_sourcetable) {
	_stack_replace(caster, stack, NULL, 0, new_sourcetable, 0, 1);
}

/*
 * Return an aggregated sourcetable as computed from our sourcetable stack.
 * If pos is not NULL, prune entries over max_dist of pos.
 */
struct sourcetable *stack_flatten_dist(struct caster_state *caster, sourcetable_stack_t *this, pos_t *pos, float max_dist) {
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
			if (local_table && (!sp->virtual && !livesource_exists(caster, sp->key, &sp->pos)))
				continue;

			struct element *e = hash_table_get_element(r->key_val, sp->key);

			if (e == NULL) {
				/*
				 * Entry not found, meaning it has the highest priority:
				 * add it if within maximum distance.
				 */
				if (!pos || distance(&sp->pos, pos) < max_dist) {
					if (_sourcetable_add_direct(r, sp) < 0) {
						P_RWLOCK_UNLOCK(&s->lock);
						P_RWLOCK_UNLOCK(&this->lock);
						goto cancel;
					}
				}
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
 * Return an aggregated sourcetable as computed from our sourcetable stack
 */
struct sourcetable *stack_flatten(struct caster_state *caster, sourcetable_stack_t *this) {
	return stack_flatten_dist(caster, this, NULL, 0);
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
		_stack_replace(caster, &caster->sourcetablestack, s->caster, s->port, s, 1, 0);
		sourcetable_decref(s);
	}
	return 200;
}
