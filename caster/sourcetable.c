#include "conf.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "livesource.h"
#include "ntrip_common.h"
#include "sourcetable.h"

/*
 * Read a sourcetable file
 */
struct sourcetable *sourcetable_read(const char *filename, int priority) {
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen;
	int nlines = 1;

	FILE *fp = fopen(filename, "r+");
	if (fp == NULL) {
		fprintf(stderr, "Can't open %s\n", filename);
		return NULL;
	}

	struct sourcetable *tmp_sourcetable = sourcetable_new("LOCAL", 0, 0);
	tmp_sourcetable->local = 1;
	tmp_sourcetable->filename = mystrdup(filename);
	while ((linelen = getline(&line, &linecap, fp)) > 0) {
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
		if (sourcetable_add(tmp_sourcetable, line, 0) < 0) {
			fprintf(stderr, "Can't parse line %d in sourcetable\n", nlines);
			sourcetable_free(tmp_sourcetable);
			return NULL;
		}
		nlines++;
	}
	tmp_sourcetable->priority = priority;
	strfree(line);
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

static int _sourcetable_add_direct(struct sourcetable *this, struct sourceline *s) {
	int r;
	P_RWLOCK_WRLOCK(&this->lock);
	r = hash_table_add(this->key_val, s->key, s);
	if (s->virtual)
		this->nvirtual++;
	P_RWLOCK_UNLOCK(&this->lock);
	return r;
}

int sourcetable_add(struct sourcetable *this, const char *sourcetable_entry, int on_demand) {
	int r = 0;
	if (!strncmp(sourcetable_entry, "STR;", 4)) {
		struct sourceline *n1 = sourceline_new_parse(sourcetable_entry,
			this->caster, this->port, this->tls,
			this->priority, on_demand);
		if (n1 == NULL)
			return -1;
		r = _sourcetable_add_direct(this, n1);
		if (r < 0)
			sourceline_free(n1);
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
struct sourceline *stack_find_mountpoint(struct caster_state *caster, sourcetable_stack_t *stack, char *mountpoint) {
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
		np = sourcetable_find_mountpoint(s, mountpoint);
		/*
		 * If the mountpoint is from our local table, skip if not live.
		 */
		if (!strcmp(s->caster, "LOCAL") && (!np->virtual && !livesource_find(caster, NULL, np->key, &np->pos)))
			continue;
		if (np && s->priority > priority) {
			priority = s->priority;
			r = np;
		}
	}

	P_RWLOCK_UNLOCK(&stack->lock);
	return r;
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
void stack_replace_host(struct caster_state *caster, sourcetable_stack_t *stack, char *host, unsigned port, struct sourcetable *new_sourcetable) {
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
		TAILQ_REMOVE(&stack->list, r, next);
		if (new_sourcetable != NULL) {
			P_RWLOCK_UNLOCK(&r->lock);
			sourcetable_diff(caster, r, new_sourcetable);
			P_RWLOCK_WRLOCK(&r->lock);
		}
		sourcetable_free_unlocked(r);
	}
	if (new_sourcetable != NULL)
		TAILQ_INSERT_TAIL(&stack->list, new_sourcetable, next);

	P_RWLOCK_UNLOCK(&stack->lock);
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
