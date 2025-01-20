#include "conf.h"

#include <ctype.h>
#include <stdio.h>
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

	struct sourcetable *tmp_sourcetable = sourcetable_new("LOCAL", 0);
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

struct sourcetable *sourcetable_new(char *host, unsigned short port) {
	struct sourcetable *this = (struct sourcetable *)malloc(sizeof(struct sourcetable));
	char *duphost = (host == NULL) ? NULL : mystrdup(host);
	char *header = mystrdup("");
	if ((host != NULL && duphost == NULL) || header == NULL || this == NULL) {
		strfree(duphost);
		strfree(header);
		free(this);
		return NULL;
	}

	TAILQ_INIT(&this->sources);
	P_RWLOCK_INIT(&this->lock, NULL);
	this->caster = duphost;
	this->port = port;
	this->filename = NULL;
	this->header = header;
	this->pullable = 0;
	this->local = 0;
	this->priority = 0;
	struct timeval t = { 0, 0 };
	this->fetch_time = t;
	return this;
}

void sourcetable_free_unlocked(struct sourcetable *this) {
	struct sourceline *n;

	strfree(this->header);
	strfree(this->caster);
	strfree((char *)this->filename);

	while ((n = TAILQ_FIRST(&this->sources))) {
		TAILQ_REMOVE_HEAD(&this->sources, next);
		sourceline_free(n);
	}

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

	TAILQ_FOREACH(n, &this->sources, next)
		len += strlen(n->value) + 2;

	char *s = (char *)strmalloc(len);

	/*
	 * Build the result per se
	 */
	if (s != NULL) {
		strcpy(s, this->header);
		TAILQ_FOREACH(n, &this->sources, next) {
			strcat(s, n->value);
			strcat(s, "\r\n");
		}
		strcat(s, "ENDSOURCETABLE\r\n");
	}
	P_RWLOCK_UNLOCK(&this->lock);
	struct mime_content *m = mime_new(s, len-1, "gnss/sourcetable", 1);
	if (m == NULL)
		strfree(s);
	return m;
}

void sourcetable_del_mountpoint(struct sourcetable *this, char *mountpoint) {
	struct sourceline *np;
	P_RWLOCK_WRLOCK(&this->lock);

	TAILQ_FOREACH(np, &this->sources, next) {
		if (!strcmp(mountpoint, np->key)) {
			TAILQ_REMOVE(&this->sources, np, next);
			break;
		}
	}

	P_RWLOCK_UNLOCK(&this->lock);
}

static void _sourcetable_add_direct(struct sourcetable *this, struct sourceline *s) {
	P_RWLOCK_WRLOCK(&this->lock);
	TAILQ_INSERT_TAIL(&this->sources, s, next);
	P_RWLOCK_UNLOCK(&this->lock);
}

int sourcetable_add(struct sourcetable *this, const char *sourcetable_entry, int on_demand) {
	if (!strncmp(sourcetable_entry, "STR;", 4)) {
		char *valueparse = mystrdup(sourcetable_entry);
		if (valueparse == NULL)
			return -1;
		char *p1 = valueparse + 4;
		char *p2 = p1;
		char *token;

		while (*p2 && *p2 != ';') p2++;
		if (!*p2) {
			fprintf(stderr, "unable to parse %s\n", sourcetable_entry);
			strfree(valueparse);
			return -1;
		}

		char *key = (char *)strmalloc(p2 - p1 + 1);
		if (key == NULL) {
			strfree(valueparse);
			return -1;
		}
		key[p2-p1] = '\0';
		memcpy(key, p1, p2-p1);
		struct sourceline *n1 = sourceline_new(this->caster, this->port, key, sourcetable_entry, this->priority);
		strfree(key);
		if (n1 == NULL) {
			strfree(valueparse);
			return -1;
		}
		n1->virtual = 0;
		n1->on_demand = on_demand;
		int err = 0, n = 0;
		pos_t pos;
		char *septmp = valueparse;
		while ((token = strsep(&septmp, ";")) != NULL) {
			//printf("TOKEN %d %s\n", n, token);
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
			fprintf(stderr, "END %d err %d\n", n, err);
		} else {
			n1->pos = pos;
			P_RWLOCK_WRLOCK(&this->lock);
			TAILQ_INSERT_TAIL(&this->sources, n1, next);
			P_RWLOCK_UNLOCK(&this->lock);
		}
		strfree(valueparse);
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
	return 0;
}

/*
 * Return the number of entries in a sourcetable, unlocked
 */
static int _sourcetable_nentries_unlocked(struct sourcetable *this, int omit_virtual) {
	struct sourceline *np;
	int n = 0;
	TAILQ_FOREACH(np, &this->sources, next) {
		if (!np->virtual || !omit_virtual)
			n++;
	}
	return n;
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
	TAILQ_FOREACH(np, &this->sources, next) {
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
	struct sourceline *np;
	struct sourceline *result = NULL;

	P_RWLOCK_RDLOCK(&this->lock);

	TAILQ_FOREACH(np, &this->sources, next) {
		if (!strcmp(mountpoint, np->key)) {
			result = np;
			break;
		}
	}

	P_RWLOCK_UNLOCK(&this->lock);

	return result;
}

void dist_table_free(struct dist_table *this) {
	free(this->dist_array);
	free(this);
}

void dist_table_display(struct ntrip_state *st, struct dist_table *this, int max) {
	float max_dist = this->size_dist_array ? this->dist_array[this->size_dist_array-1].dist : 40000;

	ntrip_log(st, LOG_INFO, "dist_table from (%f, %f) %s:%d, furthest base dist %.2f:\n", this->pos.lat, this->pos.lon, this->sourcetable->caster, this->sourcetable->port, max_dist);
	for (int i = 0; i < max && i < this->size_dist_array; i++) {
		ntrip_log(st, LOG_INFO, "%.2f: %s\n", this->dist_array[i].dist, this->dist_array[i].mountpoint);
	}
}

/*
 * Find a mountpoint in a sourcetable stack.
 */
struct sourceline *stack_find_mountpoint(sourcetable_stack_t *stack, char *mountpoint) {
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
		np = sourcetable_find_mountpoint(s, mountpoint);
		if (np) {
			r = np;
			break;
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
void stack_replace_host(sourcetable_stack_t *stack, char *host, unsigned port, struct sourcetable *new_sourcetable) {
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
		sourcetable_free_unlocked(r);
	}
	if (new_sourcetable != NULL)
		TAILQ_INSERT_TAIL(&stack->list, new_sourcetable, next);

	P_RWLOCK_UNLOCK(&stack->lock);
}

/*
 * Helper function for stack_flatten:
 *	order 2 mountpoints by name.
 */
static int _cmp_sourceline(const void *ap1, const void *ap2) {
	struct mp_prio *p1 = (struct mp_prio *)ap1;
	struct mp_prio *p2 = (struct mp_prio *)ap2;
	return strcmp(p1->sourceline->key, p2->sourceline->key);
}

/*
 * Return an aggregated sourcetable as computed from our sourcetable stack.
 */
struct sourcetable *stack_flatten(struct caster_state *caster, sourcetable_stack_t *this) {
	struct sourcetable *s;
	struct sourceline *np;
	struct mp_prio *mount_set = (struct mp_prio *)malloc(sizeof(struct mp_prio));
	int n_prio = 0;
	int i;
	char *header = mystrdup("");

	if (header == NULL)
		return NULL;
	if (mount_set == NULL)
		return NULL;

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
			strfree(header);
			header = header_tmp;
			local_table = 1;
		} else
			local_table = 0;

		TAILQ_FOREACH(np, &s->sources, next) {
			/*
			 * If the mountpoint is from our local table, skip if not live.
			 */
			if (local_table && (!np->virtual && !livesource_find(caster, NULL, np->key, &np->pos)))
				continue;

			for (i = 0; i < n_prio; i++) {

				if (!strcmp(mount_set[i].sourceline->key, np->key)) {

					/*
					 * Mountpoint already in table, keep the highest priority entry
					 */
					if (mount_set[i].priority < s->priority) {
						sourceline_free(mount_set[i].sourceline);
						mount_set[i].priority = s->priority;
						mount_set[i].sourceline = sourceline_copy(np);
						if (mount_set[i].sourceline == NULL) {
							P_RWLOCK_UNLOCK(&s->lock);
							P_RWLOCK_UNLOCK(&this->lock);
							goto cancel;
						}
					}
					break;
				}
			}
			if (i == n_prio) {
				/*
				 * Entry not found, add.
				 */

				struct mp_prio *mount_set2 = (struct mp_prio *)realloc(mount_set, sizeof(struct mp_prio)*(n_prio+1));
				if (mount_set2 == NULL)
					goto cancel;
				mount_set = mount_set2;
				mount_set[n_prio].priority = s->priority;
				mount_set[n_prio].sourceline = sourceline_copy(np);
				n_prio++;
			}
		}

		P_RWLOCK_UNLOCK(&s->lock);
	}

	P_RWLOCK_UNLOCK(&this->lock);


	/*
	 * Now the interim table is ready, build the real sourcetable from it.
	 */

	struct sourcetable *r = sourcetable_new(NULL, 0);
	if (r == NULL)
		goto cancel;
	strfree(r->header);
	r->header = header;

	/* Sort by mountpoint name */
	qsort(mount_set, n_prio, sizeof(mount_set[0]), _cmp_sourceline);

	for (i = 0; i < n_prio; i++)
		_sourcetable_add_direct(r, mount_set[i].sourceline);
	free(mount_set);
	return r;

cancel:
	for (i = 0; i < n_prio; i++)
		sourceline_free(mount_set[i].sourceline);


	strfree(header);
	free(mount_set);
	return NULL;
}
