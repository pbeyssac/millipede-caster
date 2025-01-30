#ifndef __SOURCETABLE_H__
#define __SOURCETABLE_H__

#include "conf.h"

#include "caster.h"
#include "hash.h"
#include "queue.h"
#include "sourceline.h"
#include "util.h"

struct caster_state;

/*
 * A source table
 */
struct sourcetable {
	TAILQ_ENTRY(sourcetable) next;
	P_RWLOCK_T lock;

	char *caster;                   // from which caster hostname did we get this table
	unsigned short port;            // caster port
	int tls;			// use TLS?
	char *header;                   // All "CAS" & "NET" lines
	struct hash_table *key_val;	// "STR" lines in a hash table
	int pullable;                   // 1: pull mounpoints streams from the caster on demand
	int local;                      // 1: table read from local file
	const char *filename;           // if local
	int priority;
	int nvirtual;			// number of "virtual" entries
	struct timeval fetch_time;              // time of fetch, if remote table
};
TAILQ_HEAD (sourcetableq, sourcetable);

/*
 * Sourcetable stack
 */
typedef struct sourcetable_stack {
	struct sourcetableq list;
	P_RWLOCK_T lock;
} sourcetable_stack_t;

/*
 * Position and distance to a base from a rover
 */
struct spos {
	float dist;
	char *mountpoint;
	pos_t pos;
	int on_demand;
};

/*
 * Table to determine the closest base from a rover
 */
struct dist_table {
	struct sourcetable *sourcetable;	// original sourcetable
	pos_t pos;				// known rover position
	struct spos *dist_array;		// array of distances
	int size_dist_array;
};

/*
 * Priority structure for sourcetable_stack_flatten.
 */
struct mp_prio {
	struct sourceline *sourceline;
	int priority;
};

struct sourcetable *sourcetable_read(const char *filename, int priority);
struct sourcetable *sourcetable_new(const char *host, unsigned short port, int tls);
void sourcetable_free_unlocked(struct sourcetable *this);
void sourcetable_free(struct sourcetable *this);
struct mime_content *sourcetable_get(struct sourcetable *this);
void sourcetable_del_mountpoint(struct sourcetable *this, char *mountpoint);
int sourcetable_add(struct sourcetable *this, const char *sourcetable_entry, int on_demand);
int sourcetable_nentries(struct sourcetable *this, int omit_virtual);
void sourcetable_diff(struct caster_state *caster, struct sourcetable *t1, struct sourcetable *t2);
struct sourceline *sourcetable_find_mountpoint(struct sourcetable *this, char *mountpoint);
struct dist_table *sourcetable_find_pos(struct sourcetable *this, pos_t *pos);
void dist_table_free(struct dist_table *this);
void dist_table_display(struct ntrip_state *st, struct dist_table *this, int max);
struct sourceline *stack_find_mountpoint(sourcetable_stack_t *stack, char *mountpoint);
struct sourceline *stack_find_pullable(sourcetable_stack_t *stack, char *mountpoint, struct sourcetable **sourcetable);
void stack_replace_host(struct caster_state *caster, sourcetable_stack_t *stack, char *host, unsigned port, struct sourcetable *new_sourcetable);
struct sourcetable *stack_flatten(struct caster_state *caster, sourcetable_stack_t *this);

#endif
