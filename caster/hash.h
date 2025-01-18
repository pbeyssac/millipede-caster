#ifndef _HASH_C
#define _HASH_C

/*
 * Handle a key-value store
 */

#include <sys/queue.h>

SLIST_HEAD(elementlisthead, element);

/*
 * Individual element
 */
struct element {
	const char *key;
	void *value;
	SLIST_ENTRY(element) next;
};

/*
 * Main table
 */
struct hash_table {
	int n_buckets;				// size of element_lists
	struct elementlisthead *element_lists;	// 1 element per hash bucket
};

struct hash_table *hash_table_new(int n_buckets);
void hash_table_free(struct hash_table *this);

int hash_table_add(struct hash_table *this, const char *key, void *value);
void *hash_table_get(struct hash_table *this, const char *key);
int hash_table_del(struct hash_table *this, const char *key);
int hash_table_incr(struct hash_table *this, const char *key);
void hash_table_decr(struct hash_table *this, const char *key);

#endif
