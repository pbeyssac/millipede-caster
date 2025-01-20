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
 * Easier syntax for casting:
 * (hash_free_callback) is equivalent to (void(*)(void *))
 */
typedef void (*hash_free_callback)(void *);

/*
 * Main table
 */
struct hash_table {
	int nentries;				// total number of entries
	int n_buckets;				// size of element_lists
	struct elementlisthead *element_lists;	// 1 element per hash bucket
	void (*free_callback)(void *);
};

struct hash_table *hash_table_new(int n_buckets, void free_callback(void *));
void hash_table_free(struct hash_table *this);

int hash_table_add(struct hash_table *this, const char *key, void *value);
struct element *hash_table_get_element(struct hash_table *this, const char *key);
void *hash_table_get(struct hash_table *this, const char *key);
int hash_table_del(struct hash_table *this, const char *key);
int hash_table_incr(struct hash_table *this, const char *key);
void hash_table_decr(struct hash_table *this, const char *key);
int hash_len(struct hash_table *this);

#endif
