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

struct hash_iterator {
	int bucket_number;
	struct element *e;
	struct hash_table *ht;
};

struct hash_table *hash_table_new(int n_buckets, void free_callback(void *));
void hash_table_free(struct hash_table *this);

void hash_table_replace(struct hash_table *this, struct element *e, void *value);
void hash_table_update(struct hash_table *this, struct hash_table *updates);
int hash_table_add(struct hash_table *this, const char *key, void *value);
struct element *hash_table_get_element(struct hash_table *this, const char *key);
void *hash_table_get(struct hash_table *this, const char *key);
int hash_table_del(struct hash_table *this, const char *key);
int hash_table_incr(struct hash_table *this, const char *key);
void hash_table_decr(struct hash_table *this, const char *key);
int hash_len(struct hash_table *this);

void hash_iterator_init(struct hash_iterator *this, struct hash_table *ht);
struct element *hash_iterator_next(struct hash_iterator *this);
void hash_array_free(struct element **ep);
struct element **hash_array(struct hash_table *this, int *pn);
struct hash_table *hash_from_urlencoding(char *urlencoding);

#define	HASH_FOREACH(e, kv, hi) \
			for (hash_iterator_init(&(hi), (kv)); ((e)=hash_iterator_next(&(hi)));)

#endif
