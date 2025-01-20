#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "util.h"

/*
 * Convert a key to a bucket number.
 */
static unsigned int hash_key(struct hash_table *this, const char *key) {
	unsigned int hash = 441;
	int c;
	while ((c = *key++))
		hash = hash*37 + c;
	return hash % this->n_buckets;
}

/*
 * Create a hash table with the indicated number of buckets.
 */
struct hash_table *hash_table_new(int n_buckets, void free_callback(void *)) {
	struct elementlisthead *element_lists;
	if (n_buckets <= 0)
		return NULL;
	struct hash_table *this = (struct hash_table *)malloc(sizeof(struct hash_table));
	element_lists = (struct elementlisthead *)malloc(n_buckets*sizeof(struct elementlisthead));
	if (this == NULL || element_lists == NULL) {
		free(this);
		free(element_lists);
		return NULL;
	}

	this->element_lists = element_lists;
	this->n_buckets = n_buckets;
	this->nentries = 0;
	this->free_callback = free_callback ? free_callback : free;

	/* Initialize the bucket lists */
	for (int h = 0; h < n_buckets; h++)
		SLIST_INIT(&this->element_lists[h]);
	return this;
}

/*
 * Free an element.
 */
static void _hash_table_free_element(struct hash_table *this, struct element *e) {
	strfree((char *)(e->key));
	this->free_callback(e->value);
	free(e);
}

/*
 * Free a complete hash table.
 */
void hash_table_free(struct hash_table *this) {
	struct element *e;
	int n = 0;

	for (int h = 0; h < this->n_buckets; h++) {
		struct elementlisthead *t = &this->element_lists[h];
		while ((e = SLIST_FIRST(t))) {
			SLIST_REMOVE_HEAD(t, next);
			_hash_table_free_element(this, e);
			n++;
		}
	}

	assert(n == this->nentries);
	free(this->element_lists);
	free(this);
}

/*
 * Find an element.
 * Return its pointer if found, else NULL.
 */
static struct element *hash_table_find(struct hash_table *this, const char *key, unsigned int *hk, int del) {
	unsigned int h = hash_key(this, key);
	if (hk) *hk = h;

	struct elementlisthead *head = &this->element_lists[h];
	struct elementlisthead *t = head;
	struct element *e;
	struct element *last = NULL;
	SLIST_FOREACH(e, t, next) {
		if (!strcmp(key, e->key)) {
			if (del) {
				if (last)
					SLIST_REMOVE_AFTER(last, next);
				else
					SLIST_REMOVE_HEAD(head, next);
				this->nentries--;
			}
			return e;
		}
		last = e;
	}
	return NULL;
}

/*
 * Insert an element.
 */
int hash_table_add(struct hash_table *this, const char *key, void *value) {
	unsigned int h;
	struct element *e = hash_table_find(this, key, &h, 0);
	if (e != NULL)
		return -1;
	e = (struct element *)malloc(sizeof(struct element));
	if (e == NULL)
		return -1;
	e->value = value;
	e->key = mystrdup(key);
	SLIST_INSERT_HEAD(&this->element_lists[h], e, next);
	this->nentries++;
	return 0;
}

/*
 * Get an element, return its pointer or NULL if not found.
 */
struct element *hash_table_get_element(struct hash_table *this, const char *key) {
	unsigned int h;
	return hash_table_find(this, key, &h, 0);
}

/*
 * Get an element, return its value pointer or NULL if not found.
 */
void *hash_table_get(struct hash_table *this, const char *key) {
	struct element *e = hash_table_get_element(this, key);
	return e == NULL ? e:e->value;
}

/*
 * Remove an element.
 * Return 0 if found, -1 if not.
 */
int hash_table_del(struct hash_table *this, const char *key) {
	unsigned int h;
	struct element *e = hash_table_find(this, key, &h, 1);
	if (e == NULL)
		return -1;
	_hash_table_free_element(this, e);
	return 0;
}

/*
 * Special case: increment a counter for this key, creating it if needed.
 */
int hash_table_incr(struct hash_table *this, const char *key) {
	int *v = (int *)hash_table_get(this, key);
	if (v == NULL) {
		v = (int *)malloc(sizeof(int));
		if (v == NULL)
			return 0;
		*v = 1;
		hash_table_add(this, key, v);
	} else
		(*v)++;
	return *v;
}

/*
 * Special case: decrement counter for this key.
 */
void hash_table_decr(struct hash_table *this, const char *key) {
	int *v = (int *)hash_table_get(this, key);
	if (v) {
		(*v)--;
		assert(*v >= 0);
		if (*v == 0)
			hash_table_del(this, key);
	}
}

int hash_len(struct hash_table *this) {
	return this->nentries;
}
