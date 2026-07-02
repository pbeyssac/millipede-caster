#ifndef __MBUF_H__
#define __MBUF_H__

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * Growable byte buffer.
 *
 * Extracted from prometheus.c so it can be shared by rinex.c and any
 * other module that needs to build a variable-length text payload.
 *
 * Ownership: the caller owns m->data and must free() it.
 */

struct mbuf {
	char *data;
	size_t len;
	size_t cap;
};

static inline int mbuf_init(struct mbuf *b, size_t cap) {
	b->data = (char *)malloc(cap);
	if (b->data == NULL) { b->len = b->cap = 0; return -1; }
	b->len = 0;
	b->cap = cap;
	return 0;
}

static inline int mbuf_ensure(struct mbuf *b, size_t extra) {
	if (b->len + extra + 1 <= b->cap) return 0;
	size_t new_cap = b->cap;
	while (new_cap < b->len + extra + 1) new_cap *= 2;
	char *nd = (char *)realloc(b->data, new_cap);
	if (nd == NULL) return -1;
	b->data = nd; b->cap = new_cap;
	return 0;
}

static inline int mbuf_append(struct mbuf *b, const char *s, size_t n) {
	if (mbuf_ensure(b, n) < 0) return -1;
	memcpy(b->data + b->len, s, n);
	b->len += n;
	b->data[b->len] = '\0';
	return 0;
}

static inline int mbuf_puts(struct mbuf *b, const char *s) {
	return mbuf_append(b, s, strlen(s));
}

static inline int mbuf_printf(struct mbuf *b, const char *fmt, ...) {
	char stack[256];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(stack, sizeof stack, fmt, ap);
	va_end(ap);
	if (n < 0) return -1;
	if ((size_t)n < sizeof stack)
		return mbuf_append(b, stack, (size_t)n);
	/* Didn't fit in stack — retry with a heap buffer. */
	char *heap = (char *)malloc((size_t)n + 1);
	if (heap == NULL) return -1;
	va_start(ap, fmt);
	int n2 = vsnprintf(heap, (size_t)n + 1, fmt, ap);
	va_end(ap);
	if (n2 < 0) { free(heap); return -1; }
	int r = mbuf_append(b, heap, (size_t)n2);
	free(heap);
	return r;
}

static inline void mbuf_free(struct mbuf *b) {
	free(b->data);
	b->data = NULL;
	b->len = b->cap = 0;
}

#endif /* __MBUF_H__ */
