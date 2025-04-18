#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "ip.h"
#include "util.h"

/*
 * Store in dest a string representing sockaddr, port excluded, if it is a known family
 * (AF_INET or AF_INET6).
 *
 * Return dest, or NULL if unknown family.
 */
char *ip_str(union sock *sa, char *dest, int size_dest) {
	switch(sa->generic.sa_family) {
	case AF_INET:
		inet_ntop(sa->v4.sin_family, &sa->v4.sin_addr, dest, size_dest);
		return dest;
	case AF_INET6:
		inet_ntop(sa->v6.sin6_family, &sa->v6.sin6_addr, dest, size_dest);
		return dest;
	default:
		return NULL;
	}
}

/*
 * Store in dest a string representing sockaddr, port included, if it is a known family
 * (AF_INET or AF_INET6).
 *
 * Return dest, or NULL if unknown family.
 */
char *ip_str_port(union sock *sa, char *dest, int size_dest) {
	char ip[40];
	switch(sa->generic.sa_family) {
	case AF_INET:
		snprintf(dest, size_dest, "%s:%hu",
			inet_ntop(sa->v4.sin_family, &sa->v4.sin_addr, ip, sizeof ip),
			ntohs(sa->v4.sin_port));
		return dest;
	case AF_INET6:
		snprintf(dest, size_dest, "%s.%hu",
			inet_ntop(sa->v6.sin6_family, &sa->v6.sin6_addr, ip, sizeof ip),
			ntohs(sa->v6.sin6_port));
		return dest;
	default:
		return NULL;
	}
}

/*
 * Return the port from sa, in host byte order.
 */
unsigned short ip_port(union sock *sa) {
	switch(sa->generic.sa_family) {
	case AF_INET:
		return ntohs(sa->v4.sin_port);
	case AF_INET6:
		return ntohs(sa->v6.sin6_port);
	default:
		return 0;
	}
}

/*
 * Compare two IP addresses + ports + family..
 */
int ip_cmp(union sock *s1, union sock *s2) {
	int r;
	r = s1->generic.sa_family - s2->generic.sa_family;
	if (r)
		return r;

	switch(s1->generic.sa_family) {
	case AF_INET:
		r = s1->v4.sin_addr.s_addr - s2->v4.sin_addr.s_addr;
		if (r)
			return r;
		return s1->v4.sin_port - s2->v4.sin_port;
	case AF_INET6:
		r = memcmp(&s1->v6.sin6_addr, &s2->v6.sin6_addr, sizeof(s1->v6.sin6_addr));
		if (r)
			return r;
		return s1->v6.sin6_port - s2->v6.sin6_port;
	}
	return -1;
}

/*
 * Convert a v6 or v4 IP address from a string to a union sock.
 */
int ip_convert(const char *ipstr, union sock *sock) {
	int r;
	memset(sock, 0, sizeof(union sock));
	r = inet_pton(AF_INET6, ipstr, &sock->v6.sin6_addr);
	if (r > 0) {
		sock->v6.sin6_family = AF_INET6;
#ifdef _SOCKLEN_T_DECLARED
		sock->v6.sin6_len = sizeof sock->v6;
#endif
	} else {
		r = inet_pton(AF_INET, ipstr, &sock->v4.sin_addr);
		if (r > 0) {
			sock->v4.sin_family = AF_INET;
#ifdef _SOCKLEN_T_DECLARED
			sock->v4.sin_len = sizeof sock->v4;
#endif
		}
	}
	return r;
}

/*
 * Parse a string containing IP[/prefixlen].
 * If prefixlen is not provided, use /128 for IPv6, /32 for IPv4.
 */
int ip_prefix_parse(const char *ipstr, union sock *sock, int *prefixlen) {
	int pmax;
	const int MAX_IP_LEN = 40;
	char ip[MAX_IP_LEN];

	int len = 0;
	char *p = strchr(ipstr, '/');

	len = p ? (p - ipstr) : strlen(ipstr);
	if (len > MAX_IP_LEN)
		return 0;
	memcpy(ip, ipstr, len);
	ip[len] = '\0';

	if (p && sscanf(p+1, "%d", prefixlen) != 1)
		return 0;

	if (ip_convert(ip, sock) <= 0)
		return 0;
	switch(sock->generic.sa_family) {
	case AF_INET6:
		pmax = 128;
		break;
	case AF_INET:
		pmax = 32;
		break;
	default:
		return 0;
	}

	if (!p) {
		*prefixlen = pmax;
		return 1;
	}
	if (*prefixlen >= 0 && *prefixlen <= pmax)
		return 1;
	return 0;
}

/*
 * Check the provided IP is all-0 after the prefix.
 */
static int _prefix_check_ip(union sock *sock, int prefixlen) {
	unsigned char *beg;
	int len;

	switch(sock->generic.sa_family) {
	case AF_INET:
		beg = (unsigned char *)&sock->v4.sin_addr;
		len = 4;
		break;
	case AF_INET6:
		beg = (unsigned char *)&sock->v6.sin6_addr;
		len = 16;
		break;
	}
	unsigned char *last = beg + len-1;
	int bits0 = (len << 3) - prefixlen;

	int nfull0 = bits0 >> 3;
	while (nfull0--) {
		if (*last--)
			return -1;
	}
	if (bits0 & 7) {
		int mask_remain = (1 << (bits0 & 7)) - 1;
		if (*last & mask_remain)
			return -1;
	}
	return 0;
}

/*
 * Parse a prefix + quota pair.
 * Return a filled struct prefix_quota.
 */
struct prefix_quota *prefix_quota_parse(const char *ip_prefix, const char *quota_str) {
	int quota, prefixlen;

	if (sscanf(quota_str, "%u", &quota) != 1 || quota < -1)
		return NULL;

	struct prefix_quota *r = (struct prefix_quota *)malloc(sizeof(struct prefix_quota));
	if (!r)
		return NULL;

	if (ip_prefix_parse(ip_prefix, &r->prefix.addr, &prefixlen) <= 0) {
		free(r);
		return NULL;
	}
	r->quota = quota;
	r->prefix.len = prefixlen;

	if (_prefix_check_ip(&r->prefix.addr, prefixlen) < 0) {
		free(r);
		return NULL;
	}
	return r;
}

/*
 * Return a printable string for a struct prefix_quota.
 */
char *prefix_quota_str(struct prefix_quota *ppq) {
	char ip[50];
	int maxlen = sizeof(ip)+15;
	ip_str(&ppq->prefix.addr, ip, sizeof ip);
	char *r = (char *)malloc(maxlen);
	snprintf(r, maxlen, "%s/%d %d", ip, ppq->prefix.len, ppq->quota);
	return r;
}

/*
 * Helper function to sort the prefixes by decreasing length.
 */
static int _cmp_prefix(const void *p1, const void *p2) {
	struct prefix_quota *qp1 = *(struct prefix_quota **)p1;
	struct prefix_quota *qp2 = *(struct prefix_quota **)p2;

	if (qp1->prefix.len < qp2->prefix.len)
		return -1;
	if (qp1->prefix.len > qp2->prefix.len)
		return 1;
	return 0;
}

/*
 * Sort the prefix tables
 */
static void _prefix_table_sort(struct prefix_table *this) {
	qsort(this->v6_table.entries, this->v6_table.nentries, sizeof(this->v6_table.entries[0]), _cmp_prefix);
	qsort(this->v4_table.entries, this->v4_table.nentries, sizeof(this->v4_table.entries[0]), _cmp_prefix);
}

/*
 * Add an element to a mono-protocol prefix table.
 */
static int _monofamily_prefix_table_add(struct _monofamily_prefix_table *this, struct prefix_quota *new_entry) {
	if (this->nentries + 1 >= this->maxentries) {
		int new_size = this->maxentries?this->maxentries*2:2;
		struct prefix_quota **p = (struct prefix_quota **)realloc(this->entries, sizeof(struct prefix_quota *)*new_size);
		if (p == NULL)
			return -1;
		this->maxentries = new_size;
		this->entries = p;
	}
	this->entries[this->nentries++] = new_entry;
	return 0;
}

/*
 * Add an element to an aggregate prefix table, choosing the right protocol.
 */
static int _prefix_table_add(struct prefix_table *this, struct prefix_quota *new_entry) {
	if (new_entry->prefix.addr.generic.sa_family == AF_INET6)
		return _monofamily_prefix_table_add(&this->v6_table, new_entry);
	else
		return _monofamily_prefix_table_add(&this->v4_table, new_entry);
}

/*
 * Check whether addr is inside the prefix.
 */
static int _in_prefix(struct prefix *prefix, union sock *addr) {
	unsigned char *a, *ap;
	int lenfull, remain;

	lenfull = prefix->len >> 3;
	remain = (prefix->len & 7);
	unsigned char lastmask = ~(0xff >> remain);

	switch(addr->generic.sa_family) {
	case AF_INET6:
		a = (unsigned char *)&addr->v6.sin6_addr;
		ap = (unsigned char *)&prefix->addr.v6.sin6_addr;
		break;
	case AF_INET:
		a = (unsigned char *)&addr->v4.sin_addr;
		ap = (unsigned char *)&prefix->addr.v4.sin_addr;
		break;
	}

	if (lenfull && memcmp(a, ap, lenfull))
		return 0;
	if (lastmask && ((a[lenfull] ^ ap[lenfull]) & lastmask))
		return 0;
	return 1;
}

/*
 * Return the quota for the address range to which addr belongs.
 * addr should be in the right family for the table.
 * -1 (no quota) if not found.
 */
static int _monofamily_prefix_table_get_quota(struct _monofamily_prefix_table *this, union sock *addr) {
	for (int i = this->nentries-1; i >= 0; i--)
		if (_in_prefix(&this->entries[i]->prefix, addr))
			return this->entries[i]->quota;
	return -1;
}

/*
 * Return the quota for the address range to which addr belongs.
 * addr can be AF_INET6 or AF_INET.
 *
 * -1 (no quota) if not found.
 */
int prefix_table_get_quota(struct prefix_table *this, union sock *addr) {
	switch(addr->generic.sa_family) {
	case AF_INET6:
		return _monofamily_prefix_table_get_quota(&this->v6_table, addr);
	case AF_INET:
		return _monofamily_prefix_table_get_quota(&this->v4_table, addr);
	}
	return -1;
}

/*
 * Return a new prefix table, filled from the provided file name.
 */
struct prefix_table *prefix_table_new(const char *filename, struct log *log) {
	struct parsed_file *p;
	struct prefix_table *this = (struct prefix_table *)malloc(sizeof(struct prefix_table));

	if (this == NULL)
		return NULL;

	p = file_parse(filename, 2, "\t ", 1, log);

	if (p == NULL) {
		logfmt(log, LOG_ERR, "Can't read or parse %s", filename);
		free(this);
		return NULL;
	}

	this->v4_table.maxentries = 0;
	this->v4_table.nentries = 0;
	this->v4_table.entries = NULL;
	this->v6_table.maxentries = 0;
	this->v6_table.nentries = 0;
	this->v6_table.entries = NULL;

	for (int n = 0; n < p->nlines; n++) {
		struct prefix_quota *pq;
		pq = prefix_quota_parse(p->pls[n][0], p->pls[n][1]);
		if (pq != NULL)
			_prefix_table_add(this, pq);
		else
			logfmt(log, LOG_ERR, "Can't parse %s %s, skipping", p->pls[n][0], p->pls[n][1]);
	}
	file_free(p);
	_prefix_table_sort(this);
	return this;
}

/*
 * Free a mono-family prefix table.
 */
static void _monofamily_prefix_table_free(struct _monofamily_prefix_table *this) {
	for (int i = 0; i < this->nentries; i++)
		free(this->entries[i]);
	free(this->entries);
}

/*
 * Free a prefix table.
 */
void prefix_table_free(struct prefix_table *this) {
	_monofamily_prefix_table_free(&this->v4_table);
	_monofamily_prefix_table_free(&this->v6_table);
	free(this);
}
