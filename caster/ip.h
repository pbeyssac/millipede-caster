#ifndef _IP_H_
#define _IP_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "log.h"

/*
 * Generic socket address type to encapsulate both IPv6 and IPv4.
 */
union sock {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
	struct sockaddr generic;
};

/*
 * Descriptor for an IP prefix
 */
struct prefix {
	union sock addr;	// address (AF_INET6 or AF_INET)
	int len;		// prefix length
};

/*
 * Descriptor for an IP prefix quota
 */
struct prefix_quota {
	struct prefix prefix;
	int quota;		// number of allowed connections per IP
				// -1 = unlimited
};

/*
 * Prefix table for one protocol family, sorted by decreasing length of prefix.
 */
struct _monofamily_prefix_table {
	struct prefix_quota **entries;
	int nentries, maxentries;
};

/*
 * Common prefix table for AF_INET6 and AF_INET.
 */
struct prefix_table {
	struct _monofamily_prefix_table v6_table, v4_table;
};

char *ip_str(union sock *sa, char *dest, int size_dest);
char *ip_str_port(union sock *sa, char *dest, int size_dest);
unsigned short ip_port(union sock *sa);
int ip_cmp(union sock *s1, union sock *s2);

int ip_convert(const char *ipstr, union sock *sock);
int ip_prefix_parse(const char *ipstr, union sock *sock, int *prefixlen);
struct prefix_quota *prefix_quota_parse(const char *ip_prefix, const char *quota_str);
char *prefix_quota_str(struct prefix_quota *ppq);
void prefix_table_sort(struct prefix_table *this);
int prefix_table_add(struct prefix_table *this, struct prefix_quota *new_entry);
int ip_in_prefix(struct prefix *prefix, union sock *addr);
int prefix_table_get_quota(struct prefix_table *this, union sock *addr);
struct prefix_table *prefix_table_new();
int prefix_table_read(struct prefix_table * this, const char *filename, struct log *log);
void prefix_table_free(struct prefix_table *this);

#endif
