#include <stdlib.h>
#include <string.h>

#include "ip.h"

/*
 * Return in dest a string representing sockaddr if it is a known family
 * (AF_INET or AF_INET6), else NULL.
 */
char *ip_str(union sock *sa, char *dest, int size_dest) {
	switch(sa->generic.sa_family) {
	case AF_INET:
		inet_ntop(sa->generic.sa_family, &sa->v4.sin_addr, dest, size_dest);
		return dest;
	case AF_INET6:
		inet_ntop(sa->generic.sa_family, &sa->v6.sin6_addr, dest, size_dest);
		return dest;
	default:
		return NULL;
	}
}

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
 * Convert a v6 or v4 IP address from a string to a union sock.
 */
int ip_convert(char *ipstr, union sock *sock) {
	int r;
	memset(sock, 0, sizeof(union sock));
	r = inet_pton(AF_INET6, ipstr, &sock->v6.sin6_addr);
	if (r > 0) {
		sock->v6.sin6_family = AF_INET6;
		sock->v6.sin6_len = sizeof sock->v6;
	} else {
		r = inet_pton(AF_INET, ipstr, &sock->v4.sin_addr);
		if (r > 0) {
			sock->v4.sin_family = AF_INET;
			sock->v4.sin_len = sizeof sock->v4;
		}
	}
	return r;
}
