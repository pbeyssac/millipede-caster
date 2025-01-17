#ifndef _IP_H_
#define _IP_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/*
 * Generic socket address type to encapsulate both IPv6 and IPv4.
 */
union sock {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
	struct sockaddr generic;
};

char *ip_str(union sock *sa, char *dest, int size_dest);
unsigned short ip_port(union sock *sa);
int ip_convert(char *ipstr, union sock *sock);

#endif
