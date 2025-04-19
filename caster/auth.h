#ifndef _AUTH_H_
#define _AUTH_H_

/*
 * Entry for host (as a client) or source (as a server) authorization
 */
struct auth_entry {
	const char *key;		// host name or mountpoint, depending on the file
	const char *user;		// username, if relevant (ntrip 2)
	const char *password;		// password (ntrip 1 or 2)
};

struct caster_state;
struct auth_entry *auth_parse(struct caster_state *caster, const char *filename);
void auth_free(struct auth_entry *this);

#endif
