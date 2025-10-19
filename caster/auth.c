#include "conf.h"
#include "auth.h"
#include "caster.h"
#include "util.h"

/*
 * Read user authentication file for the NTRIP server.
 */
struct auth_entry *auth_parse(struct caster_state *caster, const char *filename) {
	struct parsed_file *p;
	p = file_parse(caster->config_dir, filename, 3, ":", 0, &caster->flog);

	if (p == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Can't read or parse %s", filename);
		return NULL;
	}
	struct auth_entry *auth = (struct auth_entry *)malloc(sizeof(struct auth_entry)*(p->nlines+1));

	int n;
	for (n = 0; n < p->nlines; n++) {
		auth[n].key = mystrdup(p->pls[n][0]);
		auth[n].user = mystrdup(p->pls[n][1]);
		auth[n].password = mystrdup(p->pls[n][2]);
	}
	auth[n].key = NULL;
	auth[n].user = NULL;
	auth[n].password = NULL;
	file_free(p);
	return auth;
}

void auth_free(struct auth_entry *this) {
	struct auth_entry *p = this;
	if (this == NULL)
		return;
	while (p->key || p->user || p->password) {
		strfree((char *)p->key);
		strfree((char *)p->user);
		strfree((char *)p->password);
		p++;
	}
	free(this);
}
