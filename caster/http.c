#include <ctype.h>
#include <string.h>
#include "http.h"
#include "util.h"

/*
 * Return a "Basic" Authorization: header line.
 */
int http_headers_add_auth(struct evkeyvalq *headers, const char *user, const char *password) {
	char *user_password = (char *)strmalloc(strlen(user)+strlen(password)+2);
	if (user_password == NULL) {
		return -1;
	}
	sprintf(user_password, "%s:%s", user, password);

	char *b64 = b64encode(user_password, strlen(user_password), 1);
	strfree(user_password);

	char *auth_value = (char *)strmalloc(strlen(b64) + 7);
	if (auth_value == NULL) {
		strfree(b64);
		return -1;
	}
	sprintf(auth_value, "Basic %s", b64);
	strfree(b64);
	if (evhttp_add_header(headers, "Authorization", auth_value) < 0) {
		strfree(auth_value);
		return -1;
	}
	strfree(auth_value);
	return 0;
}

/*
 * Decode Authorization: header.
 *
 * RFC 2617 section 2, "Basic Authentication Scheme".
 */
int http_decode_auth(char *value, char **user, char **password) {
	char *p;
	for (p = value; *p && !isspace(*p); p++);
	if (!*p)
		return -1;
	*p++ = '\0';

	if (strcasecmp(value, "Basic"))
		return -1;

	while (*p && isspace (*p)) p++;
	if (!*p)
		return -1;

	char *auth = b64decode(p, strlen(p), 1);
	if (auth) {
		int colon = strcspn(auth, ":");
		if (auth[colon] == ':') {
			auth[colon] = '\0';
			*user = auth;
			*password = auth + colon + 1;
			return 0;
		} else
			strfree(auth);
	}
	return -1;
}
