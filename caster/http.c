#include <stdio.h>
#include <string.h>
#include "http.h"

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
