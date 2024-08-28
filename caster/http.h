#ifndef __HTTP_H_
#define __HTTP_H_

#include <event2/http.h>

#include "http.h"
#include "util.h"

int http_headers_add_auth(struct evkeyvalq *headers, const char *user, const char *password);
int http_decode_auth(char *value, char **user, char **password);

#endif
