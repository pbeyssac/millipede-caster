#ifndef __ADM_H__
#define __ADM_H__

#include <event2/http.h>

#include "ntrip_common.h"

int admsrv(struct ntrip_state *st, const char *root_uri, const char *uri, int *err, struct evkeyvalq *headers);

#endif
