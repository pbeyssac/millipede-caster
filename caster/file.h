#ifndef __FILE_H__
#define __FILE_H__

#include <event2/http.h>

#include "ntrip_common.h"

int filesrv(struct ntrip_state *st, const char *uri, int *err, struct evkeyvalq *headers);

#endif
