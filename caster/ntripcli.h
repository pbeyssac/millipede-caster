#ifndef __NTRIPCLI_H__
#define __NTRIPCLI_H__

#include <event2/event_struct.h>

#include "caster.h"
#include "ntrip_task.h"

void ntripcli_readcb(struct bufferevent *bev, void *arg);
void ntripcli_writecb(struct bufferevent *bev, void *arg);
void ntripcli_eventcb(struct bufferevent *bev, short events, void *arg);
int ntripcli_start(struct caster_state *caster, char *host, unsigned short port, int tls, const char *type, struct ntrip_task *task);
void ntripcli_workers_readcb(struct bufferevent *bev, void *arg);
void ntripcli_workers_writecb(struct bufferevent *bev, void *arg);
void ntripcli_workers_eventcb(struct bufferevent *bev, short events, void *arg);

#endif
