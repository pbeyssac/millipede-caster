#ifndef __NTRIPCLI_H__
#define __NTRIPCLI_H__

#include <event2/event_struct.h>

#include "caster.h"

void ntripcli_readcb(struct bufferevent *bev, void *arg);
void ntripcli_writecb(struct bufferevent *bev, void *arg);
void ntripcli_eventcb(struct bufferevent *bev, short events, void *arg);
void ntripcli_workers_readcb(struct bufferevent *bev, void *arg);
void ntripcli_workers_writecb(struct bufferevent *bev, void *arg);
void ntripcli_workers_eventcb(struct bufferevent *bev, short events, void *arg);

#endif
