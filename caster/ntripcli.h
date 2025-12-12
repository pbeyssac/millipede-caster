#ifndef __NTRIPCLI_H__
#define __NTRIPCLI_H__

#include <event2/event_struct.h>

#include "caster.h"
#include "ntrip_task.h"

void ntripcli_readcb(struct bufferevent *bev, void *arg);
void ntripcli_writecb(struct bufferevent *bev, void *arg);
void ntripcli_eventcb(struct bufferevent *bev, short events, void *arg);
struct ntrip_state * ntripcli_new(struct caster_state *caster, char *host, unsigned short port, int tls, const char *uri,
	const char *type, struct ntrip_task *task,
	struct livesource *livesource,
	int persistent,
	struct config *new_config);
int ntripcli_start(struct ntrip_state *st);

void ntripcli_workers_readcb(struct bufferevent *bev, void *arg);
void ntripcli_workers_writecb(struct bufferevent *bev, void *arg);
void ntripcli_send_request(struct ntrip_state *st, struct mime_content *m, int send_mime);
void ntripcli_workers_eventcb(struct bufferevent *bev, short events, void *arg);

#endif
