#ifndef __NTRIPSRV_H__
#define __NTRIPSRV_H__

#include <event2/http.h>

#include "ntrip_common.h"

int ntripsrv_redo_virtual_pos(struct ntrip_state *st);
int ntripsrv_send_result_ok(struct ntrip_state *this, struct evbuffer *output, char *mime_type, struct evkeyvalq *opt_headers);
int check_password(struct ntrip_state *this, char *mountpoint, char *user, char *passwd);

void ntripsrv_readcb(struct bufferevent *bev, void *arg);
void ntripsrv_writecb(struct bufferevent *bev, void *arg);
void ntripsrv_eventcb(struct bufferevent *bev, short events, void *arg);
#ifdef THREADS
void ntripsrv_workers_readcb(struct bufferevent *bev, void *arg);
void ntripsrv_workers_writecb(struct bufferevent *bev, void *arg);
void ntripsrv_workers_eventcb(struct bufferevent *bev, short events, void *arg);
#endif

#endif
