#ifndef __NTRIPSRV_H__
#define __NTRIPSRV_H__

#include "ntrip_common.h"

int ntripsrv_redo_virtual_pos(struct ntrip_state *st);

void ntripsrv_readcb(struct bufferevent *bev, void *arg);
void ntripsrv_writecb(struct bufferevent *bev, void *arg);
void ntripsrv_eventcb(struct bufferevent *bev, short events, void *arg);
#ifdef THREADS
void ntripsrv_workers_readcb(struct bufferevent *bev, void *arg);
void ntripsrv_workers_writecb(struct bufferevent *bev, void *arg);
void ntripsrv_workers_eventcb(struct bufferevent *bev, short events, void *arg);
#endif

#endif
