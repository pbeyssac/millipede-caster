#ifndef __NTRIPSRV_H__
#define __NTRIPSRV_H__

#include <event2/http.h>

#include "ntrip_common.h"

enum check_password_result {
	CHECKPW_MOUNTPOINT_INVALID,
	CHECKPW_MOUNTPOINT_VALID,
	CHECKPW_MOUNTPOINT_WILDCARD
};

void ntripsrv_redo_virtual_pos(struct ntrip_state *st);
int ntripsrv_send_result_ok(struct ntrip_state *this, struct evbuffer *output, struct mime_content *m, struct evkeyvalq *opt_headers);
int ntripsrv_send_stream_result_ok(struct ntrip_state *this, struct evbuffer *output, const char *mime_type, struct evkeyvalq *opt_headers);
void ntripsrv_deferred_output(struct ntrip_state *st, struct mime_content *(*content_cb)(struct caster_state *caster));
int check_password(struct ntrip_state *this, const char *mountpoint, const char *user, const char *passwd);

void ntripsrv_readcb(struct bufferevent *bev, void *arg);
void ntripsrv_writecb(struct bufferevent *bev, void *arg);
void ntripsrv_eventcb(struct bufferevent *bev, short events, void *arg);
void ntripsrv_workers_readcb(struct bufferevent *bev, void *arg);
void ntripsrv_workers_writecb(struct bufferevent *bev, void *arg);
void ntripsrv_workers_eventcb(struct bufferevent *bev, short events, void *arg);

#endif
