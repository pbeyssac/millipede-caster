#ifndef __NTRIP_COMMON_H__
#define __NTRIP_COMMON_H__

#include "caster.h"
#include "livesource.h"

struct ntrip_state *ntrip_new(struct caster_state *caster, char *host, unsigned short port, char *mountpoint);
void ntrip_free(struct ntrip_state *this, char *orig);
void ntrip_incref(struct ntrip_state *this);
void ntrip_decref(struct ntrip_state *this, char *orig);
struct livesource *ntrip_add_livesource(struct ntrip_state *this, char *mountpoint);
void ntrip_unregister_livesource(struct ntrip_state *this, char *mountpoint);
void ntrip_alog(void *arg, const char *fmt, ...);
void ntrip_log(void *arg, const char *fmt, ...);
int ntrip_handle_raw(struct ntrip_state *st, struct bufferevent *bev);
int ntrip_handle_raw_chunk(struct ntrip_state *st, struct bufferevent *bev);

#endif
