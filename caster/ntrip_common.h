#ifndef __NTRIP_COMMON_H__
#define __NTRIP_COMMON_H__

#include "caster.h"
#include "livesource.h"

/* Log levels, same as syslog and GEF + LOG_EDEBUG */

#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */
#define	LOG_EDEBUG	8	/* extended debug messages */

struct ntrip_state *ntrip_new(struct caster_state *caster, char *host, unsigned short port, char *mountpoint);
void ntrip_free(struct ntrip_state *this, char *orig);
struct livesource *ntrip_add_livesource(struct ntrip_state *this, char *mountpoint);
void ntrip_unregister_livesource(struct ntrip_state *this, char *mountpoint);
void ntrip_alog(void *arg, const char *fmt, ...);
void ntrip_log(void *arg, int level, const char *fmt, ...);
int ntrip_handle_raw(struct ntrip_state *st, struct bufferevent *bev);
int ntrip_handle_raw_chunk(struct ntrip_state *st, struct bufferevent *bev);

#endif
