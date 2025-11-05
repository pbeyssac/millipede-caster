#ifndef __API_H__
#define __API_H__

struct mime_content *api_ntrip_list_json(struct caster_state *caster, struct request *req);
struct mime_content *api_rtcm_json(struct caster_state *caster, struct request *req);
struct mime_content *api_mem_json(struct caster_state *caster, struct request *req);
struct mime_content *api_reload_json(struct caster_state *caster, struct request *req);
struct mime_content *api_drop_json(struct caster_state *caster, struct request *req);
struct mime_content *api_sync_json(struct caster_state *caster, struct request *req);

#endif
