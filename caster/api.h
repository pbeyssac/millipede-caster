#ifndef _API_H_
#define _API_H_

struct mime_content *api_ntrip_list_json(struct caster_state *caster, struct hash_table *h);
struct mime_content *api_mem_json(struct caster_state *caster, struct hash_table *h);
struct mime_content *api_reload_json(struct caster_state *caster, struct hash_table *h);
struct mime_content *api_drop_json(struct caster_state *caster, struct hash_table *h);

#endif
