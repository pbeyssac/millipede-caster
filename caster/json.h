#ifndef __JSON_H__
#define __JSON_H__

int json_get_source_action(const char *sourcetable_line, json_object *sources);
int json_get_authentication(json_object *config, const char *mountpoint, const char **user, const char **password);
json_object *json_file_read(const char *dir, const char *filename);

#endif