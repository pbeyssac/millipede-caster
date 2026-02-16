#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json_object.h>

#include "util.h"

/*
 * Miscellaneous Json helper functions.
 */

/*
 * Return a configured action for a sourcetable line.
 * For STR lines, look for an entry for this mountpoint in the configuration.
 * If not found, use the "*" entry as default.
 * If not found, keep the line.
 *
 * Return 1 if the line is to be kept, 0 if not.
 */
int json_get_source_action(const char *sourcetable_line, json_object *sources) {
	char *sc;

	if (sources == NULL)
		return 1;

	int len = strlen(sourcetable_line);
	if (len <= 15 || memcmp(sourcetable_line, "STR;", 4) || (sc = strchr(sourcetable_line+4, ';')) == NULL)
		return 1;

	int keylen = sc-(sourcetable_line+4);
	char *key = (char *)strmalloc(keylen+1);
	memcpy(key, sourcetable_line+4, keylen);
	key[keylen] = '\0';

	json_object *mountpoint = json_object_object_get(sources, key);
	strfree(key);

	if (mountpoint == NULL)
		mountpoint = json_object_object_get(sources, "*");

	const char *action = NULL;

	if (mountpoint != NULL)
		action = json_object_get_string(json_object_object_get(mountpoint, "action"));

	return action == NULL || !strcmp(action, "keep");
}

/*
 * Return user + password, if any, for a given mountpoint in the configuration.
 * If mountpoint is not found, look for a default "*" entry.
 */
int json_get_authentication(json_object *json_config, const char *mountpoint,
        const char **user, const char **password) {

	*user = NULL;
	*password = NULL;

	json_object *sources = json_object_object_get(json_config, "sources");
	if (sources == NULL)
		return 0;

	json_object *auth = json_object_object_get(sources, "mountpoint");
	if (auth == NULL)
		auth = json_object_object_get(sources, "*");

	if (auth != NULL) {
		*user = json_object_get_string(json_object_object_get(auth, "user"));
		*password = json_object_get_string(json_object_object_get(auth, "password"));
		return 1;
        }
        return 0;
}

/*
 * Read and parse a JSON file.
 * Return a json_object on success, else NULL.
 */
json_object *json_file_read(const char *dir, const char *filename) {
	json_object *j = NULL;

	int fd = open_absolute(dir, filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	struct mime_content *m = mime_file_read_string(fd);
	close(fd);
	if (m == NULL)
		return NULL;

	j = json_tokener_parse((const char *)m->s);
	mime_free(m);
	return j;
}
