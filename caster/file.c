#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "file.h"
#include "ntrip_common.h"
#include "ntripsrv.h"


/*
 * Check the URI for subdir evasion
 */
static int check_safe_uri(const char *uri) {
	const char *p = uri;
	while (*p) {
		/* Forbid . in the path.
		 * Probably not needed, just to be safe.
		 */
		if (p[0] == '.' && p[1] == '/')
			return -1;
		/* Forbid .. in the path */
		if (p[0] == '.' && p[1] == '.' && p[2] == '/')
			return -1;
		while (*p && *p != '/') p++;
		if (*p == '/') p++;
	}
	return 0;
}

int filesrv(struct ntrip_state *st, const char *uri, int *err, struct evkeyvalq *headers) {
	struct evbuffer *output = bufferevent_get_output(st->bev);
	struct config_webroots *wr = NULL;
	int len_uri = strlen(uri);

	for (int i = 0; i < st->config->webroots_count; i++) {
		struct config_webroots *wrt;
		wrt = st->config->webroots + i;
		int lw = strlen(wrt->uri);
		if (lw && len_uri >= lw && !memcmp(wrt->uri, uri, lw)) {
			wr = wrt;
			break;
		}
	}


	/* No webroot configured or no match */
	if (wr == NULL) {
		*err = 0;
		return -1;
	}

	if (check_safe_uri(uri) < 0) {
		*err = 404;
		return -1;
	}

	st->client_version = 0;
	st->type = "file";

	const char *paths[3];

	paths[0] = wr->path;
	paths[1] = uri;
	paths[2] = NULL;

	char *path = path_join(st->caster->config_dir, paths);
	if (path == NULL) {
		*err = 503;
		return -1;
	}

	int fd = open(path, O_RDONLY);
	strfree(path);
	if (fd < 0) {
		*err = 404;
		return -1;
	}

	struct mime_content *m = mime_file_read(fd);

	if (m == NULL) {
		*err = 503;
		return -1;
	}

	ntripsrv_send_result_ok(st, output, m, NULL);
	ntrip_set_state(st, NTRIP_WAIT_CLOSE);
	return 0;
}
