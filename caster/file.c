#include <string.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "conf.h"
#include "file.h"
#include "ntrip_common.h"
#include "ntripsrv.h"

#include <sys/stat.h>
#include <fcntl.h>

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
	struct stat sb;
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

	char *file_content;

	/* Get file stats, check it's a regular file */
	if (fstat(fd, &sb) < 0 || ((sb.st_mode & S_IFMT) != S_IFREG)) {
		*err = 404;
		close(fd);
		return -1;
	}
	if ((file_content = (char *)malloc(sb.st_size)) == NULL) {
		*err = 503;
		close(fd);
		return -1;
	}

	/* Read the full file in memory */
	int r = read(fd, file_content, sb.st_size);
	if (r != sb.st_size) {
		*err = 503;
		close(fd);
		return -1;
	}
	close(fd);

	struct mime_content *m = mime_new(file_content, sb.st_size, NULL, 0);
	ntripsrv_send_result_ok(st, output, m, NULL);
	st->state = NTRIP_WAIT_CLOSE;
	return 0;
}
