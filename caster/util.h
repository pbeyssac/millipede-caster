#ifndef __UTIL_H__
#define __UTIL_H__

#include <sys/types.h>
#include <sys/queue.h>

#include "conf.h"
#include "log.h"


// Geographical position
typedef struct pos {
	float lat, lon;
} pos_t;

typedef struct string_array {
	int count;
	char **ps;
} string_array_t;

/*
 * A parsed file
 */
struct parsed_file {
	int nlines;		// number of lines
	int nfields;		// number of fields per line
	char ***pls;
	char *filename;
};

/*
 * Content with a MIME type
 */
struct mime_content {
	STAILQ_ENTRY(mime_content) next;	// optional queue
	char *s;
	const char *mime_type;
	size_t len;
	int use_strfree, is_packet;
	struct packet *packet;
};
STAILQ_HEAD(mimeq, mime_content);

#if !DEBUG
#define strfree free
#define mystrdup strdup
#define strmalloc malloc
#define strrealloc realloc
#define strfree free
#endif

void free_callback(const void *data, size_t datalen, void *extra);
void strfree_callback(const void *data, size_t datalen, void *extra);
void mime_free_callback(const void *data, size_t datalen, void *extra);

float distance(pos_t *p1, pos_t *p2);
char *path_join(const char *abs, const char **list);
char *urldecode(char *s);
char *b64encode(const char *str, size_t len, int add_nul);
char *b64decode(char *str, size_t len, int add_nul);
unsigned long crc24q_hash(unsigned char *data, size_t len);
int parse_gga(const char *line, pos_t *pos);
char *host_port_str(char *host, unsigned short port);
char *mystrdup(const char *str);
void *strmalloc(size_t len);
void *strrealloc(void *p, size_t len);
void strfree(void *str);
int parse_header(char *line, char **key, char **val);
struct mime_content *mime_new(char *s, long long len, const char *mime_type, int use_strfree);
struct mime_content *mime_new_from_packet(const char *mime_type, struct packet *packet);
void mime_set_type(struct mime_content *this, const char *mime_type);
void mime_free(struct mime_content *this);
char *joinpath(const char *dir, const char *path);
FILE *fopen_absolute(const char *dir, const char *filename, const char *mode);

void iso_date_from_timeval(char *iso_date, size_t iso_date_len, struct timeval *t);
void timeval_from_iso_date(struct timeval *t, const char *iso_date);
void timeval_to_json(struct timeval *t, json_object *json, const char *json_key);
struct parsed_file *file_parse(const char *dir, const char *filename, int nfields, const char *seps, int skipempty, struct log *log);
void file_free(struct parsed_file *p);
void logdate(char *date, size_t len, struct timeval *ts);
void filedate(char *filename, size_t len, const char *format);

char *mystrcasestr(const char *s, const char *find);

#if DEBUG
extern int str_alloc;
struct mime_content *malloc_stats_dump(int json);
#endif

#endif
