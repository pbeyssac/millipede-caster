#ifndef __UTIL_H__
#define __UTIL_H__

#include <sys/types.h>

#include "conf.h"


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
 * Entry for host (as a client) or source (as a server) authorization
 */
struct auth_entry {
	const char *key;		// host name or mountpoint, depending on the file
	const char *user;		// username, if relevant (ntrip 2)
	const char *password;		// password (ntrip 1 or 2)
};

/*
 * Content with a MIME type
 */
struct mime_content {
	char *s;
	const char *mime_type;
	size_t len;
	int use_strfree;
};

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
char *percent_decode(char *s);
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
void mime_set_type(struct mime_content *this, const char *mime_type);
void mime_free(struct mime_content *this);
void mime_append(struct mime_content *this, const char *s);
void iso_date_from_timeval(char *iso_date, size_t iso_date_len, struct timeval *t);
struct parsed_file *file_parse(const char *filename, int nfields, const char *seps, int skipempty);
void file_free(struct parsed_file *p);
void logdate(char *date, size_t len);

char *mystrcasestr(const char *s, const char *find);

#if DEBUG
extern int str_alloc;
struct mime_content *malloc_stats_dump(int json);
#endif

#endif
