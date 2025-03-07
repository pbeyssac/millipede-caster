#include <arpa/inet.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>

#ifdef DEBUG_JEMALLOC
#include <malloc_np.h>
#endif

#include "conf.h"
#include "log.h"
#include "util.h"

/*
 * Compute distance between two geographical points.
 */
float distance(pos_t *p1, pos_t *p2) {
	float R = 6371000.;
	float dLat = (p2->lat-p1->lat)*(M_PI/180.);
	float dLon = (p2->lon-p1->lon)*(M_PI/180.);
	float sindlo = sin(dLon/2);
	float sindla = sin(dLat/2);
	float a = sindla*sindla
		+ cos(p1->lat*(M_PI/180.))
		*cos(p2->lat*(M_PI/180.))
		*sindlo*sindlo;
	float c = 2 * atan2(sqrt(a), sqrt(1-a));
	return R*c;
}

/*
 * %-decode a string in place.
 * In addition, convert '+' to ' '.
 * Return the same string pointer.
 */
char *urldecode(char *s) {
	char *src, *dst, c;

	src = s;
	while (*src && *src != '+' && *src != '%')
		src++;
	if (!*src)
		return s;

	dst = src;

	while (*src) {
		if (*src == '+') {
			c = ' ';
			src++;
		} else if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
			int d1 = tolower(src[1]) - (isdigit(src[1]) ? '0':('a'-10));
			int d2 = tolower(src[2]) - (isdigit(src[2]) ? '0':('a'-10));
			c = d1*16+d2;
			src += 3;
		} else
			c = *src++;
		*dst++ = c;
	}
	*dst++ = '\0';
	return s;
}

static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encode a string in base64
 */
char *b64encode(const char *sstr, size_t len, int add_nul) {
	const unsigned char *str = (unsigned char *)sstr;
	int remain = len % 3;
	int b64len = len/3*4 + (remain ? 4 : 0) + (add_nul ? 1 : 0);
	char *b64result = (char *)strmalloc(b64len);

	if (b64result == NULL)
		return NULL;

	char *code = b64result;

	int i = 0;
	while (i < len - remain) {
		*code++ = base64[str[i]>>2];
		*code++ = base64[((str[i]<<4) | (str[i+1]>>4)) & 63];
		*code++ = base64[((str[i+1]<<2) | (str[i+2]>>6)) & 63];
		*code++ = base64[str[i+2] & 63];
		i += 3;
	}
	if (remain == 1) {
		*code++ = base64[str[i]>>2];
		*code++ = base64[(str[i]<<4) & 63];
		*code++ = '=';
		*code++ = '=';
	} else if (remain == 2) {
		*code++ = base64[str[i]>>2];
		*code++ = base64[((str[i]<<4) | (str[i+1]>>4)) & 63];
		*code++ = base64[(str[i+1]<<2) & 63];
		*code++ = '=';
	}
	if (add_nul)
		*code++ = '\0';
	return b64result;
}

/*
 * Decode a base64 string.
 */
char *b64decode(char *str, size_t len, int add_nul) {
	unsigned long i;
	if (len % 4) {
		return NULL;
	}
	size_t result_len = len/4*3 + (add_nul ? 1 : 0);
	if (len >= 4) {
		/* Check trailing padding and adjust lengths */
		if (str[len-1] == '=') {
			result_len -= 1;
			len--;
			if (str[len-1] == '=') {
				result_len -= 1;
				len--;
			}
		}
	}

	char *result = (char *)strmalloc(result_len);

	if (result == NULL)
		return NULL;

	char *r = result;

	i = 1;
	for (int n = 0; n < len; n++) {
		int c = *str++;
		int b6;

		if (c >= 'A' && c <= 'Z') {
			b6 = c - 'A';
		} else if (c >= 'a' && c <= 'z') {
			b6 = c - ('a' - 26);
		} else if (c >= '0' && c <= '9') {
			b6 = c - ('0' - 52);
		} else if (c == '+') {
			b6 = 62;
		} else if (c == '/') {
			b6 = 63;
		} else {
			/* Invalid char */
			strfree(result);
			return NULL;
		}

		i = (i << 6) + b6;

		if (i & 0x1000000) {
			/* 3 new bytes ready to decode */
			*r++ = (i >> 16) & 0xff;
			*r++ = (i >> 8) & 0xff;
			*r++ = i & 0xff;
			i = 1;
		}
	}
	if (i & 0x40000) {
		/* 18 bits remaining, use the first 16 */
		*r++ = (i >> 10) & 0xff;
		*r++ = (i >> 2) & 0xff;
	} else if (i & 0x1000) {
		/* 12 bits remaining, use the first 8 */
		*r++ = (i >> 4) & 0xff;
	}
	if (add_nul)
		*r++ = '\0';
	return result;
}

/*
 * Parse a NMEA "GGA" line and return geographical position, if valid.
 */
int parse_gga(const char *line, pos_t *pos) {
	pos_t p;
	int n;
	int fix_type = 0;

	if (strlen(line) < 20)
		return -1;
	if (line[0] != '$' || line[1] != 'G')
		return -1;
	if (line[3] != 'G' || line[4] != 'G' || line[5] != 'A')
		return -1;
	int err = 0;
	char *token;
	char *gga_line = mystrdup(line);
	if (gga_line == NULL)
		return -1;
	char *septmp = gga_line;
	for (n = 0; (token = strsep(&septmp, ",")) != NULL; n++) {
		float s1, s2;
		switch(n) {
		case 2:
			/* Latitude */
			if (sscanf(token, "%2f%f", &s1, &s2) != 2) {
				err = 1;
			} else {
				p.lat = s1 + s2/60;
			}
			break;
		case 3:
			/* North/South */
			if (!strcmp(token, "S")) {
				p.lat = -p.lat;
			} else if (strcmp(token, "N")) {
				err = 1;
			}
			break;
		case 4:
			/* Longitude */
			if (sscanf(token, "%3f%f", &s1, &s2) != 2) {
				err = 1;
			} else {
				p.lon = s1 + s2/60;
			}
			break;
		case 5:
			/* East/West */
			if (!strcmp(token, "W")) {
				p.lon = -p.lon;
			} else if (strcmp(token, "E")) {
				err = 1;
			}
			break;
		case 6:
			/* Fix type, 0 = invalid */
			if (sscanf(token, "%d", &fix_type) != 1 || fix_type == 0)
				err = 1;
			break;
		case 7:
			/* Check number of satellites for the fix */
#if 0
			int nsats;
			if (fix_type == 0 || sscanf(token, "%d", &nsats) != 1 || nsats < 4)
				err = 1;
#endif
			break;
		}
	}
	strfree(gga_line);

	/*
	 * Number of fields should be 15
	 */
	if (err || n != 15)
		return -1;
	*pos = p;
	return 1;
}

/*
 * Return a "host:port" string for the Host: HTTP header.
 */
char *host_port_str(char *host, unsigned short port) {
	char *host_port = (char *)strmalloc(strlen(host) + 9);
	if (host_port != NULL) {
		if (strchr(host, ':'))
			sprintf(host_port, "[%s]:%d", host, port);
		else
			sprintf(host_port, "%s:%d", host, port);
	}
	return host_port;
}

/*
 * Test with:
 *	"A: B"
 *	"A: "
 *	"A:"
 */

/*
 * Parse a "Key: Value" line.
 * Return:
 *	1 if parsing successful, with key in *key and value in *value
 *	0 if failed
 */
int
parse_header(char *line, char **key, char **val) {
	char *colon = strchr(line, ':');
	char *p;
	if (colon == NULL) {
		return 0;
	}
	*colon = '\0';
	p = colon + 1;
	while (*p && (*p == ' ' || *p == '\t')) {
		p++;
	}
	// if (!*p): empty value, accept ("STR: " line for example).
	*key = line;
	*val = p;

	// Strip whitespace at the end of the value
	for (char *p2 = p + strlen(p) - 1; p2 >= p; p2--) {
		if (*p2 != ' ' && *p2 != '\t')
			break;
		*p2 = '\0';
	}
	return 1;
}

/*
 * Create a mime_content.
 *
 *	s is owned by the structure and will be freed with it
 *	if len < 0, it will be set to strlen(s)
 *	mime_type stays owned by the caller and should not be freed while the mime_content exists
 *	use_strfree says whether to use strfree() or free() in mime_free().
 */
struct mime_content *mime_new(char *s, long long len, const char *mime_type, int use_strfree) {
	struct mime_content *m = (struct mime_content *)malloc(sizeof(struct mime_content));
	if (m == NULL || s == NULL) {
		strfree(s);
		return NULL;
	}
	m->s = s;
	m->len = len >= 0 ? len : strlen(s);
	m->mime_type = mime_type;
	m->use_strfree = use_strfree;
	return m;
}

void mime_set_type(struct mime_content *this, const char *mime_type) {
	this->mime_type = mime_type;
}

void mime_free(struct mime_content *this) {
	if (this->use_strfree)
		strfree((char *)this->s);
	else
		free((void *)this->s);
	free(this);
}

void mime_append(struct mime_content *this, const char *s) {
	int len = strlen(s);
	char *new = (char *)strrealloc(this->s, this->len + len + 1);
	if (new) {
		this->s = new;
		memcpy(this->s + this->len, s, len+1);
		this->len += len;
	}
}

void iso_date_from_timeval(char *iso_date, size_t iso_date_len, struct timeval *t) {
	struct tm date;
	gmtime_r(&t->tv_sec, &date);
	strftime(iso_date, iso_date_len, "%Y-%m-%dT%H:%M:%SZ", &date);
	if (iso_date_len >= 25)
		snprintf(iso_date + 19, 6, ".%03ldZ", t->tv_usec/1000);
}

#if DEBUG
int str_alloc = 0;

static P_MUTEX_T strmutex = PTHREAD_MUTEX_INITIALIZER;

char *mystrdup(const char *str) {
	P_MUTEX_LOCK(&strmutex);
	str_alloc++;
	P_MUTEX_UNLOCK(&strmutex);
	return strdup(str);
}
void *strmalloc(size_t len) {
	P_MUTEX_LOCK(&strmutex);
	str_alloc++;
	P_MUTEX_UNLOCK(&strmutex);
	return malloc(len);
}
void *strrealloc(void *p, size_t len) {
	if (p == NULL) {
		P_MUTEX_LOCK(&strmutex);
		str_alloc++;
		P_MUTEX_UNLOCK(&strmutex);
	}
	return realloc(p, len);
}
void strfree(void *str) {
	if (str) {
		P_MUTEX_LOCK(&strmutex);
		str_alloc--;
		P_MUTEX_UNLOCK(&strmutex);
	}
	free(str);
}
#endif

/*
 * Callback to free regular malloc'd data
 */
void free_callback(const void *data, size_t datalen, void *extra) {
	free((void *)data);
}

/*
 * Callback to free strmalloc'd data
 */
void strfree_callback(const void *data, size_t datalen, void *extra) {
	strfree((void *)data);
}

/*
 * Callback to free MIME data
 */
void mime_free_callback(const void *data, size_t datalen, void *extra) {
	mime_free((struct mime_content *)extra);
}

static void string_array_free(string_array_t *s) {
	for (int i = 0; i < s->count; i++)
		strfree(s->ps[i]);
	free(s);
}

/*
 * Python-like split: split string s according to separator sep, at most maxsplits.
 * Returns an array of char * with number of elements in *count
 */
static string_array_t *split(const char *s, char sep, int maxsplits) {
	const char *p;
	int nseps = 0;
	for (p = s; *p; p++) {
		if (*s == sep)
			nseps++;
	}

	if (nseps > maxsplits)
		nseps = maxsplits;

	string_array_t *r = (string_array_t *)malloc(sizeof(string_array_t));
	char **rs = (char **)malloc(sizeof(char *)*(nseps+1));

	if (r == NULL || rs == NULL) {
		if (r) free(r);
		if (rs) free(rs);
		return NULL;
	}

	r->ps = rs;
	int i = 0;
	while (*p) {
		int len;
		const char *p0 = p;
		while (*p && *p != sep) p++;
		len = p-p0;
		char *ps = (char *)strmalloc(len+1);
		if (ps == NULL) {
			r->count = i;
			string_array_free(r);
			return NULL;
		}

		/* copy the string up to the separator; add a '\0' */
		memcpy(ps, p0, len);
		ps[len] = '\0';
		rs[i++] = ps;

		/* skip the current separator and go on */
		p++;
	}
	r->count = nseps+1;
	return r;
}

/*
 * Read a file with fields separated by characters in seps.
 * Skip empty fields if skipempty is not 0.
 */
struct parsed_file *file_parse(const char *filename, int nfields, const char *seps, const int skipempty, struct log *log) {
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen;
	char *token;
	int nlines = 0;
	int err = 0;

	FILE *fp = fopen(filename, "r+");

	if (fp == NULL) {
		logfmt(log, LOG_ERR, "Can't open %s", filename);
		return NULL;
	}

	struct parsed_file *pf = (struct parsed_file *)malloc(sizeof(struct parsed_file));
	pf->pls = NULL;
	pf->filename = mystrdup(filename);
	if (pf->filename == NULL) {
		fclose(fp);
		logfmt(log, LOG_ERR, "Can't read %s", filename);
		return NULL;
	}

	while ((linelen = getline(&line, &linecap, fp)) > 0) {
		char *septmp = line;

		for (; linelen && (line[linelen-1] == '\n' || line[linelen-1] == '\r'); linelen--)
			line[linelen-1] = '\0';

		if (!line[0])
			// skip empty line
			continue;

		char *p;

		for (p = line; *p && isspace(*p); p++);
		if (line[0] == '#')
			// skip comment line
			continue;

		char ***pls_tmp = realloc(pf->pls, (nlines+1)*(sizeof(char **)));

		if (pls_tmp == NULL) {
			err++;
			break;
		}

		nlines++;
		pf->pls = pls_tmp;

		char **pl = (char **)calloc(1, nfields*sizeof(char *));
		pf->pls[nlines-1] = pl;
		if (pl == NULL) {
			err++;
			break;
		}

		int n;
		for (n = 0; n < nfields && (token = strsep(&septmp, seps)) != NULL;) {
			if (!skipempty || token[0]) {
				char *ctoken = mystrdup(token);
				pl[n++] = ctoken;
			}
		}
		if (n != nfields) {
			logfmt(log, LOG_ERR, "Invalid line %d in %s", nlines+1, filename);
			break;
		}
	}
	pf->nlines = nlines;
	pf->nfields = nfields;
	free(line);
	fclose(fp);
	if (err) {
		file_free(pf);
		return NULL;
	}
	return pf;
}

void file_free(struct parsed_file *p) {
	for (int line = 0; line < p->nlines; line++) {
		for (int field = 0; field < p->nfields; field++)
			strfree(p->pls[line][field]);
		free(p->pls[line]);
	}
	strfree(p->filename);
	free(p->pls);
	free(p);
}

void logdate(char *date, size_t len, struct timeval *ts) {
	char tmp_date[30];
	struct tm t;
	localtime_r(&ts->tv_sec, &t);
	strftime(tmp_date, sizeof tmp_date, "%Y-%m-%d %H:%M:%S", &t);
	snprintf(date, len, "%s.%03ld", tmp_date, ts->tv_usec/1000);
}

void filedate(char *filename, size_t len, const char *format) {
	struct tm t;
	struct timeval ts;
	gettimeofday(&ts, NULL);
	localtime_r(&ts.tv_sec, &t);
	strftime(filename, len, format, &t);
}

/*
 * Find the first occurrence of find in s, ignore case.
 *
 * Stolen from the FreeBSD 14.1 source code, locale code removed.
 *
 * Included here to avoid portability issues.
 */
char *
mystrcasestr(const char *s, const char *find)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != 0) {
		c = tolower((unsigned char)c);
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return (NULL);
			} while ((char)tolower((unsigned char)sc) != c);
		} while (strncasecmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

#ifdef DEBUG_JEMALLOC
static void malloc_write_cb(void *opaque, const char *string) {
	struct mime_content *m = (struct mime_content *) opaque;
	mime_append(m, string);
}

struct mime_content *malloc_stats_dump(int json) {
	char *empty = mystrdup("");
	struct mime_content *m = mime_new(empty, 0, "application/json", 1);
	if (m == NULL)
		return NULL;

	if (json) {
		//malloc_stats_print(malloc_write_cb, m, "mdablxeJ");
		malloc_stats_print(malloc_write_cb, m, "J");
	} else {
		//malloc_stats_print(malloc_write_cb, m, "mdablxe");
		mime_set_type(m, "text/plain");
		malloc_stats_print(malloc_write_cb, m, NULL);
	}
	return m;
}

#else

struct mime_content *malloc_stats_dump(int json) {
	return mime_new(mystrdup("{\"err\": \"no malloc stats available\"}"), -1, "application/json", 1);
}

#endif
