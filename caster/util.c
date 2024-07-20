#include <malloc_np.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <ctype.h>

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


static unsigned long crc24q[] = {
    0x00000000, 0x01864CFB, 0x028AD50D, 0x030C99F6,
    0x0493E6E1, 0x0515AA1A, 0x061933EC, 0x079F7F17,
    0x08A18139, 0x0927CDC2, 0x0A2B5434, 0x0BAD18CF,
    0x0C3267D8, 0x0DB42B23, 0x0EB8B2D5, 0x0F3EFE2E,
    0x10C54E89, 0x11430272, 0x124F9B84, 0x13C9D77F,
    0x1456A868, 0x15D0E493, 0x16DC7D65, 0x175A319E,
    0x1864CFB0, 0x19E2834B, 0x1AEE1ABD, 0x1B685646,
    0x1CF72951, 0x1D7165AA, 0x1E7DFC5C, 0x1FFBB0A7,
    0x200CD1E9, 0x218A9D12, 0x228604E4, 0x2300481F,
    0x249F3708, 0x25197BF3, 0x2615E205, 0x2793AEFE,
    0x28AD50D0, 0x292B1C2B, 0x2A2785DD, 0x2BA1C926,
    0x2C3EB631, 0x2DB8FACA, 0x2EB4633C, 0x2F322FC7,
    0x30C99F60, 0x314FD39B, 0x32434A6D, 0x33C50696,
    0x345A7981, 0x35DC357A, 0x36D0AC8C, 0x3756E077,
    0x38681E59, 0x39EE52A2, 0x3AE2CB54, 0x3B6487AF,
    0x3CFBF8B8, 0x3D7DB443, 0x3E712DB5, 0x3FF7614E,
    0x4019A3D2, 0x419FEF29, 0x429376DF, 0x43153A24,
    0x448A4533, 0x450C09C8, 0x4600903E, 0x4786DCC5,
    0x48B822EB, 0x493E6E10, 0x4A32F7E6, 0x4BB4BB1D,
    0x4C2BC40A, 0x4DAD88F1, 0x4EA11107, 0x4F275DFC,
    0x50DCED5B, 0x515AA1A0, 0x52563856, 0x53D074AD,
    0x544F0BBA, 0x55C94741, 0x56C5DEB7, 0x5743924C,
    0x587D6C62, 0x59FB2099, 0x5AF7B96F, 0x5B71F594,
    0x5CEE8A83, 0x5D68C678, 0x5E645F8E, 0x5FE21375,
    0x6015723B, 0x61933EC0, 0x629FA736, 0x6319EBCD,
    0x648694DA, 0x6500D821, 0x660C41D7, 0x678A0D2C,
    0x68B4F302, 0x6932BFF9, 0x6A3E260F, 0x6BB86AF4,
    0x6C2715E3, 0x6DA15918, 0x6EADC0EE, 0x6F2B8C15,
    0x70D03CB2, 0x71567049, 0x725AE9BF, 0x73DCA544,
    0x7443DA53, 0x75C596A8, 0x76C90F5E, 0x774F43A5,
    0x7871BD8B, 0x79F7F170, 0x7AFB6886, 0x7B7D247D,
    0x7CE25B6A, 0x7D641791, 0x7E688E67, 0x7FEEC29C,
    0x803347A4, 0x81B50B5F, 0x82B992A9, 0x833FDE52,
    0x84A0A145, 0x8526EDBE, 0x862A7448, 0x87AC38B3,
    0x8892C69D, 0x89148A66, 0x8A181390, 0x8B9E5F6B,
    0x8C01207C, 0x8D876C87, 0x8E8BF571, 0x8F0DB98A,
    0x90F6092D, 0x917045D6, 0x927CDC20, 0x93FA90DB,
    0x9465EFCC, 0x95E3A337, 0x96EF3AC1, 0x9769763A,
    0x98578814, 0x99D1C4EF, 0x9ADD5D19, 0x9B5B11E2,
    0x9CC46EF5, 0x9D42220E, 0x9E4EBBF8, 0x9FC8F703,
    0xA03F964D, 0xA1B9DAB6, 0xA2B54340, 0xA3330FBB,
    0xA4AC70AC, 0xA52A3C57, 0xA626A5A1, 0xA7A0E95A,
    0xA89E1774, 0xA9185B8F, 0xAA14C279, 0xAB928E82,
    0xAC0DF195, 0xAD8BBD6E, 0xAE872498, 0xAF016863,
    0xB0FAD8C4, 0xB17C943F, 0xB2700DC9, 0xB3F64132,
    0xB4693E25, 0xB5EF72DE, 0xB6E3EB28, 0xB765A7D3,
    0xB85B59FD, 0xB9DD1506, 0xBAD18CF0, 0xBB57C00B,
    0xBCC8BF1C, 0xBD4EF3E7, 0xBE426A11, 0xBFC426EA,
    0xC02AE476, 0xC1ACA88D, 0xC2A0317B, 0xC3267D80,
    0xC4B90297, 0xC53F4E6C, 0xC633D79A, 0xC7B59B61,
    0xC88B654F, 0xC90D29B4, 0xCA01B042, 0xCB87FCB9,
    0xCC1883AE, 0xCD9ECF55, 0xCE9256A3, 0xCF141A58,
    0xD0EFAAFF, 0xD169E604, 0xD2657FF2, 0xD3E33309,
    0xD47C4C1E, 0xD5FA00E5, 0xD6F69913, 0xD770D5E8,
    0xD84E2BC6, 0xD9C8673D, 0xDAC4FECB, 0xDB42B230,
    0xDCDDCD27, 0xDD5B81DC, 0xDE57182A, 0xDFD154D1,
    0xE026359F, 0xE1A07964, 0xE2ACE092, 0xE32AAC69,
    0xE4B5D37E, 0xE5339F85, 0xE63F0673, 0xE7B94A88,
    0xE887B4A6, 0xE901F85D, 0xEA0D61AB, 0xEB8B2D50,
    0xEC145247, 0xED921EBC, 0xEE9E874A, 0xEF18CBB1,
    0xF0E37B16, 0xF16537ED, 0xF269AE1B, 0xF3EFE2E0,
    0xF4709DF7, 0xF5F6D10C, 0xF6FA48FA, 0xF77C0401,
    0xF842FA2F, 0xF9C4B6D4, 0xFAC82F22, 0xFB4E63D9,
    0xFCD11CCE, 0xFD575035, 0xFE5BC9C3, 0xFFDD8538
};

/* Compute and return CRC24Q (RTCM) checksum on a byte string. */
unsigned long crc24q_hash(unsigned char *data, size_t len) {
	unsigned long crc = 0;
	for (int d = 0; d < len; d++) {
		crc = (crc << 8) ^ crc24q[(data[d] ^ (crc>>16)) & 0xff];
	}

	crc = crc & 0x00ffffff;
	return crc;
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
 * Return a "host:port" string.
 */
char *host_port_str(char *host, unsigned short port) {
	char *host_port = (char *)strmalloc(strlen(host) + 8);
	if (host_port != NULL)
		sprintf(host_port, "%s:%d", host, port);
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

#if DEBUG
int str_alloc = 0;

char *mystrdup(const char *str) {
	str_alloc++;
	return strdup(str);
}
void *strmalloc(size_t len) {
	str_alloc++;
	return malloc(len);
}
void *strrealloc(void *p, size_t len) {
	if (p == NULL) str_alloc++;
	return realloc(p, len);
}
void strfree(void *str) {
	if (str) str_alloc--;
	free(str);
}
#endif

/*
 * Callback to free regular malloc'd data
 */
void free_callback(const void *data, size_t datalen, void *extra) {
	strfree((void *)data);
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
 * Read a colon-separated file.
 */
struct parsed_file *file_parse(const char *filename, int nfields, const char *seps) {
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen;
	char *token;
	int nlines = 0;

	FILE *fp = fopen(filename, "r+");

	if (fp == NULL) {
		fprintf(stderr, "Can't open %s\n", filename);
		return NULL;
	}

	struct parsed_file *pf = (struct parsed_file *)malloc(sizeof(struct parsed_file));
	pf->pls = NULL;
	pf->filename = strdup(filename);
	if (pf->filename == NULL) {
		fclose(fp);
		fprintf(stderr, "Can't read %s\n", filename);
		return NULL;
	}

	while ((linelen = getline(&line, &linecap, fp)) > 0) {
		char **pl = (char **)malloc(nfields*sizeof(char *));
		char *septmp = line;

		for (; line[linelen-1] == '\n' || line[linelen-1] == '\r'; linelen--)
			line[linelen-1] = '\0';

		if (!line[0])
			// skip empty line
			continue;

		char *p;

		for (p = line; *p && isspace(*p); p++);
		if (line[0] == '#')
			// skip comment line
			continue;

		int n;
		for (n = 0; n < nfields && (token = strsep(&septmp, seps)) != NULL; n++) {
			char *ctoken = mystrdup(token);
			pl[n] = ctoken;
		}
		if (n != nfields) {
			fprintf(stderr, "Invalid line %d in %s\n", nlines+1, filename);
			break;
		}
		nlines++;
		char ***pls_tmp = realloc(pf->pls, nlines*(sizeof(char **)));
		pf->pls = pls_tmp;
		pf->pls[nlines-1] = pl;
	}
	pf->nlines = nlines;
	pf->nfields = nfields;
	strfree(line);
	return pf;
}

void file_free(struct parsed_file *p) {
	for (int line = 0; line < p->nlines; line++) {
		for (int field = 0; field < p->nfields; field++)
			strfree(p->pls[line][field]);
		strfree(p->pls[line]);
	}
	free(p->pls);
	free(p);
}

void logdate(char *date, size_t len) {
	char tmp_date[30];
	struct timeval tstamp;
	gettimeofday(&tstamp, NULL);
	struct tm *t = localtime(&tstamp.tv_sec);
	strftime(tmp_date, sizeof tmp_date, "%Y-%m-%d %H:%M:%S", t);
	snprintf(date, len, "%s.%03ld ", tmp_date, tstamp.tv_usec/1000);
}

#if DEBUG
/*
 * Callback for jemalloc statistics.
 */
struct malloc_cb_opaque {
	char *result;
	int len;
};

static void malloc_write_cb(void *opaque, const char *string) {
	struct malloc_cb_opaque *o = (struct malloc_cb_opaque *) opaque;

	if (o->result) {
		int stringlen = strlen(string);
		char *newresult = (char *)strrealloc(o->result, o->len + stringlen);
		if (newresult) {
			o->result = newresult;
			memcpy(o->result + o->len-1, string, stringlen+1);
			o->len += stringlen;
		}
	}
}

char *malloc_stats_dump(int json) {
	struct malloc_cb_opaque malloc_str;

	malloc_str.result = (char *)strmalloc(1);
	if (malloc_str.result) {
		malloc_str.result[0] = '\0';
		malloc_str.len = 1;
	}

	if (json) {
		//malloc_stats_print(malloc_write_cb, &malloc_str, "mdablxeJ");
		malloc_stats_print(malloc_write_cb, &malloc_str, "J");
	} else {
		//malloc_stats_print(malloc_write_cb, &malloc_str, "mdablxe");
		malloc_stats_print(malloc_write_cb, &malloc_str, NULL);
	}
	return malloc_str.result;
}
#endif
