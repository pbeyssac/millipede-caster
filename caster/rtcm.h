#ifndef _RTCM_H_
#define _RTCM_H_

#include <sys/time.h>

#include <json-c/json.h>

struct ntrip_state;

#define	RTCM_1K_MIN	1000
#define	RTCM_1K_MAX	1230
#define	RTCM_4K_MIN	4000
#define	RTCM_4K_MAX	4095

struct rtcm_typeset {
	/* bit field for RTCM types 1000-1230 */
	char set1k[(RTCM_1K_MAX-RTCM_1K_MIN+8)>>3];
	/* bit field for RTCM types 4000-4095 */
	char set4k[(RTCM_4K_MAX-RTCM_4K_MIN+8)>>3];
};

struct rtcm_info {
	// ECEF coordinates for a base, in tenths of millimeters
	long x, y, z;
	struct rtcm_typeset typeset;
	char copy1005[25];
	char copy1006[27];
	struct timeval date1005, date1006, posdate;
};

int rtcm_typeset_parse(struct rtcm_typeset *this, const char *typelist);
char *rtcm_typeset_str(struct rtcm_typeset *this);
struct rtcm_info *rtcm_info_new();
void rtcm_info_free(struct rtcm_info *this);
json_object *rtcm_info_json(struct rtcm_info *this);
uint64_t getbits(unsigned char *d, int beg, int len);
int rtcm_packet_handle(struct ntrip_state *st);

#endif
