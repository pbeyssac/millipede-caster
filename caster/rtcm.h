#ifndef __RTCM_H__
#define __RTCM_H__

#include <sys/time.h>

#include <json-c/json_object.h>

#include "hash.h"
#include "packet.h"

struct ntrip_state;
struct caster_dynconfig;

#define	RTCM_1K_MIN	1000
#define	RTCM_1K_MAX	1230
#define	RTCM_4K_MIN	4000
#define	RTCM_4K_MAX	4095

enum rtcm_conversion {
        RTCM_CONV_MSM7_3,
        RTCM_CONV_MSM7_4
};

struct rtcm_typeset {
	/* bit field for RTCM types 1000-1230 */
	unsigned char set1k[(RTCM_1K_MAX-RTCM_1K_MIN+8)>>3];
	/* bit field for RTCM types 4000-4095 */
	unsigned char set4k[(RTCM_4K_MAX-RTCM_4K_MIN+8)>>3];
};

struct rtcm_info {
	// ECEF coordinates for a base, in tenths of millimeters
	long x, y, z;
	struct rtcm_typeset typeset;
	struct packet *copy1005, *copy1006;
	struct timeval date1005, date1006, posdate;
};

/*
 * RTCM filter description
 */
struct rtcm_filter {
	struct rtcm_typeset pass;		// types to pass directly
	struct rtcm_typeset convert;		// types to convert
	enum rtcm_conversion conversion;	// type of conversion
};

int rtcm_typeset_parse(struct rtcm_typeset *this, const char *typelist);
char *rtcm_typeset_str(struct rtcm_typeset *this);
struct hash_table *rtcm_filter_dict_parse(struct rtcm_filter *this, const char *apply);
void rtcm_filter_free(struct rtcm_filter *this);
struct rtcm_filter *rtcm_filter_new(const char *pass, const char *convert, enum rtcm_conversion conversion);
int rtcm_filter_check_mountpoint(struct caster_dynconfig *dyn, const char *mountpoint);
int rtcm_filter_pass(struct rtcm_filter *this, struct packet *packet);
struct packet *rtcm_filter_convert(struct rtcm_filter *this, struct ntrip_state *st, struct packet *p);
struct rtcm_info *rtcm_info_new();
void rtcm_info_free(struct rtcm_info *this);
struct packet *rtcm_info_pos_packet(struct rtcm_info *this, struct caster_state *caster);
json_object *rtcm_info_json(struct rtcm_info *this);
int rtcm_packet_is_pos(struct packet *p);
int rtcm_packet_handle(struct ntrip_state *st);

#endif
