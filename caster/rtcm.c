#include <assert.h>
#include <math.h>
#include <string.h>

#include <event2/buffer.h>
//#include <json-c/json.h>

#include "ntrip_common.h"
#include "rtcm.h"

/*
 * RTCM handling module.
 */

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
static unsigned long rtcm_crc24q_hash(unsigned char *data, size_t len) {
	unsigned long crc = 0;
	for (int d = 0; d < len; d++) {
		crc = (crc << 8) ^ crc24q[(data[d] ^ (crc>>16)) & 0xff];
	}

	crc = crc & 0x00ffffff;
	return crc;
}

// WGS84 constants
static double a = 6378137.0;
static double e = 8.1819190842622e-2;

/*
 * Convert ECEF coordinates in tenths of millimeters to (lat, lon, alt).
 */
static void ecef_to_lat_lon(pos_t *pos, double *palt, long ecef_x, long ecef_y, long ecef_z) {
	// Adapted from https://github.com/navdata-net/meta-navdatanet/blob/rocko/recipes-setup/gnss-station/files/ecef2llh.py

	/* Constants */
	double a2 = a*a;
	double e2 = e*e;
	double b = sqrt(a2*(1.0-e2));
	double b2 = b*b;
	double ep = sqrt((a2-b2)/b2);
	double ep2 = ep*ep;

	double x = (double)ecef_x/1e4;
	double y = (double)ecef_y/1e4;
	double z = (double)ecef_z/1e4;

	double p = hypot(x, y);

	double theta = atan2(a*z, b*p);
	double cost = cos(theta);
	double sint = sin(theta);

	double lon = atan2(y, x);
	double lat = atan2(z + ep2*b*sint*sint*sint,
		p-e2*a*cost*cost*cost);
	double sinlat = sin(lat);
	double N = a / sqrt(1.0 - e2*sinlat*sinlat);
	double alt = p / cos(lat) - N;

	pos->lon = lon*(180/M_PI);
	pos->lat = lat*(180/M_PI);
	*palt = alt;
	return;
}

/*
 * Extract a bit field in a RTCM packet.
 * beg and len are counted in bits.
 */
static inline long getbits(unsigned char *d, int beg, int len) {
	long r;
	unsigned char mask;

	// Compute all constants that depend on function arguments
	// to make the task easier for the inline optimizer.
	int offset_first = beg >> 3;
	int offset_last = (beg+len-1) >> 3;
	int bits_first = beg & 7;
	int full_bytes = (len - (8 - bits_first)) >> 3;
	int bits_last = (len - (8 - bits_first)) & 7;

	/* First, possibly incomplete, byte */
	mask = 0xff>>bits_first;
	r = d[offset_first] & mask;

	if (offset_first == offset_last)
		return r >> (8-beg-len);

	int offset = offset_first+1;

	/* Process full bytes */
	while (full_bytes--)
		r = (r<<8) + d[offset++];

	/* Last, possibly incomplete, byte */
	if (bits_last)
		r = (r << bits_last) + (d[offset] >> (8-bits_last));
	return r;
}

/*
 * Get and return a int38 as a long
 */
static inline long get_int38(unsigned char *d, int beg, int len) {
	long r = getbits(d, beg, len);
	if (r & (1L<<37)) r |= 0xffffffc000000000;
	return r;
}

/*
 * Handle packet types 1005 and 1006.
 */
static void handle_1005_1006(struct ntrip_state *st, struct rtcm_info *rp, int type, unsigned char *d, int len) {
	unsigned char *data = d+3;
	long ecef_x, ecef_y, ecef_z;

	ecef_x = get_int38(data, 34, 38);
	ecef_y = get_int38(data, 74, 38);
	ecef_z = get_int38(data, 114, 38);

	if (type == 1005) {
		gettimeofday(&rp->posdate, NULL);
		rp->date1005 = rp->posdate;
		memcpy(&rp->copy1005, d, sizeof(rp->copy1005));
	} else if (type == 1006) {
		gettimeofday(&rp->posdate, NULL);
		rp->date1006 = rp->posdate;
		memcpy(&rp->copy1006, d, sizeof(rp->copy1006));
	}
	rp->x = ecef_x;
	rp->y = ecef_y;
	rp->z = ecef_z;
}

struct rtcm_info *rtcm_info_new() {
	struct rtcm_info *this = (struct rtcm_info *)malloc(sizeof(struct rtcm_info));
	if (this == NULL)
		return NULL;
	memset(this->types1k, 0, sizeof this->types1k);
	memset(this->types4k, 0, sizeof this->types4k);
	return this;
}

void rtcm_info_free(struct rtcm_info *this) {
	free(this);
}

static void handle_1006(struct ntrip_state *st, struct rtcm_info *rp, unsigned char *d, int len) {
	handle_1005_1006(st, rp, 1006, d, len);
	// d += 3;
	// unsigned short antenna_height = getbits(d, 152, 16);
}

/*
 * Return a type bit in the type bitfields.
 */
static inline int rtcm_info_check_type(struct rtcm_info *this, int type) {
	if (type >= RTCM_1K_MIN && type <= RTCM_1K_MAX)
		return this->types1k[(type-RTCM_1K_MIN)>>3] & (1<<((type-RTCM_1K_MIN)&7));
	if (type >= RTCM_4K_MIN && type <= RTCM_4K_MAX)
		return this->types4k[(type-RTCM_4K_MIN)>>3] & (1<<((type-RTCM_4K_MIN)&7));
	return 0;
}

/*
 * Set a type bit in the type bitfields.
 */
static inline void rtcm_info_set_type(struct rtcm_info *this, int type) {
	if (type >= RTCM_1K_MIN && type <= RTCM_1K_MAX)
		this->types1k[(type-RTCM_1K_MIN)>>3] |= (1<<(type&7));
	else if (type >= RTCM_4K_MIN && type <= RTCM_4K_MAX)
		this->types4k[(type-RTCM_4K_MIN)>>3] |= (1<<(type&7));
}

/*
 * Return a string list of marked RTCM types, separated by ',',
 * ended by '\0'
 */
static char *rtcm_info_types(struct rtcm_info *this) {
	int n = 0;
	for (int i = RTCM_1K_MIN; i <= RTCM_1K_MAX; i++)
		if (rtcm_info_check_type(this, i))
			n++;
	for (int i = RTCM_4K_MIN; i <= RTCM_4K_MAX; i++)
		if (rtcm_info_check_type(this, i))
			n++;
	if (n == 0)
		return NULL;

	// 4 digits + ',' per entry or '\0' after the last,
	// + 1 for the extra '\0' stored by snprintf.
	char *r = (char *)strmalloc(n*5+1);
	if (r == NULL)
		return NULL;

	char *rp = r;
	for (int i = RTCM_1K_MIN; i <= RTCM_1K_MAX; i++)
		if (rtcm_info_check_type(this, i)) {
			snprintf(rp, 6, "%d,", i);
			rp += 5;
		}
	for (int i = RTCM_4K_MIN; i <= RTCM_4K_MAX; i++)
		if (rtcm_info_check_type(this, i)) {
			snprintf(rp, 6, "%d,", i);
			rp += 5;
		}
	// stomp over the last ','
	rp[-1] = '\0';
	return r;
}

/*
 * Return the RTCM cache as a JSON object.
 */
json_object *rtcm_info_json(struct rtcm_info *this) {
	json_object *j = json_object_new_object();
	char *types = rtcm_info_types(this);
	if (types) {
		json_object_object_add_ex(j, "types", json_object_new_string(types), JSON_C_CONSTANT_NEW);
	} else {
		json_object_object_add_ex(j, "types", json_object_new_null(), JSON_C_CONSTANT_NEW);
	}
	strfree(types);
	if (rtcm_info_check_type(this, 1005) || rtcm_info_check_type(this, 1006)) {
		pos_t pos;
		double alt;
		json_object *jpos = json_object_new_object();
		json_object_object_add_ex(jpos, "x", json_object_new_int64(this->x), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(jpos, "y", json_object_new_int64(this->y), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(jpos, "z", json_object_new_int64(this->z), JSON_C_CONSTANT_NEW);
		ecef_to_lat_lon(&pos, &alt, this->x, this->y, this->z);
		json_object_object_add_ex(jpos, "lat", json_object_new_double(pos.lat), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(jpos, "lon", json_object_new_double(pos.lon), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(jpos, "alt", json_object_new_double(alt), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(j, "pos", jpos, JSON_C_CONSTANT_NEW);

		char iso_date[30];
		iso_date_from_timeval(iso_date, sizeof iso_date, &this->posdate);
		json_object_object_add_ex(jpos, "date", json_object_new_string(iso_date), JSON_C_CONSTANT_NEW);
	}
	return j;
}

static void rtcm_handler(struct ntrip_state *st, unsigned char *d, int len, struct rtcm_info *rp) {
	unsigned short type = getbits(d+3, 0, 12);
	ntrip_log(st, LOG_DEBUG, "RTCM source %s size %d type %d", st->mountpoint, len, type);

	if (!rp)
		return;

	rtcm_info_set_type(rp, type);

	if (type == 1005 && len == 25)
		handle_1005_1006(st, rp, 1005, d, len);
	else if (type == 1006 && len == 27)
		handle_1006(st, rp, d, len);
}

/*
 * Handle receipt and retransmission of all complete RTCM packets.
 * Return 0 if more data is needed,
 *	1 if at least one packet has been processed.
 */
int rtcm_packet_handle(struct ntrip_state *st) {
	unsigned short len_rtcm;
	struct evbuffer_ptr p;
	struct evbuffer *input = st->input;
	int r = 0;

	while (1) {
		/*
		 * Look for 0xd3 header byte
		 */
		evbuffer_ptr_set(input, &p, 0, EVBUFFER_PTR_SET);
		p = evbuffer_search(input, "\xd3", 1, &p);
		if (p.pos < 0) {
			unsigned long len = evbuffer_get_length(input);
			if (len) {
				struct packet *not_rtcmp = packet_new(len, st->caster);
				evbuffer_remove(input, not_rtcmp->data, len);
				st->received_bytes += len;
				ntrip_log(st, LOG_INFO, "resending %zd bytes", len);
				if (livesource_send_subscribers(st->own_livesource, not_rtcmp, st->caster))
					st->last_send = time(NULL);
				r = 1;
				packet_free(not_rtcmp);
				continue;
			}
			return r;
		}
		if (p.pos > 0) {
			ntrip_log(st, LOG_DEBUG, "RTCM: found packet start, draining %zd bytes", p.pos);
			evbuffer_drain(input, p.pos);
		}

		unsigned char *mem = evbuffer_pullup(input, 3);
		if (mem == NULL) {
			ntrip_log(st, LOG_DEBUG, "RTCM: not enough data, waiting");
			return r;
		}

		/*
		 * Compute RTCM length from packet header
		 */
		len_rtcm = (mem[1] & 3)*256 + mem[2] + 6;
		if (len_rtcm > evbuffer_get_length(input)) {
			return r;
		}

		struct packet *rtcmp = packet_new(len_rtcm, st->caster);
		st->received_bytes += len_rtcm;
		if (rtcmp == NULL) {
			evbuffer_drain(input, len_rtcm);
			ntrip_log(st, LOG_CRIT, "RTCM: Not enough memory, dropping packet");
			continue;
		}

		evbuffer_remove(input, &rtcmp->data[0], len_rtcm);
		unsigned long crc = rtcm_crc24q_hash(&rtcmp->data[0], len_rtcm-3);
		if (crc == (rtcmp->data[len_rtcm-3]<<16)+(rtcmp->data[len_rtcm-2]<<8)+rtcmp->data[len_rtcm-1]) {
			rtcm_handler(st, rtcmp->data, len_rtcm, st->rtcm_info);
		} else {
			ntrip_log(st, LOG_INFO, "RTCM: bad checksum! %08lx %08x", crc, (rtcmp->data[len_rtcm-3]<<16)+(rtcmp->data[len_rtcm-2]<<8)+rtcmp->data[len_rtcm-1]);
		}

		if (livesource_send_subscribers(st->own_livesource, rtcmp, st->caster))
			st->last_send = time(NULL);
		packet_free(rtcmp);
		r = 1;
	}
}
