#include <assert.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

#include <event2/buffer.h>
//#include <json-c/json.h>

#include "bitfield.h"
#include "ntrip_common.h"
#include "rtcm.h"

/*
 * RTCM handling module.
 */

static inline void rtcm_typeset_init(struct rtcm_typeset *this) {
	memset(this->set1k, 0, sizeof this->set1k);
	memset(this->set4k, 0, sizeof this->set4k);
}

/*
 * Return a type bit in the type bitfields.
 */
static inline int rtcm_typeset_check(struct rtcm_typeset *this, int type) {
	if (type >= RTCM_1K_MIN && type <= RTCM_1K_MAX)
		return getbit(this->set1k, type-RTCM_1K_MIN);
	if (type >= RTCM_4K_MIN && type <= RTCM_4K_MAX)
		return getbit(this->set4k, type-RTCM_4K_MIN);
	return 0;
}

/*
 * Set a type bit in the type bitfields.
 */
static inline int rtcm_typeset_set(struct rtcm_typeset *this, int type) {
	if (type >= RTCM_1K_MIN && type <= RTCM_1K_MAX) {
		setbit(this->set1k, type-RTCM_1K_MIN);
		return 0;
	} else if (type >= RTCM_4K_MIN && type <= RTCM_4K_MAX) {
		setbit(this->set4k, type-RTCM_4K_MIN);
		return 0;
	}
	return -1;
}

/*
 * Load types from a comma-separated list.
 * Return 0 if ok, -1 if error.
 */
int rtcm_typeset_parse(struct rtcm_typeset *this, const char *typelist) {
	char typestr[5];
	int type;
	struct rtcm_typeset t;

	rtcm_typeset_init(&t);

	if (!*typelist) {
		*this = t;
		return 0;
	}

	int len = 0;
	do {
		if (*typelist == ',' || *typelist == '\0') {
			typestr[len] = '\0';
			if (sscanf(typestr, "%d", &type) != 1)
				return -1;
			if (rtcm_typeset_set(&t, type) < 0)
				return -1;
			len = 0;
		} else if (len < sizeof(typestr)-1)
			typestr[len++] = *typelist;
	} while (*typelist++);

	*this = t;
	return 0;
}

/*
 * Return a string list of marked RTCM types, separated by ',',
 * ended by '\0'
 */
char *rtcm_typeset_str(struct rtcm_typeset *this) {
	int n = 0;
	for (int i = RTCM_1K_MIN; i <= RTCM_1K_MAX; i++)
		if (rtcm_typeset_check(this, i))
			n++;
	for (int i = RTCM_4K_MIN; i <= RTCM_4K_MAX; i++)
		if (rtcm_typeset_check(this, i))
			n++;

	// 4 digits + ',' per entry or '\0' after the last,
	// + 1 for the extra '\0' stored by snprintf.
	char *r = (char *)strmalloc(n*5+1);
	if (r == NULL)
		return NULL;

	char *rp = r;
	for (int i = RTCM_1K_MIN; i <= RTCM_1K_MAX; i++)
		if (rtcm_typeset_check(this, i)) {
			snprintf(rp, 6, "%d,", i);
			rp += 5;
		}
	for (int i = RTCM_4K_MIN; i <= RTCM_4K_MAX; i++)
		if (rtcm_typeset_check(this, i)) {
			snprintf(rp, 6, "%d,", i);
			rp += 5;
		}
	// stomp over the last ',', if any.
	if (n)
		rp[-1] = '\0';
	else
		rp[0] = '\0';
	return r;
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
static unsigned long rtcm_crc24q_hash(unsigned char *data, size_t len) {
	unsigned long crc = 0;
	for (int d = 0; d < len; d++) {
		crc = (crc << 8) ^ crc24q[(data[d] ^ (crc>>16)) & 0xff];
	}

	crc = crc & 0x00ffffff;
	return crc;
}

static int rtcm_crc_check(struct packet *p) {
	int len = p->datalen;
	if (len < 4)
		return 0;
	unsigned long crc = rtcm_crc24q_hash(p->data, len-3);
	unsigned long packet_crc = (p->data[len-3]<<16) + (p->data[len-2]<<8) + (p->data[len-1]);
	if (crc != packet_crc)
		return 0;
	return 1;
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

/* Get a uint10 as a uint16_t */
static inline uint16_t get_uint10(unsigned char *d, int beg) {
	return getbits(d, beg, 10);
}

/* Get a int20 as a int32_t */
static inline int32_t get_int20(unsigned char *d, int beg) {
	uint32_t r = getbits(d, beg, 20);
	if (r & 0x80000) r |= 0xfff00000;
	return r;
}

/* Get a int24 as a int32_t */
static inline int32_t get_int24(unsigned char *d, int beg) {
	int32_t r = getbits(d, beg, 24);
	if (r & 0x800000) r |= 0xff000000;
	return r;
}

/* Get a uint32_t */
static inline uint32_t get_uint32(unsigned char *d, int beg) {
	return getbits(d, beg, 32);
}

/* Get a int38 as a uint64_t */
static inline uint64_t get_int38(unsigned char *d, int beg) {
	uint64_t r = getbits(d, beg, 38);
	if (r & (1L<<37)) r |= 0xffffffc000000000;
	return r;
}

/* Get a uint64 */
static inline uint64_t get_uint64(unsigned char *d, int beg) {
	return getbits(d, beg, 64);
}

/*
 * Handle packet types 1005 and 1006: base position.
 */
static void handle_1005_1006(struct rtcm_info *rp, int type, struct packet *p) {
	unsigned char *data = p->data+3;
	uint64_t ecef_x, ecef_y, ecef_z;

	ecef_x = get_int38(data, 34);
	ecef_y = get_int38(data, 74);
	ecef_z = get_int38(data, 114);

	if (type == 1005) {
		packet_incref(p);
		gettimeofday(&rp->posdate, NULL);
		rp->date1005 = rp->posdate;
		if (rp->copy1005)
			packet_decref(rp->copy1005);
		rp->copy1005 = p;
	} else if (type == 1006) {
		packet_incref(p);
		gettimeofday(&rp->posdate, NULL);
		rp->date1006 = rp->posdate;
		if (rp->copy1006)
			packet_decref(rp->copy1006);
		rp->copy1006 = p;
	}
	rp->x = ecef_x;
	rp->y = ecef_y;
	rp->z = ecef_z;
}

/*
 * Count set bits in v
 * Code from Brian Kernighan / https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetNaive
 */
static int count_set(uint64_t v) {
	unsigned int c;
	for (c = 0; v; c++)
		v &= v - 1; // clear the least significant bit set
	return c;
}

/*
 * Convert GNSS PhaseRange Lock Time Indicator from DF407 to DF402 format,
 * using bisection.
 */
static unsigned int rtcm_df407_to_df402(unsigned int df407) {
	if (df407 < 256) {
		if (df407 < 128) {
			if (df407 < 64) {
				if (df407 < 32)
					return 0;
				return 1;
			}
			if (df407 < 96)
				return 2;
			return 3;
		}
		if (df407 < 192) {
			if (df407 < 160)
				return 4;
			return 5;
		}
		if (df407 < 224)
			return 6;
		return 7;
	}
	if (df407 < 384) {
		if (df407 < 320) {
			if (df407 < 288)
				return 8;
			return 9;
		}
		if (df407 < 352)
			return 10;
		return 11;
	}
	if (df407 < 448) {
		if (df407 < 416)
			return 12;
		return 13;
	}
	if (df407 < 480)
		return 14;
	return 15;
}

/*
 * Convert MSM7 message to MSM3 or MSM4.
 */
static struct packet *rtcm_convert_msm7(struct ntrip_state *st, struct packet *p, int msm_version) {
	unsigned char *data = p->data+3;
	int len = p->datalen-6;
	unsigned char *data_rtcm, *data_out;
	int len_out, len_out_bits;

	int msmv = 4;

	int32_t df400, df401, df405, df406;
	uint16_t df403, df408;
	unsigned short df407;
	uint64_t df394, df396;
	uint32_t df395;
	char df393;
	int n;
	int nsat, nsig, ncell;

	int type = getbits(data, 0, 12);
	if ((type < 1077 || type > 1127 || type % 10 != 7) || len < 22)
		/* Invalid packet type or length, or too short */
		return NULL;

	int pos_out = 0;

	/* Skip message type, reference station ID and GNSS Epoch Time */
	int pos = 12 + 12 + 30;

	/* Multiple Message Bit */
	df393 = getbit(data, pos);

	// Skip IODS, Reserved field, Clock Steering Indicator, External Clock Indicator,
	// GNSS Divergence-free Smoothing Indicator, GNSS Smoothing Interval.
	pos += 1 + 3 + 7 + 2 + 2 + 1 + 3;

	/* GNSS Satellite Mask */
	df394 = get_uint64(data, pos);
	pos += 64;
	nsat = count_set(df394);

	/* GNSS Signal Mask */
	df395 = get_uint32(data, pos);
	pos += 32;
	nsig = count_set(df395);

	if (nsat*nsig > 64)
		return NULL;

	assert(pos == 169);

	int endcell = pos + nsat*nsig;

	if (endcell > len*8) {
		ntrip_log(st, LOG_EDEBUG, "packet nsat=%d nsig=%d endcell %d len %d not long enough", nsat, nsig, endcell, len*8);
		return NULL;
	}

	/* GNSS Cell Mask */
	df396 = getbits(data, pos, nsat*nsig);
	pos += nsat*nsig;
	ncell = count_set(df396);

	int endpos = pos + (8+4+10+14)*nsat + (20+24+10+1+10+15)*ncell;
	if (endpos > len*8) {
		ntrip_log(st, LOG_EDEBUG, "packet nsat=%d nsig=%d end %d len %d not long enough", nsat, nsig, endpos, len*8);
		return NULL;
	}

	ntrip_log(st, LOG_EDEBUG, "type %d MM=%d nsat=%d nsig=%d ncell=%d sat %016lx sig %08x cell %016lx",
			type, df393, nsat, nsig, ncell, df394, df395, df396);

	if (msmv == 4)
		len_out_bits = 169 + (8+10+nsig)*nsat + (15+22+4+1+6)*ncell;
	else
		/* MSM3 */
		len_out_bits = 169 + (10+nsig)*nsat + (15+22+4+1)*ncell;

	len_out = (len_out_bits+7) >> 3;

	if (len_out > 1023)
		return NULL;

	struct packet *packet = packet_new(len_out+6, st->caster);

	if (packet == NULL)
		return NULL;

	data_rtcm = packet->data;

	/* Add header */
	data_rtcm[0] = 0xd3;
	data_rtcm[1] = len_out >> 8;
	data_rtcm[2] = len_out & 0xff;
	data_out = data_rtcm + 3;

	/* Set updated type for MSM4 */
	setbits(data_out, 0, 12, type-7+msmv);

	/*
	 * Copy common MSM header + cell mask
	 * If MSM4:
	 * Copy DF397 array: Number of integer milliseconds in GNSS Satellite rough ranges
	 */
	pos = 12;
	pos_out = 12;
	copybits(data_out, &pos_out, data, &pos, 157 + nsat*nsig + (msmv == 4 ? nsat*8 : 0));

	if (msmv != 4)
		pos += nsat*8;

	/* Skip Extended Satellite Information */
	pos += 4*nsat;

	/* Copy DF398 array: GNSS Satellite rough ranges modulo 1 millisecond */
	copybits(data_out, &pos_out, data, &pos, nsat*10);

	/* Skip DF399 array: GNSS Satellite rough PhaseRangeRates */
	pos += 14*nsat;

	/*
	 * GNSS signal fine Pseudoranges
	 * Copy DF405 array as DF400 array: remove 5 trailing bits
	 */
	for (n = 0; n < ncell; n++) {
		df405 = get_int20(data, pos);
		pos += 20;

		/* Round to nearest and truncate */
		df400 = (df405 + (1<<4)) >> 5;

		setbits(data_out, pos_out, 15, df400);
		pos_out += 15;
	}

	/*
	 * GNSS signal fine PhaseRange data
	 * Copy DF406 array as DF401 array: remove 2 trailing bits
	 */
	for (n = 0; n < ncell; n++) {
		df406 = get_int24(data, pos);
		pos += 24;

		/* Round to nearest and truncate */
		df401 = (df406 + (1<<1)) >> 2;

		setbits(data_out, pos_out, 22, df401);
		pos_out += 22;
	}

	/*
	 * GNSS PhaseRange Lock Time Indicator
	 * DF407 -> DF402
	 */
	for (n = 0; n < ncell; n++) {
		df407 = get_uint10(data, pos);
		pos += 10;
		setbits(data_out, pos_out, 4, rtcm_df407_to_df402(df407));
		pos_out += 4;
	}

	/* Copy half-cycle ambiguity indicators */
	copybits(data_out, &pos_out, data, &pos, ncell);

	/*
	 * GNSS signal CNRs
	 * MSM4: copy DF408 array as DF403 array: remove 4 trailing bits
	 */
	if (msmv == 4)
		for (n = 0; n < ncell; n++) {
			df408 = get_uint10(data, pos);
			pos += 10;

			/* Round to nearest and truncate */
			df403 = (df408 + (1<<3)) >> 4;
			setbits(data_out, pos_out, 6, df403);
			pos_out += 6;
		}

	assert(pos_out == len_out_bits);

	/* Fill the last byte with trailing zeroes */
	if (pos_out & 7) {
		setbits(data_out, pos_out, 8 - (pos_out & 7), 0);
		pos_out += 8 - (pos_out & 7);
	}

	/* Compute and add CRC at the end */
	uint32_t crc = rtcm_crc24q_hash(data_rtcm, len_out+3);
	data_rtcm[len_out+3] = crc >> 16;
	data_rtcm[len_out+4] = crc >> 8;
	data_rtcm[len_out+5] = crc;
	return packet;
}

/*
 * Return 1 if the provided packet passes the filter, 0 if not.
 */
int rtcm_filter_pass(struct rtcm_filter *this, struct packet *packet) {
	if (!packet->is_rtcm)
		return 0;

	unsigned char *d = packet->data;
	unsigned short type = getbits(d+3, 0, 12);
	return rtcm_typeset_check(&this->pass, type);
}

/*
 * Return a converted packet, if relevant.
 */
struct packet *rtcm_filter_convert(struct rtcm_filter *this, struct ntrip_state *st, struct packet *packet) {
	if (!packet->is_rtcm)
		return NULL;
	if (this == NULL)
		return NULL;

	unsigned char *d = packet->data;
	unsigned short type = getbits(d+3, 0, 12);

	if (!rtcm_typeset_check(&this->convert, type))
		return NULL;

	if (this->conversion == RTCM_CONV_MSM7_4)
		return rtcm_convert_msm7(st, packet, 4);
	else if (this->conversion == RTCM_CONV_MSM7_3)
		return rtcm_convert_msm7(st, packet, 3);
	return NULL;
}

/*
 * rtcm_info routines
 */

struct rtcm_info *rtcm_info_new() {
	struct rtcm_info *this = (struct rtcm_info *)malloc(sizeof(struct rtcm_info));
	if (this == NULL)
		return NULL;
	rtcm_typeset_init(&this->typeset);
	memset(&this->date1005, 0, sizeof(this->date1005));
	memset(&this->date1006, 0, sizeof(this->date1006));
	this->copy1005 = NULL;
	this->copy1006 = NULL;
	return this;
}

void rtcm_info_free(struct rtcm_info *this) {
	if (this->copy1005)
		packet_decref(this->copy1005);
	if (this->copy1006)
		packet_decref(this->copy1006);
	free(this);
}

/*
 * Return a pointer to the most recent 1005 or 1006 packet, if any.
 */
struct packet *rtcm_info_pos_packet(struct rtcm_info *this, struct caster_state *caster) {
	struct packet *p = NULL;
	struct timeval *date = NULL;
	if (this->copy1006) {
		p = this->copy1006;
		date = &this->date1006;
	}
	if (this->copy1005 && (date == NULL || date->tv_sec < this->date1005.tv_sec))
		p = this->copy1005;
	if (p)
		packet_incref(p);
	return p;
}

/*
 * Return a comma-separated list of keys in a hash table.
 * Trim leading and trailing white space in keys.
 */
struct hash_table *rtcm_filter_dict_parse(struct rtcm_filter *this, const char *apply) {
	const char *p = apply;
	const char *key;
	char *dupkey;
	int err = 0;

	struct hash_table *h = hash_table_new(5, NULL);
	if (h == NULL)
		return NULL;

	do {
		while (isspace(*p)) p++;
		key = p;
		while (*p && *p != ',') p++;
		if (p == key) {
			err = 1;
			break;
		}
		int len = p-key;
		if (*p) p++;
		while (len && isspace(key[len-1])) len--;
		if (!len) {
			err = 1;
			break;
		}
		dupkey = (char *)strmalloc(len+1);
		if (dupkey == NULL) {
			err = 1;
			break;
		}
		memcpy(dupkey, key, len);
		dupkey[len] = '\0';
		hash_table_add(h, dupkey, NULL);
		strfree(dupkey);
	} while (*p);

	if (err) {
		hash_table_free(h);
		return NULL;
	}
	return h;
}

void rtcm_filter_free(struct rtcm_filter *this) {
	free(this);
}

struct rtcm_filter *rtcm_filter_new(const char *pass, const char *convert, enum rtcm_conversion conversion) {
	struct rtcm_filter *this = (struct rtcm_filter *)malloc(sizeof(struct rtcm_filter));
	if (this == NULL)
		return NULL;

	int r = rtcm_typeset_parse(&this->pass, pass);
	if (r >=0 && convert)
		r = rtcm_typeset_parse(&this->convert, convert);
	else
		rtcm_typeset_init(&this->convert);
	if (r < 0) {
		rtcm_filter_free(this);
		return NULL;
	}
	this->conversion = conversion;
	return this;
}

/*
 * Return whether a mountpoint has a filter.
 */
int rtcm_filter_check_mountpoint(struct caster_dynconfig *dyn, const char *mountpoint) {
	return hash_table_get_element(dyn->rtcm_filter_dict, mountpoint) != NULL;
}

static void handle_1006(struct rtcm_info *rp, struct packet *p) {
	handle_1005_1006(rp, 1006, p);
	// d += 3;
	// unsigned short antenna_height = getbits(d, 152, 16);
}

/*
 * Return the RTCM cache as a JSON object.
 */
json_object *rtcm_info_json(struct rtcm_info *this) {
	json_object *j = json_object_new_object();
	char *types = rtcm_typeset_str(&this->typeset);
	if (types) {
		json_object_object_add_ex(j, "types", json_object_new_string(types), JSON_C_CONSTANT_NEW);
	} else {
		json_object_object_add_ex(j, "types", json_object_new_null(), JSON_C_CONSTANT_NEW);
	}
	strfree(types);
	if (rtcm_typeset_check(&this->typeset, 1005) || rtcm_typeset_check(&this->typeset, 1006)) {
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

/*
 * Return whether a packet is a position packet (types 1005 or 1006).
 */
int rtcm_packet_is_pos(struct packet *p) {
	unsigned char *d = p->data;
	int len = p->datalen;
	if (!p->is_rtcm || len < 25)
		return 0;
	unsigned short type = getbits(d+3, 0, 12);
	return (type == 1005 && len == 25) || (type == 1006 && len == 27);
}

void rtcm_packet_dump(struct ntrip_state *st, struct packet *p) {
	unsigned char *d = p->data;
	int len = p->datalen;
	unsigned short type = getbits(d+3, 0, 12);
	char *out = (char *)strmalloc(4*len + 1);
	out[4*len] = '\0';
	for (int i = 0; i < len; i++)
		snprintf(out + 4*i, 5, "\\x%02x", d[i]);
	ntrip_log(st, LOG_EDEBUG, "RTCM packet %d: %s", type, out);
	strfree(out);
}

static void rtcm_handler(struct ntrip_state *st, struct packet *p, void *arg1) {
	struct rtcm_info *rp = (struct rtcm_info *)arg1;
	if (!rp)
		return;

	unsigned char *d = p->data;
	int len = p->datalen;
	unsigned short type = getbits(d+3, 0, 12);

	P_RWLOCK_WRLOCK(&st->caster->rtcm_lock);
	rtcm_typeset_set(&rp->typeset, type);

	if (type == 1005 && len == 25)
		handle_1005_1006(rp, 1005, p);
	else if (type == 1006 && len == 27)
		handle_1006(rp, p);
	P_RWLOCK_UNLOCK(&st->caster->rtcm_lock);
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
		int max_len = evbuffer_get_length(input);
		int len = p.pos < 0 ? max_len : p.pos;
		if (len) {
			struct packet *not_rtcmp = packet_new(len, st->caster);
			evbuffer_remove(input, not_rtcmp->data, len);
			st->received_bytes += len;
			ntrip_log(st, LOG_INFO, "resending %zd bytes", len);
			if (livesource_send_subscribers(st->own_livesource, not_rtcmp, st->caster))
				st->last_useful = time(NULL);
			r = 1;
			packet_free(not_rtcmp);
			max_len -= len;
		}
		if (max_len == 0)
			return r;

		unsigned char *mem = evbuffer_pullup(input, 3);
		if (mem == NULL) {
			ntrip_log(st, LOG_DEBUG, "RTCM: not enough data, waiting");
			return r;
		}

		/*
		 * Compute RTCM length from packet header
		 */
		len_rtcm = (mem[1] & 3)*256 + mem[2] + 6;
		if (len_rtcm > max_len) {
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

		if (rtcm_crc_check(rtcmp)) {
			rtcmp->is_rtcm = 1;
			unsigned short type = getbits(rtcmp->data+3, 0, 12);
			ntrip_log(st, LOG_DEBUG, "RTCM source %s size %d type %d", st->mountpoint, len_rtcm, type);
			//rtcm_packet_dump(st, rtcmp);
			joblist_append_ntrip_packet(st->caster->joblist, rtcm_handler, st, rtcmp, st->rtcm_info);
		} else
			ntrip_log(st, LOG_INFO, "RTCM: bad checksum!");

		if (livesource_send_subscribers(st->own_livesource, rtcmp, st->caster))
			st->last_useful = time(NULL);
		packet_free(rtcmp);
		r = 1;
	}
}
