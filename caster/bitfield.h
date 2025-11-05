#ifndef __BITFIELD_H__
#define __BITFIELD_H__

#include <sys/types.h>
#include <stdint.h>

/*
 * Get or set up to 64 bits from a bit field.
 * beg and len are counted in bits.
 */
static inline uint64_t get_set_bits(unsigned char *d, int beg, int len, int set, uint64_t val) {
	uint64_t r;
	unsigned char mask;

	if (len == 0)
		return 0;

	// Compute all constants that depend on function arguments
	// to make the task easier for the inline optimizer.
	int offset_first = beg >> 3;
	int offset_last = (beg+len-1) >> 3;
	int bits_first = beg & 7;
	int full_bytes = (len - (8 - bits_first)) >> 3;
	int bits_last = (len - (8 - bits_first)) & 7;

	/* First, possibly incomplete, byte */
	mask = 0xff>>bits_first;

	if (!set)
		r = d[offset_first] & mask;

	if (offset_first == offset_last) {
		if (set) {
			mask &= (0xff << ((-beg-len) & 7));
			d[offset_first] &= ~mask;
			d[offset_first] |= mask & (val << ((-beg-len) & 7));
			return 0;
		} else
			return r >> ((-beg-len) & 7);
	}

	if (set) {
		val <<= 64-len;
		d[offset_first] &= ~mask;
		d[offset_first] |= val >> (bits_first+56);
		val <<= 8-bits_first;
	}

	int offset = offset_first+1;

	/* Process full bytes */
	while (full_bytes--)
		if (set) {
			d[offset++] = val >> 56;
			val <<= 8;
		} else
			r = (r<<8) + d[offset++];

	/* Last, possibly incomplete, byte */
	if (bits_last) {
		if (set) {
			r = 0;
			mask = 0xff >> bits_last;
			d[offset] &= mask;
			d[offset] |= (val >> 56) & ~mask;
		} else
			r = (r << bits_last) + (d[offset] >> (8-bits_last));
	}
	return r;
}

/*
 * Get a bit field, up to 64 bits, as a uint64_t.
 * beg and len are counted in bits.
 */
static inline uint64_t getbits(unsigned char *d, int beg, int len) {
	return get_set_bits(d, beg, len, 0, 0);
}

/*
 * Set a bit field from a uint64_t.
 * beg and len are counted in bits.
 */
static inline void setbits(unsigned char *d, int beg, int len, uint64_t val) {
	get_set_bits(d, beg, len, 1, val);
}

/*
 * Get a single bit
 */
static inline int getbit(unsigned char *d, int beg) {
	return (d[beg>>3] & (1<<(beg&7))) != 0;
}

/*
 * Set a single bit
 */
static inline void setbit(unsigned char *d, int beg) {
	d[beg>>3] |= 1<<(beg&7);
}

void copybits(unsigned char *dst, int *pos_dst, unsigned char *src, int *pos_src, int len);

#endif
