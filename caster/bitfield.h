#ifndef _BITFIELD_H_
#define _BITFIELD_H_

#include <sys/types.h>

/*
 * Extract up to 64 bits from a bit field
 * beg and len are counted in bits.
 */
static inline uint64_t getbits(unsigned char *d, int beg, int len) {
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
		return r >> ((-beg-len) & 7);

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

#endif
