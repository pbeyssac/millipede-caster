#include "bitfield.h"

/*
 * Copy len bits from pos_src in src to pos_dst in dst, updating pos_src and pos_dst.
 */
void copybits(unsigned char *dst, int *pos_dst, unsigned char *src, int *pos_src, int len) {
	uint64_t tmp;
	while (len) {
		int lentmp = (len>64) ? 64 : len;
		tmp = getbits(src, *pos_src, lentmp);
		setbits(dst, *pos_dst, lentmp, tmp);
		len -= lentmp;
		*pos_src += lentmp;
		*pos_dst += lentmp;
	}
}
