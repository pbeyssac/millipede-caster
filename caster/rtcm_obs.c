#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bitfield.h"   /* getbits() */
#include "rtcm.h"       /* rtcm_get_type() */
#include "rtcm_obs.h"

/*
 * RTCM Observation Decoder implementation.
 *
 * Bit layout references in comments (DFxxx) follow the RTCM 3.3 spec
 * (https://rtcm.org/standard-for-differential-gnss/). Field offsets
 * are bit positions relative to the start of the payload (i.e. after
 * the 3-byte 0xD3 preamble + length header).
 *
 * The payload starts at p->data[3]. All offsets below are relative
 * to that point.
 */

/*
 * Count set bits in a uint64_t (Kernighan's algorithm).
 * Mirrors the static count_set() in rtcm.c — duplicated here because
 * that one is file-static.
 */
static int count_set_u64(uint64_t v) {
	int c;
	for (c = 0; v; c++)
		v &= v - 1;
	return c;
}

/*
 * Get a signed 38-bit integer as int64_t (for ECEF coordinates).
 * Mirrors get_int38() in rtcm.c.
 */
static int64_t get_int38(unsigned char *d, int beg) {
	uint64_t r = getbits(d, beg, 38);
	if (r & (1ULL << 37))
		r |= 0xFFFFFFC0000000ULL;
	return (int64_t)r;
}

/*
 * Decode RTCM 1005 (Stationary Antenna Reference Point).
 *
 * Layout (RTCM 3.3, section 3.5.2.3):
 *   bits  0-11  : message type (1005)
 *   bits 12-23  : reference station ID (DF003)
 *   bit   24    : indicator (DF001)
 *   bits 25-33  : reserved
 *   bits 34-71  : ECEF-X (DF025, int38, 0.0001 m)
 *   bit   72    : single receiver oscillator indicator
 *   bits 73-110 : ECEF-Y (DF026, int38, 0.0001 m)
 *   bit   111   : quarter cycle indicator
 *   bits 112-149: ECEF-Z (DF027, int38, 0.0001 m)
 */
int rtcm_obs_decode_1005(struct packet *p, double *x, double *y, double *z) {
	if (p == NULL || p->datalen < 6 + 19)  /* need at least 152 bits payload */
		return -1;

	unsigned char *d = p->data + 3;
	unsigned short type = rtcm_get_type(p);
	if (type != 1005 && type != 1006)
		return -1;

	int64_t ex = get_int38(d, 34);
	int64_t ey = get_int38(d, 74);
	int64_t ez = get_int38(d, 114);

	/* Scale: 0.0001 m per LSB */
	*x = ex * 0.0001;
	*y = ey * 0.0001;
	*z = ez * 0.0001;
	return 0;
}

/*
 * Map an RTCM message type to a GNSS system identifier.
 *
 * MSM7 type ranges (RTCM 3.3 table 3.5-92):
 *   1071-1077 : GPS
 *   1081-1087 : GLONASS
 *   1091-1097 : SBAS
 *   1101-1107 : QZSS
 *   1111-1117 : BeiDou
 *   1121-1127 : NavIC/IRNSS
 * The last digit (1..7) indicates the MSM variant (1=MSM1 ... 7=MSM7).
 */
enum rtcm_sys rtcm_obs_type_to_sys(unsigned short type) {
	if (type >= 1071 && type <= 1077) return RTCM_SYS_GPS;
	if (type >= 1081 && type <= 1087) return RTCM_SYS_GLO;
	if (type >= 1091 && type <= 1097) return RTCM_SYS_SBS;
	if (type >= 1101 && type <= 1107) return RTCM_SYS_QZS;
	if (type >= 1111 && type <= 1117) return RTCM_SYS_BDS;
	return RTCM_SYS_NONE;
}

/*
 * Decode the satellite mask into a list of PRNs.
 *
 * The 64-bit satellite mask (DF394) is MSB-first: bit 0 (MSB) = PRN 1,
 * bit 63 (LSB) = PRN 64. For GPS, PRN 1-32 are valid; for Galileo,
 * PRN 1-36. We just store the PRN for each set bit, regardless of
 * constellation (the caller already knows the system).
 *
 * Returns the number of satellites found (nsat).
 */
static int decode_sat_mask(uint64_t mask, unsigned char *prns_out, int max_prns) {
	int nsat = 0;
	for (int i = 0; i < 64 && nsat < max_prns; i++) {
		if (mask & (1ULL << (63 - i))) {
			prns_out[nsat++] = (unsigned char)(i + 1);
		}
	}
	return nsat;
}

/*
 * Decode the signal mask into a list of RINEX signal codes.
 *
 * The 32-bit signal mask (DF395) is MSB-first. The meaning of each
 * bit depends on the GNSS system. For GPS:
 *   bit 0 (MSB) = L1 C/A      -> 'C'
 *   bit 1       = L1 L1C (L2C) -> 'L'
 *   bit 2       = L2 L2C(M)   -> 'S'
 *   bit 3       = L2 L1 (L2P) -> 'P' (we'll reuse 'P')
 *   bit 4       = L2 L2C(L)   -> 'L'
 *   bit 5       = L2 L2C(M+L) -> 'X'
 *   bit 6       = L5 I        -> 'I'
 *   bit 7       = L5 Q        -> 'Q'
 *   bit 8       = L5 I+Q      -> 'X'
 *   ...
 * For Galileo:
 *   bit 0 = E1A  -> 'A'
 *   bit 1 = E1B  -> 'B'
 *   bit 2 = E1C  -> 'C'
 *   bit 3 = E1B+C -> 'X'
 *   bit 4 = E5aI -> 'I'
 *   bit 5 = E5aQ -> 'Q'
 *   bit 6 = E5aI+Q -> 'X'
 *   bit 7 = E5bI -> '7'
 *   bit 8 = E5bQ -> '8'
 *   bit 9 = E5bI+Q -> 'X'
 *   bit 10 = E6A -> '6'
 *   bit 11 = E6B -> '9'
 *   bit 12 = E6C -> '4'
 *   bit 13 = E6B+C -> 'X'
 *
 * We keep a lookup table per system. Bits beyond the table are ignored
 * (treated as 'X' = unknown).
 */
static const char GPS_SIG_TABLE[16] = {
	'C', 'L', 'S', 'P', 'L', 'X', 'I', 'Q',   /* bits 0-7  */
	'X', '?', '?', '?', '?', '?', '?', '?'     /* bits 8-15 */
};
static const char GAL_SIG_TABLE[16] = {
	'A', 'B', 'C', 'X', 'I', 'Q', 'X', '7',   /* bits 0-7  */
	'8', 'X', '6', '9', '4', 'X', '?', '?'     /* bits 8-15 */
};

static int decode_sig_mask(uint32_t mask, enum rtcm_sys sys,
			   char *sigs_out, int max_sigs) {
	const char *table = NULL;
	switch (sys) {
		case RTCM_SYS_GPS: table = GPS_SIG_TABLE; break;
		case RTCM_SYS_GAL: table = GAL_SIG_TABLE; break;
		default:            table = GPS_SIG_TABLE; break;  /* fallback */
	}
	int nsig = 0;
	for (int i = 0; i < 16 && nsig < max_sigs; i++) {
		if (mask & (1u << (15 - i))) {
			sigs_out[nsig++] = table[i];
		}
	}
	return nsig;
}

/*
 * Decode an MSM7 message into an observation epoch.
 *
 * MSM7 layout (RTCM 3.3 section 3.5.4.7):
 *   bits   0-11  : message type
 *   bits  12-23  : reference station ID (DF003)
 *   bits  24-53  : GNSS epoch time (DF401, TOW ms for GPS/Galileo)
 *   bit    54    : multiple message bit (DF393)
 *   bits  55-57  : IODS (DF409)
 *   bits  58-60  : reserved
 *   bit    61    : clock steering indicator (DF411)
 *   bit    62    : external clock indicator (DF412)
 *   bit    63    : GNSS divergence-free smoothing indicator (DF417)
 *   bits  64-66  : GNSS smoothing interval (DF418)
 *   bits  67-130 : GNSS satellite mask (DF394, 64 bits)
 *   bits 131-162 : GNSS signal mask (DF395, 32 bits)
 *   bits 163-(162+nsat*nsig) : GNSS cell mask (DF396, variable)
 *
 * Then per-satellite data (in order of set bits in sat mask):
 *   DF397 : 8-bit  satellite rough range (ms)
 *   DF398 : 10-bit satellite rough range modulo 1 ms
 *   DF399 : 14-bit satellite rough phase range rate (sign-magnitude, 1 mm/s)
 *   DF405 : 20-bit satellite fine pseudorange (0.5 mm, sign-magnitude) -- MSM7
 *   DF406 : 24-bit satellite fine phase range (0.5 mm) -- MSM7 (extended)
 *
 * Then per-cell data (in order of set bits in cell mask):
 *   DF407 : 10-bit lock time indicator (varies, see DF402 conversion table)
 *   ...etc.
 *
 * For the MVP we only decode:
 *   - satellite PRN (from sat mask)
 *   - signal code (from sig mask)
 *   - rough range (DF397) + fine pseudorange (DF405) -> pseudorange
 *   - phase range (DF406) -> phase in cycles (need frequency; we approximate)
 *   - lock time indicator (DF407)
 *   - signal CNR (DF400 for MSM7 = 10-bit, 0.25 dB-Hz)
 *
 * Skip: doppler, half-cycle, phase range rate (DF420). These are in
 * MSM7 but not strictly needed for a minimal RINEX obs file.
 */
int rtcm_obs_decode_msm7(struct packet *p, struct rtcm_obs_epoch *epoch) {
	if (p == NULL || epoch == NULL)
		return -1;

	unsigned short type = rtcm_get_type(p);
	if (type < 1071 || type > 1127 || (type % 10) != 7)
		return -1;

	enum rtcm_sys sys = rtcm_obs_type_to_sys(type);
	if (sys == RTCM_SYS_NONE)
		return -1;

	/* MVP: only GPS and Galileo. */
	if (sys != RTCM_SYS_GPS && sys != RTCM_SYS_GAL)
		return -1;

	memset(epoch, 0, sizeof(*epoch));
	epoch->sys = sys;

	if (p->datalen < 6 + 21)  /* need at least the MSM header */
		return -1;

	unsigned char *d = p->data + 3;
	int len_bits = (int)(p->datalen - 6) * 8;
	int pos = 0;

	/* Skip message type (12 bits) */
	pos += 12;

	/* DF003: reference station ID (12 bits) */
	epoch->station_id = (unsigned int)getbits(d, pos, 12);
	pos += 12;

	/* DF401: GNSS epoch time (30 bits, ms) */
	uint32_t tow_ms = (uint32_t)getbits(d, pos, 30);
	pos += 30;

	/* Store epoch time as a struct timeval (TOW in seconds + ms) */
	{
		struct timeval now;
		gettimeofday(&now, NULL);
		/* We don't know the GPS week from MSM7 alone, so we use
		 * the wall clock as the epoch timestamp and store TOW
		 * in tv_usec for debugging. The RINEX writer will use
		 * the wall clock. */
		epoch->epoch_time = now;
		(void)tow_ms;
	}

	/* Skip MMB, IODS, reserved, clock steering, external clock,
	 * smoothing indicator, smoothing interval (1+3+7+2+2+1+3 = 19 bits) */
	pos += 19;

	/* DF394: satellite mask (64 bits) */
	if (pos + 64 > len_bits) return -1;
	uint64_t sat_mask = (uint64_t)getbits(d, pos, 64);
	pos += 64;

	/* DF395: signal mask (32 bits) */
	if (pos + 32 > len_bits) return -1;
	uint32_t sig_mask = (uint32_t)getbits(d, pos, 32);
	pos += 32;

	unsigned char sat_prns[RTCM_OBS_MAX_SATS];
	int nsat = decode_sat_mask(sat_mask, sat_prns, RTCM_OBS_MAX_SATS);

	char sig_codes[RTCM_OBS_MAX_SIGS];
	int nsig = decode_sig_mask(sig_mask, sys, sig_codes, RTCM_OBS_MAX_SIGS);

	if (nsat == 0 || nsig == 0)
		return -1;

	if (nsat * nsig > 64)
		return -1;  /* per RTCM spec */

	/* DF396: cell mask (nsat*nsig bits) */
	int cell_mask_bits = nsat * nsig;
	if (pos + cell_mask_bits > len_bits) return -1;
	uint64_t cell_mask = 0;
	for (int i = 0; i < cell_mask_bits; i++) {
		if (getbits(d, pos + i, 1))
			cell_mask |= (1ULL << (cell_mask_bits - 1 - i));
	}
	pos += cell_mask_bits;

	int ncell = count_set_u64(cell_mask);
	if (ncell > RTCM_OBS_MAX_CELLS)
		return -1;

	/* Per-satellite section:
	 *   DF397 (8 bits each) : rough range in ms
	 *   DF398 (10 bits each): rough range mod 1 ms
	 *   DF399 (14 bits each): rough phase range rate (sign-magnitude, 1 mm/s)
	 * Then MSM7-specific: DF405 fine pseudorange, DF406 fine phase range
	 *   DF405 (20 bits each): fine pseudorange (sign-magnitude, 0.5 mm)
	 *   DF406 (24 bits each): fine phase range (sign-magnitude, 0.5 mm) -- MSM7
	 */

	/* DF397: rough range ms */
	if (pos + 8 * nsat > len_bits) return -1;
	int32_t rough_ms[RTCM_OBS_MAX_SATS];
	for (int i = 0; i < nsat; i++) {
		rough_ms[i] = (int32_t)getbits(d, pos, 8);
		pos += 8;
	}

	/* Skip extended satellite info (DF397b, 4 bits per sat in MSM7) */
	if (pos + 4 * nsat > len_bits) return -1;
	pos += 4 * nsat;

	/* DF398: rough range mod 1 ms (10 bits each) */
	if (pos + 10 * nsat > len_bits) return -1;
	uint32_t rough_mod[RTCM_OBS_MAX_SATS];
	for (int i = 0; i < nsat; i++) {
		rough_mod[i] = (uint32_t)getbits(d, pos, 10);
		pos += 10;
	}

	/* DF399: rough phase range rate (14 bits each, sign-magnitude) */
	if (pos + 14 * nsat > len_bits) return -1;
	pos += 14 * nsat;  /* skip for MVP */

	/* Per-cell section:
	 *   DF405 (20 bits): fine pseudorange
	 *   DF406 (24 bits): fine phase range
	 *   DF407 (10 bits): lock time indicator
	 *   DF408 (10 bits): CNR (0.25 dB-Hz)
	 *   (DF420 etc. skipped for MVP)
	 */

	/* Decode cells in order of (sat, sig) pairs where cell_mask bit is set.
	 * Cell mask bits are ordered: for each satellite (in mask order),
	 *   for each signal (in mask order):
	 *     bit = 1 if cell present.
	 */
	unsigned int cell_idx = 0;
	for (int s = 0; s < nsat && cell_idx < RTCM_OBS_MAX_CELLS; s++) {
		for (int g = 0; g < nsig && cell_idx < RTCM_OBS_MAX_CELLS; g++) {
			int cell_bit = s * nsig + g;
			if (!(cell_mask & (1ULL << (cell_mask_bits - 1 - cell_bit))))
				continue;

			/* DF405: fine pseudorange (20 bits, sign-magnitude, 0.5 mm) */
			if (pos + 20 > len_bits) return -1;
			uint32_t raw_ps = (uint32_t)getbits(d, pos, 20);
			pos += 20;

			/* DF406: fine phase range (24 bits, sign-magnitude, 0.5 mm) */
			if (pos + 24 > len_bits) return -1;
			uint32_t raw_ph = (uint32_t)getbits(d, pos, 24);
			pos += 24;

			/* DF407: lock time indicator (10 bits) */
			if (pos + 10 > len_bits) return -1;
			unsigned int lti = (unsigned int)getbits(d, pos, 10);
			pos += 10;

			/* DF408: CNR (10 bits, 0.25 dB-Hz) */
			if (pos + 10 > len_bits) return -1;
			unsigned int cnr = (unsigned int)getbits(d, pos, 10);
			pos += 10;

			/* Skip DF407b (lock time extension, 2 bits) and
			 * DF404 (half-cycle ambiguity, 1 bit) for MSM7.
			 * Actually MSM7 has more fields — we stop here for the MVP
			 * and skip the remaining per-cell bits. The remaining
			 * fields are DF404 (1 bit) and possibly DF420 (1 bit).
			 */
			pos += 1;  /* DF404 half-cycle */

			/* Compute pseudorange in meters.
			 * DF397 (8 bits) = N ms, range 0..255 ms.
			 * DF398 (10 bits) = sub-ms in 0.1024 ms units
			 *                   (so 0..1023 * 0.1024e-3 s = 0..0.1048 s)
			 * Wait — the standard says DF398 is "modulo 1 ms"
			 * with 1024 levels, so 1 ms / 1024 = ~0.977 us per LSB.
			 *
			 * Pseudorange = (DF397 * 1e-3) + (DF398 * 1e-3 / 1024) + (DF405 * 0.5e-3)
			 *
			 * Actually for MSM7 the fine pseudorange is the
			 * fractional part with 0.5 mm resolution. So:
			 *   PR = DF397 * 1e-3 (in seconds, then * c for meters)
			 *      + DF398 * (1e-3 / 1024) (seconds, * c)
			 *      + DF405 * 0.5e-3 (meters, sign-magnitude)
			 * DF405 is sign-magnitude: bit 19 = sign, bits 0-18 = magnitude.
			 */
			double pr_ms = (double)rough_ms[s] * 1e-3;
			double pr_mod = (double)rough_mod[s] * (1e-3 / 1024.0);
			/* Fine pseudorange: 20-bit sign-magnitude, 0.5 mm LSB.
			 * Magnitude is bits 0-18 (19 bits), sign is bit 19. */
			int32_t fine_sign = (raw_ps & (1u << 19)) ? -1 : 1;
			int32_t fine_mag = raw_ps & ((1u << 19) - 1);
			double pr_fine = (double)(fine_sign * fine_mag) * 0.5e-3;  /* meters */

			double pseudorange = pr_ms * 299792458.0
					   + pr_mod * 299792458.0
					   + pr_fine;

			/* Phase range in meters (DF406: 24-bit sign-magnitude, 0.5 mm). */
			int32_t ph_sign = (raw_ph & (1u << 23)) ? -1 : 1;
			int32_t ph_mag = raw_ph & ((1u << 23) - 1);
			double phase_range_m = (double)(ph_sign * ph_mag) * 0.5e-3;

			/* Convert phase range (meters) to phase (cycles) using
			 * the signal's wavelength. For GPS L1: 0.190293672 m,
			 * L2: 0.244210213 m, L5: 0.254833148 m.
			 * For Galileo E1: 0.190293672 m (same as L1),
			 * E5a: 0.254833148 m, E5b: 0.246839246 m.
			 *
			 * We use a coarse lookup by signal code + system.
			 */
			double wavelength = 0.190293672;  /* default L1/E1 */
			char sc = sig_codes[g];
			if (sys == RTCM_SYS_GPS) {
				if (sc == 'C' || sc == 'L' || sc == 'P' || sc == 'Y' || sc == 'M' || sc == 'N')
					wavelength = 0.190293672; /* L1 */
				else if (sc == 'S' || sc == 'X')
					wavelength = 0.244210213; /* L2 */
				else if (sc == 'I' || sc == 'Q')
					wavelength = 0.254833148; /* L5 */
			} else if (sys == RTCM_SYS_GAL) {
				if (sc == 'A' || sc == 'B' || sc == 'C' || sc == 'X')
					wavelength = 0.190293672; /* E1 */
				else if (sc == 'I' || sc == 'Q' || sc == 'X')
					wavelength = 0.254833148; /* E5a */
				else if (sc == '7' || sc == '8' || sc == 'X')
					wavelength = 0.246839246; /* E5b */
				else if (sc == '6' || sc == '9' || sc == '4')
					wavelength = 0.186682684; /* E6 */
			}
			double phase_cycles = phase_range_m / wavelength;

			/* SNR in dB-Hz: DF408 is 10-bit unsigned, 0.25 dB-Hz per LSB.
			 * RINEX S/N is stored as integers 1-9 (signal strength indicator).
			 * We use raw dB-Hz for now and let the RINEX writer convert. */
			double snr_dbhz = (double)cnr * 0.25;

			/* Lock time indicator: RINEX LLI is a single digit 0-7.
			 * RTCM DF407 has a non-linear mapping (see DF402 in rtcm.c).
			 * For the MVP we just store the raw value modulo 8.
			 */
			unsigned int lli = lti & 0x7;

			/* Fill the cell. */
			struct rtcm_obs_cell *cell = &epoch->cells[cell_idx++];
			cell->sat_prn = sat_prns[s];
			cell->sig_code = sc;
			cell->pseudorange = pseudorange;
			cell->phase = phase_cycles;
			cell->doppler = NAN;  /* not decoded in MVP */
			cell->snr = snr_dbhz;
			cell->lock_time = lli;
		}
	}

	epoch->ncells = cell_idx;
	if (epoch->ncells == 0)
		return -1;
	return 0;
}
