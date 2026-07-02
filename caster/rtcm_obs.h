#ifndef __RTCM_OBS_H__
#define __RTCM_OBS_H__

#include <stdint.h>
#include <sys/time.h>

#include "packet.h"

/*
 * RTCM Observation Decoder
 *
 * Minimal decoder for the RTCM 3.x message types needed to generate
 * RINEX 3.04 observation files:
 *   - 1005: Stationary Antenna Reference Point (ARP) position (ECEF)
 *   - 1071: GPS MSM7 (full Multi-Signal Message, full resolution)
 *   - 1074: Galileo MSM7
 *
 * Scope of this MVP:
 *   - Decode only the fields RINEX needs: satellite PRN, signal code,
 *     pseudorange, phase range, doppler, SNR, lock time indicator.
 *   - Skip ephemeris messages (1019, 1045, ...) — RINEX nav files are
 *     out of scope for the MVP.
 *   - Skip GLONASS (1081) and BeiDou (1121) — they need extra slots
 *     and frequency-number handling. Add later.
 *
 * The decoder is purely functional: it takes a struct packet* and
 * writes into a caller-provided rtcm_obs_epoch struct. It does NOT
 * allocate or hold state between calls.
 */

/*
 * GNSS system identifier.
 * Maps directly to the RINEX 3.04 satellite prefix character.
 */
enum rtcm_sys {
	RTCM_SYS_NONE = 0,
	RTCM_SYS_GPS     = 'G',   /* 1071-1077 */
	RTCM_SYS_GLO     = 'R',   /* 1081-1087 */
	RTCM_SYS_GAL     = 'E',   /* 1074-1077 wait, actually 1094-1097 */
	RTCM_SYS_BDS     = 'C',   /* 1121-1127 */
	RTCM_SYS_QZS     = 'J',   /* 1101-1107 */
	RTCM_SYS_SBS     = 'S',   /* 1101-1107 */
};

/*
 * RINEX 3.04 signal code (single character).
 *   GPS: 'C' (C/A), 'L' (L1C), 'S' (L2C), 'P' (P1/P2), 'W' (Z-tracking),
 *        'Y' (encrypted), 'M' (M-code), 'N' (codeless), 'X' (I+Q)
 *   Galileo: 'A' (E1A), 'B' (E1B), 'C' (E1C), 'X' (B+C), 'Z' (A+B+C),
 *            'I' (E5aI), 'Q' (E5aQ), 'X' (I+Q),
 *            '7' (E5bI), '8' (E5bQ), 'X' (I+Q),
 *            '6' (E6A), '9' (E6B), '4' (E6C)
 * For the MVP we only handle the most common ones.
 */
enum rtcm_sig {
	RTCM_SIG_NONE = 0,
	/* GPS signals (signal mask bit -> RINEX code) */
	RTCM_SIG_GPS_L1CA = 'C',   /* L1 C/A      */
	RTCM_SIG_GPS_L1P  = 'P',   /* L1 P(Y)     */
	RTCM_SIG_GPS_L2C  = 'S',   /* L2 L2C(M)   */
	RTCM_SIG_GPS_L2P  = 'P',   /* L2 P(Y)     */
	/* Galileo signals */
	RTCM_SIG_GAL_E1B  = 'B',   /* E1B         */
	RTCM_SIG_GAL_E1C  = 'C',   /* E1C         */
	RTCM_SIG_GAL_E5A  = 'X',   /* E5a I+Q     */
	RTCM_SIG_GAL_E5B  = 'X',   /* E5b I+Q     */
	RTCM_SIG_GAL_E6   = 'X',   /* E6          */
};

/*
 * Decoded observation for one satellite / signal cell.
 *
 * Ranges are stored in meters, phase in cycles, doppler in Hz.
 * Invalid/missing values are set to NaN (use isnan() to check).
 */
struct rtcm_obs_cell {
	unsigned char sat_prn;     /* 1-32 for GPS, 1-36 for Galileo */
	char sig_code;             /* RINEX signal code ('C', 'L', 'S', 'P', ...) */

	double pseudorange;        /* meters, NaN if missing */
	double phase;              /* cycles, NaN if missing */
	double doppler;            /* Hz, NaN if missing */
	double snr;                /* dB-Hz, NaN if missing */
	unsigned int lock_time;    /* lock time indicator (0-15, RINEX LLI) */
};

/*
 * Decoded observation epoch (one RTCM MSM7 message).
 *
 * An epoch contains up to RTCM_OBS_MAX_CELLS observations across
 * up to RTCM_OBS_MAX_SATS satellites and RTCM_OBS_MAX_SIGS signals.
 */
#define RTCM_OBS_MAX_SATS  64
#define RTCM_OBS_MAX_SIGS  32
#define RTCM_OBS_MAX_CELLS 64   /* per RTCM 3.3 spec (cell mask <= 64 bits) */

struct rtcm_obs_epoch {
	enum rtcm_sys sys;
	unsigned int station_id;        /* DF003 */
	struct timeval epoch_time;      /* GNSS epoch time (TOW for GPS/Galileo) */

	/* Position from latest 1005/1006 message (ECEF, meters) */
	/* Only valid if has_position is non-zero */
	int has_position;
	double ecef_x, ecef_y, ecef_z;

	/* Decoded cells */
	unsigned int ncells;
	struct rtcm_obs_cell cells[RTCM_OBS_MAX_CELLS];
};

/*
 * Decode an RTCM 1005 message into ECEF coordinates.
 *
 * Returns 0 on success, -1 on error (wrong type, truncated, etc.).
 * On success, the output parameters are filled with ECEF coordinates
 * in meters.
 */
int rtcm_obs_decode_1005(struct packet *p, double *x, double *y, double *z);

/*
 * Decode an RTCM MSM7 message (1071 GPS, 1074 Galileo, 1081 GLO,
 * 1091 SBAS, 1101 QZS, 1111 BDS) into an observation epoch.
 *
 * Returns 0 on success, -1 on error (wrong type, truncated, etc.).
 * On success, epoch->ncells > 0 and epoch->cells[0..ncells-1] are valid.
 *
 * Note: for the MVP, only GPS (1071) and Galileo (1094) are decoded.
 * Other systems return -1.
 */
int rtcm_obs_decode_msm7(struct packet *p, struct rtcm_obs_epoch *epoch);

/*
 * Map an RTCM MSM7 message type to a GNSS system identifier.
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
enum rtcm_sys rtcm_obs_type_to_sys(unsigned short type);

#endif /* __RTCM_OBS_H__ */
