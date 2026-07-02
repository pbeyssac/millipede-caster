#ifndef __RTCM_OBS_H__
#define __RTCM_OBS_H__

#include <stdint.h>
#include <sys/time.h>

#include "packet.h"

/*
 * RTCM Observation Decoder
 *
 * Decoder for the RTCM 3.x message types needed to generate
 * RINEX 3.04 observation files:
 *   - 1005: Stationary Antenna Reference Point (ARP) position (ECEF)
 *   - MSM7 (full Multi-Signal Message, full resolution) for:
 *       1077 : GPS
 *       1087 : GLONASS
 *       1097 : Galileo
 *       1107 : QZSS
 *       1117 : SBAS
 *       1127 : BeiDou
 *       1137 : NavIC/IRNSS
 *
 * Scope:
 *   - Decode only the fields RINEX needs: satellite PRN, signal code,
 *     pseudorange, phase range, doppler, SNR, lock time indicator.
 *   - Skip ephemeris messages (1019, 1020, 1043, 1044, 1045, 1046, ...)
 *     — RINEX nav files are out of scope.
 *   - QZSS / SBAS / NavIC MSM7 are decoded structurally but the signal
 *     mask table falls back to GPS attributes for unknown systems; the
 *     caller should treat any cell whose sig_code is '?' as unobserved.
 *   - GLONASS uses FDMA: each satellite has its own carrier frequency
 *     derived from the frequency-slot number n (-7..+13). The slot
 *     number is NOT in the MSM7 message; it comes from RTCM 1020
 *     ephemeris or an external slot table. As an MVP, the decoder uses
 *     the nominal central frequencies (n=0). This produces phase values
 *     that are off by n*0.5625/1602 ≈ 0.035% per slot. For real PPK
 *     work the caller must multiply the phase by (f_sat / f_nominal).
 *
 * The decoder is purely functional: it takes a struct packet* and
 * writes into a caller-provided rtcm_obs_epoch struct. It does NOT
 * allocate or hold state between calls.
 */

/*
 * GNSS system identifier.
 * Maps directly to the RINEX 3.04 satellite prefix character.
 *
 * MSM7 message-number ranges (RTCM 3.3 table 3.5-92):
 *   1071-1077 : GPS         -> 'G'
 *   1081-1087 : GLONASS     -> 'R'
 *   1091-1097 : Galileo     -> 'E'
 *   1101-1107 : QZSS        -> 'J'
 *   1111-1117 : SBAS        -> 'S'
 *   1121-1127 : BeiDou      -> 'C'
 *   1131-1137 : NavIC/IRNSS -> 'I'
 */
enum rtcm_sys {
        RTCM_SYS_NONE = 0,
        RTCM_SYS_GPS     = 'G',   /* 1071-1077 */
        RTCM_SYS_GLO     = 'R',   /* 1081-1087 */
        RTCM_SYS_GAL     = 'E',   /* 1091-1097 */
        RTCM_SYS_QZS     = 'J',   /* 1101-1107 */
        RTCM_SYS_SBS     = 'S',   /* 1111-1117 */
        RTCM_SYS_BDS     = 'C',   /* 1121-1127 */
        RTCM_SYS_NAV     = 'I',   /* 1131-1137 */
};

/*
 * Per-cell RINEX band identifier (single character).
 * Follows RINEX 3.04 table A:
 *   GPS     : '1' L1, '2' L2, '5' L5
 *   GLONASS : '1' G1, '2' G2, '3' G3 (CDMA)
 *   Galileo : '1' E1, '5' E5a, '7' E5b, '6' E6, '8' E5(E5a+E5b)
 *   BeiDou  : '1' B1C, '2' B1I/B1Q, '5' B2a, '6' B3I/B3Q, '7' B2I/B2Q
 *   QZSS    : '1' '2' '5' '6' (L1/L2/L5/L6)
 *   SBAS    : '1' '5'
 *   NavIC   : '5' A5, '9' S5, '2' A-L1, '6' S-Band
 */
enum rtcm_band {
        RTCM_BAND_NONE = 0,
        RTCM_BAND_1 = '1',
        RTCM_BAND_2 = '2',
        RTCM_BAND_3 = '3',
        RTCM_BAND_5 = '5',
        RTCM_BAND_6 = '6',
        RTCM_BAND_7 = '7',
        RTCM_BAND_8 = '8',
        RTCM_BAND_9 = '9',
};

/*
 * RINEX 3.04 attribute code (single character).
 *   GPS L1:   'C' C/A, 'L' L1C, 'P' P(Y), 'W' Z-tracking, 'Y', 'M', 'N', 'X' I+Q
 *   GPS L2:   'C' C/A, 'S' L2C(M), 'L' L2C(L), 'X' L2C(M+L), 'P' P(Y), 'W', 'Y', 'M', 'N'
 *   GPS L5:   'I', 'Q', 'X' I+Q
 *   Galileo:  'A' E1A, 'B' E1B, 'C' E1C, 'X' B+C, 'Z' A+B+C,
 *             'I' E5aI, 'Q' E5aQ, 'X' I+Q, '7'/'8'/'X' E5b, '6'/'9'/'4' E6
 *   GLONASS:  'C' C/A, 'P' P, 'A' L1OCd, 'B' L1OCp, 'X' OCd+OCp,
 *             'I' L2CSI, 'Q' L2OCp, 'X' CSI+OCp,
 *             'I'/'Q'/'X' L3
 *   BeiDou:   'I'/'Q'/'X' (B1I/B1Q/B2I/B2Q/B3I/B3Q),
 *             'C'/'D'/'X' B1C, 'D'/'P'/'X' B2a, 'P'/'W'/'N' B1A
 */
enum rtcm_attr {
        RTCM_ATTR_NONE = 0,
        /* Common attribute codes (system + band disambiguate the actual signal). */
        RTCM_ATTR_C = 'C',   /* C/A (GPS/BeiDou), E1C (Galileo), L1OCd (GLONASS) */
        RTCM_ATTR_L = 'L',   /* L1C (GPS), L2C(L) */
        RTCM_ATTR_S = 'S',   /* L2C(M) */
        RTCM_ATTR_P = 'P',   /* P(Y) (GPS), P (GLONASS), B2a Pilot (BeiDou) */
        RTCM_ATTR_W = 'W',   /* Z-tracking (GPS), B1A (BeiDou) */
        RTCM_ATTR_Y = 'Y',   /* encrypted */
        RTCM_ATTR_M = 'M',   /* M-code */
        RTCM_ATTR_N = 'N',   /* codeless */
        RTCM_ATTR_X = 'X',   /* composite (I+Q, Pilot+Data, etc.) */
        RTCM_ATTR_I = 'I',   /* Pilot / data component */
        RTCM_ATTR_Q = 'Q',   /* Pilot / data component */
        RTCM_ATTR_A = 'A',   /* E1A (Galileo), L1OCd (GLONASS, alt) */
        RTCM_ATTR_B = 'B',   /* E1B (Galileo), L1OCp (GLONASS, alt) */
        RTCM_ATTR_D = 'D',   /* Data component (B1C data, B2a data) */
        RTCM_ATTR_Z = 'Z',   /* A+B+C composite (Galileo E1) */
        RTCM_ATTR_7 = '7',   /* E5bI (Galileo) */
        RTCM_ATTR_8 = '8',   /* E5bQ (Galileo) */
        RTCM_ATTR_6 = '6',   /* E6A (Galileo), B3I (BeiDou band 6) */
        RTCM_ATTR_9 = '9',   /* E6B (Galileo) */
        RTCM_ATTR_4 = '4',   /* E6C (Galileo) */
};

/*
 * Decoded observation for one satellite / signal cell.
 *
 * Ranges are stored in meters, phase in cycles, doppler in Hz.
 * Invalid/missing values are set to NaN (use isnan() to check).
 *
 * carrier_freq_hz holds the nominal carrier frequency in Hz for the
 * (system, band) pair. For GLONASS this is the n=0 central frequency
 * (1602.0 MHz on L1, 1246.0 MHz on L2); the per-satellite frequency
 * slot must be applied by the caller. For all other constellations
 * carrier_freq_hz is the exact carrier frequency.
 */
struct rtcm_obs_cell {
        unsigned char sat_prn;     /* 1-32 (GPS), 1-36 (GAL), 1-24/32 (GLO), 1-63 (BDS) */
        char sig_code;             /* RINEX attribute code ('C','L','S','P','I','X',...) */
        char band;                 /* RINEX band code ('1','2','5','6','7','8') */
        double carrier_freq_hz;    /* nominal carrier frequency, Hz (0 if unknown) */

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
 * Decode an RTCM MSM7 message into an observation epoch.
 *
 * Supports all constellations per RTCM 3.3 table 3.5-92:
 *   GPS (1077), GLONASS (1087), Galileo (1097), QZSS (1107),
 *   SBAS (1117), BeiDou (1127), NavIC (1137).
 *
 * Returns 0 on success, -1 on error (wrong type, truncated, etc.).
 * On success, epoch->ncells > 0 and epoch->cells[0..ncells-1] are valid.
 */
int rtcm_obs_decode_msm7(struct packet *p, struct rtcm_obs_epoch *epoch);

/*
 * Map an RTCM MSM message type to a GNSS system identifier.
 *
 * MSM type ranges (RTCM 3.3 table 3.5-92):
 *   1071-1077 : GPS
 *   1081-1087 : GLONASS
 *   1091-1097 : Galileo
 *   1101-1107 : QZSS
 *   1111-1117 : SBAS
 *   1121-1127 : BeiDou
 *   1131-1137 : NavIC/IRNSS
 * The last digit (1..7) indicates the MSM variant (1=MSM1 ... 7=MSM7).
 */
enum rtcm_sys rtcm_obs_type_to_sys(unsigned short type);

#endif /* __RTCM_OBS_H__ */
