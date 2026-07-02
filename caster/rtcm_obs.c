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
 * that one is file-static. Currently unused after the cell-mask
 * rewrite to a byte-array form, but kept for future use.
 */
static int count_set_u64(uint64_t v) __attribute__((unused));
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
 * Speed of light (m/s). Used for the rough-range ms -> meters conversion.
 */
#define C_SPEED 299792458.0

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
 * Process-wide GLONASS frequency-slot table.
 *
 * Indexed by GLONASS PRN (1-24). Entry 0 is unused. A value of 0
 * means "no 1020 message seen yet for this PRN" (the decoder falls
 * back to the n=0 nominal carrier in that case).
 *
 * Access is via stdatomic (relaxed ordering is sufficient: a stale
 * read simply yields the n=0 fallback, which is still a valid carrier
 * frequency, just less accurate).
 */
#include <stdatomic.h>
static _Atomic int8_t glo_freq_slots[25];   /* [0..24], index 0 unused */

void rtcm_obs_set_glo_freq_slot(unsigned int prn, int freq_n) {
        if (prn < 1 || prn > 24)
                return;
        if (freq_n < -7 || freq_n > 13)
                return;     /* out of valid range, ignore */
        atomic_store_explicit(&glo_freq_slots[prn], (int8_t)freq_n,
                              memory_order_relaxed);
}

int rtcm_obs_get_glo_freq_slot(unsigned int prn) {
        if (prn < 1 || prn > 24)
                return 0;
        return (int)atomic_load_explicit(&glo_freq_slots[prn],
                                         memory_order_relaxed);
}

/*
 * Decode RTCM 1020 (GLONASS ephemeris).
 *
 * Layout (RTCM 3.3 section 3.5.84):
 *   bits  0-11 : message type (1020)
 *   bits 12-17 : satellite ID (DF096, 6 bits, 1-24)
 *   bits 18-22 : GLONASS frequency channel (DF097, 5 bits, signed 2's
 *                complement, valid range -7..+13)
 *   bits 23+   : remainder of ephemeris (skipped here)
 *
 * getbits() returns a uint64_t without sign extension; we manually
 * sign-extend the 5-bit value (if bit 4 is set, subtract 32) to get
 * the signed slot number in [-7, +13].
 */
int rtcm_obs_decode_1020(struct packet *p,
                         unsigned int *prn_out, int *freq_n_out) {
        if (p == NULL || p->datalen < 6 + 3)   /* need at least 23 bits payload */
                return -1;

        unsigned short type = rtcm_get_type(p);
        if (type != 1020)
                return -1;

        unsigned char *d = p->data + 3;
        unsigned int prn = (unsigned int)getbits(d, 12, 6);
        uint32_t raw = (uint32_t)getbits(d, 18, 5);
        int freq_n = (int)raw;
        if (raw & 0x10)              /* sign bit of 5-bit field */
                freq_n -= 32;        /* sign-extend: 31 -> -1, 25 -> -7, etc. */

        if (prn < 1 || prn > 24)
                return -1;
        if (freq_n < -7 || freq_n > 13)
                return -1;     /* invalid slot, ignore */

        rtcm_obs_set_glo_freq_slot(prn, freq_n);

        if (prn_out)   *prn_out = prn;
        if (freq_n_out) *freq_n_out = freq_n;
        return 0;
}

/*
 * Map an RTCM message type to a GNSS system identifier.
 *
 * MSM7 type ranges (RTCM 3.3 table 3.5-92):
 *   1071-1077 : GPS
 *   1081-1087 : GLONASS
 *   1091-1097 : Galileo
 *   1101-1107 : QZSS
 *   1111-1117 : SBAS
 *   1121-1127 : BeiDou
 *   1131-1137 : NavIC/IRNSS
 * The last digit (1..7) indicates the MSM variant (1=MSM1 ... 7=MSM7).
 */
enum rtcm_sys rtcm_obs_type_to_sys(unsigned short type) {
        if (type >= 1071 && type <= 1077) return RTCM_SYS_GPS;
        if (type >= 1081 && type <= 1087) return RTCM_SYS_GLO;
        if (type >= 1091 && type <= 1097) return RTCM_SYS_GAL;
        if (type >= 1101 && type <= 1107) return RTCM_SYS_QZS;
        if (type >= 1111 && type <= 1117) return RTCM_SYS_SBS;
        if (type >= 1121 && type <= 1127) return RTCM_SYS_BDS;
        if (type >= 1131 && type <= 1137) return RTCM_SYS_NAV;
        return RTCM_SYS_NONE;
}

/*
 * Decode the satellite mask into a list of PRNs.
 *
 * The 64-bit satellite mask (DF394) is MSB-first: bit 0 (MSB) = PRN 1,
 * bit 63 (LSB) = PRN 64. The PRN range depends on the constellation:
 *   GPS      1-32
 *   GLONASS  1-24 (32 with extended slots)
 *   Galileo  1-36
 *   BeiDou   1-63 (BeiDou-3 numbering)
 *   QZSS     193-199 (mapped to 1-7 inside the mask)
 *   SBAS     120-151 (mapped to 1-32 inside the mask)
 *   NavIC    1-14
 * We just store the PRN for each set bit (1-indexed); the caller
 * already knows the system.
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
 * Per-signal descriptor: RINEX band + attribute + nominal carrier
 * frequency. The signal mask in MSM messages is 32 bits wide, but only
 * the low 16 bits are used for any constellation in practice; we
 * therefore keep a 16-entry table per system.
 *
 * carrier_freq_hz = 0.0 means "unknown / not in the MVP"; the
 * wavelength lookup will fall back to a system+band default.
 *
 * is_glo_fdma: 1 for GLONASS FDMA signals (L1 C/A, L1 P, L2 C/A, L2 P).
 * For these, freq_hz is the n=0 nominal carrier; the MSM7 decoder
 * looks up the per-satellite slot n (from RTCM 1020) and replaces
 * freq_hz with (1602.0 + n*0.5625) MHz on L1 or (1246.0 + n*0.4375)
 * MHz on L2 before computing the wavelength. CDMA GLONASS signals
 * (L1OC, L2OC, L3) and all non-GLONASS signals have is_glo_fdma=0
 * and use freq_hz verbatim.
 */
struct sig_entry {
        char band;             /* '0' = invalid (skip) */
        char attr;             /* RINEX attribute code */
        double freq_hz;        /* nominal carrier frequency, Hz */
        int is_glo_fdma;       /* 1 = GLONASS FDMA, freq_hz is n=0 nominal */
};

/* Sentinel: band=0 means "this signal mask bit is unused". */
#define SIG_UNUSED { '0', '?', 0.0, 0 }

/*
 * GPS signal mask (RTCM 3.3 table 3.5-15):
 *   bit 0 : L1 C/A        -> 1C  (1575.42 MHz)
 *   bit 1 : L1 L1C (P)    -> 1L
 *   bit 2 : L1 L1C (D)    -> 1S (RTCM uses 'S' for L1C data, but RINEX
 *                                reserves 'S' for L2C(M); for L1C the
 *                                correct RINEX attrs are 'L' pilot,
 *                                'S' data, 'X' pilot+data — we keep
 *                                'S' for both, see below)
 *   bit 3 : L1 L1C (D+P)  -> 1X
 *   bit 4 : L2 L2C (M)    -> 2S  (1227.60 MHz)
 *   bit 5 : L2 L2C (L)    -> 2L
 *   bit 6 : L2 L2C (M+L)  -> 2X
 *   bit 7 : L2 P(Y)       -> 2P
 *   bit 8 : L5 I          -> 5I  (1176.45 MHz)
 *   bit 9 : L5 Q          -> 5Q
 *   bit 10: L5 I+Q        -> 5X
 *   bit 11: L2 Z-tracking -> 2W
 *   bit 12: L2 Y          -> 2Y
 *   bit 13: L2 M          -> 2M
 *   bit 14: L1 P          -> 1P  (rarely used)
 *   bit 15: L1 Z-tracking -> 1W
 */
static const struct sig_entry GPS_SIG_TABLE[16] = {
        { '1', 'C', 1575420000.0, 0 },   /* bit 0: L1 C/A          */
        { '1', 'L', 1575420000.0, 0 },   /* bit 1: L1 L1C pilot    */
        { '1', 'S', 1575420000.0, 0 },   /* bit 2: L1 L1C data     */
        { '1', 'X', 1575420000.0, 0 },   /* bit 3: L1 L1C pilot+data */
        { '2', 'S', 1227600000.0, 0 },   /* bit 4: L2 L2C(M)       */
        { '2', 'L', 1227600000.0, 0 },   /* bit 5: L2 L2C(L)       */
        { '2', 'X', 1227600000.0, 0 },   /* bit 6: L2 L2C(M+L)     */
        { '2', 'P', 1227600000.0, 0 },   /* bit 7: L2 P(Y)         */
        { '5', 'I', 1176450000.0, 0 },   /* bit 8: L5 I            */
        { '5', 'Q', 1176450000.0, 0 },   /* bit 9: L5 Q            */
        { '5', 'X', 1176450000.0, 0 },   /* bit 10: L5 I+Q         */
        { '2', 'W', 1227600000.0, 0 },   /* bit 11: L2 Z-tracking  */
        { '2', 'Y', 1227600000.0, 0 },   /* bit 12: L2 Y           */
        { '2', 'M', 1227600000.0, 0 },   /* bit 13: L2 M           */
        { '1', 'P', 1575420000.0, 0 },   /* bit 14: L1 P           */
        { '1', 'W', 1575420000.0, 0 },   /* bit 15: L1 Z-tracking  */
};

/*
 * GLONASS signal mask (RTCM 3.3 table 3.5-30):
 *   bit 0 : L1 C/A        -> 1C  (G1 nominal 1602.0 MHz)
 *   bit 1 : L1 P          -> 1P
 *   bit 2 : L2 C/A        -> 2C  (G2 nominal 1246.0 MHz)
 *   bit 3 : L2 P          -> 2P
 *   bit 4 : L1 OCd        -> 1A  (L1 CDMA, 1600.995 MHz)
 *   bit 5 : L1 OCp        -> 1B
 *   bit 6 : L1 OCd+OCp    -> 1X
 *   bit 7 : L1 SCd        -> 1D
 *   bit 8 : L1 SCp        -> 1E
 *   bit 9 : L1 SCd+SCp    -> 1Z
 *   bit 10: L2 CSI        -> 2I  (L2 CDMA, 1248.06 MHz)
 *   bit 11: L2 OCp        -> 2B
 *   bit 12: L2 CSI+OCp    -> 2X
 *   bit 13: L2 SCd        -> 2D
 *   bit 14: L2 SCp        -> 2E
 *   bit 15: L2 SCd+SCp    -> 2Z
 *
 * The G1/G2 carrier frequencies are FDMA and vary per satellite:
 *   f_L1 = 1602.0 + n * 0.5625 MHz (n = -7..+13, frequency slot)
 *   f_L2 = 1246.0 + n * 0.4375 MHz
 * The slot number n is NOT in the MSM7 message; it comes from the
 * GLONASS ephemeris (RTCM 1020). The MVP uses n=0 (nominal). Callers
 * that need accurate phase must rescale: phase_correct = phase *
 * (f_sat / f_nominal). The L1/L2 CDMA frequencies are fixed.
 *
 * L3 frequencies are not in RTCM 3.3 table 3.5-30; L3 ICD is at
 * ~1202.025 MHz (RTCM 3.4 adds it but we mark it unused here).
 */
static const struct sig_entry GLO_SIG_TABLE[16] = {
        { '1', 'C', 1602000000.0, 1 },   /* bit 0: L1 C/A (FDMA, n=0 nominal) */
        { '1', 'P', 1602000000.0, 1 },   /* bit 1: L1 P   (FDMA, n=0 nominal) */
        { '2', 'C', 1246000000.0, 1 },   /* bit 2: L2 C/A (FDMA, n=0 nominal) */
        { '2', 'P', 1246000000.0, 1 },   /* bit 3: L2 P   (FDMA, n=0 nominal) */
        { '1', 'A', 1600995000.0, 0 },   /* bit 4: L1 OCd (CDMA)              */
        { '1', 'B', 1600995000.0, 0 },   /* bit 5: L1 OCp (CDMA)              */
        { '1', 'X', 1600995000.0, 0 },   /* bit 6: L1 OCd+OCp                 */
        { '1', 'D', 1600995000.0, 0 },   /* bit 7: L1 SCd (CDMA)              */
        { '1', 'E', 1600995000.0, 0 },   /* bit 8: L1 SCp (CDMA)              */
        { '1', 'Z', 1600995000.0, 0 },   /* bit 9: L1 SCd+SCp                 */
        { '2', 'I', 1248060000.0, 0 },   /* bit 10: L2 CSI (CDMA)             */
        { '2', 'B', 1248060000.0, 0 },   /* bit 11: L2 OCp (CDMA)             */
        { '2', 'X', 1248060000.0, 0 },   /* bit 12: L2 CSI+OCp                */
        { '2', 'D', 1248060000.0, 0 },   /* bit 13: L2 SCd (CDMA)             */
        { '2', 'E', 1248060000.0, 0 },   /* bit 14: L2 SCp (CDMA)             */
        { '2', 'Z', 1248060000.0, 0 },   /* bit 15: L2 SCd+SCp                */
};

/*
 * Galileo signal mask (RTCM 3.3 table 3.5-49):
 *   bit 0 : E1A           -> 1A  (1575.42 MHz)
 *   bit 1 : E1B           -> 1B
 *   bit 2 : E1C           -> 1C
 *   bit 3 : E1B+C         -> 1X
 *   bit 4 : E1A+B+C       -> 1Z
 *   bit 5 : E5aI          -> 5I  (1176.45 MHz)
 *   bit 6 : E5aQ          -> 5Q
 *   bit 7 : E5aI+Q        -> 5X
 *   bit 8 : E5bI          -> 7I  (1207.14 MHz)
 *   bit 9 : E5bQ          -> 7Q
 *   bit 10: E5bI+Q        -> 7X
 *   bit 11: E5(b+a)       -> 8X  (1191.795 MHz)
 *   bit 12: E6A           -> 6A  (1278.75 MHz)
 *   bit 13: E6B           -> 6B
 *   bit 14: E6C           -> 6C
 *   bit 15: E6B+C         -> 6X
 */
static const struct sig_entry GAL_SIG_TABLE[16] = {
        { '1', 'A', 1575420000.0, 0 },   /* bit 0: E1A            */
        { '1', 'B', 1575420000.0, 0 },   /* bit 1: E1B            */
        { '1', 'C', 1575420000.0, 0 },   /* bit 2: E1C            */
        { '1', 'X', 1575420000.0, 0 },   /* bit 3: E1B+C          */
        { '1', 'Z', 1575420000.0, 0 },   /* bit 4: E1A+B+C        */
        { '5', 'I', 1176450000.0, 0 },   /* bit 5: E5aI           */
        { '5', 'Q', 1176450000.0, 0 },   /* bit 6: E5aQ           */
        { '5', 'X', 1176450000.0, 0 },   /* bit 7: E5aI+Q         */
        { '7', 'I', 1207140000.0, 0 },   /* bit 8: E5bI           */
        { '7', 'Q', 1207140000.0, 0 },   /* bit 9: E5bQ           */
        { '7', 'X', 1207140000.0, 0 },   /* bit 10: E5bI+Q        */
        { '8', 'X', 1191795000.0, 0 },   /* bit 11: E5(b+a)       */
        { '6', 'A', 1278750000.0, 0 },   /* bit 12: E6A           */
        { '6', 'B', 1278750000.0, 0 },   /* bit 13: E6B           */
        { '6', 'C', 1278750000.0, 0 },   /* bit 14: E6C           */
        { '6', 'X', 1278750000.0, 0 },   /* bit 15: E6B+C         */
};

/*
 * BeiDou signal mask (RTCM 3.3 table 3.5-74 for BDS-2, extended
 * in RTCM 3.3 amendment for BDS-3):
 *   bit 0 : B1I           -> 2I  (1561.098 MHz)
 *   bit 1 : B1Q           -> 2Q
 *   bit 2 : B1I+Q         -> 2X
 *   bit 3 : B3I           -> 6I  (1268.52 MHz)
 *   bit 4 : B3Q           -> 6Q
 *   bit 5 : B3I+Q         -> 6X
 *   bit 6 : B2I           -> 7I  (1207.14 MHz)
 *   bit 7 : B2Q           -> 7Q
 *   bit 8 : B2I+Q         -> 7X
 *   bit 9 : B1C (Pilot)   -> 1C  (1575.42 MHz)
 *   bit 10: B1C (Data)    -> 1D
 *   bit 11: B1C Pilot+Data -> 1X
 *   bit 12: B2a (Pilot)   -> 5P  (1176.45 MHz)
 *   bit 13: B2a (Data)    -> 5D
 *   bit 14: B2a Pilot+Data -> 5X
 *   bit 15: B2b (Data)    -> 7D  (1207.14 MHz, same band as B2I)
 *
 * Note: BeiDou band '2' = B1 (legacy B1I at 1561.098 MHz), NOT the
 * GPS-style L2 (1227.6 MHz). Band '1' is reserved for modernized B1C
 * at 1575.42 MHz (same as GPS L1).
 */
static const struct sig_entry BDS_SIG_TABLE[16] = {
        { '2', 'I', 1561098000.0, 0 },   /* bit 0: B1I            */
        { '2', 'Q', 1561098000.0, 0 },   /* bit 1: B1Q            */
        { '2', 'X', 1561098000.0, 0 },   /* bit 2: B1I+Q          */
        { '6', 'I', 1268520000.0, 0 },   /* bit 3: B3I            */
        { '6', 'Q', 1268520000.0, 0 },   /* bit 4: B3Q            */
        { '6', 'X', 1268520000.0, 0 },   /* bit 5: B3I+Q          */
        { '7', 'I', 1207140000.0, 0 },   /* bit 6: B2I            */
        { '7', 'Q', 1207140000.0, 0 },   /* bit 7: B2Q            */
        { '7', 'X', 1207140000.0, 0 },   /* bit 8: B2I+Q          */
        { '1', 'C', 1575420000.0, 0 },   /* bit 9: B1C Pilot      */
        { '1', 'D', 1575420000.0, 0 },   /* bit 10: B1C Data      */
        { '1', 'X', 1575420000.0, 0 },   /* bit 11: B1C P+D       */
        { '5', 'P', 1176450000.0, 0 },   /* bit 12: B2a Pilot     */
        { '5', 'D', 1176450000.0, 0 },   /* bit 13: B2a Data      */
        { '5', 'X', 1176450000.0, 0 },   /* bit 14: B2a P+D       */
        { '7', 'D', 1207140000.0, 0 },   /* bit 15: B2b Data      */
};

/*
 * SBAS signal mask (RTCM 3.3 table 3.5-95):
 *   bit 0 : L1 C/A        -> 1C  (1575.42 MHz)
 *   bit 5 : L5 I          -> 5I  (1176.45 MHz)
 *   bit 6 : L5 Q          -> 5Q
 *   bit 7 : L5 I+Q        -> 5X
 * Bits 1-4 are reserved.
 */
static const struct sig_entry SBS_SIG_TABLE[16] = {
        { '1', 'C', 1575420000.0, 0 },   /* bit 0: L1 C/A         */
        SIG_UNUSED, SIG_UNUSED, SIG_UNUSED, SIG_UNUSED,
        { '5', 'I', 1176450000.0, 0 },   /* bit 5: L5 I           */
        { '5', 'Q', 1176450000.0, 0 },   /* bit 6: L5 Q           */
        { '5', 'X', 1176450000.0, 0 },   /* bit 7: L5 I+Q         */
        SIG_UNUSED, SIG_UNUSED, SIG_UNUSED, SIG_UNUSED,
        SIG_UNUSED, SIG_UNUSED, SIG_UNUSED, SIG_UNUSED,
};

/*
 * QZSS signal mask (RTCM 3.3 table 3.5-87) — same signal set as GPS
 * plus L1S and L6. The MVP reuses the GPS table for bits 0-15; bits
 * beyond 15 are out of range for our 16-entry table.
 */
#define QZS_SIG_TABLE GPS_SIG_TABLE

/*
 * NavIC/IRNSS signal mask — not in RTCM 3.3 table; NavIC was added
 * in RTCM 3.4. The MVP falls back to the GPS table for bits 0-15.
 */
#define NAV_SIG_TABLE GPS_SIG_TABLE

/*
 * Decode the signal mask into a list of per-signal descriptors.
 *
 * The 32-bit signal mask (DF395) is MSB-first in the bitstream: the
 * first bit read corresponds to spec "bit 0", the last bit read to
 * "bit 31". When stored in a uint32_t via getbits(), the first bit
 * read becomes the MSB (bit 31) and the last becomes the LSB (bit 0).
 *
 * Per RTCM 3.3, only bits 0-15 (the first 16 bits read = uint32_t
 * bits 31..16) carry meaning for any constellation; bits 16-31 are
 * reserved for future use. We therefore iterate the table entries
 * i=0..15 and check `mask & (1u << (31 - i))` to test spec-bit i.
 *
 * Returns the number of signals found (nsig).
 */
static int decode_sig_mask(uint32_t mask, enum rtcm_sys sys,
                           struct sig_entry *sigs_out, int max_sigs) {
        const struct sig_entry *table;
        switch (sys) {
                case RTCM_SYS_GPS: table = GPS_SIG_TABLE; break;
                case RTCM_SYS_GLO: table = GLO_SIG_TABLE; break;
                case RTCM_SYS_GAL: table = GAL_SIG_TABLE; break;
                case RTCM_SYS_SBS: table = SBS_SIG_TABLE; break;
                case RTCM_SYS_QZS: table = QZS_SIG_TABLE; break;
                case RTCM_SYS_BDS: table = BDS_SIG_TABLE; break;
                case RTCM_SYS_NAV: table = NAV_SIG_TABLE; break;
                default:            table = GPS_SIG_TABLE; break;
        }
        int nsig = 0;
        for (int i = 0; i < 16 && nsig < max_sigs; i++) {
                if (mask & (1u << (31 - i))) {
                        if (table[i].band != '0') {
                                sigs_out[nsig++] = table[i];
                        }
                }
        }
        return nsig;
}

/*
 * Compute the wavelength (meters) for a given carrier frequency.
 */
static double wavelength_for_freq(double freq_hz) {
        if (freq_hz <= 0.0)
                return 0.0;
        return C_SPEED / freq_hz;
}

/*
 * Decode an MSM7 message into an observation epoch.
 *
 * MSM7 layout (RTCM 3.3 section 3.5.4.7):
 *   bits   0-11  : message type
 *   bits  12-23  : reference station ID (DF003)
 *   bits  24-53  : GNSS epoch time (DF401; TOW ms for GPS/Galileo/QZSS,
 *                  ms-of-day for GLONASS, etc.)
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
 *   - signal code + band + frequency (from sig mask)
 *   - rough range (DF397) + fine pseudorange (DF405) -> pseudorange
 *   - phase range (DF406) -> phase in cycles (need frequency; we use
 *     the nominal carrier_freq_hz from the sig_entry table)
 *   - lock time indicator (DF407)
 *   - signal CNR (DF408 for MSM7 = 10-bit, 0.25 dB-Hz)
 *
 * Skip: doppler, half-cycle, phase range rate (DF420). These are in
 * MSM7 but not strictly needed for a minimal RINEX obs file.
 */
int rtcm_obs_decode_msm7(struct packet *p, struct rtcm_obs_epoch *epoch) {
        if (p == NULL || epoch == NULL)
                return -1;

        unsigned short type = rtcm_get_type(p);
        /* Accept MSM1..MSM7 (last digit 1-7), not just MSM7, since the
         * payload layout up to the per-cell section is identical. The
         * per-cell field widths differ between MSM1/2/3/4/5/6/7, but
         * for the MVP we only support MSM7 (last digit 7). */
        if (type < 1071 || type > 1137)
                return -1;
        if ((type % 10) != 7)
                return -1;

        enum rtcm_sys sys = rtcm_obs_type_to_sys(type);
        if (sys == RTCM_SYS_NONE)
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

        /* DF401: GNSS epoch time (30 bits, ms). Semantics depend on
         * system: TOW (ms) for GPS/Galileo/QZSS, ms-of-day for
         * GLONASS/SBAS. We don't use it because we lack the week
         * number / day number; instead we use wall-clock as the
         * RINEX epoch timestamp. */
        uint32_t tow_ms = (uint32_t)getbits(d, pos, 30);
        pos += 30;
        {
                struct timeval now;
                gettimeofday(&now, NULL);
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

        struct sig_entry sigs[RTCM_OBS_MAX_SIGS];
        int nsig = decode_sig_mask(sig_mask, sys, sigs, RTCM_OBS_MAX_SIGS);

        if (nsat == 0 || nsig == 0)
                return -1;

        /* Per RTCM 3.3 spec, the cell mask has nsat*nsig bits but the
         * number of SET bits (observed cells) is at most 64. We allow
         * nsat*nsig up to 64*16 = 1024 bits, stored in a 128-byte
         * bit array. The decoder will silently skip cells beyond
         * RTCM_OBS_MAX_CELLS (defensive cap). */
        int cell_mask_bits = nsat * nsig;
        if (cell_mask_bits > 1024)
                return -1;
        if (pos + cell_mask_bits > len_bits) return -1;

        /* Read cell mask into a byte array (MSB-first within each byte
         * of the conceptual bitstream, but for cell-presence lookup we
         * just store bits in their natural order: bit i of the cell
         * mask = bit (i & 7) of cell_mask[i >> 3]). */
        unsigned char cell_mask[128] = {0};
        for (int i = 0; i < cell_mask_bits; i++) {
                if (getbits(d, pos + i, 1))
                        cell_mask[i >> 3] |= (1u << (i & 7));
        }
        pos += cell_mask_bits;

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
         *   DF405 (20 bits): fine pseudorange        (MSM4/6/7)
         *   DF406 (24 bits): fine phase range        (MSM5/6/7)
         *   DF407 (10 bits): lock time indicator     (all MSM)
         *   DF408 (10 bits): CNR (0.25 dB-Hz)        (MSM4/5/6/7)
         *   DF404 ( 1 bit ): half-cycle ambiguity    (MSM4/5/6/7)
         *   DF420 (15 bits): fine phase range rate   (MSM7 only)
         * Total: 80 bits per cell in MSM7.
         * We skip DF420 (not needed for RINEX obs). Failing to skip
         * it would mis-align every cell after the first.
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
                        /* Look up bit `cell_bit` in the cell_mask byte array. */
                        int present = (cell_mask[cell_bit >> 3] >> (cell_bit & 7)) & 1;
                        if (!present)
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

                        /* DF404: half-cycle ambiguity (1 bit). */
                        pos += 1;

                        /* DF420: fine phase range rate (15 bits, MSM7 only).
                         * Skipping this would break alignment for cell N+1
                         * because MSM7 packs 80 bits per cell. */
                        if (pos + 15 > len_bits) return -1;
                        pos += 15;

                        /* Compute pseudorange in meters.
                         *   PR = DF397 * 1e-3 (s) * c
                         *      + DF398 * (1e-3 / 1024) (s) * c
                         *      + DF405 * 0.5e-3 (m, sign-magnitude)
                         * DF405 is sign-magnitude: bit 19 = sign, bits 0-18 = magnitude.
                         */
                        double pr_ms = (double)rough_ms[s] * 1e-3;
                        double pr_mod = (double)rough_mod[s] * (1e-3 / 1024.0);
                        int32_t fine_sign = (raw_ps & (1u << 19)) ? -1 : 1;
                        int32_t fine_mag = raw_ps & ((1u << 19) - 1);
                        double pr_fine = (double)(fine_sign * fine_mag) * 0.5e-3;

                        double pseudorange = pr_ms * C_SPEED
                                           + pr_mod * C_SPEED
                                           + pr_fine;

                        /* Phase range in meters (DF406: 24-bit sign-magnitude, 0.5 mm). */
                        int32_t ph_sign = (raw_ph & (1u << 23)) ? -1 : 1;
                        int32_t ph_mag = raw_ph & ((1u << 23) - 1);
                        double phase_range_m = (double)(ph_sign * ph_mag) * 0.5e-3;

                        /* Convert phase range (meters) to phase (cycles) using
                         * the carrier frequency for this signal.
                         *
                         * For GLONASS FDMA signals (L1 C/A, L1 P, L2 C/A, L2 P)
                         * the per-satellite carrier depends on the frequency
                         * slot n (-7..+13), which is read from the process-wide
                         * slot table populated by rtcm_obs_decode_1020(). If no
                         * 1020 message has been seen for this PRN yet, we fall
                         * back to the n=0 nominal (sigs[g].freq_hz).
                         */
                        double freq_hz = sigs[g].freq_hz;
                        if (sigs[g].is_glo_fdma) {
                                int n = rtcm_obs_get_glo_freq_slot(sat_prns[s]);
                                if (n != 0) {
                                        if (sigs[g].band == '1')
                                                freq_hz = 1602.0e6 + (double)n * 0.5625e6;
                                        else  /* band == '2' */
                                                freq_hz = 1246.0e6 + (double)n * 0.4375e6;
                                }
                        }
                        double wavelength = wavelength_for_freq(freq_hz);
                        double phase_cycles;
                        if (wavelength > 0.0) {
                                phase_cycles = phase_range_m / wavelength;
                        } else {
                                phase_cycles = NAN;  /* unknown carrier */
                        }

                        /* SNR in dB-Hz: DF408 is 10-bit unsigned, 0.25 dB-Hz per LSB. */
                        double snr_dbhz = (double)cnr * 0.25;

                        /* Lock time indicator: RINEX LLI is a single digit 0-7.
                         * RTCM DF407 has a non-linear mapping (see DF402 in rtcm.c).
                         * For the MVP we just store the raw value modulo 8.
                         */
                        unsigned int lli = lti & 0x7;

                        /* Fill the cell. */
                        struct rtcm_obs_cell *cell = &epoch->cells[cell_idx++];
                        cell->sat_prn = sat_prns[s];
                        cell->sig_code = sigs[g].attr;
                        cell->band = sigs[g].band;
                        cell->carrier_freq_hz = freq_hz;
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
