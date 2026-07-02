#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mbuf.h"
#include "rinex.h"
#include "rtcm.h"        /* rtcm_get_type() */
#include "rtcm_obs.h"

/*
 * RINEX 3.04 Observation File Writer implementation.
 *
 * Output format reference: IGS RINEX 3.04 specification.
 * Each line is 80 columns max (RINEX legacy limit, though most
 * modern parsers accept longer lines; we stay within 80).
 */

/*
 * Format a double in RINEX's F14.3 style (14-char wide, 3 decimals).
 * Used for pseudorange and phase observations.
 */
static void fmt_f14_3(struct mbuf *out, double v) {
        if (isnan(v)) {
                mbuf_append(out, "              ", 14);
                return;
        }
        char buf[32];
        snprintf(buf, sizeof buf, "%14.3f", v);
        mbuf_append(out, buf, 14);
}

/*
 * Format SNR as a single digit 1-9 (RINEX signal strength indicator).
 * Mapping (RINEX 3.04 table):
 *   0: unknown or don't care
 *   1: SNR < 12 dB-Hz
 *   2: 12-17
 *   3: 18-23
 *   4: 24-29
 *   5: 30-35
 *   6: 36-41
 *   7: 42-47
 *   8: 48-53
 *   9: >= 54
 */
static char snr_to_ssi(double snr_dbhz) {
        if (isnan(snr_dbhz) || snr_dbhz < 12)
                return '0';
        int s = (int)(snr_dbhz / 6.0) + 1;
        if (s > 9) s = 9;
        /* Map: 12-17 -> '2', 18-23 -> '3', ..., 54+ -> '9' */
        /* The table is actually 1-9 with 6 dB-Hz bins starting at 12.
         * snr_dbhz in [12, 18) -> '2'
         *            [18, 24) -> '3'
         *            ...
         *            [54, inf) -> '9'
         */
        int bin = (int)((snr_dbhz - 12) / 6.0) + 2;
        if (bin > 9) bin = 9;
        if (bin < 1) bin = 1;
        (void)s;
        return (char)('0' + bin);
}

/*
 * Write the RINEX 3.04 header.
 *
 * The header is a fixed-format block of 60+ column lines, terminated
 * by "END OF HEADER".
 */
int rinex_writer_init(struct mbuf *out,
                      const char *mountpoint,
                      unsigned int station_id,
                      double ecef_x, double ecef_y, double ecef_z) {
        /* RINEX 3.04 header lines are 80 columns. The first 60 are
         * content, columns 61-80 are the label. We build the header
         * line by line. */

        /* Line 1: RINEX VERSION / TYPE.
         * File-type marker is "M (MIXED)" because the file may contain
         * observations from multiple constellations (GPS, GLONASS,
         * Galileo, BeiDou). RINEX 3.04 table A1 lists the alternatives:
         *   G (GPS)  R (GLONASS)  E (Galileo)  J (QZSS)
         *   C (BeiDou)  I (NavIC)  S (SBAS)    M (MIXED) */
        mbuf_puts(out, "     3.04           OBSERVATION DATA    M (MIXED)           RINEX VERSION / TYPE\n");

        /* Line 2: PGM / RUN BY / DATE */
        {
                time_t now = time(NULL);
                struct tm tm;
                gmtime_r(&now, &tm);
                char datebuf[32];
                strftime(datebuf, sizeof datebuf, "%Y%m%d %H%M%S UTC", &tm);
                char line[128];
                snprintf(line, sizeof line,
                         "MILLIPEDE-CASTER  %s                                  PGM / RUN BY / DATE\n",
                         datebuf);
                /* Pad to 80 if needed (snprintf left-aligns, but we may be short) */
                mbuf_puts(out, line);
        }

        /* Line 3: MARKER NAME (the mountpoint, uppercased, left-justified in cols 1-60) */
        {
                char marker[64] = {0};
                if (mountpoint) {
                        size_t i;
                        for (i = 0; i < 60 && mountpoint[i]; i++)
                                marker[i] = (char)toupper((unsigned char)mountpoint[i]);
                }
                char line[128];
                snprintf(line, sizeof line, "%-60.60sMARKER NAME\n", marker);
                mbuf_puts(out, line);
        }

        /* Line 4: MARKER TYPE */
        mbuf_puts(out, "  GEODETIC                                               MARKER TYPE\n");

        /* Line 5: OBSERVER / AGENCY */
        mbuf_puts(out, "MILLIPEDE         MILLIPEDE                            OBSERVER / AGENCY\n");

        /* Line 6: REC # / TYPE / VERS — leave blank (caster doesn't know) */
        mbuf_puts(out, "                                                            REC # / TYPE / VERS\n");

        /* Line 7: ANT # / TYPE — leave blank */
        mbuf_puts(out, "                                                            ANT # / TYPE\n");

        /* Line 8: APPROX POSITION XYZ (ECEF, meters, F14.4) */
        {
                double x = isnan(ecef_x) ? 0.0 : ecef_x;
                double y = isnan(ecef_y) ? 0.0 : ecef_y;
                double z = isnan(ecef_z) ? 0.0 : ecef_z;
                char line[128];
                snprintf(line, sizeof line,
                         "%14.4f%14.4f%14.4f                  APPROX POSITION XYZ\n",
                         x, y, z);
                mbuf_puts(out, line);
        }

        /* Line 9: ANTENNA: DELTA H/E/N — zeros (we don't know) */
        mbuf_puts(out, "         0.0000        0.0000        0.0000          ANTENNA: DELTA H/E/N\n");

        /* Line 10: SYS / # / OBS TYPES — one line per constellation we
         * support. For the MVP we declare a single signal per system
         * (3 obs types: C pseudorange, L phase, S SNR), chosen as the
         * most common signal of that constellation:
         *   G : L1 C/A    -> C1C L1C S1C
         *   R : L1 C/A    -> C1C L1C S1C  (GLONASS, FDMA slot adjusted at decode)
         *   E : E1B       -> C1B L1B S1B
         *   C : B1I       -> C2I L2I S2I  (BeiDou band 2 = B1I at 1561.098 MHz)
         *   J : L1 C/A    -> C1C L1C S1C  (QZSS, same signal codes as GPS)
         *   S : L1 C/A    -> C1C L1C S1C  (SBAS)
         * The RINEX 3.04 spec requires the SYS / # / OBS TYPES lines to
         * come in alphabetical system order (C, E, G, J, R, S). We emit
         * them in that order; declaring a system with no actual
         * observations in the file is allowed. */
        mbuf_puts(out, "C    3 C2I L2I S2I                                      SYS / # / OBS TYPES\n");
        mbuf_puts(out, "E    3 C1B L1B S1B                                      SYS / # / OBS TYPES\n");
        mbuf_puts(out, "G    3 C1C L1C S1C                                      SYS / # / OBS TYPES\n");
        mbuf_puts(out, "J    3 C1C L1C S1C                                      SYS / # / OBS TYPES\n");
        mbuf_puts(out, "R    3 C1C L1C S1C                                      SYS / # / OBS TYPES\n");
        mbuf_puts(out, "S    3 C1C L1C S1C                                      SYS / # / OBS TYPES\n");

        /* Line 11: INTERVAL — assume 1 second (MVP) */
        mbuf_puts(out, "     1.000                                                INTERVAL\n");

        /* Line 12: TIME OF FIRST OBS — placeholder. RINEX 3.04 allows the
         * time system to be "G" (GPS), "R" (GLONASS), "E" (Galileo),
         * "C" (BeiDou), "J" (QZSS), "I" (NavIC), or "M" (mixed). Since
         * the file may contain epochs from multiple constellations and
         * each MSM7 message only carries its own system's time, we mark
         * the file as "M" (mixed) and use the wall clock. Real PPK
         * software should reconcile the small inter-system offsets
         * (GPS↔Galileo ~19 ns, GPS↔BeiDou ~14 ns, etc.). */
        mbuf_puts(out, "  2026     7     2     0     0    0.0000000  MIX         TIME OF FIRST OBS\n");

        /* Line 13: END OF HEADER */
        mbuf_puts(out, "                                                            END OF HEADER\n");

        (void)station_id;
        return 0;
}

/*
 * Append one observation epoch.
 *
 * Format (per RINEX 3.04):
 *   - Epoch line: "> YYYY MM DD HH MM SS.SSSSSSS  N  sat1 sat2 ..."
 *     where N is the number of satellites observed, followed by N
 *     3-character satellite identifiers (e.g. "G01", "E12").
 *   - Then for each satellite, one or more observation lines (up to 5
 *     obs per line, each F14.3 + LLI + SSI).
 *
 * For the MVP, each satellite gets exactly 3 observations (C, L, S)
 * on a single line.
 */
int rinex_writer_append_epoch(struct mbuf *out,
                              const struct rtcm_obs_epoch *epoch) {
        if (epoch == NULL || epoch->ncells == 0)
                return 0;

        /* Build the epoch line. */
        struct tm tm;
        time_t t = epoch->epoch_time.tv_sec;
        gmtime_r(&t, &tm);

        /* Collect unique satellites (one per (sys, prn) pair) in epoch order.
         * All cells in a single MSM7 message share the same system
         * (epoch->sys), so we only need to dedup by PRN. */
        char sat_ids[RTCM_OBS_MAX_CELLS][5];
        unsigned int nsats = 0;
        for (unsigned int i = 0; i < epoch->ncells; i++) {
                const struct rtcm_obs_cell *c = &epoch->cells[i];
                char id[5];
                id[0] = (char)epoch->sys;
                snprintf(id + 1, sizeof id - 1, "%02d", c->sat_prn);

                /* Check if we've already seen this sat. */
                int found = 0;
                for (unsigned int j = 0; j < nsats; j++) {
                        if (memcmp(sat_ids[j], id, 3) == 0) { found = 1; break; }
                }
                if (!found && nsats < RTCM_OBS_MAX_CELLS) {
                        memcpy(sat_ids[nsats], id, 3);
                        sat_ids[nsats][3] = '\0';
                        nsats++;
                }
        }

        /* "> " epoch line: the ">" is in col 1, then year (4 cols),
         * month, day, hour, min (2 cols each), sec (10 cols with .sssssss),
         * then 4-char epoch flag, then nsats (3 cols). */
        char epoch_line[256];
        snprintf(epoch_line, sizeof epoch_line,
                 "> %4d %2d %2d %2d %2d %10.7f  %u%3u",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min,
                 (double)tm.tm_sec + epoch->epoch_time.tv_usec / 1e6,
                 0u, nsats);
        mbuf_puts(out, epoch_line);
        /* Append satellite IDs (3 chars each, up to 12 per line, then wrap). */
        for (unsigned int i = 0; i < nsats; i++) {
                if (i > 0 && i % 12 == 0)
                        mbuf_puts(out, "\n");
                mbuf_puts(out, " ");
                mbuf_append(out, sat_ids[i], 3);
        }
        mbuf_puts(out, "\n");

        /* For each satellite, emit one observation line with 3 obs:
         *   C (pseudorange), L (phase), S (SNR).
         * Each obs is F14.3 + LLI (1 char) + SSI (1 char) = 16 chars.
         * 3 obs = 48 chars + 1 leading space = 49. */
        for (unsigned int i = 0; i < nsats; i++) {
                /* Find the first cell matching this sat_id (MVP: ignore
                 * multi-signal — just take the first). */
                const struct rtcm_obs_cell *cell = NULL;
                for (unsigned int j = 0; j < epoch->ncells; j++) {
                        char id[5];
                        id[0] = (char)epoch->sys;
                        snprintf(id + 1, sizeof id - 1, "%02d", epoch->cells[j].sat_prn);
                        if (memcmp(sat_ids[i], id, 3) == 0) {
                                cell = &epoch->cells[j];
                                break;
                        }
                }
                if (cell == NULL) {
                        /* Shouldn't happen, but be defensive. */
                        mbuf_puts(out, "              0              0              0\n");
                        continue;
                }

                /* Pseudorange (C), Phase (L), SNR (S) */
                mbuf_puts(out, " ");
                fmt_f14_3(out, cell->pseudorange);
                /* LLI: single digit, ' ' if 0 */
                char lli = (cell->lock_time & 0x7) ? ('0' + (cell->lock_time & 0x7)) : ' ';
                char ssi = snr_to_ssi(cell->snr);
                char lli_ssi[3] = { lli, ssi, '\0' };
                mbuf_puts(out, lli_ssi);

                mbuf_puts(out, " ");
                fmt_f14_3(out, cell->phase);
                mbuf_puts(out, "  ");  /* LLI+SSI for phase */

                mbuf_puts(out, " ");
                fmt_f14_3(out, cell->snr);
                mbuf_puts(out, "  ");  /* LLI+SSI for SNR */

                mbuf_puts(out, "\n");
        }

        return 0;
}

int rinex_writer_finalize(struct mbuf *out) {
        /* RINEX files end with a blank line (some parsers require it). */
        mbuf_puts(out, "\n");
        return 0;
}

/*
 * High-level convenience: build a complete RINEX file from an array
 * of RTCM packets.
 */
int rinex_build_from_packets(struct mbuf *out,
                             struct packet **packets, size_t npackets,
                             const char *mountpoint) {
        if (out == NULL || packets == NULL)
                return -1;

        /* Pass 1: find the latest 1005/1006 to get the station position,
         * and feed every RTCM 1020 (GLONASS ephemeris) into the slot
         * table so that subsequent MSM7 GLONASS decoding can resolve
         * FDMA carriers per satellite. */
        double ecef_x = NAN, ecef_y = NAN, ecef_z = NAN;
        unsigned int station_id = 0;
        for (size_t i = 0; i < npackets; i++) {
                struct packet *p = packets[i];
                if (p == NULL || !p->is_rtcm)
                        continue;
                unsigned short type = rtcm_get_type(p);
                if (type == 1005 || type == 1006) {
                        double x, y, z;
                        if (rtcm_obs_decode_1005(p, &x, &y, &z) == 0) {
                                ecef_x = x;
                                ecef_y = y;
                                ecef_z = z;
                        }
                } else if (type == 1020) {
                        /* Populate GLONASS FDMA slot table; ignore errors. */
                        (void)rtcm_obs_decode_1020(p, NULL, NULL);
                }
        }

        /* Write the header. */
        if (rinex_writer_init(out, mountpoint, station_id,
                              ecef_x, ecef_y, ecef_z) != 0)
                return -1;

        /* Pass 2: decode and emit each MSM7 epoch.
         *
         * MSM7 message types span 1071-1137 (last digit 7), covering
         * GPS (1077), GLONASS (1087), Galileo (1097), QZSS (1107),
         * SBAS (1117), BeiDou (1127), NavIC (1137). rtcm_obs_decode_msm7
         * will reject any system it can't handle. */
        for (size_t i = 0; i < npackets; i++) {
                struct packet *p = packets[i];
                if (p == NULL || !p->is_rtcm)
                        continue;
                unsigned short type = rtcm_get_type(p);
                if (type < 1071 || type > 1137 || (type % 10) != 7)
                        continue;

                struct rtcm_obs_epoch epoch;
                if (rtcm_obs_decode_msm7(p, &epoch) == 0) {
                        rinex_writer_append_epoch(out, &epoch);
                }
        }

        rinex_writer_finalize(out);
        return 0;
}
