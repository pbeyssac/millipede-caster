#ifndef __RINEX_H__
#define __RINEX_H__

#include <stddef.h>
#include <sys/time.h>

#include "mbuf.h"
#include "rtcm_obs.h"

/*
 * RINEX 3.04 Observation File Writer
 *
 * Generates a RINEX 3.04 observation file from a sequence of decoded
 * RTCM observation epochs. The output is built into a caller-provided
 * struct mbuf.
 *
 * Scope of this MVP:
 *   - RINEX 3.04 format (not 2.11, not 4.00)
 *   - GPS + Galileo observations only (G + E system markers)
 *   - Single signal per system in the header (L1C for GPS, E1B for Galileo)
 *     — multiple signals per satellite are emitted as additional obs
 *     columns but the header lists only the ones actually seen.
 *   - No navigation file (.nav) — PPK software can get ephemerides
 *     elsewhere (e.g. from IGS).
 *   - No compression — caller can gzip if needed.
 *
 * Reference: https://files.igs.org/pub/data/format/rinex304.pdf
 */

/*
 * Initialize a RINEX writer context.
 *
 * mountpoint: the NTRIP mountpoint name (used in the header as MARKER NAME)
 * station_id: RTCM reference station ID (DF003)
 * ecef_x/y/z: station ECEF coordinates (meters), or NaN if unknown
 *   (if NaN, the APPROX POSITION XYZ line is set to all zeros)
 *
 * Returns 0 on success, -1 on error.
 */
int rinex_writer_init(struct mbuf *out,
		      const char *mountpoint,
		      unsigned int station_id,
		      double ecef_x, double ecef_y, double ecef_z);

/*
 * Append one observation epoch to the RINEX output.
 *
 * Returns 0 on success, -1 on error.
 */
int rinex_writer_append_epoch(struct mbuf *out,
			      const struct rtcm_obs_epoch *epoch);

/*
 * Finalize the RINEX output (write the EOF marker).
 *
 * After this call, out->data contains the complete RINEX file.
 */
int rinex_writer_finalize(struct mbuf *out);

/*
 * High-level convenience function: build a complete RINEX file from
 * an array of RTCM packets.
 *
 * packets: array of RTCM packet pointers (each must be a valid RTCM
 *   packet — i.e. p->is_rtcm != 0)
 * npackets: number of packets
 * mountpoint: MARKER NAME for the RINEX header
 *
 * The function decodes 1005/1006 (position) and MSM7 (observations)
 * packets, skips all others, and writes the RINEX file into `out`.
 *
 * Returns 0 on success, -1 on error. On success, out->data is a
 * heap-allocated NUL-terminated string containing the RINEX file
 * (caller must free()).
 */
int rinex_build_from_packets(struct mbuf *out,
			     struct packet **packets, size_t npackets,
			     const char *mountpoint);

#endif /* __RINEX_H__ */
