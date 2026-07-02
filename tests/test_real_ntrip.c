/*
 * Real-data integration test for the RTCM MSM7 decoder.
 *
 * Reads one or more RTCM3 binary frame files (output of ntrip_capture.py,
 * one file per message type, each file holding one or more concatenated
 * frames), feeds them through rtcm_obs_decode_msm7() and
 * rtcm_obs_decode_1020(), and prints a per-system summary.
 *
 * Compile:
 *   gcc -Wall -D_XOPEN_SOURCE -D_GNU_SOURCE -Icaster \
 *       caster/rtcm_obs.c caster/bitfield.c \
 *       tests/test_real_ntrip.c -lm -o /tmp/test_real_ntrip
 *
 * Usage:
 *   /tmp/test_real_ntrip <msg_dir> [msg_dir2 ...]
 *
 * Where <msg_dir> is the directory produced by ntrip_capture.py
 * (e.g. /home/z/my-project/download/rtcm_BangorCH_msgs/).
 *
 * Each file in the dir is named "<type>.rtcm" (e.g. 1077.rtcm, 1020.rtcm,
 * 1006.rtcm). Multiple concatenated frames per file are OK; the parser
 * walks them via the 0xD3 + 14-bit length framing.
 */
#include <dirent.h>
#include <math.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "bitfield.h"
#include "mbuf.h"
#include "packet.h"
#include "rtcm.h"
#include "rinex.h"
#include "rtcm_obs.h"

/* ---- Minimal packet helpers (same as test_msm7_multi.c) ------------------ */

static struct packet *make_packet_from_frame(unsigned char *frame, size_t frame_len) {
        /* struct packet uses a flexible array member for .data */
        struct packet *p = calloc(1, sizeof(*p) + frame_len);
        if (!p) { perror("calloc"); return NULL; }
        p->datalen = frame_len;
        p->is_rtcm = 1;
        atomic_init(&p->refcnt, 1);
        memcpy(p->data, frame, frame_len);
        return p;
}

/* ---- RTCM3 frame walker: invoke cb for each frame in a buffer ----------- */

/*
 * Walk the buffer and call cb(type, payload, payload_len, frame, frame_len,
 * userdata) for each complete RTCM3 frame. Returns the number of frames.
 */
typedef void (*frame_cb)(unsigned short type,
                         const unsigned char *payload, size_t payload_len,
                         const unsigned char *frame, size_t frame_len,
                         void *ud);

static size_t walk_rtcm_frames(const unsigned char *buf, size_t len,
                               frame_cb cb, void *ud) {
        size_t i = 0, count = 0;
        while (i + 3 <= len) {
                if (buf[i] != 0xD3) { i++; continue; }
                size_t length = ((buf[i+1] & 0x03) << 8) | buf[i+2];
                size_t frame_end = i + 3 + length + 3;     /* payload + CRC */
                if (frame_end > len) break;
                const unsigned char *payload = buf + i + 3;
                unsigned short type = 0;
                if (length >= 2)
                        type = (unsigned short)(((payload[0] << 4) & 0xFF0) |
                                                ((payload[1] >> 4) & 0x0F));
                cb(type, payload, length, buf + i, frame_end - i, ud);
                count++;
                i = frame_end;
        }
        return count;
}

/* ---- Per-system accumulators -------------------------------------------- */

struct sys_stats {
        unsigned int n_msgs;
        unsigned int n_cells;
        unsigned int n_sats;        /* unique PRNs seen */
        unsigned char prns_seen[64];
        double min_freq_mhz;
        double max_freq_mhz;
        double sample_pr_mins[5];   /* first 5 sample PRs */
        double sample_phases[5];
        unsigned int n_samples;
};

static struct sys_stats stats[256];   /* indexed by system char */

static void mark_prn(struct sys_stats *s, unsigned char prn) {
        for (unsigned i = 0; i < s->n_sats; i++)
                if (s->prns_seen[i] == prn) return;
        if (s->n_sats < 64) s->prns_seen[s->n_sats++] = prn;
}

static void init_stats(void) {
        for (int i = 0; i < 256; i++) {
                stats[i].min_freq_mhz = 1e9;
                stats[i].max_freq_mhz = 0;
        }
}

/* GLONASS slot table dump */
static void dump_glo_slots(void) {
        printf("  GLONASS FDMA slot table (PRN -> n):\n    ");
        int n_known = 0;
        for (unsigned p = 1; p <= 24; p++) {
                int n = rtcm_obs_get_glo_freq_slot(p);
                if (n != 0) {
                        printf(" R%u=%d ", p, n);
                        n_known++;
                }
        }
        if (n_known == 0) printf("(empty — no 1020 seen yet)");
        printf("\n  %d slots known\n", n_known);
}

/* ---- Frame callback ----------------------------------------------------- */

struct cb_state {
        const char *filename;
        unsigned int n_frames;
        unsigned int n_decoded_ok;
        unsigned int n_decoded_fail;
};

static void on_frame(unsigned short type,
                     const unsigned char *payload, size_t payload_len,
                     const unsigned char *frame, size_t frame_len,
                     void *ud) {
        struct cb_state *st = (struct cb_state *)ud;
        (void)payload; (void)payload_len;
        st->n_frames++;

        /* Build a packet struct for the decoder */
        struct packet *p = make_packet_from_frame((unsigned char *)frame, frame_len);
        if (!p) return;

        if (type == 1020) {
                unsigned prn; int n;
                if (rtcm_obs_decode_1020(p, &prn, &n) == 0) {
                        st->n_decoded_ok++;
                        if (st->filename)  /* only print on first pass */
                                printf("  [1020] GLONASS PRN=%u freq_slot_n=%+d -> L1=%.4f MHz\n",
                                       prn, n, 1602.0 + n * 0.5625);
                } else {
                        st->n_decoded_fail++;
                }
        } else if (type >= 1071 && type <= 1137 && (type % 10) == 7) {
                struct rtcm_obs_epoch ep;
                if (rtcm_obs_decode_msm7(p, &ep) == 0) {
                        st->n_decoded_ok++;
                        char sysc = (char)ep.sys;
                        struct sys_stats *s = &stats[(unsigned char)sysc];
                        s->n_msgs++;
                        for (unsigned i = 0; i < ep.ncells; i++) {
                                struct rtcm_obs_cell *c = &ep.cells[i];
                                s->n_cells++;
                                mark_prn(s, c->sat_prn);
                                double f = c->carrier_freq_hz / 1e6;
                                if (f < s->min_freq_mhz) s->min_freq_mhz = f;
                                if (f > s->max_freq_mhz) s->max_freq_mhz = f;
                                if (s->n_samples < 5) {
                                        s->sample_pr_mins[s->n_samples] = c->pseudorange;
                                        s->sample_phases[s->n_samples] = c->phase;
                                        s->n_samples++;
                                }
                        }
                } else {
                        st->n_decoded_fail++;
                        if (st->filename)
                                fprintf(stderr, "  WARN: type %u decode failed (%s)\n",
                                        type, st->filename);
                }
        }

        free(p);
}

/* ---- File / directory walker -------------------------------------------- */

static int ends_with(const char *s, const char *suf) {
        size_t ls = strlen(s), lf = strlen(suf);
        return ls >= lf && strcmp(s + ls - lf, suf) == 0;
}

static void process_file(const char *path) {
        FILE *f = fopen(path, "rb");
        if (!f) { perror(path); return; }
        struct stat sb;
        if (stat(path, &sb) != 0) { fclose(f); return; }
        size_t sz = sb.st_size;
        unsigned char *buf = malloc(sz);
        if (!buf) { fclose(f); return; }
        size_t got = fread(buf, 1, sz, f);
        fclose(f);
        if (got != sz) { free(buf); return; }

        struct cb_state st = { path, 0, 0, 0 };
        size_t n = walk_rtcm_frames(buf, got, on_frame, &st);
        if (n > 0) {
                printf("  %-40s %5zu frames, %u ok, %u fail\n",
                       path, n, st.n_decoded_ok, st.n_decoded_fail);
        }
        free(buf);
}

static void process_dir(const char *dir) {
        DIR *d = opendir(dir);
        if (!d) { perror(dir); return; }
        struct dirent *de;
        char path[1024];
        while ((de = readdir(d)) != NULL) {
                if (!ends_with(de->d_name, ".rtcm")) continue;
                snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
                process_file(path);
        }
        closedir(d);
}

/* ---- Main --------------------------------------------------------------- */

int main(int argc, char **argv) {
        if (argc < 2) {
                fprintf(stderr,
                        "Usage: %s <msg_dir> [msg_dir2 ...]\n", argv[0]);
                return 1;
        }

        init_stats();

        printf("=== Pass 1: process 1020 first to populate GLONASS slot table ===\n");
        for (int a = 1; a < argc; a++) {
                char path[1024];
                snprintf(path, sizeof path, "%s/1020.rtcm", argv[a]);
                process_file(path);
        }
        dump_glo_slots();

        printf("\n=== Pass 2: process all MSM7 files ===\n");
        for (int a = 1; a < argc; a++)
                process_dir(argv[a]);

        printf("\n=== Per-system summary ===\n");
        const char *sysnames[] = { "G:GPS", "R:GLONASS", "E:Galileo",
                                   "J:QZSS", "S:SBAS", "C:BeiDou", "I:NavIC" };
        for (int i = 0; i < 7; i++) {
                char sc = sysnames[i][0];
                struct sys_stats *s = &stats[(unsigned char)sc];
                if (s->n_msgs == 0) continue;
                printf("  %s  msgs=%u  cells=%u  unique_sats=%u  freq=[%.3f, %.3f] MHz\n",
                       sysnames[i], s->n_msgs, s->n_cells, s->n_sats,
                       s->min_freq_mhz, s->max_freq_mhz);
                printf("    sats seen:");
                for (unsigned j = 0; j < s->n_sats; j++)
                        printf(" %c%02u", sc, s->prns_seen[j]);
                printf("\n");
                printf("    first 5 cells (PR m, phase cyc):\n");
                for (unsigned j = 0; j < s->n_samples; j++)
                        printf("      PR=%14.3f   phase=%14.3f\n",
                               s->sample_pr_mins[j], s->sample_phases[j]);
        }

        /* Validate: GLONASS frequencies should span multiple FDMA slots */
        struct sys_stats *glo = &stats[(unsigned char)'R'];
        if (glo->n_msgs > 0) {
                printf("\n=== GLONASS FDMA validation ===\n");
                int n_known = 0;
                for (unsigned p = 1; p <= 24; p++)
                        if (rtcm_obs_get_glo_freq_slot(p) != 0) n_known++;
                if (n_known == 0) {
                        printf("  WARN: no 1020 frames decoded, cannot validate slot resolution\n");
                } else {
                        double spread = glo->max_freq_mhz - glo->min_freq_mhz;
                        printf("  GLONASS carrier freq spread: %.4f MHz (min=%.3f, max=%.3f)\n",
                               spread, glo->min_freq_mhz, glo->max_freq_mhz);
                        if (spread > 0.5) {
                                printf("  OK: spread > 0.5 MHz confirms multiple FDMA slots are resolved\n");
                        } else if (spread < 0.001 && n_known > 0) {
                                printf("  WARN: spread == 0 suggests slot table not applied\n");
                        } else {
                                printf("  OK: spread looks reasonable\n");
                        }
                }
        }

        /* Pass 3: build a complete RINEX file from all captured frames. */
        printf("\n=== Pass 3: RINEX generation from real RTCM stream ===\n");
        size_t total_pkts = 0;
        struct packet **pkts = calloc(8192, sizeof(*pkts));
        if (!pkts) { perror("calloc"); return 1; }
        for (int a = 1; a < argc; a++) {
                DIR *d = opendir(argv[a]);
                if (!d) continue;
                struct dirent *de;
                char path[1024];
                while ((de = readdir(d)) != NULL && total_pkts < 8192) {
                        if (!ends_with(de->d_name, ".rtcm")) continue;
                        /* skip the _all.rtcm dumps; we already process one
                         * frame per type from the per-type .rtcm files. */
                        if (strstr(de->d_name, "_all.rtcm")) continue;
                        snprintf(path, sizeof path, "%s/%s", argv[a], de->d_name);
                        FILE *f = fopen(path, "rb");
                        if (!f) continue;
                        struct stat sb;
                        if (stat(path, &sb) != 0) { fclose(f); continue; }
                        size_t sz = sb.st_size;
                        unsigned char *buf = malloc(sz);
                        if (!buf) { fclose(f); continue; }
                        size_t got = fread(buf, 1, sz, f);
                        fclose(f);
                        if (got != sz) { free(buf); continue; }
                        /* Extract the first frame from the file */
                        size_t i = 0;
                        while (i + 3 <= got) {
                                if (buf[i] != 0xD3) { i++; continue; }
                                size_t length = ((buf[i+1] & 0x03) << 8) | buf[i+2];
                                size_t frame_end = i + 3 + length + 3;
                                if (frame_end > got) break;
                                pkts[total_pkts] = make_packet_from_frame(buf + i, frame_end - i);
                                if (pkts[total_pkts]) total_pkts++;
                                break;
                        }
                        free(buf);
                }
                closedir(d);
        }
        printf("  loaded %zu packets\n", total_pkts);

        struct mbuf out;
        if (mbuf_init(&out, 65536) < 0) { perror("mbuf_init"); return 1; }
        int rc = rinex_build_from_packets(&out, (struct packet **)pkts, total_pkts, "BangorCH");
        if (rc != 0) {
                printf("  FAIL: rinex_build_from_packets returned %d\n", rc);
        } else {
                const char *rinex_path = "/home/z/my-project/download/rtcm_BangorCH_rinex.obs";
                FILE *f = fopen(rinex_path, "w");
                if (f) {
                        fwrite(out.data, 1, out.len, f);
                        fclose(f);
                        printf("  wrote %zu bytes -> %s\n", out.len, rinex_path);
                        /* Print first 20 lines for visual inspection */
                        printf("\n  --- RINEX header (first 20 lines) ---\n");
                        int line = 0;
                        for (size_t i = 0; i < out.len && line < 20; i++) {
                                if (out.data[i] == '\n') { line++; putchar('\n'); }
                                else putchar(out.data[i]);
                        }
                }
        }
        mbuf_free(&out);
        for (size_t i = 0; i < total_pkts; i++) free(pkts[i]);
        free(pkts);

        return 0;
}
