# RINEX / PPK on-the-fly generation — Roadmap

## Goal

Provide an HTTP endpoint that generates RINEX observation files on demand
from the caster's recent RTCM stream cache, enabling Post-Processed Kinematic
(PPK) workflows without requiring the rover to be online during the survey.

```
GET /api/v1/rinex?mountpoint=BASE01&from=2026-07-01T10:00:00Z&to=2026-07-01T11:30:00Z
```

Returns a `Content-Type: application/gnss-rinex` (or `text/plain`) body
containing a RINEX 3.x observation file for the requested time window.

## Why

Today, PPK users have two options:

1. **Record at the base**: requires SSH access to the receiver, manual
   RINEX conversion with `rtkconv` or `teqc`, then file transfer. Slow,
   error-prone, and not feasible for shared base stations.
2. **Pull RTCM from the caster and convert locally**: works, but the
   rover must be online during the entire survey window and the user
   must run their own conversion stack.

A server-side RINEX endpoint collapses both paths into a single HTTP
GET: any PPK software (RTKLIB, GrafNav, Emlid Studio) can fetch a RINEX
file directly from the caster URL.

## Design

### Architecture

```
                +-----------------------+
   RTCM in ---->|  rtcm_ringbuffer      |  (existing: rtcm_cache + rtcm_freq)
                |  (per-mountpoint,     |
                |   sliding window)     |
                +-----------+-----------+
                            |
                            v
                +-----------------------+
   GET /rinex ->|  rinex_builder        |  (new module: caster/rinex.c)
                |  - select window      |
                |  - decode RTCM 1005/  |
                |    107x/108x/109x     |
                |  - emit RINEX 3.04    |
                |    obs + nav records  |
                +-----------+-----------+
                            |
                            v
                +-----------------------+
                |  HTTP response body   |  (streamed, chunked)
                +-----------------------+
```

### Storage: extend rtcm_ringbuffer

The existing `rtcm_freq` tracker keeps per-second bucket counts but
discards packet contents. We need a new ring buffer that keeps the raw
RTCM packets themselves for the last N minutes (default: 30 min, capped
at e.g. 64 MiB per mountpoint to bound memory).

```c
struct rtcm_ringbuffer {
    struct packet *packets[RINGBUFFER_CAPACITY];
    struct timeval timestamps[RINGBUFFER_CAPACITY];
    int head, tail;
    P_MUTEX_T lock;
};
```

Each `livesource` gets one `rtcm_ringbuffer`. The packet destructor
reuses `packet_free()` from `caster/packet.c`.

### Endpoint

```
GET /api/v1/rinex?mountpoint=<name>&from=<iso8601>&to=<iso8601>&format=<rinex3|rinex4>
```

Query parameters:

| Parameter    | Required | Default     | Description                                      |
|--------------|----------|-------------|--------------------------------------------------|
| `mountpoint` | yes      | —           | Source mountpoint name                           |
| `from`       | yes      | —           | ISO8601 start time (UTC)                         |
| `to`         | yes      | —           | ISO8601 end time (UTC)                           |
| `format`     | no       | `rinex3`    | Output format: `rinex3` (3.04) or `rinex4` (4.00)|
| `interval`   | no       | `1`         | Sampling interval in seconds (decimate if > 1)   |
| `systems`    | no       | `GREJ`      | Constellations to include (e.g. `G`, `GE`)       |

### Response

- `200 OK` with `Content-Type: application/octet-stream` and
  `Content-Disposition: attachment; filename="<mountpoint>-<from>-<to>.obs"`
- `404 Not Found` if the mountpoint doesn't exist or has no data in
  the requested window
- `400 Bad Request` if `from` >= `to` or the time range exceeds the
  ring buffer's retention
- `413 Payload Too Large` if the requested window would exceed a
  configurable max size (e.g. 256 MiB)

The body is streamed in HTTP/1.1 chunked encoding to avoid buffering
the entire file in memory.

### RINEX generation

Reuse an existing C library where possible:

- **[RTKLIB](https://www.rtklib.com/)** has a permissive license and
  its `rinex.c` module can be extracted with modest refactoring. It
  handles RTCM → RINEX 3.x conversion including MSM7 message decoding
  for GPS / GLONASS / Galileo / BeiDou / QZSS / NavIC / SBAS.
- **[BNC](https://igs.bkg.bund.de/nindex_igs_ntrip.htm)** (BKG NTRIP
  Client) also has a mature RINEX writer but is GPL — incompatible
  with millipede-caster's MIT license.

If RTKLIB extraction proves too invasive, a minimal in-house RINEX 3.04
writer for GPS+Galileo+GLONASS MSM7 messages is ~800 lines of C and
covers ~95% of real-world bases.

### Configuration

New YAML keys:

```yaml
rinex:
  ringbuffer_minutes: 30        # how long to retain RTCM packets
  ringbuffer_max_mb: 64         # cap per-mountpoint memory
  max_window_hours: 24          # cap on |to - from|
  default_interval: 1           # default sampling interval
  enable: true                  # set false to disable the endpoint entirely
```

When `ringbuffer_max_mb` is exceeded, oldest packets are dropped first
and a warning is logged.

### Auth & rate limiting

- Same auth as other `/api/v1/` endpoints (Basic / Bearer / `?token=`).
- Additional per-IP rate limit: 1 concurrent RINEX request per IP,
  configurable via `rinex.max_concurrent_per_ip` (default 1).
- A `Retry-After` header is returned with HTTP 429 if the limit is hit.

### Threading

The RINEX builder runs in the worker thread pool (via
`joblist_append_ntrip_unlocked_content`), same as the existing JSON
API. For large windows, the worker thread is blocked for the duration
of the conversion — this is acceptable because the worker pool size is
configurable and PPK downloads are infrequent.

For very large windows (> 1 hour at 1 Hz), consider forking a child
process and returning HTTP 202 with a job ID, then polling
`/api/v1/rinex/status?job=<id>`. This is a v2 concern.

## Estimated effort

| Phase                                | Effort  |
|--------------------------------------|---------|
| rtcm_ringbuffer module + tests       | 1 day   |
| RINEX 3.04 writer (G+E MSM7)         | 2 days  |
| HTTP endpoint + streaming            | 0.5 day |
| Config + docs                        | 0.5 day |
| Integration tests (RTCM → RINEX)     | 1 day   |
| **Total**                            | **5 days** |

Adding BeiDou + GLONASS + SBAS adds ~2 days. RINEX 4.00 format adds
~1 day (mostly header changes).

## Open questions

1. **Should the endpoint also emit navigation files** (RINEX `.nav`)?
   RTCM messages 1019, 1020, 1043, 1044, 1045, 1046 contain ephemerides
   that can be converted to RINEX nav. Useful for older PPK software
   that doesn't read RTCM directly. Default: yes, emit a `.zip` with
   `.obs` + `.nav` per constellation.

2. **Should we cache generated RINEX files** for repeated requests in
   the same window? Likely yes — a small LRU cache keyed by
   `(mountpoint, from, to, format, interval)` with a 256 MiB cap. TTL
   = ring buffer retention.

3. **How to handle sources that are no longer live**? The ring buffer
   is attached to the livesource. When the source disconnects, we
   could either (a) drop the ring buffer immediately (simple), or (b)
   keep it for `ringbuffer_minutes` after disconnect so users can still
   pull RINEX for the last session (better UX, costs memory). Default:
   (b) with a global cap of 1 GiB across all disconnected sources.

## Non-goals

- Real-time kinematic (RTK) corrections — already handled by the
  existing caster functionality.
- RINEX for rover-side data — rovers should record their own raw
  observations; the caster only has base-side RTCM.
- Conversion of proprietary formats (u-blox UBX, NovAtel OEM, etc.) —
  out of scope; users should use `convbin` for that.

## Alternatives considered

- **Sidecar process**: run a separate Python/Go service that pulls
  RTCM from the caster and exposes RINEX. Simpler to develop but adds
  an extra moving part, doubles the RTCM parsing, and breaks the
  "single binary" deployment story.
- **On-disk recording**: write RTCM to daily `.rtcm` files on disk,
  then convert on demand. More robust to caster restarts but requires
  disk I/O and file management. Could be a future mode for users who
  want longer retention than RAM allows.
