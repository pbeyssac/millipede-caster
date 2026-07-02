#!/usr/bin/env python3
"""
Test the RINEX on-the-fly generation endpoint.

Verifies that:
1. GET /api/v1/rinex without mountpoint returns 400.
2. GET /api/v1/rinex?mountpoint=NOPE returns 404.
3. After sending RTCM 1006 packets, GET /api/v1/rinex?mountpoint=C77
   returns 200 with a RINEX 3.04 header (even if no MSM7 obs are
   present, the header + EOF marker should be emitted).
4. The RINEX file contains the expected header markers.

This is the MVP test for the /api/v1/rinex endpoint. A full
end-to-end test with real MSM7 observations requires a synthetic
RTCM 1071/1094 packet generator, which is out of scope for the MVP.

Usage: python3 test-rinex.py
"""
import base64
import sys
import time
import urllib.request
import urllib.error

import testlib

HOST = ('::1', 2103)
USER = 'admin'
PASSWORD = '=adminpw...'

# RTCM 1006 packet (station position) — same as test-rtcm-freq.py
RTCM_1006 = b"\xd3\x00\x15\x3e\xe0\x00\x03\x89\xc8\x55\xac\xd7\x80\x71\x2a\x81\xc9\x8b\x20\x8b\x7f\x54\x00\x00\x7c\x4f\x32"


def auth_header():
    creds = base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()
    return {'Authorization': f'Basic {creds}'}


def api_get_raw(path, expect_status=200):
    """GET the endpoint and return (status, content_type, body_bytes)."""
    url = f'http://127.0.0.1:2103/adm{path}'
    req = urllib.request.Request(url, headers=auth_header())
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.headers.get('Content-Type', ''), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get('Content-Type', ''), e.read()


def main():
    err = 0

    # 1. Missing mountpoint -> 400
    print("[1] Missing mountpoint...", end=' ')
    status, ct, body = api_get_raw('/api/v1/rinex')
    if status != 400:
        print(f"FAIL (expected 400, got {status})")
        err += 1
    else:
        print("OK")

    # 2. Non-existent mountpoint -> 404
    print("[2] Non-existent mountpoint...", end=' ')
    status, ct, body = api_get_raw('/api/v1/rinex?mountpoint=NOPE')
    if status != 404:
        print(f"FAIL (expected 404, got {status})")
        err += 1
    else:
        print("OK")

    # 3. Send RTCM 1006 packets to populate the ring buffer
    print("[3] Sending RTCM 1006 packets to C77...", end=' ')
    src = testlib.SourceStream(HOST, 'C77', 'test1:testpw!', 200,
                               start_delay=1, packet_delay=0.01,
                               packet=RTCM_1006)
    src.start()
    time.sleep(2)
    print("OK")

    # 4. GET /api/v1/rinex?mountpoint=C77 -> 200 with RINEX header
    print("[4] Generate RINEX from C77...", end=' ')
    status, ct, body = api_get_raw('/api/v1/rinex?mountpoint=C77')
    if status != 200:
        print(f"FAIL (expected 200, got {status})")
        print(f"   body: {body[:200]}")
        err += 1
    else:
        text = body.decode('utf-8', errors='replace')
        # Validate RINEX 3.04 header markers
        must_contain = [
            '3.04',
            'OBSERVATION DATA',
            'RINEX VERSION / TYPE',
            'MARKER NAME',
            'END OF HEADER',
        ]
        missing = [m for m in must_contain if m not in text]
        if missing:
            print(f"FAIL (missing markers: {missing})")
            print(f"   body[:500]: {text[:500]}")
            err += 1
        else:
            # The MARKER NAME line should contain "C77" (uppercased mountpoint)
            if 'C77' not in text.split('\n')[3] if len(text.split('\n')) > 3 else True:
                # Be lenient — just check C77 appears somewhere in first 10 lines
                head = '\n'.join(text.split('\n')[:10])
                if 'C77' not in head:
                    print(f"FAIL (C77 not in marker name line)")
                    print(f"   head: {head}")
                    err += 1
                else:
                    print(f"OK ({len(body)} bytes, header valid)")
            else:
                print(f"OK ({len(body)} bytes, header valid)")

    src.stop()

    # 5. With time window that excludes all packets -> 404
    print("[5] Time window excludes all packets...", end=' ')
    # Use a far-future window
    status, ct, body = api_get_raw(
        '/api/v1/rinex?mountpoint=C77&from=2099-01-01T00:00:00Z&to=2099-01-01T01:00:00Z')
    if status != 404:
        print(f"FAIL (expected 404, got {status})")
        err += 1
    else:
        print("OK")

    print()
    if err:
        print(f"FAIL: {err} error(s)")
    else:
        print("PASS")
    sys.exit(err)


if __name__ == '__main__':
    main()
