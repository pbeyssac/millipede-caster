#!/usr/bin/env python3
"""
Test the RTCM frequency tracker API endpoint.

Verifies that:
1. The /api/v1/rtcm/frequencies endpoint returns 200 with valid JSON.
2. After sending RTCM packets to a mountpoint, the tracker reports
   the expected type with a positive rate.
3. The mountpoint filter (?mountpoint=X) works.
4. The mountpoint filter for a non-existent mountpoint returns {}.

Usage: python3 test-rtcm-freq.py
"""
import base64
import json
import sys
import time
import urllib.request
import urllib.parse

import testlib

HOST = ('::1', 2103)
USER = 'admin'
PASSWORD = '=adminpw...'

# RTCM 1006 packet (station position) — same as test-rtcm.py
RTCM_1006 = b"\xd3\x00\x15\x3e\xe0\x00\x03\x89\xc8\x55\xac\xd7\x80\x71\x2a\x81\xc9\x8b\x20\x8b\x7f\x54\x00\x00\x7c\x4f\x32"


def auth_header():
    creds = base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()
    return {'Authorization': f'Basic {creds}'}


def api_get(path):
    url = f'http://127.0.0.1:2103/adm{path}'
    req = urllib.request.Request(url, headers=auth_header())
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, json.loads(r.read().decode())


def main():
    err = 0

    # 1. Empty tracker (before any RTCM traffic)
    print("[1] Empty tracker...", end=' ')
    status, data = api_get('/api/v1/rtcm/frequencies')
    if status != 200 or not isinstance(data, dict):
        print("FAIL")
        print(f"   expected 200 + dict, got {status} + {type(data).__name__}")
        err += 1
    else:
        print("OK")

    # 2. Send some RTCM packets to C77
    print("[2] Sending RTCM 1006 packets to C77...", end=' ')
    src = testlib.SourceStream(HOST, 'C77', 'test1:testpw!', 500,
                               start_delay=1, packet_delay=0.01,
                               packet=RTCM_1006)
    src.start()
    time.sleep(2)  # let packets flow
    print("OK")

    # 3. Query the tracker — should show C77 with type 1006
    print("[3] Tracker after RTCM traffic...", end=' ')
    status, data = api_get('/api/v1/rtcm/frequencies')
    if status != 200:
        print(f"FAIL (HTTP {status})")
        err += 1
    elif 'C77' not in data:
        print(f"FAIL (no C77 in {list(data.keys())})")
        err += 1
    elif '1006' not in data['C77']:
        print(f"FAIL (no 1006 in {list(data['C77'].keys())})")
        err += 1
    else:
        info = data['C77']['1006']
        if info['total'] < 10:
            print(f"FAIL (total={info['total']} < 10)")
            err += 1
        elif info['rate_hz'] <= 0:
            print(f"FAIL (rate={info['rate_hz']} <= 0)")
            err += 1
        else:
            print(f"OK (total={info['total']}, rate={info['rate_hz']:.2f} Hz)")

    src.stop()

    # 4. Test the mountpoint filter
    print("[4] Filter by mountpoint=C77...", end=' ')
    status, data = api_get('/api/v1/rtcm/frequencies?mountpoint=C77')
    if status != 200:
        print(f"FAIL (HTTP {status})")
        err += 1
    elif '1006' not in data:
        print(f"FAIL (no 1006 in {list(data.keys())})")
        err += 1
    else:
        print("OK")

    # 5. Filter by non-existent mountpoint
    print("[5] Filter by non-existent mountpoint...", end=' ')
    status, data = api_get('/api/v1/rtcm/frequencies?mountpoint=NOPE')
    if status != 200:
        print(f"FAIL (HTTP {status})")
        err += 1
    elif data != {}:
        print(f"FAIL (expected {{}}, got {data})")
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
