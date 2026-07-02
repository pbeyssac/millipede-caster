#!/usr/bin/env python3
"""
Test the RTCM ring buffer API endpoint.

Verifies that:
1. The /api/v1/rtcm/ringbuffer endpoint returns 200 with valid JSON.
2. After sending RTCM packets to a mountpoint, the ring buffer reports
   the expected packet count, byte count, and timestamps.
3. The mountpoint filter (?mountpoint=X) works.
4. The mountpoint filter for a non-existent mountpoint returns {}.
5. No packets are evicted under normal conditions (within the retention
   window and well below the memory cap).

This is the MVP test for the rtcm_ringbuffer module. A follow-up test
will exercise rtcm_ringbuffer_extract_range() via the future
GET /api/v1/rinex endpoint.

Usage: python3 test-rtcm-ringbuffer.py
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

# RTCM 1006 packet (station position) — same as test-rtcm-freq.py
RTCM_1006 = b"\xd3\x00\x15\x3e\xe0\x00\x03\x89\xc8\x55\xac\xd7\x80\x71\x2a\x81\xc9\x8b\x20\x8b\x7f\x54\x00\x00\x7c\x4f\x32"
RTCM_1006_LEN = len(RTCM_1006)  # 26 bytes


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
    print("[1] Empty ring buffer...", end=' ')
    status, data = api_get('/api/v1/rtcm/ringbuffer')
    if status != 200 or not isinstance(data, dict):
        print("FAIL")
        print(f"   expected 200 + dict, got {status} + {type(data).__name__}")
        err += 1
    elif data != {}:
        print(f"FAIL (expected {{}}, got {data})")
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

    # 3. Query the ring buffer — should show C77 with packet count > 0
    print("[3] Ring buffer after RTCM traffic...", end=' ')
    status, data = api_get('/api/v1/rtcm/ringbuffer')
    if status != 200:
        print(f"FAIL (HTTP {status})")
        err += 1
    elif 'C77' not in data:
        print(f"FAIL (no C77 in {list(data.keys())})")
        err += 1
    else:
        info = data['C77']
        # Validate the per-mountpoint JSON shape
        required_keys = {'packets', 'bytes', 'capacity_slots',
                         'first_seen', 'last_seen',
                         'total_packets', 'evicted_packets'}
        missing = required_keys - set(info.keys())
        if missing:
            print(f"FAIL (missing keys: {missing})")
            err += 1
        elif info['packets'] < 10:
            print(f"FAIL (packets={info['packets']} < 10)")
            err += 1
        elif info['bytes'] < info['packets'] * RTCM_1006_LEN:
            print(f"FAIL (bytes={info['bytes']} < {info['packets']}*{RTCM_1006_LEN})")
            err += 1
        elif info['total_packets'] < info['packets']:
            print(f"FAIL (total_packets={info['total_packets']} < packets={info['packets']})")
            err += 1
        elif info['evicted_packets'] != 0:
            print(f"FAIL (evicted_packets={info['evicted_packets']} != 0)")
            err += 1
        elif not info['first_seen'] or not info['last_seen']:
            print(f"FAIL (empty timestamps: first={info['first_seen']!r}, last={info['last_seen']!r})")
            err += 1
        else:
            print(f"OK (packets={info['packets']}, bytes={info['bytes']}, "
                  f"total={info['total_packets']}, evicted={info['evicted_packets']})")

    src.stop()

    # 4. Test the mountpoint filter
    print("[4] Filter by mountpoint=C77...", end=' ')
    status, data = api_get('/api/v1/rtcm/ringbuffer?mountpoint=C77')
    if status != 200:
        print(f"FAIL (HTTP {status})")
        err += 1
    elif 'packets' not in data:
        print(f"FAIL (no 'packets' key in {list(data.keys())})")
        err += 1
    elif data['packets'] < 10:
        print(f"FAIL (packets={data['packets']} < 10)")
        err += 1
    else:
        print(f"OK (packets={data['packets']}, bytes={data['bytes']})")

    # 5. Filter by non-existent mountpoint
    print("[5] Filter by non-existent mountpoint...", end=' ')
    status, data = api_get('/api/v1/rtcm/ringbuffer?mountpoint=NOPE')
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
