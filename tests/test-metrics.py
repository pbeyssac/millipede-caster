#!/usr/bin/env python3
"""
Test the Prometheus metrics exporter endpoint.

Verifies that:
1. The /api/v1/metrics endpoint returns 200 with text/plain content type.
2. The response contains the Prometheus version 0.0.4 content type.
3. All expected metrics are present with proper HELP/TYPE annotations.
4. The metrics reflect actual caster state (e.g. uptime_seconds > 0).
5. After sending RTCM packets, per-mountpoint RTCM metrics appear.
6. Authentication is enforced (401 without credentials).

Usage: python3 test-metrics.py
"""
import base64
import re
import sys
import time
import urllib.request
import urllib.error

import testlib

HOST = ('::1', 2103)
USER = 'admin'
PASSWORD = '=adminpw...'

# RTCM 1006 packet (station position)
RTCM_1006 = b"\xd3\x00\x15\x3e\xe0\x00\x03\x89\xc8\x55\xac\xd7\x80\x71\x2a\x81\xc9\x8b\x20\x8b\x7f\x54\x00\x00\x7c\x4f\x32"

EXPECTED_METRICS = [
    'millipede_uptime_seconds',
    'millipede_connections_total',
    'millipede_received_bytes_total',
    'millipede_sent_bytes_total',
    'millipede_mountpoints',
    'millipede_log_stream_subscribers',
]

# Metrics that only appear once there is RTCM traffic
RTCM_DEPENDENT_METRICS = [
    'millipede_rtcm_packets_total',
    'millipede_rtcm_rate_hz',
]


def auth_header():
    creds = base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()
    return {'Authorization': f'Basic {creds}'}


def fetch_metrics():
    url = 'http://127.0.0.1:2103/adm/api/v1/metrics'
    req = urllib.request.Request(url, headers=auth_header())
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.headers.get('Content-Type', ''), r.read().decode()


def parse_metrics(text):
    """Parse Prometheus text format into {name: [(labels_dict, value_str), ...]}."""
    metrics = {}
    current_name = None
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        # Strip optional label section
        m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([0-9.eE+-]+)\s*$', line)
        if not m:
            continue
        name, labels_str, value = m.group(1), m.group(2), m.group(3)
        labels = {}
        if labels_str:
            for kv in re.findall(r'(\w+)="([^"]*)"', labels_str):
                labels[kv[0]] = kv[1]
        metrics.setdefault(name, []).append((labels, value))
    return metrics


def main():
    err = 0

    # 1. Auth required
    print("[1] Auth enforced...", end=' ')
    try:
        url = 'http://127.0.0.1:2103/adm/api/v1/metrics'
        req = urllib.request.Request(url)  # no auth
        urllib.request.urlopen(req, timeout=5)
        print("FAIL (no 401)")
        err += 1
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("OK")
        else:
            print(f"FAIL (expected 401, got {e.code})")
            err += 1

    # 2. Fetch metrics and check headers
    print("[2] Headers and content type...", end=' ')
    status, ct, body = fetch_metrics()
    if status != 200:
        print(f"FAIL (status {status})")
        err += 1
    elif 'text/plain' not in ct:
        print(f"FAIL (Content-Type: {ct!r})")
        err += 1
    elif 'version=0.0.4' not in ct:
        print(f"FAIL (no version=0.0.4 in {ct!r})")
        err += 1
    else:
        print("OK")

    # 3. All expected metrics present
    print("[3] Expected metrics present...", end=' ')
    metrics = parse_metrics(body)
    missing = [m for m in EXPECTED_METRICS if m not in metrics]
    if missing:
        print(f"FAIL (missing: {missing})")
        err += 1
    else:
        print(f"OK ({len(metrics)} metric series)")

    # 4. uptime > 0 and gauge type annotation
    print("[4] uptime_seconds has valid value...", end=' ')
    if 'millipede_uptime_seconds' not in metrics:
        print("FAIL (no uptime metric)")
        err += 1
    else:
        uptime_val = float(metrics['millipede_uptime_seconds'][0][1])
        if uptime_val <= 0:
            print(f"FAIL (uptime={uptime_val})")
            err += 1
        else:
            print(f"OK ({uptime_val:.1f}s)")

    # 5. Check HELP and TYPE annotations
    print("[5] HELP/TYPE annotations...", end=' ')
    help_count = body.count('# HELP millipede_')
    type_count = body.count('# TYPE millipede_')
    if help_count < 5 or type_count < 5:
        print(f"FAIL (help={help_count}, type={type_count})")
        err += 1
    else:
        print(f"OK ({help_count} HELP, {type_count} TYPE)")

    # 6. Per-mountpoint RTCM metrics appear after traffic
    print("[6] Per-mountpoint RTCM metrics after traffic...", end=' ')
    # 1000 packets at 0.01s = 10s of traffic — keeps the source connected
    # long enough for the live counter check at step 7.
    src = testlib.SourceStream(HOST, 'C77', 'test1:testpw!', 1000,
                               start_delay=1, packet_delay=0.01,
                               packet=RTCM_1006)
    src.start()
    time.sleep(2.5)
    # Fetch metrics WHILE the source is still connected (so the source
    # counter below is non-zero).
    _, _, body2 = fetch_metrics()
    metrics2 = parse_metrics(body2)

    rtcms = [m for m in metrics2.get('millipede_rtcm_packets_total', [])
             if m[0].get('mountpoint') == 'C77']
    if not rtcms:
        print("FAIL (no C77 RTCM metrics)")
        err += 1
    else:
        labels, val = rtcms[0]
        if labels.get('type') != '1006':
            print(f"FAIL (type={labels.get('type')!r}, expected 1006)")
            err += 1
        elif int(val) < 10:
            print(f"FAIL (count={val} < 10)")
            err += 1
        else:
            print(f"OK (type={labels['type']}, count={val})")

    # 7. Connection counter reflects the active source (still connected)
    print("[7] connections_total{type=source}...", end=' ')
    conns = metrics2.get('millipede_connections_total', [])
    sources = [c for c in conns if c[0].get('type') == 'source']
    if not sources:
        print("FAIL (no source counter)")
        err += 1
    elif float(sources[0][1]) < 1:
        print(f"FAIL (source count={sources[0][1]} < 1)")
        err += 1
    else:
        print(f"OK (sources={sources[0][1]})")

    src.stop()

    print()
    if err:
        print(f"FAIL: {err} error(s)")
    else:
        print("PASS")
    sys.exit(err)


if __name__ == '__main__':
    main()
