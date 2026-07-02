#!/usr/bin/env python3
"""
Test the SSE log stream API endpoint.

Verifies that:
1. The /api/v1/logs/stream endpoint returns 200 with the right headers.
2. An initial 'hello' event is sent on connection.
3. Log entries are pushed in real-time as they are generated.
4. The connection stays open until the client closes it.

Usage: python3 test-logs-stream.py
"""
import base64
import json
import socket
import sys
import time
import urllib.parse
import urllib.request

import testlib

HOST = ('::1', 2103)
HTTP_HOST = '127.0.0.1'
PORT = 2103
USER = 'admin'
PASSWORD = '=adminpw...'

# RTCM 1006 packet — used to generate log traffic
RTCM_1006 = b"\xd3\x00\x15\x3e\xe0\x00\x03\x89\xc8\x55\xac\xd7\x80\x71\x2a\x81\xc9\x8b\x20\x8b\x7f\x54\x00\x00\x7c\x4f\x32"


def open_sse():
    """Open a raw SSE connection and return the socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HTTP_HOST, PORT))
    pwd_q = urllib.parse.quote(PASSWORD)
    url = f'/adm/api/v1/logs/stream?user={USER}&password={pwd_q}'
    req = f'GET {url} HTTP/1.1\r\nHost: {HTTP_HOST}:{PORT}\r\nConnection: close\r\n\r\n'
    s.sendall(req.encode())
    return s


def read_until(s, marker, timeout=5):
    """Read from socket until marker is seen or timeout."""
    s.settimeout(timeout)
    buf = b''
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if marker.encode() in buf:
                return buf.decode(errors='replace')
        except socket.timeout:
            break
    return buf.decode(errors='replace')


def main():
    err = 0

    # 1. Open SSE and check the HTTP response + hello event
    print("[1] SSE handshake...", end=' ')
    s = open_sse()
    data = read_until(s, 'event: hello', timeout=3)
    if 'HTTP/1.1 200 OK' not in data:
        print("FAIL (no 200 OK)")
        err += 1
    elif 'Content-Type: text/event-stream' not in data:
        print("FAIL (no SSE Content-Type)")
        err += 1
    elif 'event: hello' not in data:
        print("FAIL (no hello event)")
        err += 1
    else:
        print("OK")

    # 2. Generate some log traffic (RTCM packets produce log lines)
    print("[2] Generating log traffic...", end=' ')
    src = testlib.SourceStream(HOST, 'C77', 'test1:testpw!', 200,
                               start_delay=1, packet_delay=0.01,
                               packet=RTCM_1006)
    src.start()
    print("OK")

    # 3. Read the SSE stream and check that 'log' events are pushed
    print("[3] Receiving real-time log events...", end=' ')
    data = read_until(s, 'event: log', timeout=3)
    if 'event: log' not in data:
        print("FAIL (no log event)")
        err += 1
    else:
        # Try to parse one log event
        idx = data.find('event: log\ndata: ')
        if idx < 0:
            print("FAIL (malformed event)")
            err += 1
        else:
            json_part = data[idx + len('event: log\ndata: '):].split('\n')[0]
            try:
                entry = json.loads(json_part)
                if 'level' not in entry or 'message' not in entry:
                    print(f"FAIL (missing fields: {entry})")
                    err += 1
                else:
                    print(f"OK (level={entry['level']}, msg={entry['message'][:50]!r})")
            except json.JSONDecodeError as e:
                print(f"FAIL (invalid JSON: {e})")
                err += 1

    src.stop()
    s.close()

    print()
    if err:
        print(f"FAIL: {err} error(s)")
    else:
        print("PASS")
    sys.exit(err)


if __name__ == '__main__':
    main()
