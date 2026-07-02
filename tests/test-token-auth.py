#!/usr/bin/env python3
"""
Test the Bearer token / ?token= authentication for /api/v1/ endpoints.

Verifies that:
1. /api/v1/mem with no auth returns 401.
2. /api/v1/mem with wrong Bearer token returns 401.
3. /api/v1/mem with correct Bearer token returns 200.
4. /api/v1/mem with ?token=... query string returns 200.
5. /api/v1/mem with HTTP Basic still works (backward compat).
6. SSE /api/v1/logs/stream with ?token= returns 200 + hello event.
7. SSE /api/v1/logs/stream with wrong ?token= returns 401.

Usage: python3 test-token-auth.py
"""
import base64
import json
import socket
import sys
import time
import urllib.parse

import testlib

HOST = ('::1', 2103)
HTTP_HOST = '127.0.0.1'
PORT = 2103
USER = 'admin'
PASSWORD = '=adminpw...'
TOKEN = 'test-secret-token'
WRONG_TOKEN = 'this-is-wrong'
API_PREFIX = '/adm'   # /api/v1/* endpoints live under /adm/*


def http_request(method, path, headers=None, body=None, read_reply=True, timeout=3):
    """Send an HTTP request and return (status_line, headers, body) as text."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((HTTP_HOST, PORT))
    req_line = f'{method} {path} HTTP/1.1\r\nHost: {HTTP_HOST}:{PORT}\r\n'
    if headers:
        for k, v in headers.items():
            req_line += f'{k}: {v}\r\n'
    req_line += 'Connection: close\r\n\r\n'
    s.sendall(req_line.encode())
    if body:
        s.sendall(body if isinstance(body, bytes) else body.encode())
    buf = b''
    if read_reply:
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
    s.close()
    text = buf.decode(errors='replace')
    if not text:
        return '', '', ''
    # Split status line / headers / body
    head, _, body_text = text.partition('\r\n\r\n')
    status_line, _, header_text = head.partition('\r\n')
    return status_line, header_text, body_text


def main():
    err = 0
    basic_auth = 'Basic ' + base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()
    bearer_ok = f'Bearer {TOKEN}'
    bearer_bad = f'Bearer {WRONG_TOKEN}'
    mem_path = API_PREFIX + '/api/v1/mem'
    sse_path_tpl = API_PREFIX + '/api/v1/logs/stream?token={}'

    # 1. No auth → 401
    print('[1] No auth → 401...', end=' ')
    status, _, _ = http_request('GET', mem_path)
    if '401' in status:
        print('OK')
    else:
        print(f"FAIL (got {status!r})")
        err += 1

    # 2. Wrong Bearer → 401
    print('[2] Wrong Bearer → 401...', end=' ')
    status, _, _ = http_request('GET', mem_path, headers={'Authorization': bearer_bad})
    if '401' in status:
        print('OK')
    else:
        print(f"FAIL (got {status!r})")
        err += 1

    # 3. Correct Bearer → 200
    print('[3] Correct Bearer → 200...', end=' ')
    status, headers, body = http_request('GET', mem_path,
                                          headers={'Authorization': bearer_ok})
    if '200' in status:
        try:
            j = json.loads(body)
            # /api/v1/mem returns malloc stats; just check it parsed
            if isinstance(j, dict):
                print('OK')
            else:
                print(f"FAIL (unexpected JSON: {body[:100]!r})")
                err += 1
        except json.JSONDecodeError:
            print(f"FAIL (not JSON: {body[:100]!r})")
            err += 1
    else:
        print(f"FAIL (got {status!r})")
        err += 1

    # 4. ?token= query string → 200
    print('[4] ?token= query → 200...', end=' ')
    path = mem_path + '?token=' + urllib.parse.quote(TOKEN)
    status, _, body = http_request('GET', path)
    if '200' in status:
        print('OK')
    else:
        print(f"FAIL (got {status!r})")
        err += 1

    # 5. Wrong ?token= → 401
    print('[5] Wrong ?token= → 401...', end=' ')
    path = mem_path + '?token=' + urllib.parse.quote(WRONG_TOKEN)
    status, _, _ = http_request('GET', path)
    if '401' in status:
        print('OK')
    else:
        print(f"FAIL (got {status!r})")
        err += 1

    # 6. Basic auth still works (backward compat)
    print('[6] Basic auth backward compat → 200...', end=' ')
    status, _, _ = http_request('GET', mem_path,
                                 headers={'Authorization': basic_auth})
    if '200' in status:
        print('OK')
    else:
        print(f"FAIL (got {status!r})")
        err += 1

    # 7. SSE with ?token= → 200 + hello event
    print('[7] SSE with ?token= → 200 + hello...', end=' ')
    sse = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sse.settimeout(3)
    sse.connect((HTTP_HOST, PORT))
    path = sse_path_tpl.format(urllib.parse.quote(TOKEN))
    req = f'GET {path} HTTP/1.1\r\nHost: {HTTP_HOST}:{PORT}\r\nConnection: close\r\n\r\n'
    sse.sendall(req.encode())
    buf = b''
    try:
        while b'event: hello' not in buf and len(buf) < 8192:
            chunk = sse.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    sse.close()
    text = buf.decode(errors='replace')
    if '200 OK' in text and 'event: hello' in text:
        print('OK')
    else:
        print(f"FAIL (got {text[:120]!r})")
        err += 1

    # 8. SSE with wrong ?token= → 401
    print('[8] SSE with wrong ?token= → 401...', end=' ')
    sse = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sse.settimeout(3)
    sse.connect((HTTP_HOST, PORT))
    path = sse_path_tpl.format(urllib.parse.quote(WRONG_TOKEN))
    req = f'GET {path} HTTP/1.1\r\nHost: {HTTP_HOST}:{PORT}\r\nConnection: close\r\n\r\n'
    sse.sendall(req.encode())
    buf = b''
    try:
        while len(buf) < 256:
            chunk = sse.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    sse.close()
    text = buf.decode(errors='replace')
    if '401' in text.split('\r\n')[0]:
        print('OK')
    else:
        print(f"FAIL (got {text[:120]!r})")
        err += 1

    print()
    if err:
        print(f'FAIL: {err} error(s)')
    else:
        print('PASS')
    sys.exit(err)


if __name__ == '__main__':
    main()
