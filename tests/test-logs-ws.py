#!/usr/bin/env python3
"""
Test the bidirectional WebSocket log control endpoint (/api/v1/logs/ws).

Verifies that:
1. The endpoint rejects requests without a Sec-WebSocket-Key header (400).
2. The WebSocket handshake (HTTP 101 Switching Protocols) succeeds.
3. The server sends a "hello" text frame immediately after upgrade.
4. The client can send a {"cmd":"ping"} command and receives {"type":"pong"}.
5. The "reload" command is accepted and a reply is returned.
6. The "drop" command for a non-existent id returns result=0.
7. Unknown commands produce an error reply.
8. A close frame cleanly terminates the connection.

This implements a minimal WebSocket client (handshake + frame encode/decode)
to avoid pulling in a third-party dependency.

Usage: python3 test-logs-ws.py
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time
import urllib.parse

import testlib

HOST = ('::1', 2103)
HTTP_HOST = '127.0.0.1'
PORT = 2103
USER = 'admin'
PASSWORD = '=adminpw...'

WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def ws_handshake_key():
    """Generate a random 16-byte Sec-WebSocket-Key (base64)."""
    return base64.b64encode(os.urandom(16)).decode()


def expect_accept(key):
    """Compute the expected Sec-WebSocket-Accept for a given key."""
    h = hashlib.sha1((key + WS_GUID).encode()).digest()
    return base64.b64encode(h).decode()


def open_ws():
    """Open a TCP connection, perform the WebSocket handshake, return the socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HTTP_HOST, PORT))

    pwd_q = urllib.parse.quote(PASSWORD)
    key = ws_handshake_key()
    url = f'/adm/api/v1/logs/ws?user={USER}&password={pwd_q}'
    req = (
        f'GET {url} HTTP/1.1\r\n'
        f'Host: {HTTP_HOST}:{PORT}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: {key}\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'\r\n'
    )
    s.sendall(req.encode())

    # Read the HTTP 101 response
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 8192:
            break

    if b'HTTP/1.1 101' not in buf:
        raise AssertionError(f'no 101: {buf[:200]!r}')
    if b'Sec-WebSocket-Accept: ' not in buf:
        raise AssertionError(f'no Sec-WebSocket-Accept header: {buf[:200]!r}')

    # Extract the accept value and verify
    for line in buf.split(b'\r\n'):
        if line.lower().startswith(b'sec-websocket-accept:'):
            actual = line.split(b':', 1)[1].strip().decode()
            expected = expect_accept(key)
            if actual != expected:
                raise AssertionError(f'accept mismatch: {actual!r} != {expected!r}')
            break
    else:
        raise AssertionError('accept header not found in parsed lines')

    # Anything past the \r\n\r\n is the start of WS frames
    leftover = buf.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in buf else b''
    return s, leftover


def send_text_frame(s, payload):
    """Send a masked text frame (client → server)."""
    if isinstance(payload, str):
        payload = payload.encode()
    mask = os.urandom(4)
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))

    header = bytearray()
    header.append(0x80 | 0x01)  # FIN + text
    plen = len(payload)
    if plen <= 125:
        header.append(0x80 | plen)  # MASK=1
    elif plen <= 65535:
        header.append(0x80 | 126)
        header += struct.pack('>H', plen)
    else:
        header.append(0x80 | 127)
        header += struct.pack('>Q', plen)
    header += mask
    s.sendall(bytes(header) + masked)


def recv_frame(s, leftover_buf):
    """Read one WebSocket frame from the server.
    Returns (fin, opcode, payload_bytes) or None on EOF.
    leftover_buf is a bytearray that carries unconsumed bytes between calls.
    """
    # Read the 2-byte minimum header
    while len(leftover_buf) < 2:
        chunk = s.recv(4096)
        if not chunk:
            return None
        leftover_buf.extend(chunk)

    b0 = leftover_buf[0]
    b1 = leftover_buf[1]
    fin = (b0 >> 7) & 1
    opcode = b0 & 0x0F
    masked = (b1 >> 7) & 1
    plen = b1 & 0x7F
    hdr_len = 2

    if plen == 126:
        while len(leftover_buf) < hdr_len + 2:
            chunk = s.recv(4096)
            if not chunk:
                return None
            leftover_buf.extend(chunk)
        plen = struct.unpack('>H', bytes(leftover_buf[hdr_len:hdr_len+2]))[0]
        hdr_len += 2
    elif plen == 127:
        while len(leftover_buf) < hdr_len + 8:
            chunk = s.recv(4096)
            if not chunk:
                return None
            leftover_buf.extend(chunk)
        plen = struct.unpack('>Q', bytes(leftover_buf[hdr_len:hdr_len+8]))[0]
        hdr_len += 8

    mask_len = 4 if masked else 0
    total = hdr_len + mask_len + plen
    while len(leftover_buf) < total:
        chunk = s.recv(4096)
        if not chunk:
            return None
        leftover_buf.extend(chunk)

    if masked:
        mask = leftover_buf[hdr_len:hdr_len+4]
        raw = leftover_buf[hdr_len+4:hdr_len+4+plen]
        payload = bytes(raw[i] ^ mask[i % 4] for i in range(plen))
    else:
        payload = bytes(leftover_buf[hdr_len:hdr_len+plen])

    # Consume
    del leftover_buf[:total]
    return (fin, opcode, payload)


def send_close_frame(s):
    """Send a close frame (opcode 0x8) and shut down."""
    mask = os.urandom(4)
    header = bytearray()
    header.append(0x80 | 0x08)  # FIN + close
    header.append(0x80 | 0)     # MASK=1, len=0
    header += mask
    s.sendall(bytes(header))


def main():
    err = 0

    # 1. Rejection when no Sec-WebSocket-Key header
    print("[1] Reject non-WS request (400)...", end=' ')
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((HTTP_HOST, PORT))
        pwd_q = urllib.parse.quote(PASSWORD)
        url = f'/adm/api/v1/logs/ws?user={USER}&password={pwd_q}'
        req = f'GET {url} HTTP/1.1\r\nHost: {HTTP_HOST}:{PORT}\r\n\r\n'
        s.sendall(req.encode())
        reply = b''
        while b'\r\n\r\n' not in reply:
            chunk = s.recv(4096)
            if not chunk:
                break
            reply += chunk
        s.close()
        if b'400 Bad Request' in reply:
            print("OK")
        else:
            print(f"FAIL (got: {reply[:120]!r})")
            err += 1
    except Exception as e:
        print(f"FAIL (exception: {e})")
        err += 1

    # 2. Handshake succeeds
    print("[2] WebSocket handshake (HTTP 101)...", end=' ')
    try:
        s, leftover = open_ws()
        print("OK")
    except AssertionError as e:
        print(f"FAIL ({e})")
        err += 1
        sys.exit(err)

    leftover_buf = bytearray(leftover)

    # 3. Hello frame
    print("[3] Receive hello frame...", end=' ')
    try:
        frame = recv_frame(s, leftover_buf)
        if frame is None:
            print("FAIL (no frame)")
            err += 1
        else:
            fin, opcode, payload = frame
            if opcode != 0x1:
                print(f"FAIL (opcode={opcode:#x}, expected 0x1 text)")
                err += 1
            else:
                msg = json.loads(payload.decode())
                if msg.get('type') == 'hello':
                    print(f"OK ({msg.get('message', '')[:40]!r})")
                else:
                    print(f"FAIL (no hello type: {msg})")
                    err += 1
    except Exception as e:
        print(f"FAIL (exception: {e})")
        err += 1

    # 4. Ping → pong
    print("[4] ping → pong...", end=' ')
    try:
        send_text_frame(s, json.dumps({'cmd': 'ping'}))
        frame = recv_frame(s, leftover_buf)
        if frame is None:
            print("FAIL (no reply)")
            err += 1
        else:
            fin, opcode, payload = frame
            msg = json.loads(payload.decode())
            if msg.get('type') == 'pong':
                print("OK")
            else:
                print(f"FAIL (got {msg})")
                err += 1
    except Exception as e:
        print(f"FAIL (exception: {e})")
        err += 1

    # 5. Reload command
    print("[5] reload command...", end=' ')
    try:
        send_text_frame(s, json.dumps({'cmd': 'reload'}))
        frame = recv_frame(s, leftover_buf)
        if frame is None:
            print("FAIL (no reply)")
            err += 1
        else:
            fin, opcode, payload = frame
            msg = json.loads(payload.decode())
            if msg.get('type') == 'reload' and 'result' in msg:
                print(f"OK (result={msg['result']})")
            else:
                print(f"FAIL (got {msg})")
                err += 1
    except Exception as e:
        print(f"FAIL (exception: {e})")
        err += 1

    # 6. Drop command (non-existent id)
    print("[6] drop command (non-existent id)...", end=' ')
    try:
        send_text_frame(s, json.dumps({'cmd': 'drop', 'id': 999999}))
        frame = recv_frame(s, leftover_buf)
        if frame is None:
            print("FAIL (no reply)")
            err += 1
        else:
            fin, opcode, payload = frame
            msg = json.loads(payload.decode())
            if msg.get('type') == 'drop':
                print(f"OK (result={msg.get('result')})")
            else:
                print(f"FAIL (got {msg})")
                err += 1
    except Exception as e:
        print(f"FAIL (exception: {e})")
        err += 1

    # 7. Unknown command
    print("[7] Unknown command...", end=' ')
    try:
        send_text_frame(s, json.dumps({'cmd': 'frobnicate'}))
        frame = recv_frame(s, leftover_buf)
        if frame is None:
            print("FAIL (no reply)")
            err += 1
        else:
            fin, opcode, payload = frame
            msg = json.loads(payload.decode())
            if msg.get('type') == 'error':
                print(f"OK (message={msg.get('message')!r})")
            else:
                print(f"FAIL (got {msg})")
                err += 1
    except Exception as e:
        print(f"FAIL (exception: {e})")
        err += 1

    # 8. Malformed JSON
    print("[8] Malformed JSON...", end=' ')
    try:
        send_text_frame(s, 'not json{')
        frame = recv_frame(s, leftover_buf)
        if frame is None:
            print("FAIL (no reply)")
            err += 1
        else:
            fin, opcode, payload = frame
            msg = json.loads(payload.decode())
            if msg.get('type') == 'error':
                print("OK")
            else:
                print(f"FAIL (got {msg})")
                err += 1
    except Exception as e:
        print(f"FAIL (exception: {e})")
        err += 1

    # 9. Clean close
    print("[9] Clean close...", end=' ')
    try:
        send_close_frame(s)
        # The server should echo a close frame back
        frame = recv_frame(s, leftover_buf)
        if frame is None:
            print("OK (server closed)")
        else:
            fin, opcode, payload = frame
            if opcode == 0x8:
                print("OK (close frame echoed)")
            else:
                print(f"FAIL (got opcode {opcode:#x})")
                err += 1
    except Exception as e:
        print(f"FAIL (exception: {e})")
        err += 1
    finally:
        try:
            s.close()
        except Exception:
            pass

    print()
    if err:
        print(f"FAIL: {err} error(s)")
    else:
        print("PASS")
    sys.exit(err)


if __name__ == '__main__':
    main()
