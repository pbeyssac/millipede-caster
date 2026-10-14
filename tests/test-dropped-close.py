#!/usr/bin/env python3

import base64
import socket
import sys
import time

#
# Connections dropped by ntripsrv_readcb() without a reply must be force-closed at once
# instead of waiting anything more from the client.
#
# Runs on testconfig/caster2.yaml (port 2103).
#

HOST='::1'
PORT=2103
DELAY=3

def closed_within(s, delay):
  # True if the caster closes s within delay seconds
  s.settimeout(delay)
  end = time.time() + delay
  try:
    while time.time() < end:
      if s.recv(1024) == b'':
        return True
  except ConnectionResetError:
    return True
  except (OSError, TimeoutError):
    pass
  return False

err = 0

# 1. Over quota after X-Forwarded-For
req = b'GET / HTTP/1.1\r\nUser-Agent: NTRIP test\r\nX-Forwarded-For: 9.9.9.9\r\n'
held = []
for i in range(6):
  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  s.connect((HOST, PORT))
  # headers not ended: the connection holds its quota slot and gets no reply
  s.sendall(req)
  held.append(s)
  # let the caster move it from ::1 (quota 3) to 9.9.9.9 before the next one
  time.sleep(.2)

s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(req + b'\r\n')
s.settimeout(DELAY)
try:
  r = s.recv(1024)
except ConnectionResetError:
  r = b''
except (OSError, TimeoutError):
  r = None
if r is None:
  print("FAIL: connection over quota not closed within %d s" % DELAY)
  err = 1
elif r != b'':
  print("FAIL: connection over quota got an answer: %s" % r[:40])
  err = 1
else:
  print(".", end='')
s.close()
for s in held:
  s.close()

# 2. End of a chunked source stream
auth = base64.b64encode(b'wildcard_user:wildcard_pw//')
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(b'POST /DROPCLOSE HTTP/1.1\r\nUser-Agent: NTRIP test\r\nAuthorization: Basic %s\r\n'
          b'Ntrip-Version: Ntrip/2.0\r\nTransfer-Encoding: chunked\r\n\r\n' % auth)
s.settimeout(5)
r = s.recv(1024)
if not r.startswith(b'HTTP/1.1 200'):
  print("FAIL: source not accepted: %s" % r)
  err = 1
else:
  s.sendall(b'4\r\nABCD\r\n0\r\n\r\n')
  if not closed_within(s, DELAY):
    print("FAIL: source not closed within %d s after its last chunk" % DELAY)
    err = 1
  else:
    print(".", end='')
s.close()

print()
sys.exit(err)
