#!/usr/bin/env python3

import re
import socket
import sys
import urllib.parse
import urllib.request
import json

#
# send/expect tests
#

HOST='::1'
PORT=2103

test_series = [
  [(b'AB\r\n', (('received_bytes', 104), ('sent_bytes', 203))),
   (b'b\r\n12345', (('received_bytes', 112), ('sent_bytes', 203))),
   (b'6789A\n\r\n8\r\nABCDEFG\n\r\n', (('received_bytes', 133), ('sent_bytes', 203))),
   (b'4\r\nDEF\n\r\n', (('received_bytes', 142), ('sent_bytes', 203))),
   (b'0\r\n\r\n', (('received_bytes', 147), ('sent_bytes', 203))),
  ],
]

err = 0

for tests in test_series:
  ssource = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  ssource.connect((HOST, PORT))

  ssource.sendall(b'POST /TEST1 HTTP/1.1\nUser-Agent: NTRIP test\nAuthorization: Basic dGVzdDE6dGVzdHB3IQ==\n\nABCDEFGH\n')
  sdata = ssource.recv(1024)

  sclient = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  sclient.connect((HOST, PORT))
  sclient.sendall(b'GET /TEST1 HTTP/1.1\nUser-Agent: NTRIP test\n\n')

  # Drain the ICY reply sent on subscription. The caster updates the source
  # byte counters before forwarding data to clients, so waiting for the
  # forwarded bytes guarantees the counters have been updated before the
  # API query below.
  reply = b''
  while b'\r\n\r\n' not in reply:
    d = sclient.recv(1024)
    if not d:
      break
    reply += d
  forwarded = reply.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in reply else b''

  expected_forwarded = 0
  for send, expect in tests:
    ssource.sendall(send)
    expected_forwarded += len(send)
    while len(forwarded) < expected_forwarded:
      d = sclient.recv(1024)
      if not d:
        break
      forwarded += d

    url = "http://[%s]:%d/adm/api/v1/net" % (HOST, PORT)
    params = urllib.parse.urlencode({'user': 'admin', 'password': '=adminpw...'})
    with urllib.request.urlopen("%s?%s" % (url, params)) as r:
      data = json.loads(r.read().decode())

    j = [m for m in data.values() if 'mountpoint' in m and m['mountpoint'] == 'TEST1']
    j = j[0]

    print(".", end='')
    sys.stdout.flush()

    for k, v in expect:
      if j[k] != v:
        print(k, "=", j[k], '!=', v)
        err += 1

  ssource.close()
  sclient.close()

print()

sys.exit(err != 0)
