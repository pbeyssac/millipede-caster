#!/usr/local/bin/python3

import re
import socket
import sys

import requests

#
# send/expect tests
#

HOST='::1'
PORT=2103

test_series = [
  [(b'AB\r\n', (('received_bytes', 96), ('sent_bytes', 180))),
   (b'b\r\n12345', (('received_bytes', 104), ('sent_bytes', 180))),
   (b'6789A\n\r\n8\r\nABCDEFG\n\r\n', (('received_bytes', 125), ('sent_bytes', 180))),
   (b'4\r\nDEF\n\r\n', (('received_bytes', 134), ('sent_bytes', 180))),
   (b'0\r\n\r\n', (('received_bytes', 139), ('sent_bytes', 180))),
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

  for send, expect in tests:
    ssource.sendall(send)
    data = sclient.recv(1024)

    r = requests.get("http://[%s]:%d/adm/api/v1/net" % (HOST, PORT), params={'user': 'admin', 'password': '=adminpw...'})
    j = [m for m in r.json().values() if 'mountpoint' in m and m['mountpoint'] == 'TEST1']
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
