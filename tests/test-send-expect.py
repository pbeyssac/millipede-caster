#!/usr/local/bin/python3

import re
import socket
import sys

#
# send/expect tests
#

HOST='::1'
PORT=2103

tests = [
  (b'GET /adm/ HTTP/1.1\nUser-Agent: NTRIP test\n\n',
   b'^HTTP/1\.1 401 Unauthorized\r\nServer: NTRIP Millipede Server .*\r\nDate: .* GMT\r\nConnection: close\r\nWWW-Authenticate: Basic realm="/adm"\r\n\r\n401\r\n$'),
  (b'GET /adm HTTP/1.1\nUser-Agent: NTRIP test\n\n',
   b'^SOURCETABLE 200 OK\r\n')
]

err = 0

for send, expect in tests:
  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  s.connect((HOST, PORT))
  s.sendall(send)
  data = s.recv(1024)
  if re.match(expect, data):
    print(".", end='')
  else:
    print("FAIL\nExpected: %s\nGot: %s" % (expect, data))
    err = 1

print()
sys.exit(err)
