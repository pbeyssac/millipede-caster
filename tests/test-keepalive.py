#!/usr/local/bin/python3

import re
import socket
import sys

#
# send/expect tests on 1 connection
#

HOST='::1'
PORT=2103

tests = [
  (b'GET / HTTP/1.1\r\nHost: devcaster.ntrip.eu.org:2101\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n',
   b'^HTTP/1\.1 200 OK\r\n'),
  (b'BADREQ\r\n',
   b'^HTTP/1\.1 400 Bad Request\r\n')
]

err = 0

#
# Repeated to give time for a double free to manifest itself
#
for i in range(1000):
  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  s.connect((HOST, PORT))

  for send, expect, in tests:
    s.sendall(send)
    data = s.recv(10240)
    if re.match(expect, data):
      print(".", end='')
    else:
      print("FAIL ON s\nExpected: %s\nGot: %s" % (expect, data))
      err = 1
  s.close()

print()
sys.exit(err)
