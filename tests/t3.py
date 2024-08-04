#!/usr/local/bin/python3

import socket

#
# Test behaviour on backloggued connections with a on-demand source.
#

HOST='::1'
PORT=2102

tests = [b'ENSG', b'RICE', b'OUIL', b'SOPH', b'RIOM', b'WINTZ', b'WITT']
n = 100

socks = [socket.socket(socket.AF_INET6, socket.SOCK_STREAM) for i in range(n)]

for i, s in enumerate(socks):
  s.connect((HOST, PORT))
  s.sendall(b'GET /%s HTTP/1.1\nUser-Agent: NTRIP test\n\n' % tests[i % len(tests)])
  data = s.recv(1024)
  print('Received', repr(data))
