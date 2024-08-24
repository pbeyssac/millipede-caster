#!/usr/local/bin/python3

import socket

HOST='::1'
PORT=2103

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
  s.connect((HOST, PORT))
  s.sendall(b'GET /V HTTP/1.1\nUser-Agent: NTRIP test\n\n')
  data = s.recv(1024)
print('Received', repr(data))
