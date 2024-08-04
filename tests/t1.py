#!/usr/local/bin/python3

import socket

HOST='::1'
PORT=2102

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
  s.connect((HOST, PORT))
  s.sendall(b'GET /V HTTP/1.1\nUser-Agent: NTRIP test\n\n$GNGGA,172829.20,4332.3917404,N,00651.1321922,E,5,12,0.68,158.545,M,47.390,M,1.2,0000*62\n')
  data = s.recv(1024)
print('Received', repr(data))
