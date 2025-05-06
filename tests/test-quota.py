#!/usr/local/bin/python3

import socket
import sys
import time

HOST='::1'
PORT=2103

rounds = 30
n = 10

quota_list = [
	(b'GET / HTTP/1.1\nUser-Agent: NTRIP test\n', 3, True),
	(b'GET / HTTP/1.1\nUser-Agent: NTRIP test\nX-Forwarded-For: 9.9.9.9\nConnection: keep-alive\n', 6, False),
	(b'GET / HTTP/1.1\nUser-Agent: NTRIP test\nX-Forwarded-For: 9.8.7.6,9.9.9.9\nConnection: keep-alive\n', 6, False),
	(b'GET / HTTP/1.1\nUser-Agent: NTRIP test\nX-Forwarded-For: 9.9.9.9,9.8.7.6\nConnection: keep-alive\n', 0, False),
	(b'GET / HTTP/1.1\nUser-Agent: NTRIP test\nX-Forwarded-For: 9.9.9.9,::9:8:7:6\nConnection: keep-alive\n', 0, False),
	(b'GET / HTTP/1.1\nUser-Agent: NTRIP test\nX-Forwarded-For: 9.9.9.9,::9\nConnection: keep-alive\n', 6, False),
]

for req, quota, simult in quota_list:
 for _ in range(rounds):
  nok = 0
  nko = 0
  nunknown = 0

  socks = [socket.socket(socket.AF_INET6, socket.SOCK_STREAM) for i in range(n)]

  if simult:
    for i in range(n):
      socks[i].connect((HOST, PORT))
      try:
        socks[i].sendall(req)
      except BrokenPipeError:
        nko += 1
        continue
    for i in range(n):
      try:
        socks[i].sendall(b'\n')
      except ConnectionResetError:
        nko += 1
        continue
      except BrokenPipeError:
        nko += 1
        continue
    for i in range(n):
      r = None
      try:
        r = socks[i].recv(200)
      except ConnectionResetError:
        nko += 1
        continue

      if r.startswith(b'SOURCETABLE 200 OK'):
        nok += 1
      elif r == b'':
        nko += 1
      else:
        nunknown += 1

  else:
    for i in range(n):
      socks[i].connect((HOST, PORT))
      try:
        socks[i].sendall(req)
      except ConnectionResetError:
        nko += 1
        continue
      except BrokenPipeError:
        nko += 1
        continue

      time.sleep(.01)

    for i in range(n):
      try:
        socks[i].sendall(b'\n')
      except ConnectionResetError:
        nko += 1
        continue
      except BrokenPipeError:
        nko += 1
        continue

    for i in range(n):
      r = None
      try:
        r = socks[i].recv(200)
      except ConnectionResetError:
        nko += 1
        continue

      if r.startswith(b'SOURCETABLE 200 OK'):
        nok += 1
      elif r == b'':
        nko += 1
      else:
        print(r)
        nunknown += 1

  for i in range(n):
    socks[i].close()

  time.sleep(.01)

  if nok != quota or nunknown != 0 or (nok + nko) != n:
    print("FAIL on %s ok %d ko %d unknown %d" % (req, nok, nko, nunknown))
    sys.exit(1)

  print(".", end='')
  sys.stdout.flush()

print()
sys.exit(0)
