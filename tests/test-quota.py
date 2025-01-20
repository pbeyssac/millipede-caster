#!/usr/local/bin/python3

import socket
import sys

HOST='::1'
PORT=2103

rounds = 30
n = 10

str_get = b'GET / HTTP/1.1\nUser-Agent: NTRIP test\n'

for _ in range(rounds):
  nok = 0
  nko = 0
  nunknown = 0

  socks = [socket.socket(socket.AF_INET6, socket.SOCK_STREAM) for i in range(n)]

  for i in range(n):
    socks[i].connect((HOST, PORT))

  for i in range(n):
    try:
      socks[i].sendall(str_get)
    except BrokenPipeError:
      nko += 1
      continue

    try:
      socks[i].sendall(b'\n')
    except ConnectionResetError:
      nko += 1
      continue
    except BrokenPipeError:
      nko += 1
      continue

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

  for i in range(n):
    socks[i].close()

  if nok != 2 or nunknown != 0 or (nok + nko) != n:
    print("FAIL ok %d ko %d unknown %d" % (nok, nko, nunknown))
    sys.exit(1)

  print(".", end='')
  sys.stdout.flush()

print()
sys.exit(0)
