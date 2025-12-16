#!/usr/local/bin/python3

import socket
import sys

#
# Check for a crash due to a reload race in fetcher_sourcetable.
#

HOST='::1'
PORT=2103

err = 0

post_str = b'POST /adm/api/v1/reload HTTP/1.1\r\nContent-Length: 33\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&password=%3dadminpw...'
for i in range(400):
  s1 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  s2 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  s1.connect((HOST, PORT))
  s2.connect((HOST, PORT))
  s1.sendall(post_str)
  s2.sendall(post_str)
  r1 = s1.recv(1024)
  r2 = s2.recv(1024)

  if not r1.endswith(b'\r\n\r\n{"result": 0}\n') or not r2.endswith(b'\r\n\r\n{"result": 0}\n'):
    print("FAIL: got", r1)
    err = 1
    break

  print(".", end='')
  sys.stdout.flush()
  s1.close()
  s2.close()

print()

sys.exit(err)
