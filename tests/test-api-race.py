#!/usr/local/bin/python3

import socket
import sys
import time

HOST='::1'
PORT=2103

#
# Test for race condition on API calls
#
err = 0
for i in range(100):
  sclient = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  try:
    sclient.connect((HOST, PORT))
    sclient.sendall(b'POST /adm/api/v1/sync HTTP/1.1\r\nContent-Length: 11\r\nAuthorization: internal 587e5bbadbc6186fad0d6177eb10a6cd9d5cb934d3d5f155107592535bd20290\r\nContent-Type: application/json\r\n\r\n{"a":null}\n')
    sclient.close()

  except BrokenPipeError as e:
    err = 1
    print(e)
    break
  except ConnectionResetError as e:
    err = 1
    print(e)
    break

  print('.', end='')
  sys.stdout.flush()

if err:
  print("FAILED")
else:
  print()

sys.exit(err)
