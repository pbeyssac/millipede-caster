#!/usr/local/bin/python3

import socket
import sys
import time

HOST='::1'
PORT=2103

#
# Test for race condition between livesource deletion/subscription/unsubscription.
#
err = 0
for i in range(1000):
  ssource = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  sclient = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  try:
    ssource.connect((HOST, PORT))
    sclient.connect((HOST, PORT))
    ssource.sendall(b'POST /TEST1 HTTP/1.1\nUser-Agent: NTRIP test\nAuthorization: Basic dGVzdDE6dGVzdHB3IQ==\nTransfer-Encoding: chunked\n\n')
    sclient.sendall(b'GET /TEST1 HTTP/1.1\nUser-Agent: NTRIP test\n\n')
    ssource.close()
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
  if (i+1) % 100 == 0:
    # Delay every 100 to avoid listen queue saturation
    time.sleep(.05)

if err:
  print("FAILED")
else:
  print()

sys.exit(err)
