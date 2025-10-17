#!/usr/local/bin/python3

import socket
import sys
import threading
import time

#
# Client timeout test
#

HOST='::1'
PORT=2103

err = 0

stop_source = False
source_ok = False

def source_stream():
  global source_ok
  global stop_source
  ssource = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  ssource.connect((HOST, PORT))
  ssource.sendall(b'POST /TEST1 HTTP/1.1\nUser-Agent: NTRIP test\nAuthorization: Basic dGVzdDE6dGVzdHB3IQ==\n\n')
  sdata = ssource.recv(10240)
  source_ok = True
  for i in range(200):
    if stop_source:
      break
    ssource.sendall(b'%d\n' % i)
    time.sleep(1)
  ssource.close()

def client_stream():
  global stop_source
  global err
  sclient = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  sclient.connect((HOST, PORT))
  sclient.sendall(b'GET /TEST1 HTTP/1.1\r\nUser-Agent: NTRIP test\r\n\r\n')

  for i in range(30):
    data = sclient.recv(10240)
    if data == b'':
      print("FAIL: unexpected stop")
      err = 1
      break
    print(".", end='')
    sys.stdout.flush()
  print()
  stop_source = True
  sclient.close()

thr1 = threading.Thread(target=source_stream, daemon=True, args=())
thr1.start()

# Give time for the source to start
while not source_ok and thr1.is_alive():
  time.sleep(.1)

thr2 = threading.Thread(target=client_stream, daemon=True, args=())
thr2.start()

thr2.join(120)
if thr2.is_alive():
  err = 1
  print("FAIL: timeout")

print()
sys.exit(err)
