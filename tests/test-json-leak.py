#!/usr/bin/env python3

import sys
import time

import testlib


HOST='::1'
PORT=2103
FAKE_SERVER_PORT=2163

print("Starting server")
source_server = testlib.SourceServer((HOST, FAKE_SERVER_PORT), 'TEST1')
source_server.start()
time.sleep(1)

err = 0

for j in range(2):
  print("Starting client")
  client_stream = testlib.ClientStream((HOST, PORT), "TEST1", 5, '')
  client_stream.start()
  time.sleep(1)
  client_stream.join(None)
  err += client_stream.err
  if err:
    break
  else:
    print(".", end='')
  if testlib.API_reload(HOST, PORT) != 0:
    err += 1
    print("FAIL")
    break
  time.sleep(1)

source_server.stop()

if err:
  print("FAIL")

sys.exit(err)
