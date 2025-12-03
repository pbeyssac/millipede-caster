#!/usr/local/bin/python3

import re
import socket
import sys
import threading
import time

import testlib


#
# fetched source test
#

HOST='::1'
PORT=2103
FAKE_SERVER_PORT=2163

print("Starting server")
source_server = testlib.SourceServer((HOST, FAKE_SERVER_PORT), 'C63')
source_server.start()
time.sleep(6)

err = 0

for j in range(2):
  print("Starting client")
  client_stream = testlib.ClientStream((HOST, PORT), "C63", 5, '')
  client_stream.start()
  client_stream.join(None)
  err += client_stream.err
  if err:
    break
  else:
    print(".", end='')
  time.sleep(6)

err += source_server.err
if err:
  print("FAILED")
else:
  print()


sys.exit(err)
