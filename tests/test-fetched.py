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
print("Test 1: ", end='')

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

source_server.err = 0
err2 = 0
print("Test 2: ", end='')

print("Starting client+source")
source_stream = testlib.SourceStream((HOST, PORT), "C63", "test1:testpw!", 2000)
client_stream = testlib.ClientStream((HOST, PORT), "C63", 1, '')
client_stream.start()
source_stream.start()
client_stream.stop()
source_stream.stop()

err2 += client_stream.err
if err2:
  print("FAILED")
else:
  print()

print("Test 3: ", end='')
for i in range(3):
  e = threading.Event()
  source_server.set_endevent(e)
  time.sleep(6)
  e.set()
  time.sleep(1)
  source_server.set_endevent(None)

err3 = testlib.TestServerAlive(HOST, PORT)
if err3:
  print("FAILED")
else:
  print()

sys.exit(err + err2 + err3)
