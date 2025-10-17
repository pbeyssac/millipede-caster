#!/usr/local/bin/python3

import sys

import testlib

#
# Client timeout test:
# Check the client connection is not closed when it doesn't send anything to the server
#

HOST='::1'
PORT=2103

err = 0

source_stream = testlib.SourceStream((HOST, PORT), "TEST1", "test1:testpw!", 200)
source_stream.start()

client_stream = testlib.ClientStream((HOST, PORT), "TEST1", 30)
client_stream.start()
client_stream.join(120)
source_stream.stop()

if client_stream.is_alive():
  err += client_stream.err + 1
  print("FAIL: timeout")
else:
  err += client_stream.err

print()
sys.exit(err)
