#!/usr/local/bin/python3

import sys
import time


import testlib

#
# Client early-close
#
# Check for crashes in multithreaded mode, in case the client closes its connection just before a GGA line
# is processed.
#

HOST='::1'
PORT=2103

err = 0

source_stream = testlib.SourceStream((HOST, PORT), "C63", "test1:testpw!", 2000)
source_stream.start()

s = "$GNGGA,172829.20,4546.2000000,N,00306.0000000,E,5,12,0.68,158.545,M,47.390,M,1.2,0000*6F\r\n"

for i in range(100):
  client_stream = testlib.ClientStream((HOST, PORT), "V", 0, s)
  client_stream.start()
  client_stream.join(10)
  client_stream.stop()
  err += client_stream.err

source_stream.stop()
print()
sys.exit(err)
