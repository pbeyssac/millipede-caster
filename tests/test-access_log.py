#!/usr/local/bin/python3

import sys
import time


import testlib

#
# Check access_log is correctly filled
#

HOST='::1'
PORT=2103

err = 0

client_stream = testlib.ClientStream((HOST, PORT), "", 0, '')
client_stream.start()
client_stream.join(1)
client_stream.stop()
err += client_stream.err

try:
   s = os.path.getsize('test-access.log')
except:
   s = None
if s != 0:
  print("FAIL")
  err += 1

sys.exit(err)
