#!/usr/local/bin/python3

import sys
import time


import testlib

#
# Check for server and graylog sender stability after a reload
#

HOST='::1'
PORT=2103

err = 0

gr = testlib.HttpServer(HOST, 9998, b'^POST /gelf HTTP/1\.1\r\n(?s:.)*Content-Length: (\d+)\r\n', 1000, timeout=200)

gr.start()

time.sleep(6)

for i in range(100):
  err += testlib.API_reload(HOST, PORT)
  if err:
    print("FAIL")
    sys.exit(err)

time.sleep(20)


err += testlib.TestServerAlive(HOST, PORT)
err += gr.err

if err:
  print("FAIL")
else:
  print(".")
sys.exit(err)
