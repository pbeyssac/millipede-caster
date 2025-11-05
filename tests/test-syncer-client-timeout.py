#!/usr/local/bin/python3

import sys
import time


import testlib

#
# Check for syncer timeout
#

HOST='::1'
PORT=2103

err = 0

sy = testlib.HttpServer(HOST, 9999, b'^POST /adm/api/v1/sync HTTP/1\.1\r\n(?s:.)*Content-Length: (\d+)\r\n', 1000, timeout=200, keepalive=True)

sy.start()

time.sleep(20)

if sy.naccept != 1:
  err += 1

if err:
  print("FAIL")
else:
  print(".")
sys.exit(err)
