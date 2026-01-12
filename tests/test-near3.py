#!/usr/local/bin/python3

import sys
import time


import testlib


HOST='::1'
PORT=2103

err = 0

source1 = testlib.SourceStream((HOST, PORT), "V", "wildcard_user:wildcard_pw//", 20, post=True)
source1.start()
time.sleep(.1)
source1.stop()
if source1.status != b'404':
  print("FAIL")
  err += 1
else:
  print('.', end='')

source1 = testlib.SourceStream((HOST, PORT), "V", "wildcard_user:wildcard_pw//", 20, post=False)
source1.start()
time.sleep(.1)
source1.stop()
if source1.httpreply != b'ERROR - Mount Point Taken or Invalid':
  print("FAIL", source1.httpreply)
  err += 1
else:
  print('.', end='')

print()
sys.exit(err)
