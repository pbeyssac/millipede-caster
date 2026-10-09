#!/usr/bin/env python3

import os
import sys
import time


import testlib

#
# Test an assertion failure when a given mountpoint is switched
# from "regular" to "virtual".
#

def reload_sourcetable(content):
  os.unlink('testconfig/sourcetable4.dat')
  with open('testconfig/sourcetable4.dat', 'w') as out:
    out.write(content)
  testlib.API_reload(HOST, PORT)

HOST='::1'
PORT=2103

err = 0

st_4nonear = open('testconfig/sourcetable4nonear.dat', 'r').read()
st_4near = open('testconfig/sourcetable4near.dat', 'r').read()

os.umask(0o333)

reload_sourcetable(st_4nonear)

source1 = testlib.SourceStream((HOST, PORT), "C63", "test1:testpw!", 2000)
source1.start()
source2 = testlib.SourceStream((HOST, PORT), "C43", "test1:testpw!", 2000)
source2.start()

time.sleep(.1)

source_v = testlib.SourceStream((HOST, PORT), "V", "wildcard_user:wildcard_pw//", 2000)
source_v.start()

time.sleep(.1)
reload_sourcetable(st_4near)
time.sleep(.1)

s = "$GNGGA,172829.20,4546.2000000,N,00306.0000000,E,5,12,0.68,158.545,M,47.390,M,1.2,0000*6F\r\n"

for j in range(100):
  client_list = []
  print('.', end='')
  sys.stdout.flush()
  for i in range(20):
    client = testlib.ClientStream((HOST, PORT), "V", 0, s)
    client.start()
    client_list.append(client)
  time.sleep(.1)
  for client in client_list:
    err += client.err
    client.stop()

  if err:
    break

source_v.stop()

if err:
  print("FAIL")

print()
sys.exit(err)
