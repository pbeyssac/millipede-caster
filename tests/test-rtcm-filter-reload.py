#!/usr/bin/env python3

import os
import socket
import sys
import time

import testlib

#
# Reload removing the rtcm_filter block while a client is on a filtered mountpoint.
# use_rtcm_filter is decided when the client subscribes, but in threaded mode the client's
# config follows reloads: the next packet was filtered through the new config's NULL
# rtcm_filter, and the caster crashed (SIGSEGV in rtcm_filter_pass()).
#

HOST='::1'
PORT=2103
CONFIG='testconfig/caster6.yaml'

err = 0

conf = open('testconfig/caster6-orig.yaml').read()

ssource = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
ssource.connect((HOST, PORT))
ssource.sendall(b'POST /TEST1 HTTP/1.1\r\nUser-Agent: NTRIP test\r\nAuthorization: Basic dGVzdDE6dGVzdHB3IQ==\r\n\r\n')
ssource.recv(1024)

sclient = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sclient.connect((HOST, PORT))
sclient.sendall(b'GET /TEST1 HTTP/1.1\r\nUser-Agent: NTRIP test\r\nNtrip-Version: Ntrip/2.0\r\n\r\n')
sclient.settimeout(5)
sclient.recv(1024)

def wait_packet():
  data = b''
  try:
    while testlib.rtcm_1006 not in data:
      d = sclient.recv(10240)
      if not d:
        break
      data += d
  except socket.timeout:
    pass
  return testlib.rtcm_1006 in data

ssource.sendall(testlib.rtcm_1006)
if not wait_packet():
  print("FAIL: no data before the reload")
  err += 1

# Same configuration, without the rtcm_filter block
with open(CONFIG, 'w') as out:
  out.write(conf.split('rtcm_filter:')[0])
err += testlib.API_reload(HOST, PORT)
time.sleep(.5)

# Any input from the client makes its connection pick up the new configuration
sclient.sendall(b'\r\n')
time.sleep(.5)
ssource.sendall(testlib.rtcm_1006)
time.sleep(1)

if not wait_packet():
  print("FAIL: no data after the reload")
  err += 1
else:
  print(".")

ssource.close()
sclient.close()
os.unlink(CONFIG)
sys.exit(err)
