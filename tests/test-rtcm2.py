#!/usr/local/bin/python3

import sys
import time

import testlib

#
# RTCM 1005-1006 + NEAR memory leak test
#

HOST='::1'
PORT=2103

err = 0

rtcm_1006 = b"\xd3\x00\x15\x3e\xe0\x00\x03\x89\xc8\x55\xac\xd7\x80\x71\x2a\x81\xc9\x8b\x20\x8b\x7f\x54\x00\x00\x7c\x4f\x32"

source_stream = testlib.SourceStream((HOST, PORT), "C77", "test1:testpw!", 20000000000000, packet_delay=1, packet=rtcm_1006)
source_stream.start()
time.sleep(.1)
client_stream = testlib.ClientStream((HOST, PORT), "V", 200000000,
  firstline="$GNGGA,104710.00,4832.5844943,N,00229.8320136,E,5,12,0.84,80.418,M,46.332,M,1.0,0000*5A\r\n")
client_stream.start()
client_stream.join(1.1)
client_stream.stop()
err += client_stream.err
source_stream.stop()
if err:
  print("FAIL")
sys.exit(err)
