#!/usr/local/bin/python3

import sys

import testlib

#
# RTCM test
#

HOST='::1'
PORT=2103

err = 0

rtcm_1006 = b"\xd3\x00\x15\x3e\xe0\x00\x03\x89\xc8\x55\xac\xd7\x80\x71\x2a\x81\xc9\x8b\x20\x8b\x7f\x54\x00\x00\x7c\x4f\x32"

source_stream = testlib.SourceStream((HOST, PORT), "C77", "test1:testpw!", 20000000000000, start_delay=1, packet_delay=0.0001, packet=rtcm_1006)
client_stream = testlib.ClientStream((HOST, PORT), "C77", 200000000)
source_stream.start()
client_stream.start()
client_stream.join(30)
client_stream.stop()
err += client_stream.err

source_stream.stop()
print()
sys.exit(err)
