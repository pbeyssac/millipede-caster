#!/usr/bin/env python3

import sys

import testlib

#
# RTCM test
#

HOST='::1'
PORT=2103

err = 0

source_stream = testlib.SourceStream((HOST, PORT), "C77", "test1:testpw!", 20000000000000, start_delay=1, packet_delay=0.0001, packet=testlib.rtcm_1006)
client_stream = testlib.ClientStream((HOST, PORT), "C77", 200000000)
source_stream.start()
client_stream.start()
client_stream.join(30)
client_stream.stop()
err += client_stream.err

source_stream.stop()
print()
sys.exit(err)
