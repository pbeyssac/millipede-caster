#!/usr/local/bin/python3

import sys
import time


import testlib


HOST='::1'
PORT=2103

err = 0

source1 = testlib.SourceStream((HOST, PORT), "C63", "test1:testpw!", 2000)
source1.start()
source2 = testlib.SourceStream((HOST, PORT), "C43", "test1:testpw!", 2000)
source2.start()

s = "$GNGGA,172829.20,4546.2000000,N,00306.0000000,E,5,12,0.68,158.545,M,47.390,M,1.2,0000*6F\r\n"

#
# Check for seamless base switch in case the current base dies
#
client_stream = testlib.ClientStream((HOST, PORT), "V", 400, s)
client_stream.start()
time.sleep(.1)
client_stream.set_expect("^C63 \d+$")
time.sleep(2)
client_stream.set_expect("^C(43|63) \d+$")
source1.stop()
time.sleep(1)
client_stream.set_expect("^C43 \d+$")
client_stream.join(3)
source3 = testlib.SourceStream((HOST, PORT), "C63", "test1:testpw!", 2000)
client_stream.set_expect("^C(43|63) \d+$")
source3.start()
time.sleep(1)
client_stream.set_expect("^C63 \d+$")
source2.stop()
client_stream.join(3)
client_stream.stop()
err += client_stream.err

print()
sys.exit(err)
