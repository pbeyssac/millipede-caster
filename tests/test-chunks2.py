#!/usr/local/bin/python3

import socket
import sys
import time


import testlib

#
# Wrong chunk len hang test
#

HOST='::1'
PORT=2103

err = 0

ssource = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
ssource.connect((HOST, PORT))
ssource.sendall(b'POST /TEST1 HTTP/1.1\nUser-Agent: NTRIP test\nAuthorization: Basic dGVzdDE6dGVzdHB3IQ==\nTransfer-Encoding: chunked\r\n\r\nzzz\r\n')
time.sleep(.01)
ssource.sendall(b'ZZZ')

err += testlib.TestServerAlive(HOST, PORT)

print()
sys.exit(err)
