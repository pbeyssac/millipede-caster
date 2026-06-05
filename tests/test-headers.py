#!/usr/local/bin/python3

import socket
import sys
import time

import testlib

#
# Fetched source test: memory leak on client side.
#
# Will not return an error, use with valgrind --memcheck
#

HOST='::1'
PORT=2103
FAKE_SERVER_PORT=2163

print("Starting server")
source_server = testlib.SourceServer((HOST, FAKE_SERVER_PORT), 'C63',
    raw_headers='Content-Type: xxx\nContent-Type: xxx\nUser-Agent: xyz\nUser-Agent: xyz\nSource-Agent: xyz\n')
source_server.start()

err = 0

print("Starting client")
client_stream = testlib.ClientStream((HOST, PORT), "C63", 1, '')
client_stream.start()
client_stream.join(None)

time.sleep(2)
source_server.stop()

err += client_stream.err
err += source_server.err
if err:
  print("FAILED")
else:
  print()

sys.exit(err)
