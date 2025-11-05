#!/usr/local/bin/python3

import sys

import testlib

#
# Syncer timeout test:
# Check the syncer connection is not closed when it doesn't send anything to the server
#

HOST='::1'
PORT=2103

err = 0

r = b'POST /adm/api/v1/sync HTTP/1.1\r\nContent-Length: 11\r\nAuthorization: internal 587e5bbadbc6186fad0d6177eb10a6cd9d5cb934d3d5f155107592535bd20290\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n{"a":null}\n'

client_stream = testlib.ClientStream((HOST, PORT), None, 30, req=r)
client_stream.start()
client_stream.join(20)

if client_stream.is_alive():
  err += client_stream.err
else:
  err += client_stream.err + 1
  print("FAIL: timeout")

print()
sys.exit(err)
