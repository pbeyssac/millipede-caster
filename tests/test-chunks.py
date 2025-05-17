#!/usr/local/bin/python3

import re
import socket
import sys

#
# send/expect tests
#

HOST='::1'
PORT=2103

test_series = [
  [(b'AB\r\n', b'AB'),
   (b'b\r\n12345', b'^12345$'),
   (b'6789A\n\r\n8\r\nABCDEFG\n\r\n', b'^6789A\nABCDEFG\n$'),
   (b'4\r\nDEF\n\r\n', b'^DEF\n$'),
   (b'0\r\n\r\n', b'^$'),
  ],
  [(b'CD\r\n', b'CD'),
   (b'a\r\n012345678\n', b'^012345678\n$'),
   (b'\r\n9\r\n022345678\r\na', b'^022345678$'),
   (b'\r\n032345678\n\r\n', b'^032345678\n$'),
   (b'0\r\n\r\na\r\n012345678\n\r\n', b'^$'),
  ],
  [(b'EF\r\n', b'EF'),
   (b'W\r\n01234', b'^$'),
  ],
  [(b'EF\r\nW\r\nVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV', b'^$'),
  ],
]

err = 0

for tests in test_series:
  ssource = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  ssource.connect((HOST, PORT))

  # include a chunk len right after the headers, to check it is not lost
  # but not a full chunk as it would be dropped for lack of clients.
  ssource.sendall(b'POST /TEST1 HTTP/1.1\nUser-Agent: NTRIP test\nAuthorization: Basic dGVzdDE6dGVzdHB3IQ==\nTransfer-Encoding: chunked\n\n2\r\n')
  sdata = ssource.recv(1024)

  sclient = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  sclient.connect((HOST, PORT))
  sclient.sendall(b'GET /TEST1 HTTP/1.1\nUser-Agent: NTRIP test\n\n')
  sclient.recv(1024)

  for send, expect in tests:
    ssource.sendall(send)
    data = sclient.recv(1024)
    if re.match(expect, data):
      print(".", end='')
    else:
      print("FAIL\nSent: %s Expected: %s Got: %s" % (send, expect, data))
      err = 1

  ssource.close()
  sclient.close()

print()
sys.exit(err)
