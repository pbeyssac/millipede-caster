#!/usr/bin/env python3

import socket
import sys

#
# Sourcetable requests pipelined on a keep-alive connection.
#
# After answering a keep-alive sourcetable request, ntripsrv_readcb() went back to the next
# request with "continue", skipping the free of the line it had just read (the empty line
# ending the headers). The next request's line overwrote it: one leak per pipelined
# sourcetable request, unbounded on a long-running caster. Under the runner's memcheck mode
# valgrind reports it as definitely lost; here every request must also get its answer.
#
# Runs on testconfig/caster.yaml (port 2103).
#

HOST='::1'
PORT=2103
N=5

req = (b'GET / HTTP/1.1\r\nHost: [::1]:2103\r\nNtrip-Version: Ntrip/2.0\r\n'
       b'User-Agent: NTRIP test\r\nConnection: keep-alive\r\n\r\n')

err = 0
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((HOST, PORT))
s.sendall(req * N)

data = b''
try:
  while data.count(b'HTTP/1.1 200') < N:
    d = s.recv(65536)
    if not d:
      break
    data += d
except (OSError, TimeoutError):
  pass
s.close()

n = data.count(b'HTTP/1.1 200')
if n != N:
  print("FAIL: %d answers to %d pipelined sourcetable requests" % (n, N))
  err = 1
else:
  print(".")
sys.exit(err)
