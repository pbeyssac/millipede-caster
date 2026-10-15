#!/usr/bin/env python3

import json
import socket
import sys
import time

import testlib

#
# A client too slow to read is dropped for its backlog: the caster must close the connection,
# not leave it subscribed to nothing.
#
# livesource_kill_subscribers_unlocked(), asked to kill backlogged subscribers, unsubscribed
# them but closed only the others (since b402d3c): a slow client was left connected and silent
# until the idle check closed it, 10-20 s later, instead of being closed so it reconnects.
#

HOST='::1'
PORT=2103

source_stream = testlib.SourceStream((HOST, PORT), "C77", "test1:testpw!", 20000000000000, start_delay=1, packet_delay=0.0001, packet=testlib.rtcm_1006)
source_stream.start()

c = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
c.connect((HOST, PORT))
c.sendall(b'GET /C77 HTTP/1.1\r\nUser-Agent: NTRIP test\r\nNtrip-Version: Ntrip/2.0\r\n\r\n')

def nsubscribers():
  # C77's subscriber count from the caster's livesource list, None if C77 is not listed
  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  s.settimeout(10)
  s.connect((HOST, PORT))
  s.sendall(b'GET /adm/api/v1/livesources?user=admin&password=%3dadminpw... HTTP/1.1\r\n\r\n')
  d = b''
  while True:
    r = s.recv(65536)
    if not r:
      break
    d += r
  s.close()
  j = json.loads(d.split(b'\r\n\r\n', 1)[1])
  ls = j.get('LOCAL', {}).get('livesources', {}).get('C77')
  return None if ls is None else ls.get('nsubscribers')

# Do not read: the caster's output to us backs up past backlog_evbuffer, and it drops us
# (our subscription goes away). How long that takes depends on the caster's speed.
time.sleep(2)
end = time.time() + 60
while time.time() < end and nsubscribers() != 0:
  time.sleep(.5)
if nsubscribers() != 0:
  print("FAIL: the caster did not drop the backlogged client within 60 s")
  sys.exit(1)

# Now read: the caster must have closed the connection, so we get its backlog then EOF
c.settimeout(1)
err = 0
t0 = time.time()
closed = False
while time.time() - t0 < 5:
  try:
    d = c.recv(65536)
  except socket.timeout:
    continue
  except ConnectionResetError:
    closed = True
    break
  if not d:
    closed = True
    break
c.close()
source_stream.stop()

if not closed:
  print("FAIL: backlogged client not closed within 5 s of reading")
  err = 1
else:
  print("closed after %.1f s of reading" % (time.time() - t0))

if testlib.TestServerAlive(HOST, PORT):
  print("FAIL: caster not answering")
  err = 1
sys.exit(err)
