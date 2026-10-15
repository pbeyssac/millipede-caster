#!/usr/bin/env python3

import base64
import socket
import sys
import threading

import testlib

#
# A source and its clients going away at the same moment, again and again (caster8.yaml).
#
# livesource_del_subscriber() read st->subscription, then sub->livesource, with no lock held,
# while the departing source could drop and free that subscription
# (livesource_kill_subscribers_unlocked()): a use-after-free. The window is a few instructions;
# this exercises it for the sanitizers and valgrind, and checks the caster survives.
#

HOST='::1'
PORT=2103
NWORKERS=4
NROUNDS=50
NCLIENTS=6

auth = base64.b64encode(b'wildcard_user:wildcard_pw//')
err = 0

def one_round(k):
  mp = b'SUB%d' % (k % 4)
  src = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  src.settimeout(5)
  src.connect((HOST, PORT))
  src.sendall(b'POST /%s HTTP/1.1\r\nUser-Agent: NTRIP test\r\nAuthorization: Basic %s\r\n\r\n' % (mp, auth))
  src.recv(1024)
  src.sendall(testlib.rtcm_1006)
  clients = []
  for i in range(NCLIENTS):
    c = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    c.settimeout(5)
    c.connect((HOST, PORT))
    c.sendall(b'GET /%s HTTP/1.1\r\nUser-Agent: NTRIP test\r\nNtrip-Version: Ntrip/2.0\r\n\r\n' % mp)
    clients.append(c)
  src.sendall(testlib.rtcm_1006 * 3)
  for c in clients:
    try:
      c.recv(1024)
    except OSError:
      pass
  # everyone leaves at once
  src.close()
  for c in clients:
    c.close()

def worker(w):
  for k in range(NROUNDS):
    try:
      one_round(w * 1000 + k)
    except OSError:
      pass

threads = [threading.Thread(target=worker, args=(w,)) for w in range(NWORKERS)]
for t in threads:
  t.start()
for t in threads:
  t.join()

if testlib.TestServerAlive(HOST, PORT):
  print("FAIL: caster not answering")
  err = 1

sys.exit(err)
