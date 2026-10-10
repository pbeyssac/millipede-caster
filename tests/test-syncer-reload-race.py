#!/usr/bin/env python3

import base64
import socket
import sys
import threading

import testlib

#
# Livesource changes during reloads, on a caster with a node: block (caster8.yaml).
#
# A reload hands the syncer to the new configuration and sets the entry in the old one to NULL
# (caster_reload_syncers()), while the old configuration is still the current one and
# syncers_count is still 1. A source registering or going away in that window reached
# syncer_queue() with a NULL syncer: SIGSEGV.
#

HOST='::1'
PORT=2103
NSOURCES=6
NRELOADS=400

auth = base64.b64encode(b'wildcard_user:wildcard_pw//')
stop = threading.Event()

def source(i):
  # register a source, send one packet, go away; again until stopped
  while not stop.is_set():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
      s.connect((HOST, PORT))
      s.sendall(b'POST /RACE%d HTTP/1.1\r\nUser-Agent: NTRIP test\r\nAuthorization: Basic %s\r\n\r\n' % (i, auth))
      s.recv(1024)
      s.sendall(testlib.rtcm_1006)
    except OSError:
      pass
    s.close()

threads = [threading.Thread(target=source, args=(i,)) for i in range(NSOURCES)]
for t in threads:
  t.start()

post_str = b'POST /adm/api/v1/reload HTTP/1.1\r\nContent-Length: 33\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&password=%3dadminpw...'
err = 0
for i in range(NRELOADS):
  try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((HOST, PORT))
    s.sendall(post_str)
    r = s.recv(1024)
    s.close()
  except OSError as e:
    print("FAIL: caster gone at reload %d (%s)" % (i, e))
    err = 1
    break
  if not r.endswith(b'\r\n\r\n{"result": 0}\n'):
    print("FAIL: reload %d got" % i, r)
    err = 1
    break
  print(".", end='')
  sys.stdout.flush()

print()
stop.set()
for t in threads:
  t.join()

if not err and testlib.TestServerAlive(HOST, PORT):
  print("FAIL: caster not answering after %d reloads" % NRELOADS)
  err = 1

sys.exit(err)
