#!/usr/bin/env python3

import base64
import os
import shutil
import socket
import sys
import threading

import testlib

#
# Livesource changes during reloads that change the number of sync nodes (caster9.yaml,
# switched between caster9a.yaml, 1 node, and caster9b.yaml, 3 nodes, before each reload).
#
# syncer_queue() read this->ntask without the lock, then took the task array under the lock:
# a reload changing the node count in between made it walk past the end of the array it had
# just allocated (fewer nodes), or leave task references behind (more nodes).
#

HOST='::1'
PORT=2103
NSOURCES=6
NRELOADS=400
CONFIG='testconfig/caster9.yaml'
CONFIGS=('testconfig/caster9a.yaml', 'testconfig/caster9b.yaml')

auth = base64.b64encode(b'wildcard_user:wildcard_pw//')
stop = threading.Event()

def source(i):
  # register a source, send one packet, go away; again until stopped
  while not stop.is_set():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
      s.connect((HOST, PORT))
      s.sendall(b'POST /NODES%d HTTP/1.1\r\nUser-Agent: NTRIP test\r\nAuthorization: Basic %s\r\n\r\n' % (i, auth))
      s.recv(1024)
      s.sendall(testlib.rtcm_1006)
    except OSError:
      pass
    s.close()

def use_config(src):
  # replace the file rather than write into it: the test configuration files are read-only
  tmp = CONFIG + '.tmp'
  shutil.copy2(src, tmp)
  os.replace(tmp, CONFIG)

threads = [threading.Thread(target=source, args=(i,)) for i in range(NSOURCES)]
for t in threads:
  t.start()

post_str = b'POST /adm/api/v1/reload HTTP/1.1\r\nContent-Length: 33\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&password=%3dadminpw...'
err = 0
for i in range(NRELOADS):
  use_config(CONFIGS[(i + 1) % 2])
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
use_config(CONFIGS[0])

if not err and testlib.TestServerAlive(HOST, PORT):
  print("FAIL: caster not answering after %d reloads" % NRELOADS)
  err = 1

sys.exit(err)
