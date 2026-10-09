#!/usr/bin/env python3

import sys

import testlib

#
# A differential livesource update from a node that names no mountpoint.
#
# livesource_update_execute_diff() read "mountpoint" out of the update and passed it
# straight to hash_table_get(), which hashes the string: an update with the key absent (or
# holding anything but a string) crashed the caster on a NULL pointer. The update must be
# refused, the table left alone, and the serial not consumed.
#

HOST='::1'
PORT=2103
AUTH=b'587e5bbadbc6186fad0d6177eb10a6cd9d5cb934d3d5f155107592535bd20290'
HOSTNAME='peer1.example'
START='2026-01-01 00:00:00'
SERIAL=7

err = 0


def diff(type, livesource, serial=SERIAL):
  return {"type": type, "hostname": HOSTNAME, "serial": serial,
          "start_date": START, "livesource": livesource}


sync = testlib.SyncPoster(HOST, PORT)

# The node must be known before it can send differential updates
st = sync.post({"type": "fulltable", "hostname": HOSTNAME, "serial": SERIAL,
  "start_date": START, "endpoints": [{"host": "::1", "port": 2108, "tls": False}],
  "livesources": {"SYNC1": {"state": "RUNNING", "type": "DIRECT"}}}, AUTH)
if st != 200:
  print("FAIL: initial table refused with status %d" % st)
  err += 1

# A non-string "mountpoint" is not tested: json_object_get_string() serializes it rather
# than returning NULL, so it arrives as a (nonsensical) name and is handled as one.
cases = [
  ("add with no mountpoint",		diff("add", {"state": "RUNNING", "type": "DIRECT"})),
  ("update with no mountpoint",		diff("update", {"state": "INIT", "type": "DIRECT"})),
  ("del with no mountpoint",		diff("del", {})),
]

if not err:
  for what, body in cases:
    st = sync.post(body, AUTH)
    print(".", end='')
    if st == 0:
      print("FAIL: %s: no answer, caster gone" % what)
      err += 1
      break
    if st == 200:
      print("FAIL: %s: update accepted" % what)
      err += 1
    if testlib.TestServerAlive(HOST, PORT):
      print("FAIL: %s: caster no longer serving" % what)
      err += 1
      break

# The refusals must not have consumed the serial: a well-formed "add" still fits at SERIAL
if not err:
  st = sync.post(diff("add", {"mountpoint": "SYNC2", "state": "RUNNING", "type": "DIRECT"}), AUTH)
  print(".", end='')
  if st != 200:
    print("FAIL: well-formed add refused with status %d" % st)
    err += 1

if not err:
  print()

sync.close()
sys.exit(err)
