#!/usr/bin/env python3

import sys

import testlib

#
# A livesource table from a node whose "livesources" or "endpoints" is of the wrong JSON type.
#
# livesource_process_fulltable() checked both were present, then handed "livesources" to
# json_object_iter_begin() and "endpoints" to json_object_array_length(). Both only assert
# their argument's type, so with a library built -DNDEBUG they reinterpret the value union
# of whatever was sent and the caster crashes; with asserts in, it aborts. A table of the
# wrong shape must be refused instead, and the caster must stay up for the other nodes.
#
# The test starts its own caster on testconfig/caster8.yaml (port 2108). The caster binary
# is $CASTER, by default ../caster/caster.
#

HOST='::1'
PORT=2103
AUTH=b'587e5bbadbc6186fad0d6177eb10a6cd9d5cb934d3d5f155107592535bd20290'

err = 0

# not TEST1: testlib.TestServerAlive() probes that mountpoint
GOOD_LS = {"SYNC1": {"state": "RUNNING", "type": "DIRECT"}}
GOOD_EP = [{"host": "::1", "port": 2108, "tls": False}]


def table(livesources=GOOD_LS, endpoints=GOOD_EP, serial=1):
  return {"type": "fulltable", "hostname": "peer1.example", "serial": serial,
          "start_date": "2026-01-01 00:00:00",
          "endpoints": endpoints, "livesources": livesources}


# Everything but an object under "livesources", and everything but an array under
# "endpoints". A JSON null is not tested: json_object_object_get() returns NULL for it, so
# it is caught by the existing presence check.
sync = testlib.SyncPoster(HOST, PORT)

cases = [
  ("livesources is a string",	table(livesources="SYNC1")),
  ("livesources is an array",	table(livesources=[{"mountpoint": "SYNC1"}])),
  ("livesources is a number",	table(livesources=1)),
  ("livesources is a boolean",	table(livesources=True)),
  ("endpoints is a string",	table(endpoints="::1:2108")),
  ("endpoints is an object",	table(endpoints={"host": "::1", "port": 2108, "tls": False})),
  ("endpoints is a number",	table(endpoints=1)),
]


for what, body in cases:
  st = sync.post(body, AUTH)
  if st == 0:
    print("FAIL: %s: no answer, caster gone" % what)
    err += 1
    break
  if st == 200:
    print("FAIL: %s: table accepted" % what)
    err += 1
  if testlib.TestServerAlive(HOST, PORT):
    print("FAIL: %s: caster no longer serving" % what)
    err += 1
    break

# A well-formed table must still be accepted after all that
if not err:
  st = sync.post(table(), AUTH)
  if st != 200:
    print("FAIL: well-formed table refused with status %d" % st)
    err += 1

sync.close()
sys.exit(err)
