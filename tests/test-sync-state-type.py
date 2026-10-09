#!/usr/bin/env python3

import json
import sys

import testlib

#
# A livesource table from a node whose entries carry no usable "state"/"type".
#
# convert_state()/convert_type() ran strcmp() on the value without testing it, so an entry
# with the key missing (or holding anything but a string) crashed the caster on a NULL
# argument. An unrecognized name was no better: both converters return -1 and the value was
# stored as-is, so livesource_remote_json() later indexed livesource_types[-1] when the
# table was serialized back for /adm/api/v1/livesources.
#
# Either way a single peer -- an older version, a different spelling -- takes the caster
# down. Entries that cannot be converted are now ignored, and the rest of the table kept.
#

HOST='::1'
PORT=2103
AUTH=b'587e5bbadbc6186fad0d6177eb10a6cd9d5cb934d3d5f155107592535bd20290'

err = 0


def table(livesources, serial=1):
  return {"type": "fulltable", "hostname": "peer1.example", "serial": serial,
          "start_date": "2026-01-01 00:00:00",
          "endpoints": [{"host": "::1", "port": 2108, "tls": False}],
          "livesources": livesources}


# Each table mixes one usable entry with one the converters must refuse: no "state"/"type"
# at all, a non-string value, an unknown name, and the right names in the wrong case.
cases = [
  ("missing state and type",	{"GOOD1": {"state": "RUNNING", "type": "DIRECT"},
				 "BAD1": {}}),
  ("state and type not strings",	{"GOOD1": {"state": "RUNNING", "type": "DIRECT"},
					 "BAD2": {"state": 1, "type": []}}),
  ("unknown state name",	{"GOOD1": {"state": "RUNNING", "type": "DIRECT"},
				 "BAD3": {"state": "ZOMBIE", "type": "DIRECT"}}),
  ("unknown type name",		{"GOOD1": {"state": "RUNNING", "type": "DIRECT"},
				 "BAD4": {"state": "RUNNING", "type": "GUESSED"}}),
  ("names in the wrong case",	{"GOOD1": {"state": "RUNNING", "type": "DIRECT"},
				 "BAD5": {"state": "running", "type": "direct"}}),
]

sync = testlib.SyncPoster(HOST, PORT)

for serial, (what, ls) in enumerate(cases, 1):
  st = sync.post(table(ls, serial), AUTH)
  if st != 200:
    print("FAIL: %s: table refused with status %d" % (what, st))
    err += 1
    break

  # Serializing the table back out is what reads livesource_types[]
  body = testlib.admin_get(HOST, PORT, '/adm/api/v1/livesources')
  if body is None:
    print("FAIL: %s: no livesource list after the update" % what)
    err += 1
    break
  try:
    j = json.loads(body)
  except ValueError:
    print("FAIL: %s: livesource list is not JSON: %r" % (what, body[:200]))
    err += 1
    break

  peer = j.get('peer1.example')
  if peer is None:
    print("FAIL: %s: node missing from the livesource list" % what)
    err += 1
    break
  got = sorted(peer.get('livesources', {}))
  if got != ['GOOD1']:
    print("FAIL: %s: expected GOOD1 alone, got %s" % (what, got))
    err += 1

sync.close()

if not err:
  print(".")
sys.exit(err)
