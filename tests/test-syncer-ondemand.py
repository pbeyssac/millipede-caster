#!/usr/local/bin/python3

import json
import sys
import time

import testlib

#
# Syncer update for an on-demand source: when a client starts an on-demand fetch, the nodes
# must receive an "add" for it. livesource_find_unlocked() tested *jp after setting it to
# NULL, so the "add" was never built, and nodes only got "update"/"del" for a source they
# did not know.
#

HOST='::1'
PORT=2103
FAKE_SERVER_PORT=2163
NODE_PORT=9999

err = 0

def wait_for(cond, timeout):
  end = time.time() + timeout
  while time.time() < end:
    if cond():
      return True
    time.sleep(.1)
  return cond()

def source_updates():
  types = []
  for body in list(sy.bodies):
    try:
      j = json.loads(body)
    except ValueError:
      continue
    ls = j.get('livesource') if isinstance(j, dict) else None
    if ls and ls.get('mountpoint') == 'C63':
      types.append(j.get('type'))
  return types

# The node and the upstream caster first, so the caster finds both at its first attempt
sy = testlib.HttpServer(HOST, NODE_PORT, b'^POST /adm/api/v1/sync HTTP/1\\.1\r\n(?s:.)*Content-Length: (\\d+)\r\n', 1000, timeout=60, keepalive=True)
sy.start()

source_server = testlib.SourceServer((HOST, FAKE_SERVER_PORT), 'C63')
source_server.start()

# C63 is only fetched once the caster has the upstream's sourcetable; a client asking before
# that gets a 404 and creates nothing.
if not wait_for(lambda: source_server.naccept >= 1, 15):
  print("FAIL: the caster did not fetch the sourcetable from port %d" % FAKE_SERVER_PORT)
  err += 1
time.sleep(1)

client_stream = testlib.ClientStream((HOST, PORT), "C63", 3, '')
client_stream.start()
client_stream.join(20)
err += client_stream.err
if client_stream.is_alive():
  print("FAIL: no data from on-demand source C63")
  client_stream.stop()
  err += 1

# Wait for the syncer to deliver the first update for C63, then a little longer for the next
wait_for(lambda: source_updates(), 20)
time.sleep(1)
types = source_updates()

if sy.naccept == 0:
  print("FAIL: the caster never connected to the node on port %d" % NODE_PORT)
  err += 1
elif 'add' not in types:
  print("FAIL: no \"add\" sent to the node for on-demand source C63, got", types)
  err += 1
else:
  print(".")

source_server.stop()
sy.stop()

sys.exit(err)
