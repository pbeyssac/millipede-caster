#!/usr/local/bin/python3

import re
import socket
import sys
import threading
import time

#
# fetched source test
#

HOST='::1'
PORT=2103
FAKE_SERVER_PORT=2163

sourcetable = b"""CAS;castera.ntrip.eu.org;2101;NTRIP-Caster-2.0.45;INRAE;0;FRA;48.82;2.34;0.0.0.0;0;http://caster.centipede.fr/home\r
NET;CENTIPEDE-RTK;INRAE;B;N;https://centipede.fr;https://docs.centipede.fr;contact@centipede.fr;none\r
STR;TEST1;TEST1;RTCM3;1004,1005(10),1006,1008(10),1012,1019,1020,1033(10),1042,1045,1046,1077,1087,1097,1107,1127,1230;;GPS+GLO+GAL+BDS+QZS;NONE;NONE;48.824;2.344;0;0;RTKBase_U-blox_ZED-F9P,2.5.0;NONE;N;N;;\r
STR;C63;C63;RTCM3;1004,1005,1006,1008,1012,1019,1020,1033,1042,1045,1046,1077,1087,1097,1107,1127,1230;;GPS+GLO+GAL+BDS+QZS;NONE;NONE;45.77;3.1;0;0;Test 63,0;NONE;N;N;;\r
"""

err = 0

def source_server():
  global err
  nr = 0

  sl = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  sl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sl.bind((HOST, FAKE_SERVER_PORT))
  sl.listen(200)

  str_request = b'^GET (/.*) HTTP/1\.[01]'
  re_request = re.compile(str_request)

  for i in range(1000):
    (s, remote_addr) = sl.accept()
    print("Fake server accepted connection")
    s.settimeout(20)

    data = b''
    d = s.recv(10240)
    try:
      while d != b'':
        data += d
        if b'\r\n\r\n' in data:
          req, rest = data.split(b'\r\n\r\n', 1)
          m = re_request.match(req)
          if m is None:
            print("expected", str_request, "received", req)
            err += 1
            print("FAIL")
            break
          uri = m.groups(0)[0]
          print("URI", uri)
          try:
            if uri == b'/':
              s.send(b'HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n%sENDSOURCETABLE\r\n' % sourcetable)
            elif uri == b'/C63':
              s.send(b'HTTP/1.0 200 OK\r\n\r\n')
              for j in range(500):
                s.send(b'%d\r\n' % j)
                time.sleep(1)
          except BrokenPipeError:
            s.close()
            break
          s.close()
          break
        else:
          d = s.recv(10240)
    except socket.timeout:
        d = b''
        err += 1
        print("FAIL")


def source_client():
  global err
  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  try:
    s.connect((HOST, PORT))
  except ConnectionRefusedError:
    err += 1
    print("FAIL")
    return
  s.sendall(b'GET /C63 HTTP/1.1\r\n\r\n')
  for i in range(5):
    d = s.recv(10240)
    if d == b'':
      break
    print('.', end='')
    sys.stdout.flush()
  print()


print("Starting server")
thr1 = threading.Thread(target=source_server, daemon=True, args=())
thr1.start()
time.sleep(15)

for j in range(2):
  print("Starting client")
  thr2 = threading.Thread(target=source_client, daemon=True, args=())
  thr2.start()
  thr2.join()
  time.sleep(10)

sys.exit(err)
