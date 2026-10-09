#!/usr/bin/env python3

import re
import socket
import sys
import threading

#
# send/expect tests
#

HOST='::1'

err = 0

def run():
  global err
  nr = 0
  for port, str_request in [
      (9999, b'^POST /adm/api/v1/sync HTTP/1\\.1\r\n(?s:.)*Content-Length: (\\d+)\r\n'),
      (9998, b'^POST /gelf HTTP/1\\.1\r\n(?s:.)*Content-Length: (\\d+)\r\n')]:
    #str_request = b'^POST (?:/adm/api/v1/sync|//gelf) HTTP/1\\.1\r\n(?s:.)*Content-Length: (\\d+)\r\n'
    re_request = re.compile(str_request)

    for i in range(3):
      sl = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
      sl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sl.bind((HOST, port))
      sl.listen(200)

      (s, remote_addr) = sl.accept()
      print("Accepted")
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
              length = 0
            else:
              print(req)
              print(".", end='')
              length = int(m.groups(0)[0])
            data = rest
            while len(data) < length:
              d = s.recv(10240)
              data += d
            reply = [b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 4\r\n\r\nABCD',
                     b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nAB\r\n0\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\nABCD'][nr % 4]
            print("REPLY", reply)
            s.send(reply)
            nr += 1
            data = b''
          d = s.recv(10240)
      except socket.timeout:
        d = b''
        err += 1
        print("FAIL")

thr = threading.Thread(target=run, daemon=True, args=())
thr.start()
thr.join(120)
if thr.is_alive():
  err += 1
  print("FAIL: timeout")

print()
sys.exit(err)
