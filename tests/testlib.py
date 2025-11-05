#!/usr/local/bin/python3

import base64
import re
import socket
import sys
import threading
import time


#
# Source stream to server on a given mountpoint, user+password, number of samples
#
class SourceStream(object):
  def __init__(self, host, mountpoint, userpass, n):
    self._stop = False
    self._ok = False
    self.host = host
    self.mountpoint = mountpoint.encode('ascii')
    self.b64userpass = base64.b64encode(userpass.encode('ascii'))
    self.n = n
  def start(self):
    self._thr = threading.Thread(target=self._run, daemon=True, args=())
    self._thr.start()
    # Give time for the source to start
    while not self._ok and self.is_alive():
      time.sleep(.1)
  def _run(self):
    ssource = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    ssource.connect(self.host)
    ssource.sendall(b'POST /%s HTTP/1.1\nUser-Agent: NTRIP test\nAuthorization: Basic %s\n\n'
        % (self.mountpoint, self.b64userpass))
    sdata = ssource.recv(10240)
    self._ok = True
    for i in range(self.n):
      if self._stop:
        break
      ssource.sendall(b'%s %d\n' % (self.mountpoint, i))
      time.sleep(1)
    ssource.close()
  def stop(self):
    self._stop = True
  def is_alive(self):
    return self._thr.is_alive()

#
# Client stream to server on a given mountpoint: wait for n samples
#
class ClientStream(object):
  def __init__(self, host, mountpoint, n, firstline='', req=None):
    self.mountpoint = mountpoint
    self.req = req or b'GET /%s HTTP/1.1\r\nUser-Agent: NTRIP test\r\n\r\n' % self.mountpoint.encode('ascii')
    self.host = host
    self.n = n
    self.err = 0
    self.firstline = firstline.encode('ascii')
    self._stop = False
    self.re_expect = None
  def set_expect(self, re_expect):
    self.re_expect = None if re_expect is None else re.compile(re_expect.encode('ascii'))
  def start(self):
    self._thr = threading.Thread(target=self._run, daemon=True, args=())
    self._thr.start()
  def _run(self):
    sclient = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sclient.connect(self.host)
    sclient.sendall(self.req)

    if self.firstline:
      sclient.send(self.firstline)

    for i in range(self.n):
      if self._stop:
        break
      data = sclient.recv(10240)
      if data == b'':
        print("FAIL: unexpected stop")
        self.err += 1
        break
      if not self.re_expect:
        print(".", end='')
      elif self.re_expect.match(data):
        print(".", end='')
      else:
        print("Got", data)
        print("X", end='')
        self.err += 1
      sys.stdout.flush()
    if self.n:
      print()
    sclient.close()
  def is_alive(self):
    return self._thr.is_alive()
  def join(self, timeout):
    self._thr.join(timeout)
  def stop(self):
    self._stop = True

#
# Send an API reload command and check reply
#
def API_reload(host, port):
  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  s.connect((host, port))
  print("Reload")
  s.sendall(b'POST /adm/api/v1/reload HTTP/1.1\r\nContent-Length: 33\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&password=%3dadminpw...')
  s.settimeout(2)
  try:
    d = s.recv(10240)
  except TimeoutError:
    return 1
  s.close()
  if not re.compile(b'^HTTP/1\.1 200 OK\r\nServer: NTRIP Millipede Server .*\r\nDate: .*\r\nNtrip-Version: Ntrip/2\.0\r\nContent-Length: \d+\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{"result": 0}').match(d):
    return 1
  return 0

#
# Fake HTTP server
#
class HttpServer(object):
  def __init__(self, host, port, str_request, maxaccept, timeout=20, keepalive=False):
    self.err = 0
    self.nr = 0
    self.naccept = 0
    self.host = host
    self.port = port
    self.str_request = str_request
    self.re_request = re.compile(self.str_request)
    self.maxaccept = maxaccept
    self.timeout = timeout
    self._stop = False
    self.replies = [
      b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 4\r\n\r\nABCD',
      b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n',
      b'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nAB\r\n0\r\n\r\n'
    ]
    if not keepalive:
      self.replies.append(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\nABCD')
  def start(self):
    self._thr = threading.Thread(target=self.run, daemon=True, args=())
    self._thr.start()
  def stop(self):
    self._stop = True
  def is_alive(self):
    return self._thr.is_alive()
  def run(self):
    self.nr = 0
    self.naccept = 0
    sl = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sl.bind((self.host, self.port))
    sl.listen(200)

    for i in range(self.maxaccept):
      (s, remote_addr) = sl.accept()
      self.naccept += 1
      ncurrent = 0
      print("Accepted", i+1)
      s.settimeout(self.timeout)

      data = b''
      d = s.recv(10240)
      try:
        while d != b'':
          if self._stop:
            return
          ncurrent += 1
          data += d
          if b'\r\n\r\n' in data:
            req, rest = data.split(b'\r\n\r\n', 1)
            m = self.re_request.match(req)
            if m is None:
              print("FAIL: expected", str_request, "received", req)
              self.err += 1
              length = 0
            else:
              print(req)
              print(".", end='')
              length = int(m.groups(0)[0])
            data = rest
            while len(data) < length:
              d = s.recv(10240)
              data += d
            s.send(self.replies[self.nr % len(self.replies)])
            self.nr += 1
            data = b''
          d = s.recv(10240)
        if ncurrent == 0:
          print("FAIL: empty client request")
          self.err += 1
      except socket.timeout:
        d = b''
        self.err += 1
        print("FAIL: timeout")


def TestServerAlive(host, port):
  s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
  try:
    s.connect((host, port))
  except ConnectionRefusedError:
    return 1
  return 0
