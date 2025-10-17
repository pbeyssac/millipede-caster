#!/usr/local/bin/python3

import base64
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
    self.mountpoint = mountpoint
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
        % (self.mountpoint.encode('ascii'), self.b64userpass))
    sdata = ssource.recv(10240)
    self._ok = True
    for i in range(self.n):
      if self._stop:
        break
      ssource.sendall(b'%d\n' % i)
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
  def __init__(self, host, mountpoint, n, firstline=''):
    self.host = host
    self.n = n
    self.mountpoint = mountpoint
    self.err = 0
    self.firstline = firstline.encode('ascii')
    self._stop = False
  def start(self):
    self._thr = threading.Thread(target=self._run, daemon=True, args=())
    self._thr.start()
  def _run(self):
    sclient = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sclient.connect(self.host)
    sclient.sendall(b'GET /%s HTTP/1.1\r\nUser-Agent: NTRIP test\r\n\r\n'
        % self.mountpoint.encode('ascii'))

    if self.firstline:
      sclient.send(self.firstline)

    for i in range(self.n):
      if self._stop:
        break
      data = sclient.recv(10240)
      if data == b'':
        print("FAIL: unexpected stop")
        self.err = 1
        break
      print(".", end='')
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
