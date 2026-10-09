#!/usr/bin/env python3

import os
import signal
import subprocess
import sys
import time

#
# Graylog sender retries: with the Graylog server unreachable, the sender must back off
# (retry_delay, doubling up to max_retry_delay). max_retry_delay had no default, so after the
# first retry the delay was capped to 0 and the caster reconnected in a tight loop: about
# 650 000 attempts in 10 s, and as many log lines.
#
# Should be tested with a caster having config test-caster5.yaml
#

LOG='test-caster.log'
DURATION=5
LOG_MAX=1000000

err = 0

# Stop early if the log explodes
end = time.time() + DURATION
while time.time() < end:
  time.sleep(.2)
  if os.path.exists(LOG) and os.path.getsize(LOG) > LOG_MAX:
    break

# Default retry_delay 1 s: attempts at about 0, 1 and 3 s
n = 0
with open(LOG, 'rb') as f:
  for line in f:
    if b'Starting graylog_sender from' in line:
      n += 1

if n == 0 or n > 10:
  print("FAIL: %d connection attempts to Graylog in %d s" % (n, DURATION))
  err += 1
else:
  print(".")
sys.exit(err)
