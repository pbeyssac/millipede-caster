#!/bin/sh

for i in 1 2 3 4 5 6 7 8 9; do
  cp -pf testconfig/caster3a.yaml testconfig/caster3.yaml
  echo kill $i-1
  kill -HUP ${RUNNING_PID}
  sleep 5
  echo kill $i-2
  cp -pf testconfig/caster3b.yaml testconfig/caster3.yaml
  kill -HUP ${RUNNING_PID}
  sleep 5
done
