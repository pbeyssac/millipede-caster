Millipede 0.3
=============


Millipede is a high-performance NTRIP caster written in C for the [CentipedeRTK](https://github.com/CentipedeRTK) project, a network of [RTK](https://en.wikipedia.org/wiki/Real-time_kinematic_positioning) bases based in France (see https://centipede.fr).


Millipede uses libevent2 for minimal memory footprint.

It can easily handle tens of thousands of NTRIP sessions on a minimal server.

Currently runs on FreeBSD.

Features:
 * "Virtual" base algorithm which picks the nearest base from the source table
 * High performance
 * Low memory footprint
 * Supports IPv6 and IPv4
 * NTRIP proxy to fetch from an external caster
 * On-demand stream subscription

The current version requires:
 * libcyaml
 * libevent2

Building
========

`cd caster; make`

Installation
============

1. `cd caster; sudo make install`
2. Create configuration files in (default) `/usr/local/etc/millipede/`,
   samples in `sample-config/`.
	* `caster.yaml` main configuration file
	* `sourcetable.dat` our local sourcetable
	* `source.auth` authentication of sources from our sourcetable
	* `host.auth` authentication as a client to other hosts

Running
=======

Start the `/usr/local/sbin/millipede` binary.

A start/restart/stop script for FreeBSD is provided as `sample-config/caster.sh` and can be installed in `/usr/local/etc/rc.d`.

Documentation
=============

There are 3 main functions the caster can fulfill simulataneously, configured from `caster.yaml`.

## Regular NTRIP caster

Configure `sourcetable.dat` for the local sources, `source.auth` for their authentication, and the `listen` section for the IP addresses to listen on.

## NTRIP proxy

Configure the `proxy` section with a reference caster.

The local caster will fetch the sourcetable from the reference caster at `table_refresh_delay` (in seconds) intervals, and announce it merged with its own sourcetable.

Sources will be fetched and served to clients on-demand from the reference caster.

## "V" base

Should be declared in the local sourcetable (see default config) with its "virtual" field (12th field) set to "1".

When a NTRIP client connects to this base and announces its location through $G*GGA NMEA lines, the caster will serve it the nearest base from its general sourcetable (local + proxy), switching over time when the client moves.
