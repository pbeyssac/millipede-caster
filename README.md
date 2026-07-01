Millipede 0.8.2
===============


Millipede is a high-performance NTRIP caster written in C for the [Centipede-RTK](https://github.com/CentipedeRTK) project, a network of [RTK](https://en.wikipedia.org/wiki/Real-time_kinematic_positioning) bases based in France (see https://centipede-rtk.org).


Millipede uses libevent2 for minimal memory footprint.

It can easily handle tens of thousands of NTRIP sessions on a minimal server.

Currently runs on FreeBSD and Linux.

Features:
 * "Virtual" "near" base algorithm which picks the nearest base from the source table
 * High performance
 * Low memory footprint
 * Supports IPv6 and IPv4
 * NTRIP proxy to fetch from an external caster
 * TLS/SSL server and client support
 * "blocklist" with quotas per IP prefix
 * On-demand stream subscription
 * "wildcard" base configuration to allow unregistered sources to send hidden streams
 * GELF/Graylog export with bulk mode
 * JSON API for remote administration and monitoring
 * API tool `mapi`
 * Multi-threaded mode

The current version requires:
 * libcyaml
 * libevent2
 * json-c >= 0.16
 * openssl >= 3.0.15

Dependencies
============

FreeBSD: `sudo pkg install libevent libcyaml json-c`

Debian: `sudo apt install libcyaml-dev libevent-dev libjson-c-dev libssl-dev`

Building
========

FreeBSD: `cd caster; make clean depend all`

Debian: `cd caster; make clean all`

Or with CMake (recommended, also used by CI):

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Installation
============

There are two installation paths: the quick install scripts (recommended for
Linux/FreeBSD servers) and the manual installation (for custom setups).

Quick install (Linux systemd or FreeBSD rc.d)
---------------------------------------------

From the root of the source tree:

```
sudo ./install.sh
```

This will:
1. Install build dependencies (apt on Debian, pkg on FreeBSD).
2. Build the caster binary.
3. Create a `caster` system user, `/etc/millipede/` (config) and
   `/var/log/millipede/` (logs).
4. Install the binary at `/usr/local/sbin/caster` and the default
   configuration at `/etc/millipede/`.
5. Install the systemd unit `millipede-caster.service` (Linux) or the
   rc.d script `caster` (FreeBSD).

Then start the service:

```
# Linux
sudo systemctl enable --now millipede-caster

# FreeBSD
sudo sysrc caster_enable=YES
sudo service caster start
```

Updating an existing installation:

```
sudo ./update.sh	    # git pull + rebuild + restart
sudo ./update.sh --no-pull  # rebuild from current source
```

Uninstalling (keeps config and logs):

```
sudo ./uninstall.sh		# remove binary + service, keep config & logs
sudo ./uninstall.sh --purge	# remove everything including config & logs
```

Manual installation (FreeBSD)
=============================

As root:
1. Create a `caster` user: `pw useradd -n caster -d /nonexistent -s /bin/nologin`
2. `cd caster; make install`
3. Create configuration files in (default) `/usr/local/etc/millipede/`,
   samples in `sample-config/`.
	* `caster.yaml` main configuration file
	* `sourcetable.dat` our local sourcetable
	* `source.auth` authentication of sources from our sourcetable
	* `host.auth` authentication as a client to other hosts
4. `mkdir /var/log/millipede && chown caster /var/log/millipede`
5. `install -m 0755 sample-config/caster.sh /usr/local/etc/rc.d/caster`
6. `sysrc caster_enable=YES`


Running
=======

`service caster start`, or start the `/usr/local/sbin/caster` binary.

Documentation
=============

There are 3 main functions the caster can fulfill simultaneously, configured from `caster.yaml`.

## Regular NTRIP caster

Configure `sourcetable.dat` for the local sources, `source.auth` for their authentication, and the `listen` section for the IP addresses to listen on.

## NTRIP proxy

Configure the `proxy` section with a reference caster.

The local caster will fetch the sourcetable from the reference caster at `table_refresh_delay` (in seconds) intervals, and announce it merged with its own sourcetable.

Sources will be fetched and served to clients on-demand from the reference caster.

## "NEAR" base

(Previously known as the "V" base)

Should be declared in the local sourcetable (see default config) with its "virtual" field (12th field) set to "1".

When a NTRIP client connects to this base and announces its location through $G*GGA NMEA lines, the caster will serve it the nearest base from its general sourcetable (local + proxy), switching over time when the client moves.

JSON API
========

The caster exposes a JSON admin API under `/adm/api/v1/`. All endpoints
require HTTP Basic auth (or `user`/`password` query-string parameters)
with credentials from the account configured as `admin_user` in
`caster.yaml` (typically defined in `source.auth`).

| Method | Endpoint			     | Description				    |
|--------|-----------------------------------|----------------------------------------------|
| GET	 | `/adm/api/v1/net`		     | List all NTRIP sessions (sources + clients)  |
| GET	 | `/adm/api/v1/rtcm`		     | RTCM cache (last 1005/1006 per mountpoint)   |
| GET	 | `/adm/api/v1/rtcm/frequencies`    | RTCM per-type rate (sliding 60s window)	    |
| GET	 | `/adm/api/v1/mem`		     | Memory statistics (debug builds only)	    |
| GET	 | `/adm/api/v1/nodes`		     | Node table (cluster sync)		    |
| GET	 | `/adm/api/v1/livesources`	     | Live sources (local + remote)		    |
| GET	 | `/adm/api/v1/sourcetables`	     | Known sourcetables			    |
| POST	 | `/adm/api/v1/reload`		     | Reload the configuration			    |
| POST	 | `/adm/api/v1/drop?id=<n>`	     | Drop a connection by id			    |
| POST	 | `/adm/api/v1/sync`		     | Push a syncer update			    |
| GET	 | `/adm/api/v1/logs/stream`	     | SSE stream of real-time log lines	    |

A companion CLI tool `mapi` (in `caster/bin/`) wraps these endpoints.

Examples:

```sh
# List all sessions
curl -u "admin:admin" http://localhost:2101/adm/api/v1/net

# RTCM frequency tracker (per-mountpoint, per-type)
curl -u "admin:admin" http://localhost:2101/adm/api/v1/rtcm/frequencies

# Subscribe to the real-time log stream (SSE)
curl -N -u "admin:admin" http://localhost:2101/adm/api/v1/logs/stream
```

Hardware detection (companion tool)
===================================

For deployments where the caster also manages a local GNSS receiver, a
companion script `tools/detect_receiver.sh` probes serial/USB devices
and identifies known receivers (U-blox ZED-F9P, Septentrio mosaic-X5,
Unicore UM980). See `docs/HARDWARE.md` for details.

The caster itself does not manage receivers — this is by design. The
caster is a pure NTRIP relay; receiver management is left to RTKBase
or to the companion scripts.

