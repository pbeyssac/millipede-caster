Megapede 0.1
============

Megapede is a high-performance NTRIP caster written in C.

It uses libevent2 for minimal memory footprint.

It can easily handle tens of thousands of NTRIP sessions on a minimal server.

Features:
	* High performance
	* Supports IPv6 and IPv4
	* NTRIP proxy to fetch from an external caster
	* On-demand stream subscription

The current version requires:

	* libcyaml
	* libevent2

INSTALLATION:

1. `cd caster; make`
2. `cd caster; sudo make install`
2. Create configuration files in (default) `/usr/local/etc/millipede/`,
   samples in `sample-config/`
3. Start the millipede binary
