#! /bin/sh

# PROVIDE: caster
# REQUIRE: DAEMON
# KEYWORD: shutdown

#
# Add the following lines to /etc/rc.conf to enable the caster daemon:
#
#caster_enable="YES"

. /etc/rc.subr

name="caster"
rcvar="caster_enable"

load_rc_config $name

: ${caster_user:=caster}
: ${caster_group:=caster}
: ${caster_enable:=NO}
: ${caster_args:=-d}

command="/usr/local/sbin/caster"
command_args="${caster_args}"

run_rc_command "$1"
