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
extra_commands="reload"
reload_cmd="${name}_reload"

load_rc_config $name

: ${caster_user:=caster}
: ${caster_group:=caster}
: ${caster_enable:=NO}
: ${caster_args:=-d}
: ${caster_chdir:=/tmp}

command="/usr/local/sbin/caster"
command_args="${caster_args}"

caster_reload() {
	rc_pid=$(check_process ${command})
	echo "Reloading ${name}."
        kill -HUP $rc_pid
}

cd ${caster_chdir}
run_rc_command "$1"
