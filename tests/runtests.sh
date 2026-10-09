#!/bin/sh

VALGRIND_PATH=`command -v valgrind`
TMP=tmp

VALGRIND_ARGS_HELGRIND="--tool=helgrind -s --log-file=${TMP}/valgrind-helgrind.%p.log --gen-suppressions=all --suppressions=valgrind.suppressions"
VALGRIND_ARGS_MEMCHECK="--tool=memcheck -s --leak-check=full --log-file=${TMP}/valgrind-memcheck.%p.log --gen-suppressions=all --suppressions=valgrind.suppressions"
CASTER_ARGS1="-t12"
CASTER_ARGS2=""

export nfail

keeperr() {
	ID="$1"
	FILE="$2"
	if [ ! -e errs/"$ID" ]; then
		mkdir errs/"$ID"
	fi
	mv -f $FILE errs/"$ID"
}

start() {
	TYPE="$1"
	shift
	ARGS=$*
	ln ../caster/caster ${TMP}/castertmp
	rm -f test-caster.log test-access.log

	case "$TYPE" in
	"memcheck")
		echo -n "Starting ${VALGRIND_PATH} ${VALGRIND_ARGS_MEMCHECK} ${TMP}/castertmp ${ARGS}"
		${VALGRIND_PATH} ${VALGRIND_ARGS_MEMCHECK} ${TMP}/castertmp ${ARGS} &
		sleep 5
		;;
	"helgrind")
		echo -n "Starting ${VALGRIND_PATH} ${VALGRIND_ARGS_HELGRIND} ${TMP}/castertmp ${ARGS}"
		${VALGRIND_PATH} ${VALGRIND_ARGS_HELGRIND} ${TMP}/castertmp ${ARGS} &
		sleep 5
		;;
	*)
		echo -n "Starting ${TMP}/castertmp ${ARGS}"
		${TMP}/castertmp ${ARGS} &
		;;
	esac
	PID=$!
	RUNBIN=${TMP}/caster.${PID}
	mv -f ${TMP}/castertmp ${RUNBIN}
	echo " PID=${PID}"
	sleep ${DELAY_START}
        t=0
	while [ '(' ! -f test-caster.log -o ! -f test-access.log ')' -a $t -le 10 ] && kill -0 ${PID} 2>/dev/null; do
		echo $t
		t=`expr $t + 1`
		sleep 1
	done
}

run() {
	TYPE=$1
	PID=$2
	shift 2
	list=$*
	OUT=${TMP}/out.${PID}
	for file in $list; do
		echo -n Test: $file
		if ! ./${file} >${OUT} 2>&1; then
			nfail=`expr $nfail + 1`
			keeperr ${file} ${OUT}
			echo " FAIL"
		else
			echo " OK"
			rm -f ${OUT}
		fi
		if ! kill -0 ${PID} 2>/dev/null; then
			echo ${PID} died unexpectedly when running ${file}
			touch ${TMP}/${file}.${PID}.die
			keeperr ${file} ${TMP}/${file}.${PID}.die
			cleanup $TYPE $PID
			return
		fi
	done
	echo nfail: $nfail
	stop $TYPE $PID
}

checknotrunning() {
	ID="$1"
	if ! kill -0 ${PID} 2>/dev/null; then
		return 0
	fi
	echo FAIL: caster ${PID} running, should not be.
	kill -TERM ${PID} 2>/dev/null
	touch ${TMP}/${ID}.${PID}.notdead
	keeperr ${ID} ${TMP}/${ID}.${PID}.notdead
	nfail=`expr $nfail + 1`
	return 1
}

checkrunning() {
	ID="$1"
	if kill -0 ${PID} 2>/dev/null; then
		return 0
	fi
	echo FAIL: caster ${PID} not running, should be.
	touch ${TMP}/${ID}.${PID}.die
	keeperr ${ID} ${TMP}/${ID}.${PID}.die
	nfail=`expr $nfail + 1`
	return 1
}

stop() {
	TYPE=$1
	PID=$2
	kill ${PID} 2>/dev/null
	echo -n Waiting for ${PID} to exit.
	while kill -0 ${PID} 2>/dev/null; do
		echo -n '.'
		sleep 1
	done
	echo " done."
	cleanup $TYPE $PID
}

cleanup() {
	TYPE=$1
	PID=$2
	mv -f test-caster.log test-caster.${PID}.log 2>/dev/null
	mv -f test-access.log test-access.${PID}.log 2>/dev/null

	if [ "${TYPE}" = "normal" ] || grep "ERROR SUMMARY: 0 errors from 0 contexts" ${TMP}/valgrind*.${PID}.log >/dev/null 2>&1; then
		export normal_or_ok=1
	else
		export normal_or_ok=0
	fi

	if [ ! -f caster.${PID}.core -a ! -f castertmp.${PID}.core -a ! -f valgrind*.${PID}.log.core.${PID} \
	    -a "$normal_or_ok" = "1" ]; then
		rm -f ${RUNBIN} 
		rm -f ${TMP}/valgrind*.${PID}.log
		rm -f test-caster.${PID}.log
		rm -f test-access.${PID}.log
	else
		mv -f ${RUNBIN} caster.${PID}.core castertmp.${PID}.core valgrind*.${PID}.log.core.${PID} cores 2>/dev/null
		mv -f test-caster.${PID}.log test-access.${PID}.log logs 2>/dev/null
		mv -f ${TMP}/valgrind*.${PID}.log logs 2>/dev/null
	fi
}

DELAY_START=1

excode=0
for i in testconfig/*; do
	if [ -f "$i" -a -w "$i" ]; then
		echo "$i is not read-only, please chmod 444 $i"
		excode=1
	fi
done
if [ "$excode" != 0 ]; then exit $excode; fi

rm -f test-caster.log test-access.log
mkdir ${TMP} errs logs cores 2>/dev/null

totalfail=0
for caster_args in "${CASTER_ARGS1}" "${CASTER_ARGS2}"; do
    for type in helgrind memcheck normal; do
	nfail=0

	start ${type} ${caster_args} -c testconfig/caster_badconfig1.yaml
	checknotrunning caster_okconfig1 ${PID}
	stop ${type} ${PID}

	start ${type} ${caster_args} -c testconfig/caster_badconfig2.yaml
	checknotrunning caster_okconfig1 ${PID}
	stop ${type} ${PID}

	start ${type} ${caster_args} -c testconfig/caster_okconfig1.yaml
	checkrunning caster_okconfig1 ${PID}
	stop ${type} ${PID}

	start ${type} ${caster_args} -c testconfig/caster.yaml
	run ${type} ${PID} test-keepalive.py test-api-race.py test-fetcher-reload-race.py test-livesource-race.py test-livesource-race2.py test-send-expect.py test-chunks.py test-chunks2.py test-source-json.py test-timeout.py test-syncer-timeout.py test-near1.py test-near2.py test-rtcm.py test-rtcm2.py

	start ${type} ${caster_args} -c testconfig/caster2.yaml
	run ${type} ${PID} test-syncer-ondemand.py test-headers.py test-fetched.py test-httpclient.py test-syncer-client-timeout.py test-quota.py test-send-expect2.py test-graylog-reload.py test-near3.py test-access_log.py test-json-leak.py

	cp -pf testconfig/caster3a.yaml testconfig/caster3.yaml
	start ${type} ${caster_args} -c testconfig/caster3.yaml
	run ${type} ${PID} test-reload.sh

	cp -pf testconfig/sourcetable4nonear.dat testconfig/sourcetable4.dat
	start ${type} ${caster_args} -c testconfig/caster4.yaml
	run ${type} ${PID} test-near4.py

	start ${type} ${caster_args} -c testconfig/caster5.yaml
	run ${type} ${PID} test-graylog-retry.py

	cp -pf testconfig/caster6-orig.yaml testconfig/caster6.yaml
	start ${type} ${caster_args} -c testconfig/caster6.yaml
	chmod 644 testconfig/caster6.yaml
	run ${type} ${PID} test-rtcm-filter-reload.py

	start ${type} ${caster_args} -c testconfig/caster7.yaml
	run ${type} ${PID} test-sync-badtable.py test-sync-state-type.py ./test-sync-baddiff.py

    done
    echo FAILS $nfail
    totalfail=`expr $totalfail + $nfail`
done

echo TOTAL FAILS $totalfail$
exit $totalfail
