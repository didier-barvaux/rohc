#!/bin/bash

print_green()
{
	echo -en "\e[0;32m$@\e[m"
}

print_red()
{
	echo -en "\e[1;31m$@\e[m"
}

print_yellow()
{
	echo -en "\e[0;33m$@\e[m"
}

# skip test in case of cross-compilation without emulator
if [ "${CROSS_COMPILATION}" = "yes" ] && \
   [ -z "${CROSS_COMPILATION_EMULATOR}" ] ; then
	exit 77
fi

test -z "${SED}" && SED="`which sed`"
test -z "${GREP}" && GREP="`which grep`"
test -z "${AWK}" && AWK="`which gawk`"
test -z "${AWK}" && AWK="`which awk`"

SCRIPT="${PWD}/$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_malformed_rohc_packets${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR="$( dirname "${SCRIPT}" )/"
	APP="${BASEDIR}/test_malformed_rohc_packets${CROSS_COMPILATION_EXEEXT}"
fi

rohc_version_str=$( basename $0 | ${AWK} -F'_' '{ print $4 }' )
if [ "${rohc_version_str}" = "rohcv2" ] ; then
	rohc_version=2
else
	rohc_version=1
fi
max_contexts=$( basename $0 | ${AWK} -F'_' '{ print $5 }' | ${SED} -e 's/mc//g' )
wlsb_str=$( basename $0 | ${AWK} -F'_' '{ print $6 }' )
cid_type=$( basename $0 | ${AWK} -F'_' '{ print $7 }' | ${SED} -e 's/cid//g' -e 's/.sh//g' )
capture_variant="${rohc_version_str}_maxcontexts${max_contexts}_${wlsb_str}_${cid_type}cid"

failures_nr=0

# run the test for all capures of the given variant:
# rohc_version/max_contexts/wlsb/cid
for capture in $( find ${BASEDIR}/../../non_regression/ -name ${capture_variant}.pcap ) ; do

	# run the test for one capture
	${APP} \
		--cid-type ${cid_type} \
		--rohc-version ${rohc_version} \
		${capture} \
		-1 \
	&>/dev/null
	ret=$?

	if [ $ret -eq 0 ] ; then
		print_green "PASS"
	elif [ $ret -eq 77 ] ; then
		print_green "SKIP"
	else
		print_red "FAIL"
		failures_nr=$(($failures_nr+1))
	fi
	echo ": $( echo ${capture} | ${SED} -e 's/^.*\/non_regression\///g' -e 's/inputs\///g' )"

done

echo
echo "${failures_nr} failures detected"
echo

exit ${failures_nr}

