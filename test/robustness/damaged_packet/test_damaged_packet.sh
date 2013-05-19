#!/bin/sh
#
# file:        test_damaged_packet.sh
# description: Check that the ROHC library correctly handle damaged packets
# author:      Didier Barvaux <didier@barvaux.org>
#
# This script may be used by creating a link "test_damaged_packet_NUM_CAPTURE.sh"
# where:
#    NUM      is the packet # to damage
#    CAPTURE  is the source capture to use for the test, it must begins with
#             the name of the packet to damage (ie. ir, irdyn, uo0, uo1id,
#             uor2 or uor2ts)
#
# Script arguments:
#    test_damaged_packet_NUM_CAPTURE.sh [verbose [verbose]]
# where:
#   verbose          prints the traces of test application
#   verbose verbose  prints the traces of test application and the ones of the
#                    library
#

# skip test in case of cross-compilation
if [ "${CROSS_COMPILATION}" = "yes" ] && \
   [ -z "${CROSS_COMPILATION_EMULATOR}" ] ; then
	exit 77
fi

test -z "${SED}" && SED="`which sed`"
test -z "${GREP}" && GREP="`which grep`"
test -z "${AWK}" && AWK="`which gawk`"

# parse arguments
SCRIPT="$0"
VERBOSE="$1"
VERY_VERBOSE="$2"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_damaged_packet${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_damaged_packet${CROSS_COMPILATION_EXEEXT}"
fi

# extract the packet to damage and source capture from the name of the script
PARAMS=$( echo "${SCRIPT}" | \
          ${SED} -e 's#^.*/test_damaged_packet_##' -e 's#\.sh$##' )
PACKET_TO_DAMAGE=$( echo "${PARAMS}" | ${AWK} -F'_' '{ print $1 }' )
CAPTURE_NAME=$( echo "${PARAMS}" | \
                ${AWK} -F'_' '{ if($3 == "") { print $2 } else { print $2 "_" $3 } }' )
EXPECTED_PACKET=$( echo "${PARAMS}" | ${AWK} -F'_' '{ print $2 }' )
CAPTURE_SOURCE="${BASEDIR}/inputs/${CAPTURE_NAME}.pcap"

# check that capture exists
if [ ! -r "${CAPTURE_SOURCE}" ] ; then
	echo "source capture not found or not readable, please do not run ${APP}.sh directly!"
	exit 1
fi

# check that the expected packet and packet to damage are not empty
if [ -z "${PACKET_TO_DAMAGE}" ] || [ -z "${EXPECTED_PACKET}" ] ; then
	echo "failed to parse packet infos, please do not run ${APP}.sh directly!"
	exit 1
fi

CMD="${CROSS_COMPILATION_EMULATOR} ${APP} ${CAPTURE_SOURCE} ${PACKET_TO_DAMAGE} ${EXPECTED_PACKET}"

# source valgrind-related functions
. ${BASEDIR}/../../valgrind.sh

# run without valgrind in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	if [ "${VERY_VERBOSE}" = "verbose" ] ; then
		run_test_without_valgrind ${CMD} || exit $?
	else
		run_test_without_valgrind ${CMD} > /dev/null || exit $?
	fi
else
	run_test_without_valgrind ${CMD} > /dev/null 2>&1 || exit $?
fi

[ "${USE_VALGRIND}" != "yes" ] && exit 0

# run with valgrind in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	if [ "${VERY_VERBOSE}" = "verbose" ] ; then
		run_test_with_valgrind ${BASEDIR}/../../valgrind.xsl ${CMD} || exit $?
	else
		run_test_with_valgrind ${BASEDIR}/../../valgrind.xsl ${CMD} >/dev/null || exit $?
	fi
else
	run_test_with_valgrind ${BASEDIR}/../../valgrind.xsl ${CMD} > /dev/null 2>&1 || exit $?
fi

