#!/bin/sh
#
# file:        test_lost_packet.sh
# description: Check that the ROHC library correctly handles lost packets
# author:      Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
#
# This script may be used by creating a link "test_lost_packet_NUM_CAPTURE.sh"
# where:
#    NUM      is the packet # to lose
#    CAPTURE  is the source capture to use for the test
#
# Script arguments:
#    test_lost_packet_NUM_CAPTURE.sh [verbose [verbose]]
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
test -z "${AWK}" && AWK="`which awk`"

# parse arguments
SCRIPT="$0"
REPAIR="$1"
PARAMS="$2"
VERBOSE="$3"
VERY_VERBOSE="$4"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_lost_packet${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_lost_packet${CROSS_COMPILATION_EXEEXT}"
fi

# extract the packet to lose and source capture from the name of the script
PACKETS_TO_LOSE=$( echo "${PARAMS}" | \
                   ${SED} -e 's#^test_lost_packet_\([0-9-]*\)_.*#\1#' )
FIRST_PACKET_TO_LOSE=$( echo "${PACKETS_TO_LOSE}" | ${AWK} -F'-' '{ print $1 }' )
LAST_PACKET_TO_LOSE=$( echo "${PACKETS_TO_LOSE}" | ${AWK} -F'-' '{ print $2 }' )
PACKETS_ERROR=$( echo "${PARAMS}" | \
                 ${SED} -e 's#^test_lost_packet_[0-9-]*_\([0-9]*\).*#\1#' )
CAPTURE_NAME=$( echo "${PARAMS}" | \
                ${SED} -e 's#^test_lost_packet_[0-9-]*_[0-9]*_\(.*\)#\1#' )
CAPTURE_SOURCE="${BASEDIR}/inputs/${CAPTURE_NAME}.pcap"

# check that capture exists
if [ ! -r "${CAPTURE_SOURCE}" ] ; then
	echo "source capture not found or not readable, please do not run ${APP}.sh directly!"
	exit 1
fi

# check that the packet to lose is not empty
if [ -z "${FIRST_PACKET_TO_LOSE}" ] || \
   [ -z "${LAST_PACKET_TO_LOSE}" ] || \
   [ -z "${PACKETS_ERROR}" ] ; then
	echo "failed to parse packet infos, please do not run ${APP}.sh directly!"
	exit 1
fi

if [ "${REPAIR}" = "norepair" ] ; then
	REPAIR=""
elif [ "${REPAIR}" = "repair" ] ; then
	REPAIR="--repair"
else
	echo "wrong repair argument" >&2
	exit 1
fi

CMD="${CROSS_COMPILATION_EMULATOR} ${APP} ${REPAIR} ${CAPTURE_SOURCE} \
    ${FIRST_PACKET_TO_LOSE} ${LAST_PACKET_TO_LOSE} ${PACKETS_ERROR}"

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

