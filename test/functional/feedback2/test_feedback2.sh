#!/bin/sh
#
# file:        test_feedback2.sh
# description: Check that the ROHC library creates expected FEEDBACK-2 packets
# author:      Didier Barvaux <didier@barvaux.org>
#
# This script may be used by creating a link "test_feedback2_ACKTYPE_TESTTYPE_OPTIONS.sh"
# where:
#    ACKTYPE  is the ACK type to check for, it is used to choose the source
#             capture located in the 'inputs' subdirectory.
#    TESTTYPE is the type of test to run, it is used to choose the source
#             capture located in the 'inputs' subdirectory.
#    OPTIONS  a underscore-separated list of feedback options that are
#             expected to be generated in the FEEDBACK-2 packet.
#
# Script arguments:
#    test_feedback2_ACKTYPE_TESTTYPE_OPTIONS.sh [verbose]
# where:
#   verbose          prints the traces of test application
#

# skip test in case of cross-compilation
if [ "${CROSS_COMPILATION}" = "yes" ] && \
   [ -z "${CROSS_COMPILATION_EMULATOR}" ] ; then
	exit 77
fi

# parse arguments
SCRIPT="$0"
VERBOSE="verbose" #$1"
VERY_VERBOSE="$2"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_feedback2${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_feedback2${CROSS_COMPILATION_EXEEXT}"
fi

# extract the ACK type and test type from the name of the script
ACKTYPE=$( echo "${SCRIPT}" | \
           ${SED} -e 's#^.*/test_feedback2_\([^_]\+\)_\([^_]\+\)_\([^_]\+\)_\(.\+\)\.sh#\1#' )
CID_TYPE=$( echo "${SCRIPT}" | \
            ${SED} -e 's#^.*/test_feedback2_\([^_]\+\)_\([^_]\+\)_\([^_]\+\)_\(.\+\)\.sh#\2#' )
SN_TYPE=$( echo "${SCRIPT}" | \
           ${SED} -e 's#^.*/test_feedback2_\([^_]\+\)_\([^_]\+\)_\([^_]\+\)_\(.\+\)\.sh#\3#' )
OPTIONS=$( echo "${SCRIPT}" | \
           ${SED} -e 's#^.*/test_feedback2_\([^_]\+\)_\([^_]\+\)_\([^_]\+\)_\(.\+\)\.sh#\4#' | \
           ${SED} -e 's/none//g' | \
           ${SED} -e 's/_/ /g' )
CAPTURE_SOURCE="${BASEDIR}/inputs/${ACKTYPE}_${CID_TYPE}_${SN_TYPE}.pcap"

# check that capture exists
if [ ! -r "${CAPTURE_SOURCE}" ] ; then
	echo "source capture ${CAPTURE_SOURCE} not found or not readable, please do not run $(dirname $0)/test_feedback2.sh directly!"
	exit 1
fi

CMD="${CROSS_COMPILATION_EMULATOR} ${APP} ${CAPTURE_SOURCE} ${CID_TYPE} ${ACKTYPE} ${OPTIONS}"

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

