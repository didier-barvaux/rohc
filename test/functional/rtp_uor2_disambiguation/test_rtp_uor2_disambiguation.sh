#!/bin/sh
#
# file:        test_rtp_uor2_disambiguation.sh
# description: Check that the ROHC library correctly disambiguates UOR-2* packets
# author:      Didier Barvaux <didier@barvaux.org>
#
# This script may be used by creating a link "test_rtp_uor2_disambiguation_CAPTURE.sh"
# where:
#    CAPTURE  is the source capture to use for the test, it must ends with
#             the name of the expected packet (ie. uor2rtp, uor2id or uor2ts)
#
# Script arguments:
#    test_rtp_uor2_disambiguation_CAPTURE.sh [verbose [verbose]]
# where:
#   verbose          prints the traces of test application
#   verbose verbose  prints the traces of test application and the ones of the
#                    library
#

# parse arguments
SCRIPT="$0"
VERBOSE="$1"
VERY_VERBOSE="$2"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_rtp_uor2_disambiguation"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_rtp_uor2_disambiguation"
fi

# extract the source capture and the expected packet from the name of the script
CAPTURE_NAME=$( echo "${SCRIPT}" | \
                ${SED} -e 's#^.*/test_rtp_uor2_disambiguation_\(.\+\)\.sh#\1#' )
EXPECTED_PACKET=$( echo "${SCRIPT}" | \
                   ${SED} -e 's#^.*/test_rtp_uor2_disambiguation_\(.\+\)_\([^_]\+\)\.sh#\2#' )
CAPTURE_SOURCE="${BASEDIR}/inputs/${CAPTURE_NAME}.pcap"

# check that capture exists
if [ ! -r "${CAPTURE_SOURCE}" ] ; then
	echo "source capture not found or not readable, please do not run ${APP}.sh directly!"
	exit 1
fi

# check that the expected packet is not empty
if [ -z "${EXPECTED_PACKET}" ] ; then
	echo "failed to parse packet infos, please do not run ${APP}.sh directly!"
	exit 1
fi

CMD="${APP} ${CAPTURE_SOURCE} ${EXPECTED_PACKET}"

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

