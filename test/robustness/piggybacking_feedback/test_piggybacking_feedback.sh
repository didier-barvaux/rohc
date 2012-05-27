#!/bin/sh
#
# file:        test_piggybacking_feedback.sh
# description: Check that the ROHC compressor handles correctly feedbacks being
#              piggybacked when a compression error occurs
# author:      Didier Barvaux <didier@barvaux.org>
#
# This script may be used directly.
#
# Script arguments:
#   test_piggybacking_feedback.sh [verbose [verbose]]
# where:
#   verbose          prints the traces of test application, then library traces
#

# parse arguments
SCRIPT="$0"
VERBOSE="$1"
VERY_VERBOSE="$2"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_piggybacking_feedback"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_piggybacking_feedback"
fi

CMD="${APP}"

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

