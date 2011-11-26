#!/bin/sh
#
# file:        test_decompress_feedback_only.sh
# description: Check that the ROHC library decompresses feedback-only packets
#              successfully
# author:      Didier Barvaux <didier@barvaux.org>
#
# Script arguments:
#    test_decompress_feedback_only.sh [verbose [verbose]]
# where:
#   verbose          prints the traces of test application
#   verbose verbose  prints the traces of library
#

# parse arguments
SCRIPT="$0"
VERBOSE="$1"
VERY_VERBOSE="$2"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_decompress_feedback_only"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_decompress_feedback_only"
fi

CMD="${APP}"

# run in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	if [ "${VERY_VERBOSE}" = "verbose" ] ; then
		${CMD} || exit $?
	else
		${CMD} > /dev/null || exit $?
	fi
else
	${CMD} > /dev/null 2>&1 || exit $?
fi

