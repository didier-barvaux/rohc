#!/bin/sh
#
# file:        test.sh
# description: Check that the behaviour of the ROHC library did not changed
#              without developpers noticing it.
# author:      Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#
# This script may be used by creating a link "test_STREAM.sh"
# where:
#    STREAM  is the path to the capture file that contains the IP stream to
#            test library with (separators '/' are replaced by '_')
#
# Script arguments:
#    test_STREAM.sh [verbose]
# where:
#   verbose          prints the traces of test application
#

# parse arguments
SCRIPT="$0"
VERBOSE="$1"
BASEDIR=$( dirname "${SCRIPT}" )
APP="${BASEDIR}/test"

# extract the capture name from the name of the script
STREAM=$( echo "${SCRIPT}" | \
          sed -e 's#^.*/test_\(.\+\)\.sh#\1#' | \
          sed -e 's#_#/#g' )
CAPTURE_SOURCE="${BASEDIR}/report/samples/${STREAM}/source.pcap"
CAPTURE_COMPARE="${BASEDIR}/report/samples/${STREAM}/rohc.pcap"

# check that capture names are not empty
if [ -z "${CAPTURE_SOURCE}" ] ; then
	echo "empty source capture name, please do not run $0 directly!"
	exit 1
fi
if [ -z "${CAPTURE_COMPARE}" ] ; then
	echo "empty compare capture name, please do not run $0 directly!"
	exit 1
fi

CMD="${APP} -c ${CAPTURE_COMPARE} ${CAPTURE_SOURCE}"

# run in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	${CMD} || exit $?
else
	${CMD} > /dev/null 2>&1 || exit $?
fi

