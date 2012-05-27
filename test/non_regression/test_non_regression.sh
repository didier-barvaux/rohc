#!/bin/sh
#
# file:        test_non_regression.sh
# description: Check that the behaviour of the ROHC library did not changed
#              without developpers noticing it.
# author:      Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#
# This script may be used by creating a link "test_non_regression_STREAM.sh"
# where:
#    STREAM  is the path to the capture file that contains the IP stream to
#            test library with (separators '/' are replaced by '_')
#
# Script arguments:
#    test_non_regression_STREAM.sh [verbose]
# where:
#   verbose          prints the traces of test application
#

# parse arguments
SCRIPT="$0"
VERBOSE="$1"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_non_regression"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_non_regression"
fi

# extract the CID type and capture name from the name of the script
CID_TYPE=$( echo "${SCRIPT}" | \
            sed -e 's#^.*/test_non_regression_\(.\+\)_\(.\+\)\.sh#\2#' )
STREAM=$( echo "${SCRIPT}" | \
          sed -e 's#^.*/test_non_regression_\(.\+\)_\(.\+\)\.sh#\1#' | \
          sed -e 's#_#/#g' )
CAPTURE_SOURCE="${BASEDIR}/inputs/${STREAM}/source.pcap"
CAPTURE_COMPARE="${BASEDIR}/inputs/${STREAM}/rohc_${CID_TYPE}.pcap"
SIZE_COMPARE="${BASEDIR}/inputs/${STREAM}/rohc_sizes_${CID_TYPE}"

# check that capture names are not empty
if [ -z "${CAPTURE_SOURCE}" ] ; then
	echo "empty source capture name, please do not run $0 directly!"
	exit 1
fi
if [ -z "${CAPTURE_COMPARE}" ] ; then
	echo "empty compare capture name, please do not run $0 directly!"
	exit 1
fi

#CMD="${APP} -o ${CAPTURE_COMPARE} --rohc-size-ouput ${SIZE_COMPARE} ${CID_TYPE} ${CAPTURE_SOURCE}"
CMD="${APP} -c ${CAPTURE_COMPARE} ${CID_TYPE} ${CAPTURE_SOURCE}"

# source valgrind-related functions
. ${BASEDIR}/../valgrind.sh

# run without valgrind in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	run_test_without_valgrind ${CMD} || exit $?
else
	run_test_without_valgrind ${CMD} > /dev/null 2>&1 || exit $?
fi

[ "${USE_VALGRIND}" != "yes" ] && exit 0

# run with valgrind in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	run_test_with_valgrind ${BASEDIR}/../valgrind.xsl ${CMD} || exit $?
else
	run_test_with_valgrind ${BASEDIR}/../valgrind.xsl ${CMD} > /dev/null 2>&1 || exit $?
fi

