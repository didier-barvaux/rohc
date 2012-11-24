#!/bin/sh
#
# file:        test_non_regression.sh
# description: Check that the behaviour of the ROHC library did not changed
#              without developpers noticing it.
# authors:     Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
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

# skip test in case of cross-compilation
if [ "${CROSS_COMPILATION}" = "yes" ] && \
   [ -z "${CROSS_COMPILATION_EMULATOR}" ] ; then
	exit 77
fi

# parse arguments
SCRIPT="$0"
VERBOSE="$1"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_non_regression${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_non_regression${CROSS_COMPILATION_EXEEXT}"
fi

# extract the CID type and capture name from the name of the script
PARAMS=$( echo "${SCRIPT}" | \
          ${SED} -e 's#^.*/test_non_regression_##' -e 's#\.sh$##' )
CID_TYPE=$( echo "${PARAMS}" | ${AWK} -F'_' '{ print $NF }' )
STREAM=$( echo "${PARAMS}" | ${AWK} -F'_' '{ OFS="/" ; $NF="" ; print $0 }' )
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

CMD="${CROSS_COMPILATION_EMULATOR} ${APP}"
if [ "${VERBOSE}" = "generate" ] ; then
	# generate ROHC output captures
	CMD="${CMD} -o ${CAPTURE_COMPARE} --rohc-size-output ${SIZE_COMPARE} ${CID_TYPE} ${CAPTURE_SOURCE}"
else
	# normal mode: compare with existing ROHC output captures
	CMD="${CMD} -c ${CAPTURE_COMPARE} ${CID_TYPE} ${CAPTURE_SOURCE}"
fi

# source valgrind-related functions
. ${BASEDIR}/../valgrind.sh

# run without valgrind in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	run_test_without_valgrind ${CMD} --verbose || exit $?
else
	run_test_without_valgrind ${CMD} > /dev/null || exit $?
fi

[ "${USE_VALGRIND}" != "yes" ] && exit 0

# run with valgrind in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	run_test_with_valgrind ${BASEDIR}/../valgrind.xsl ${CMD} --verbose || exit $?
else
	run_test_with_valgrind ${BASEDIR}/../valgrind.xsl ${CMD} > /dev/null 2>&1 || exit $?
fi

