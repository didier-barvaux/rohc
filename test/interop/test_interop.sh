#!/bin/sh
#
# file:        test_interop.sh
# description: Check that the behaviour of the ROHC library matches the
#              one of other ROHC implementations.
# authors:     Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#
# This script may be used by creating a link "test_interop_STREAM.sh"
# where:
#    STREAM  is the path to the capture file that contains the stream to
#            test library with (separators '/' are replaced by '_')
#
# Script arguments:
#    test_interop_STREAM.sh [verbose]
# where:
#   verbose          prints the traces of test application
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
VERBOSE="$1"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_interop${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_interop${CROSS_COMPILATION_EXEEXT}"
fi

# extract the CID type and capture name from the name of the script
STREAM=$( echo "${SCRIPT}" | \
          ${SED} -e 's#^.*/test_interop_##' -e 's#\.sh$##' )
CAPTURE_SOURCE="${BASEDIR}/inputs/${STREAM}/source_rohc.pcap"
CAPTURE_COMPARE="${BASEDIR}/inputs/${STREAM}/ref_uncomp.pcap"

# check that capture names are not empty
if [ -z "${CAPTURE_SOURCE}" ] ; then
	echo "empty source capture name, please do not run $0 directly!"
	exit 1
fi
if [ ! -f "${CAPTURE_SOURCE}" ] ; then
	echo "source capture '${CAPTURE_SOURCE}' not found!"
	exit 1
fi
if [ -z "${CAPTURE_COMPARE}" ] ; then
	echo "empty compare capture name, please do not run $0 directly!"
	exit 1
fi
if [ ! -f "${CAPTURE_COMPARE}" ] ; then
	echo "compare capture '${CAPTURE_COMPARE}' not found!"
	exit 1
fi

CMD="${CROSS_COMPILATION_EMULATOR} ${APP} -c ${CAPTURE_COMPARE}"
if [ "${VERBOSE}" = "verbose" ] ; then
	CMD="${CMD} --verbose"
fi
CMD="${CMD} smallcid ${CAPTURE_SOURCE}"

# source valgrind-related functions
. ${BASEDIR}/../valgrind.sh

# run without valgrind
run_test_without_valgrind ${CMD} || exit $?

# skip Valgrind tests if they are not enabled
[ "${USE_VALGRIND}" != "yes" ] && exit 0

# run with valgrind in verbose mode or quiet mode
run_test_with_valgrind ${BASEDIR}/../valgrind.xsl ${CMD} || exit $?

