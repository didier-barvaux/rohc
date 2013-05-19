#!/bin/sh
#
# file:        test_segment.sh
# description: Check that the ROHC library creates expected ROHC segments
# author:      Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#
# Script arguments:
#    test_segment.sh [verbose [verbose]]
# where:
#   verbose          prints the traces of test application
#   verbose          prints the traces of test application and the ones of
#                    the ROHC library
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
	APP="./test_segment${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_segment${CROSS_COMPILATION_EXEEXT}"
fi

# no argument
CMD="${CROSS_COMPILATION_EMULATOR} ${APP}"

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

