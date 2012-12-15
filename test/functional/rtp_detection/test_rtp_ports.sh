#!/bin/sh
#
# file:        test_rtp_ports.sh
# description: Check RTP ports management
# authors:     Julien Bernard <julien.bernard@toulouse.viveris.com>
#              Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
#
# This script may be used by creating a link "test_rtp_ports_TYPE.sh"
# where:
#    TYPE  is the type of of check to run
#
# Script arguments:
#    test_rtp_ports_TYPE.sh [verbose [verbose]]
# where:
#   verbose          prints the traces of test application
#   verbose verbose  prints the traces of test application and ROHC library
#

# skip test in case of cross-compilation
if [ "${CROSS_COMPILATION}" = "yes" ] && \
   [ -z "${CROSS_COMPILATION_EMULATOR}" ] ; then
	exit 77
fi

# parse arguments
SCRIPT="$0"
VERBOSE="$1"
VERY_VERBOSE="$2"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./test_rtp_ports${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/test_rtp_ports${CROSS_COMPILATION_EXEEXT}"
fi

# extract the type of check from the name of the script
TYPE=$( echo "${SCRIPT}" | \
        ${SED} -e 's#^.*/test_rtp_ports_\([^.]\+\)\.sh#\1#' )
CAPTURE="${BASEDIR}/input/rtp.pcap"

# check that capture name is not empty
if [ -z "${CAPTURE}" ] ; then
	echo "empty capture name, please do not run $0 directly!"
	exit 1
fi

# build command line
CMD="${CROSS_COMPILATION_EMULATOR} ${APP} ${TYPE} ${CAPTURE}"

# source valgrind-related functions
. ${BASEDIR}/../../valgrind.sh

if [ "${VERBOSE}" = "verbose" ] ; then
	if [ "${VERY_VERBOSE}" = "verbose" ] ; then
		run_test_without_valgrind ${CMD} --verbose || exit 1
	else
		run_test_without_valgrind ${CMD} || exit 1
	fi
else
	run_test_without_valgrind ${CMD} > /dev/null 2>&1 || exit 1
fi

[ "${USE_VALGRIND}" != "yes" ] && exit 0

# run with valgrind in verbose mode or quiet mode
if [ "${VERBOSE}" = "verbose" ] ; then
	if [ "${VERY_VERBOSE}" = "verbose" ] ; then
		run_test_with_valgrind ${BASEDIR}/../../valgrind.xsl ${CMD} --verbose || exit $?
	else
		run_test_with_valgrind ${BASEDIR}/../../valgrind.xsl ${CMD} || exit $?
	fi
else
	run_test_with_valgrind ${BASEDIR}/../../valgrind.xsl ${CMD} > /dev/null 2>&1 || exit $?
fi

