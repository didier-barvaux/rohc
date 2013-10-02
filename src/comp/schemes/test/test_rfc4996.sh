#!/bin/sh

# skip test in case of cross-compilation
if [ "${CROSS_COMPILATION}" = "yes" ] && \
   [ -z "${CROSS_COMPILATION_EMULATOR}" ] ; then
	exit 77
fi

# parse arguments
SCRIPT="$0"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./$( basename "${SCRIPT}" .sh)${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/$( basename "${SCRIPT}" .sh)${CROSS_COMPILATION_EXEEXT}"
fi

${CROSS_COMPILATION_EMULATOR} ${APP} $@ || exit $?

