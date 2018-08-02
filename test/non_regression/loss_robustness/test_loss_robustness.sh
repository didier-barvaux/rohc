#!/bin/sh
#
# Copyright 2018 Viveris Technologies
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

#
# file:        test_robustness_to_loss.sh
# description: Check that the behaviour of the ROHC library wrt to packet loss
#              is robust enough
# authors:     Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#
# This script may be used by creating a link "test_robustness_to_loss_rfcXXXX_keep_KEEP_on_BURST.sh"
# where:
#    XXXX    is the ROHC RFC to use
#    KEEP    is the packet to keep in a burst (ie. the only packet not to be lost)
#    BURST   is the number of packets in a burst
#
# Script arguments:
#   test_robustness_to_loss_rfcXXXX_keep_KEEP_on_BURST.sh [verbose]
# where:
#   verbose          prints the traces of test application
#

# skip test in case of cross-compilation
if [ "${CROSS_COMPILATION}" = "yes" ] && \
   [ -z "${CROSS_COMPILATION_EMULATOR}" ] ; then
	exit 77
fi

test -z "${SED}" && SED="`which sed`"
test -z "${AWK}" && AWK="`which gawk`"
test -z "${AWK}" && AWK="`which awk`"

# parse arguments
SCRIPT="${PWD}/$0"
VERBOSE="$1"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}/../"
	APP="../test_non_regression${KERNEL_SUFFIX}${CROSS_COMPILATION_EXEEXT}"
else
	BASEDIR="$( dirname "${SCRIPT}" )/../"
	APP="${BASEDIR}/test_non_regression${KERNEL_SUFFIX}${CROSS_COMPILATION_EXEEXT}"
fi

# extract test parameters from the name of the script
PARAMS=$( echo "${SCRIPT}" | \
          ${SED} -e 's#^.*/test_loss_robustness_##' -e 's#\.sh$##' )
RFC_NUM=$( echo "${PARAMS}" | ${AWK} -F'_' '{ print $(NF-4) }' | ${SED} -e 's/rfc//' )
KEEP=$( echo "${PARAMS}" | ${AWK} -F'_' '{ print $(NF-2) }' )
BURST_SIZE=$( echo "${PARAMS}" | ${AWK} -F'_' '{ print $(NF) }' )

# enable ROHCv2 profiles for RFC5225, ROHCv1 otherwise
if [ "${RFC_NUM}" = "5225" ] ; then
	ROHC_VERSION=2
else
	ROHC_VERSION=1
fi

APP="${CROSS_COMPILATION_EMULATOR} ${APP}"

echo "RFC ${RFC_NUM}: keep packet #${KEEP} every ${BURST_SIZE} packets:"

all_errors_nr=0
for cid_type in small large ; do

	# determine the maximum number of contexts if MAX_CONTEXTS == 0
	if [ "${cid_type}" = "small" ] ; then
		MAX_CONTEXTS=16
	else
		MAX_CONTEXTS=16384
	fi

	for wlsb_width in 4 64 ; do
		for max_contexts in 1 ${MAX_CONTEXTS} ; do
			CMD_PARAMS=""
			CMD_PARAMS="${CMD_PARAMS} --optimistic-approach ${wlsb_width}"
			CMD_PARAMS="${CMD_PARAMS} --max-contexts ${max_contexts}"
			CMD_PARAMS="${CMD_PARAMS} --rohc-version ${ROHC_VERSION}"
			CMD_PARAMS="${CMD_PARAMS} --loss-ratio ${KEEP} ${BURST_SIZE}"
			CMD_PARAMS="${CMD_PARAMS} --no-comparison"
			CMD_PARAMS="${CMD_PARAMS} --quiet"
			CMD_PARAMS="${CMD_PARAMS} ${cid_type}cid"

			echo -en "\t${cid_type} CID + W-LSB ${wlsb_width} + ${max_contexts} context(s): "
			runs_nr=0
			errors_nr=0
			for capture in $( find ${BASEDIR}/rfc${RFC_NUM}/inputs/ -name source.pcap ) ; do
				capture_name="$( echo ${capture} | ${SED} -e "s|${BASEDIR}/rfc${RFC_NUM}/inputs/||" )"
				if [ -f "$( dirname ${capture} )/no_loss_robustness_${PARAMS}" ] ; then
					[ ${runs_nr} -eq 0 ] && [ ${errors_nr} -eq 0 ] && echo
					[ "${VERBOSE}" = "verbose" ] && echo -e "\t\t${capture_name}: SKIP"
				else
					${APP} ${CMD_PARAMS} ${capture}
					ret=$?
					if [ ${ret} -eq 0 ] ; then
						[ "${VERBOSE}" = "verbose" ] && [ ${runs_nr} -eq 0 ] && echo
						[ "${VERBOSE}" = "verbose" ] && echo -e "\t\t${capture_name}: PASS"
					elif [ ${ret} -eq 77 ] ; then
						[ ${runs_nr} -eq 0 ] && [ ${errors_nr} -eq 0 ] && echo
						echo -e "\t\t${capture_name}: SKIP"
						errors_nr=$(( ${errors_nr} + 1 ))
					elif [ ${ret} -ne 1 ] ; then
						[ ${runs_nr} -eq 0 ] && [ ${errors_nr} -eq 0 ] && echo
						echo -e "\t\t${capture_name}: CRASH"
						errors_nr=$(( ${errors_nr} + 1 ))
					else
						[ ${runs_nr} -eq 0 ] && [ ${errors_nr} -eq 0 ] && echo
						echo -e "\t\t${capture_name}: FAIL"
						errors_nr=$(( ${errors_nr} + 1 ))
					fi
				fi
				runs_nr=$(( ${runs_nr} + 1 ))
			done

			[ ${errors_nr} -gt 0 ] && echo -en "\t\t"
			echo "${errors_nr}/${runs_nr} failures"

			all_errors_nr=$(( ${all_errors_nr} + ${errors_nr} ))
		done
	done
done

echo "${all_errors_nr} failures"
if [ ${all_errors_nr} -ne 0 ] ; then
	exit 1
else
	exit 0
fi

