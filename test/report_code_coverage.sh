#!/bin/sh
#
# Copyright 2013,2014 Didier Barvaux
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
# Create a report of code coverage with the help of lcov.
#
# Do not use this script directly, run configure with --enable-code-coverage,
# build the library, then run the tests:
#   ./configure --enable-code-coverage
#   make clean
#   make all
#   make check
#
# note: LANG=C and LC_ALL=C are required for lcov to work correctly
#       MAKELEVEL makes the non-regression script to mis-compute paths
#

coverage_lines_min_req=89
coverage_functions_min_req=98
coverage_branches_min_req=58

LCOV_BIN="lcov --rc lcov_function_coverage=1 --rc lcov_branch_coverage=1"
LCOV_FILE="coverage.info"
LCOV_FILTERED="coverage.info.filtered"

export LANG=C
export LC_ALL=C
unset MAKELEVEL

echo "" >&2

rm -f "${LCOV_FILE}" "${LCOV_FILTERED}"

# run the non-regression test in verbose mode to cover those bits
$(dirname $0)/non_regression/rfc3095/scripts/test_non_reg_ipv4_udp_rtp_voip_mc1_wlsb64_smallcid.sh verbose &>/dev/null
if [ $? -ne 0 ] ; then
	echo "fail to run non-regression test in verbose mode to improve coverage" >&2
	exit 1
fi

# scan for gcov output files, create the output.zcov report file
echo -n "Collect information about code coverage... " >&2
${LCOV_BIN} --capture --directory . --output-file "${LCOV_FILE}" &>/dev/null || exit 1
echo "done." >&2

echo -n "Filter information about system headers... " >&2
${LCOV_BIN} -r "${LCOV_FILE}" /usr/include/\* --output-file "${LCOV_FILTERED}" &>/dev/null || exit 1
${LCOV_BIN} -r "${LCOV_FILTERED}" src/comp/test/\* --output-file "${LCOV_FILTERED}.new" &>/dev/null || exit 1
mv -f "${LCOV_FILTERED}.new" "${LCOV_FILTERED}" || exit 1
${LCOV_BIN} -r "${LCOV_FILTERED}" src/comp/schemes/test/\* --output-file "${LCOV_FILTERED}.new" &>/dev/null || exit 1
mv -f "${LCOV_FILTERED}.new" "${LCOV_FILTERED}" || exit 1
${LCOV_BIN} -r "${LCOV_FILTERED}" src/decomp/test/\* --output-file "${LCOV_FILTERED}.new" &>/dev/null || exit 1
mv -f "${LCOV_FILTERED}.new" "${LCOV_FILTERED}" || exit 1
${LCOV_BIN} -r "${LCOV_FILTERED}" src/decomp/schemes/test/\* --output-file "${LCOV_FILTERED}.new" &>/dev/null || exit 1
mv -f "${LCOV_FILTERED}.new" "${LCOV_FILTERED}" || exit 1
${LCOV_BIN} -r "${LCOV_FILTERED}" src/test/\* --output-file "${LCOV_FILTERED}.new" &>/dev/null || exit 1
mv -f "${LCOV_FILTERED}.new" "${LCOV_FILTERED}" || exit 1
${LCOV_BIN} -r "${LCOV_FILTERED}" test/\* --output-file "${LCOV_FILTERED}.new" &>/dev/null || exit 1
mv -f "${LCOV_FILTERED}.new" "${LCOV_FILTERED}" || exit 1
echo "done." >&2

# generate one HTML report from the collected data
echo -n "Generate HTML report about code coverage... " >&2
results=$( genhtml --show-details --title "ROHC library" \
                   --function-coverage --branch-coverage \
                   -f "${LCOV_FILTERED}" \
                   --output-directory coverage-report/ \
           | tee ./coverage-report.log \
			  | grep -A3 "^Overall coverage rate:" )
if [ $? -ne 0 ] ; then
	echo "failure." >&2
	exit 1
fi
coverage_lines_float=$( echo -e "${results}" | grep "^  lines" | awk '{ print $2 }' )
coverage_functions_float=$( echo -e "${results}" | grep "^  functions" | awk '{ print $2 }' )
coverage_branches_float=$( echo -e "${results}" | grep "^  branches" | awk '{ print $2 }' )
coverage_lines=$( echo -e "${coverage_lines_float}" | sed -e 's|\.[0-9]%||' )
coverage_functions=$( echo "${coverage_functions_float}" | sed -e 's|\.[0-9]%||' )
coverage_branches=$( echo "${coverage_branches_float}" | sed -e 's|\.[0-9]%||' )
echo "done." >&2

# check results against minimal requirements
failures=0
if [ ${coverage_lines} -lt ${coverage_lines_min_req} ] ; then
	echo "[FAIL] lines coverage: ${coverage_lines_float} < ${coverage_lines_min_req}%"
	failures=$(( ${failures} + 1 ))
else
	echo "[PASS] lines coverage: ${coverage_lines_float} >= ${coverage_lines_min_req}%"
fi
if [ ${coverage_functions} -lt ${coverage_functions_min_req} ] ; then
	echo "[FAIL] functions coverage: ${coverage_functions_float} < ${coverage_functions_min_req}%"
	failures=$(( ${failures} + 1 ))
else
	echo "[PASS] functions coverage: ${coverage_functions_float} >= ${coverage_functions_min_req}%"
fi
if [ ${coverage_branches} -lt ${coverage_branches_min_req} ] ; then
	echo "[FAIL] branches coverage: ${coverage_branches_float} < ${coverage_branches_min_req} %"
	failures=$(( ${failures} + 1 ))
else
	echo "[PASS] branches coverage: ${coverage_branches_float} >= ${coverage_branches_min_req} %"
fi

echo "" >&2
echo "Load ./coverage-report/index.html in your favorite browser." >&2
echo "" >&2

exit ${failures}

