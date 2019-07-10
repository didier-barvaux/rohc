#!/bin/sh
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
# file:        run_test.sh
# description: Run the non-regression tool with personal or external captures
# author:      Didier Barvaux <didier@barvaux.org>
#
# usage: run_test.sh personal|external
#

print_green()
{
	echo -en "\e[0;32m$@\e[m"
}

print_red()
{
	echo -en "\e[1;31m$@\e[m"
}

print_processing_time()
{
	local hours=0
	local minutes=0
	local seconds=$1

	if [ ${seconds} -ge 3600 ] ; then
		hours=$(( ${seconds} / 3600 ))
		seconds=$(( ${seconds} - ${hours} * 3600 ))
		echo -n "${hours}h"
	fi
	if [ ${seconds} -ge 60 ] ; then
		minutes=$(( ${seconds} / 60 ))
		seconds=$(( ${seconds} - ${minutes} * 60 ))
	fi
	if [ ${hours} -gt 0 ] || [ ${minutes} -gt 0 ] ; then
		echo -n "${minutes}m"
	fi
	echo -n "${seconds}s"
}

curdir=$( dirname "$0" )

options="--no-comparison --ignore-malformed --max-contexts 450 largecid"
test_dirs=""
if [ "$1" = "personal" ] ; then
	test_dirs="${test_dirs} ${curdir}/personal_inputs/"
elif [ "$1" == "external" ] ; then
	test_dirs="${test_dirs} ${curdir}/external_inputs/"
elif [ "$1" == "all" ] ; then
	test_dirs="${test_dirs} ${curdir}/personal_inputs/"
	test_dirs="${test_dirs} ${curdir}/external_inputs/"
else
	echo "usage: $0 personal|external|all" >&2
	exit 1
fi
captures=$( find -L ${test_dirs}/ -type f -or -type l 2>/dev/null | sort )
nr_captures=$( echo -e "${captures}" | wc -l )


# run 10 tests in parallel
logger -t rohc_non_reg "start non-regression tests"
time_start=$( date +%s )
find -L ${test_dirs}/ -type f -or -type l 2>/dev/null | \
	sort | \
	parallel -j10 --bar --joblog ${curdir}/run_tests.log \
		${curdir}/run_test.sh "{}" --ignore-malformed
nr_fail=$?
time_end=$(date +%s)
processing_time=$(( ${time_end} - ${time_start} ))
logger -t rohc_non_reg "non-regression tests ended (${nr_fail} failures)"


# print summary of results
echo -n "all captures processed in " ; print_processing_time ${processing_time} ; echo
if [ ${nr_fail} -ne 0 ] ; then
	print_red "${nr_fail} captures caused compression/decompression errors"
	global_ret=1
else
	print_green "all captures were successfully compressed/decompressed"
	global_ret=0
fi
echo

exit ${global_ret}

