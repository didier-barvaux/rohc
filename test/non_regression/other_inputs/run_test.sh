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

print_yellow()
{
	echo -en "\e[0;33m$@\e[m"
}

print_processing_time()
{
	local hours=0
	local minutes=0
	local seconds=$1

	echo -n " ["
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
	echo -n "${seconds}s]"
}


curdir=$( dirname "$0" )

nr_all=0
nr_pass=0
nr_skip=0
nr_malformed=0
nr_fail=0
global_processing_time=0

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

count=0
for capture in ${captures} ; do

	count=$(( ${count} + 1 ))

	echo -n "${count}/${nr_captures} - $( basename "${capture}" ): "
	nr_all=$(( ${nr_all} + 1 ))

	mime=$( file --brief --mime-type "${capture}" )
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		print_yellow "FAIL (unknown MIME type, code ${ret})"
		echo
		nr_fail=$(( ${nr_fail} + 1 ))
		continue
	fi
	if [ "${mime}" = "inode/symlink" ] ; then
		new_capture="$( readlink "${capture}" )"
		echo "${new_capture}" | grep -q '^/'
		if [ $? -eq 0 ] ; then
			capture="${new_capture}"
		else
			capture="$( dirname "${capture}" )/${new_capture}"
		fi
		mime=$( file --brief --mime-type "${capture}" )
		ret=$?
		if [ ${ret} -ne 0 ] ; then
			print_yellow "FAIL (unknown MIME type, code ${ret})"
			echo
			nr_fail=$(( ${nr_fail} + 1 ))
			continue
		fi
	fi
	file_type=$( file --brief "${capture}" )
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		print_yellow "FAIL (unknown file type, code ${ret})"
		echo
		nr_fail=$(( ${nr_fail} + 1 ))
		continue
	fi

	is_file_supported=0
	if [ "${mime}" = "application/vnd.tcpdump.pcap" ] ; then
		is_file_supported=1
	elif [ "${mime}" = "application/octet-stream" ] ; then
		echo "${file_type}" | grep -Eq "^extended tcpdump capture file"
		etcpdump=$?
		echo "${file_type}" | grep -Eq "^pcap-ng capture file"
		pcapng=$?
		if [ ${etcpdump} -eq 0 ] || \
		   [ ${pcapng} -eq 0 ] ; then
			is_file_supported=1
		fi
		unset etcpdump
		unset pcapng
	fi
	if [ ${is_file_supported} -ne 1 ] ; then
		print_yellow "SKIP (unsupported MIME type '${mime}' ; file type '${file_type}')"
		echo
		nr_skip=$(( ${nr_skip} + 1 ))
		continue
	fi
	unset is_file_supported
	unset file_type
	unset mime

	# print capture size
	echo -n "[$( ls -lh "${capture}" | gawk '{print $5}' )] "

	# test the capture, compute the processing time
	date_start=$( date +%s )
	${curdir}/../test_non_regression ${options} "${capture}" \
		>/dev/null 2>&1
	ret=$?
	date_end=$( date +%s )
	processing_time=$(( ${date_end} - ${date_start} ))
	global_processing_time=$(( ${global_processing_time} + ${processing_time} ))
	unset date_start
	unset date_end

	# print the test results
	if [ ${ret} -eq 0 ] ; then
		print_green "PASS"
		nr_pass=$(( ${nr_pass} + 1 ))
	elif [ ${ret} -eq 77 ] ; then
		print_yellow "SKIP"
		nr_skip=$(( ${nr_skip} + 1 ))
	else
		print_red "FAIL (${ret})"
		nr_fail=$(( ${nr_fail} + 1 ))
	fi
	print_processing_time ${processing_time}
	echo

	unset ret
	unset processing_time
done

# print summary of results
echo -n "${nr_all} processed captures in "
print_processing_time ${global_processing_time}
echo
echo "${nr_pass} captures successfully compressed/decompressed"
echo "${nr_fail} captures with compression/decompression errors"
echo "${nr_skip} unsupported captures"
echo

if [ ${nr_fail} -ne 0 ] ; then
	global_ret=1
elif [ ${nr_skip} -ne 0 ] ; then
	global_ret=77
else
	global_ret=0
fi

exit ${global_ret}

