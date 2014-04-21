#!/bin/sh
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
	echo -e "\e[0;32m$@\e[m"
}

print_red()
{
	echo -e "\e[1;31m$@\e[m"
}

print_yellow()
{
	echo -e "\e[0;33m$@\e[m"
}

curdir=$( dirname "$0" )

nr_all=0
nr_pass=0
nr_skip=0
nr_malformed=0
nr_fail=0

options="--no-comparison"
if [ "$1" = "personal" ] ; then
	test_dir="${curdir}/personal_inputs/"
elif [ "$1" == "external" ] ; then
	options="${options} --no-tcp"
	test_dir="${curdir}/external_inputs/"
else
	echo "usage: $0 personal|external" >&2
	exit 1
fi
captures=$( ls -1 ${test_dir}/* 2>/dev/null )
nr_captures=$( echo -e "${captures}" | wc -l )

count=0
for capture in ${captures} ; do

	count=$(( ${count} + 1 ))

	echo -n "${count}/${nr_captures} - $( basename "${capture}" ): "
	nr_all=$(( ${nr_all} + 1 ))

	mime=$( file --brief --mime-type "${capture}" )
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		print_yellow "SKIP (unknown MIME type, code ${ret})"
		nr_skip=$(( ${nr_skip} + 1 ))
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
			print_yellow "SKIP (unknown MIME type, code ${ret})"
			nr_skip=$(( ${nr_skip} + 1 ))
			continue
		fi
	fi
	if [ "${mime}" != "application/vnd.tcpdump.pcap" ] ; then
		print_yellow "SKIP (unsupported MIME type ${mime})"
		nr_skip=$(( ${nr_skip} + 1 ))
		continue
	fi

	${curdir}/../test_non_regression ${options} smallcid "${capture}" \
		>/dev/null 2>&1
	ret=$?
	if [ ${ret} -eq 0 ] ; then
		print_green "PASS"
		nr_pass=$(( ${nr_pass} + 1 ))
	elif [ ${ret} -eq 77 ] ; then
		print_yellow "SKIP"
		nr_skip=$(( ${nr_skip} + 1 ))
	else
		print_red "FAIL"
		nr_fail=$(( ${nr_fail} + 1 ))
	fi
done

echo
echo "${nr_all} processed captures"
echo "${nr_pass} captures successfully compressed/decompressed"
echo "${nr_fail} captures with compression/decompression errors"
echo "${nr_skip} unsupported captures"
echo

if [ ${nr_fail} -ne 0 ] ; then
	global_ret=0
elif [ ${nr_skip} -ne 0 ] ; then
	global_ret=77
else
	global_ret=0
fi

exit ${global_ret}

