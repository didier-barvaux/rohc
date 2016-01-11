#!/bin/sh
#
# Copyright 2015,2016 Didier Barvaux
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
# file:        coverage.sh
# description: Run all test cases to get good code coverage
# authors:     Didier Barvaux <didier@barvaux.org>
#

print_status()
{
	local test_name="$1"
	local test_xstatus="$2"
	local test_status=$3
	case ${test_status} in
		0)
			if [ "${test_xstatus}" = "xpass" ] ; then
				echo "[PASS] ${test_name}"
			else
				echo "[FAIL] ${test_name}"
			fi
			;;
		77)
			echo "[SKIP] ${test_name}"
			;;
		*)
			if [ "${test_xstatus}" = "xpass" ] ; then
				echo "[FAIL] ${test_name}"
			else
				echo "[XFAIL] ${test_name}"
			fi
			;;
	esac
}

test -f .coverage && rm -f .coverage

use_python_version="$1"
if [ -z "${use_python_version}" ] ; then
	echo "usage: $0 <python-version>" >&2
	echo "" >&2
	echo "examples:" >&2
	echo "  $ $0 2.7" >&2
	echo "  $ $0 3.3" >&2
	echo "  $ $0 3.4" >&2
	echo "" >&2
	exit 1
fi

tests_status=0

# successes
for is_verbose in "" "verbose" "verbose verbose" ; do
	if [ "${is_verbose}" = "verbose" ] ; then
		verbose_descr="verbose"
	else
		verbose_descr="quiet"
	fi
	for packets_nr in 1 2 10 ; do
		PYTHONPATH=build/lib.linux-x86_64-${use_python_version}/ \
			LD_LIBRARY_PATH=../../src/.libs/:build/lib.linux-x86_64-${use_python_version}/ \
			python${use_python_version} \
			/usr/bin/coverage run --append \
			example.py ${packets_nr} ${is_verbose} \
			&>/dev/null
		test_status=$?
		print_status "(de)compress ${packets_nr} packets in ${verbose_descr} mode" "xpass" ${test_status}
		tests_status=$(( ${tests_status} + ${test_status} ))
	done
done

# failures
PYTHONPATH=build/lib.linux-x86_64-${use_python_version}/ \
	LD_LIBRARY_PATH=../../src/.libs/:build/lib.linux-x86_64-${use_python_version}/ \
	python${use_python_version} \
	/usr/bin/coverage run --append \
	example.py \
	&>/dev/null
test_status=$?
print_status "run without argument" "xfail" ${test_status}
[ ${test_status} -ne 1 ] && tests_status=$(( ${tests_status} + 1 ))
PYTHONPATH=build/lib.linux-x86_64-${use_python_version}/ \
	LD_LIBRARY_PATH=../../src/.libs/:build/lib.linux-x86_64-${use_python_version}/ \
	python${use_python_version} \
	/usr/bin/coverage run --append \
	example.py 1 foobar \
	&>/dev/null
test_status=$?
print_status "run with unnexpected verbose argument" "xfail" ${test_status}
[ ${test_status} -ne 1 ] && tests_status=$(( ${tests_status} + 1 ))

# print report on console, then generate HTML report
echo
for report_type in report html ; do
	PYTHONPATH=build/lib.linux-x86_64-${use_python_version}/ \
		LD_LIBRARY_PATH=../../src/.libs/:build/lib.linux-x86_64-${use_python_version}/ \
		python${use_python_version} \
		/usr/bin/coverage ${report_type}
done
echo
echo "HTML report is located in ./htmlcov/index.html"
echo

exit ${tests_status}

