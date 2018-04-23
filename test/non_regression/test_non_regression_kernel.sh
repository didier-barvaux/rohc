#!/bin/sh
#
# file:        test_non_regression_kernel.sh
# description: Check that the behaviour of the ROHC library did not changed
#              without developpers noticing it (in Linux kernel).
# authors:     Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
#

cur_dir="$( dirname "$0" )"
tests_nr=0
statuses=0

for standard in rfc3095 rfc6846 ; do
	for testfile in ${cur_dir}/${standard}/test_non_regression_*_maxcontexts0_wlsb4_smallcid.sh ; do

		echo -n "running ${testfile}... "
		tests_nr=$(( ${tests_nr} + 1 ))

		KERNEL_SUFFIX=_kernel ./${testfile} >/dev/null 2>&1
		ret=$?
		statuses=$(( ${statuses} + ${ret} ))

		if [ ${ret} -eq 0 ] ; then
			echo "OK"
		elif [ ${ret} -eq 1 ] ; then
			echo "FAIL"
		elif [ ${ret} -eq 77 ] ; then
			echo "SKIP"
		else
			echo "ERROR (${ret})"
		fi
	done
done

echo "${tests_nr} tests performed, exiting with code ${statuses}"
exit ${statuses}

