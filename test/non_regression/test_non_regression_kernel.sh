#!/bin/sh
#
# file:        test_non_regression_kernel.sh
# description: Check that the behaviour of the ROHC library did not changed
#              without developpers noticing it (in Linux kernel).
# authors:     Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#

for testfile in ./test/non_regression/test_non_regression_*_smallcid.sh ; do

	testname=$( basename ${testfile} "_smallcid.sh" )

	echo -n "running ${testname}... "

	SED=sed AWK=gawk KERNEL_SUFFIX=_kernel \
		./${testfile}
	ret=$?

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

