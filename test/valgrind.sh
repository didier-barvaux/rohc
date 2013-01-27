#
# file:        test_valgrind.sh
# description: Functions to run a test with or without valgrind to check
#              or not check for memory leaks.
# authors:     Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>


# Run a test with valgrind to check for memory leaks
#  param #1      the path to the XSL file used to parse valgrind XML output
#  next params   the command line to run for the test
#  return value  0 in case of success, 1 in case of failure
run_test_with_valgrind()
{
	OPTIONS="--tool=memcheck --trace-children=yes --track-fds=yes 
	         --leak-check=full --show-reachable=yes 
	         --malloc-fill=0xaa --free-fill=0x55 
	         ${VALGRIND_OPTS}"
	XSL="$1"
	shift
	CMD="$@"

	local global_ret=0

	# compute a unique temporary file
	TMP_FILE="/tmp/valgrind_$(id -u)_$( echo "${CMD}" | md5sum | cut -d' ' -f1 )_$(date '+%s').xml"

	echo "run test with valgrind..."

	valgrind=$( which valgrind )
	if [ ! -x "${valgrind}" ] ; then
		echo "valgrind program not found or not usable" >&2
		return 1
	fi

	xsltproc=$( which xsltproc )
	if [ -z "${xsltproc}" ] || [ ! -x "${xsltproc}" ] ; then
		echo "xsltproc program not found or not usable" >&2
		return 1
	fi

	if [ -z "${GREP}" ] ; then
		echo "no grep-like tool available, please install one of the grep, or "\
		     "ggrep, tool."
		return 1
	fi

	libtool --mode=execute \
		${valgrind} -q ${OPTIONS} --xml=yes --xml-file="${TMP_FILE}" \
		${CMD}
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		echo "test failed inside valgrind (exit code ${ret})" >&2
		# do not return here because the valgrind report may be useful
		# to find the problem
		global_ret=${ret}
	fi

	# workaround a valgrind bug that writes several closing valgrindoutput
	# tags to the XML stream
	( ${GREP} -v '</valgrindoutput>' "${TMP_FILE}" ; \
	  echo '</valgrindoutput>' ) > "${TMP_FILE}.filtered"
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		echo "failed to filter superfluous '</valgrindoutput>' from valgrind XML output" >&2
		rm -f "${TMP_FILE}"
		rm -f "${TMP_FILE}.filtered"
		return ${ret}
	fi

	errors=$( ${xsltproc} "${XSL}" "${TMP_FILE}.filtered" 2>/dev/null )
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		echo "XSL transformation failed:" >&2
		echo "command: ${xsltproc} \"${XSL}\" \"${TMP_FILE}.filtered\"" >&2
		${xsltproc} "${XSL}" "${TMP_FILE}.filtered" 1>&2
		return 1
	fi

	nb_errors=$( echo -e "${errors}" | head -n 1 )
	if [ ${nb_errors} -ne 0 ] ; then
		echo >&2
		echo "valgrind detected ${nb_errors} error(s)" >&2
		echo >&2
		echo -e "${errors}" | tail -n +2 >&2
		rm -f "${TMP_FILE}"
		rm -f "${TMP_FILE}.filtered"
		return 1
	fi

	[ ${global_ret} -eq 0 ] && echo "test run with valgrind without any error"

	rm -f "${TMP_FILE}"
	rm -f "${TMP_FILE}.filtered"
	return ${global_ret}
}


# Run a test without valgrind to not check for memory leaks
#  all params    the command line to run for the test
#  return value  0 in case of success, 1 in case of failure
run_test_without_valgrind()
{
	echo "run test without valgrind..."
	$@
	ret=$?
	echo "test run without valgrind (exit code ${ret})"
	return ${ret}
}

