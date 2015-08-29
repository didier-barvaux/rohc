#!/bin/sh

verbose=0
failures=0
sourcefiles_nr=0

[ "$1" = "-v" ] && verbose=1

for sourcefile in $( find src/ test/ app/ -type f -and -name \*.c ; \
                     find src/ test/ app/ -type f -and -name \*.h ) ; do

	sourcefiles_nr=$(( ${sourcefiles_nr} + 1 ))

	[ ${verbose} -ne 0 ] && echo -n "reformat '${sourcefile}'... "

	uncrustify -c contrib/uncrustify.cfg --replace --no-backup "${sourcefile}" &>/dev/null
	if [ $? -ne 0 ] ; then
		[ ${verbose} -ne 0 ] && echo "uncrustify failed."
		failures=$(( ${failures} + 1 ))
		continue
	fi

	# work around some uncrustify problems
	#  - always put a tab before __attribute__ keywords for functions
	#  - don't put spaces around ':' for bitfields
	#  - put back '§' characters for RFC paragraphs
	sed -i \
		-e 's/^__attribute__/\t__attribute__/g' \
		-e 's/\([a-zA-Z_][a-zA-Z_0-9]*\) : \([0-9]\+\);/\1:\2;/g' \
		-e 's/\(RFC \?[0-9]\+,\?\) \([0-9.]\+\)/\1 §\2/g' \
		"${sourcefile}"
	if [ $? -ne 0 ] ; then
		[ ${verbose} -ne 0 ] && echo "sed failed."
		failures=$(( ${failures} + 1 ))
		continue
	fi

	[ ${verbose} -ne 0 ] && echo "done."

done

echo "${sourcefiles_nr} source files reformated."

if [ ${failures} -ne 0 ] ; then
	echo "${failures} failures occurred."
	exit 1
else
	echo "no error occurred."
	exit 0
fi

