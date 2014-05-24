#!/bin/sh
#
# Create a report of code coverage with the help of zcov.
#
# Do not use this script directly, run configure with --enable-code-coverage,
# build the library, then run the tests:
#   ./configure --enable-code-coverage
#   make clean
#   make all
#   make check
#
# note: LANG=C and LC_ALL=C are required for zcov to work correctly

echo "" >&2

# scan for gcov output files, create the output.zcov report file
echo -n "Collect information about code coverage... " >&2
LANG=C LC_ALL=C zcov-scan output.zcov . || exit 1
echo "done." >&2

# generate one HTML report from the collected data
echo -n "Generate HTML report about code coverage... " >&2
LANG=C LC_ALL=C zcov-genhtml --root="${PWD}" output.zcov coverage-report/ || exit 1
echo "done." >&2

echo "" >&2
echo "Load ./coverage-report/index.html in your favorite browser." >&2
echo "" >&2

