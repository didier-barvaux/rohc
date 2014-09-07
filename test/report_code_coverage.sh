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
#

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

