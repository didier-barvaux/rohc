#!/bin/sh
#
# Copyright 2014 Didier Barvaux
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

PERF_BIN=$( which perf 2>/dev/null )
PERF_OPTS="stat -e cycles -a -r "
PERF_ITER=5
TEST_BIN="$( dirname "$0" )/$( basename "$0" ".sh" )"

usage()
{
	echo "rohc_test_performance.sh comp|decomp smallcid|largecid capture-file [nr-iter]"
}


[ ! -f "${PERF_BIN}" ] && PERF_BIN="/usr/sbin/perf"
if [ ! -f "${PERF_BIN}" ] ; then
	echo "perf executable not found" >&2
	exit 1
fi
if [ ! -x "${PERF_BIN}" ] ; then
	echo "perf executable not executable" >&2
	exit 1
fi
if [ ! -f "${TEST_BIN}" ] ; then
	echo "${TEST_BIN} executable not found" >&2
	exit 1
fi
if [ ! -x "${TEST_BIN}" ] ; then
	echo "${TEST_BIN} executable not executable" >&2
	exit 1
fi


test_mode="$1"
test_cid_type="$2"
test_capture="$3"
test_iter="$4"
if [ -z "${test_mode}" ] || \
   [ -z "${test_cid_type}" ] || \
   [ -z "${test_capture}" ] ; then
	usage
	exit 1
fi
if [ "${test_mode}" != "comp" ] && [ "${test_mode}" != "decomp" ] ; then
	usage
	exit 1
fi
if [ "${test_cid_type}" != "smallcid" ] && \
	[ "${test_cid_type}" != "largecid" ] ; then
	usage
	exit 1
fi
if [ ! -f "${test_capture}" ] ; then
	echo "${test_capture} capture file not found" >&2
	exit 1
fi
if [ ! -r "${test_capture}" ] ; then
	echo "${test_capture} capture file not readable" >&2
	exit 1
fi
if [ -z "${test_iter}" ] ; then
	test_iter=${PERF_ITER}
fi

${PERF_BIN} ${PERF_OPTS} ${test_iter} -- \
	${TEST_BIN} ${test_mode} ${test_cid_type} ${test_capture}

