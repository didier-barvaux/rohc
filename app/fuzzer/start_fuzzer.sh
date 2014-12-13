#!/bin/sh
#
# Copyright 2013 Didier Barvaux
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
# @file   start_fuzzer.sh
# @brief  ROHC fuzzer helper script
# @author Didier Barvaux <didier@barvaux.org>
#
# Stress test the ROHC decompressor to discover bugs.
# Send report to the given email address.
#

usage()
{
	echo "usage: $0 foo@example.com [seed]" >&2
}

email_addr="$1"
if [ -z "${email_addr}" ] ; then
	echo -e "too few arguments\n" >&2
	usage
	exit 1
fi
if [ "${email_addr}" = "-h" ] || \
   [ "${email_addr}" = "--help" ] || \
   [ "${email_addr}" = "help" ] ; then
	usage
	exit 1
fi
# TODO: check that email_addr is an email address

seed="$2"
if [ -z "${seed}" ] ; then
	cmd="play"
else
	# TODO: check that seed is a number
	cmd="replay ${seed}"
fi

if [ -n "$3" ] ; then
	echo -e "too many arguments\n" >&2
	usage
	exit 1
fi

echo "enable coredumps"
ulimit -c unlimited

nice -n 19 \
	ionice -c 3 \
	./app/fuzzer/rohc_fuzzer ${cmd}
ret=$?

msg="ROHC fuzzer stopped on $(uname -n) with return code $ret"

which mailsubj >/dev/null 2>&1
if [ $? -eq 0 ] ; then
	echo "${msg}" | mailsubj "${msg}" "${email_addr}"
else
	echo "${msg}"
fi

exit ${ret}

