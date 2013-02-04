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
# @file   start_fuzzer.sh
# @brief  ROHC fuzzer helper script
# @author Didier Barvaux <didier@barvaux.org>
# @author Yura
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

echo "ROHC fuzzer stopped on $(uname -n) with return code $ret" | \
	mailsubj "ROHC fuzzer stopped on $(uname -n) with code $ret" "${email_addr}"

exit 0

