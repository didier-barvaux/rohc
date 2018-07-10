#!/bin/sh
#
# Copyright 2007,2009-2010,2013 Viveris Technologies
# Copyright 2011-2014 Didier Barvaux
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

# Script to generate all required files for `configure' when
# starting from a fresh repository checkout.

run()
{
  binary_name="$1"
  shift
  args="$@"

  echo -n "Running ${binary_name}... "

  binary_path=$( which ${binary_name} 2>/dev/null )
  if [ -z "$binary_path" ] || [ ! -x "$binary_path" ] ; then
    echo "failed"
    echo "Command ${binary_name} not found, please install it"
    exit 1
  fi

  $binary_path $args >/dev/null 2>&1
  if [ $? -eq 0 ] ; then
    echo "done"
  else
    echo "failed"
    echo "Running ${binary_name} again with errors unmasked:"
    $binary_path $args
    exit 1
  fi
}

rm -f config.cache
rm -f config.log

OLD_PWD="$PWD"
NEW_PWD="`dirname $0`"
cd "${NEW_PWD}" >/dev/null

run aclocal
run libtoolize --force
run autoconf
run autoheader
run automake --add-missing

cd "${OLD_PWD}" >/dev/null

# autodetect some dev options
add_opts=""
doxygen="$( which doxygen 2>/dev/null )"
if [ $? -eq 0 ] && [ "x${doxygen}" != "x" ] && [ -x "${doxygen}" ] ; then
	dot="$( which dot 2>/dev/null )"
	if [ $? -eq 0 ] && [ "x${dot}" != "x" ] && [ -x "${dot}" ] ; then
		add_opts="${add_opts} --enable-doc"
	fi
fi
doxy2man="$( which doxy2man 2>/dev/null )"
if [ $? -eq 0 ] && [ "x${doxy2man}" != "x" ] && [ -x "${doxy2man}" ] ; then
	add_opts="${add_opts} --enable-doc-man"
fi
if [ "${USE_VALGRIND}" = yes ] ; then
	add_opts="${add_opts} --enable-rohc-tests-valgrind"
fi
if [ -e "/lib/modules/`uname -r`/build" ] ; then
	add_opts="${add_opts} --enable-linux-kernel-module"
fi

# run configure with failure on compiler warnings enabled since autogen.sh
# is for developpers not users, also enable tests, stats, doc and examples.
chmod +x ${NEW_PWD}/configure
${NEW_PWD}/configure \
	--enable-rohc-debug \
	--enable-fail-on-warning \
	--enable-fortify-sources \
	--enable-app-sniffer \
	--enable-app-stats \
	--enable-rohc-tests \
	--enable-examples \
	${add_opts} \
	$@

