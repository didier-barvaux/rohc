#!/bin/sh
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
cd $( dirname $0 ) &>/dev/null

run aclocal
run libtoolize --force
run autoconf
run autoheader
run automake --add-missing

cd ${OLD_PWD} &>/dev/null

# run configure with failure on compiler warnings enabled since autogen.sh
# is for developpers not users, also enable tests, stats, doc and examples.
chmod +x $( dirname $0 )/configure
$( dirname $0 )/configure \
	--enable-rohc-debug \
	--enable-fail-on-warning \
	--enable-fortify-sources \
	--enable-app-fuzzer \
	--enable-app-performance \
	--enable-app-sniffer \
	--enable-app-tunnel \
	--enable-rohc-tests \
	--enable-rohc-stats \
	--enable-doc \
	--enable-examples \
	--enable-linux-kernel-module \
	$@

