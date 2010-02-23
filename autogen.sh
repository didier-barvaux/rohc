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

export WANT_AUTOMAKE=1.7

rm -f config.cache
rm -f config.log

run aclocal
run libtoolize --force
run autoconf
run autoheader
run automake --add-missing

chmod +x ./configure
./configure $@

