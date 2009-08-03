#!/bin/sh
# Script to generate all required files for `configure' when
# starting from a fresh repository checkout.

#!/bin/sh
# Generate the autotools files

function run()
{
  echo -n "Running $1... "
  $@ >/dev/null 2>&1
  if [ $? -eq 0 ] ; then
    echo "done"
  else
    echo "failed"
    echo "Running $1 again with errors unmasked:"
    $@
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

