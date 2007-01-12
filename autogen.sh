#!/bin/sh
# Script to generate all required files for `configure' when
# starting from a fresh repository checkout.

ACLOCAL="aclocal"
AUTOCONF="autoconf"
AUTOHEADER="autoheader"
LIBTOOLIZE="libtoolize --automake"
AUTOMAKE="automake -a -c --foreign"

function build {
    echo -n "Building '$1'... "
    eval "$2"
    if [ $? -ne 0 ] ; then
        echo "failed"
        exit 1
    fi
    echo "done"
}

# Clean up old files which could hurt otherwise.
rm -f config.cache config.log config.status

# Generate `aclocal.m4'.
rm -f aclocal.m4
build "aclocal.m4" "$ACLOCAL"

# Generate `config.h.in'.
build "config.h.in" "$AUTOHEADER"

# Generate `configure' from `configure.ac'.
build "configure" "$AUTOCONF"

# Generate `ltmain.sh'.
build "ltmain.sh" "$LIBTOOLIZE"

# Generate `stamp-h1' and all `Makefile.in' files.
rm -f stamp-h1
build "Makefile templates" "$AUTOMAKE"

echo
echo "Run './configure ; make'"
echo
