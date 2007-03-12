################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#	Description: create the ROHC libraries and the test application
################################################################################

SUBDIRS = src

configure_files = \
	aclocal.m4 \
	config.h.in \
	configure \
	Makefile.am \
	configure.in \
	install-sh \
	mkinstalldirs \
	missing \
	depcomp

AM_MAKEFLAGS = -s

.PHONY: doc report

doc:
	doxygen doc/doxygen

test: test/test.c test/test.h all
	$(MAKE) -C test

report:
	./test/report/report.sh

tunnel: app/tunnel/tunnel.c
	$(MAKE) -C app/tunnel

clean-doc:
	$(RM) -r doc/html

