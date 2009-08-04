################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#	Description: create the ROHC libraries and the test application
################################################################################

SUBDIRS = src test app

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

.PHONY: doc report measures

doc:
	doxygen doc/doxygen

report:
	./test/report/report.sh

measures:
	$(MAKE) -C measures

clean-doc:
	$(RM) -r doc/html

