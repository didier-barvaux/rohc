################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC libraries and the test application
################################################################################

if ROHC_TESTS
TESTS_DIR = test
else
TESTS_DIR = 
endif

SUBDIRS = src $(TESTS_DIR) app

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
if ROHC_TESTS
	./test/report/report.sh
else
	@echo "tests are disabled, so report can not be created"
endif

measures:
	$(MAKE) -C measures

clean-doc:
	$(RM) -r doc/html

