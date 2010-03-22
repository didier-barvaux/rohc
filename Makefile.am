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

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = rohc.pc

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

# extra files for releases
EXTRA_DIST = \
	autogen.sh \
	doc/doxygen

# other extra files for releases
dist-hook:
	mkdir -p $(distdir)/measures
	cp -f $(srcdir)/measures/*.sh $(distdir)/measures/
	cp -f $(srcdir)/measures/Makefile $(distdir)/measures/
	mkdir -p $(distdir)/measures/rtp
	cp -f $(srcdir)/measures/rtp/Makefile $(distdir)/measures/rtp/
	cp -f $(srcdir)/measures/rtp/*.plot $(distdir)/measures/rtp/
	cp -f $(srcdir)/measures/rtp/*.comp_data $(distdir)/measures/rtp/
	cp -f $(srcdir)/measures/rtp/*.decomp_data $(distdir)/measures/rtp/
	mkdir -p $(distdir)/measures/ftp
	cp -f $(srcdir)/measures/ftp/Makefile $(distdir)/measures/ftp/
	cp -f $(srcdir)/measures/ftp/*.plot $(distdir)/measures/ftp/
	cp -f $(srcdir)/measures/ftp/*.comp_data $(distdir)/measures/ftp/
	cp -f $(srcdir)/measures/ftp/*.decomp_data $(distdir)/measures/ftp/
	mkdir -p $(distdir)/statistics
	cp -f $(srcdir)/statistics/* $(distdir)/statistics/
	find $(distdir)/test/report/samples \
		-type f -and \
		-not -name source.pcap -and \
		-not -name rohc_smallcid.pcap -and \
		-not -name rohc_largecid.pcap -and \
		-not -name description \
		-exec $(RM) \{\} \;

