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

if ROHC_STATS
STATS_DIR = statistics
else
STATS_DIR = 
endif

if BUILD_DOC
DOC_DIR = doc
else
DOC_DIR =
endif

if BUILD_EXAMPLES
EXAMPLES_DIR = examples
else
EXAMPLES_DIR =
endif

SUBDIRS = src $(TESTS_DIR) $(STATS_DIR) app $(DOC_DIR) $(EXAMPLES_DIR)

dist_doc_DATA = \
	README \
	INSTALL \
	COPYING \
	AUTHORS \
	ChangeLog

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = rohc.pc

.PHONY: report measures

report:
if ROHC_TESTS
	./test/non_regression/report/report.sh
else
	@echo "tests are disabled, so report can not be created"
endif

measures:
	$(MAKE) -C measures

# configure options for distcheck
DISTCHECK_CONFIGURE_FLAGS = \
	--enable-fail-on-warning \
	--enable-rohc-tests \
	--enable-doc \
	--disable-examples

# extra files for releases
EXTRA_DIST = \
	autogen.sh

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
	find $(distdir)/test/non_regression/report/samples \
		-type f -and \
		-not -name source.pcap -and \
		-not -name rohc_smallcid.pcap -and \
		-not -name rohc_largecid.pcap -and \
		-not -name description \
		-exec $(RM) \{\} \;

