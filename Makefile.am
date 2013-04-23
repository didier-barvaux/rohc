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

if ROHC_LINUX_MODULE
LINUX_MODULE_DIR = linux
else
LINUX_MODULE_DIR =
endif

if ROHC_STATS
STATS_DIR = statistics
else
STATS_DIR = 
endif

if ROHC_APPS
APPS_DIR = app
else
APPS_DIR =
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

SUBDIRS = \
	src \
	$(TESTS_DIR) \
	$(LINUX_MODULE_DIR) \
	$(STATS_DIR) \
	$(APPS_DIR) \
	$(DOC_DIR) \
	$(EXAMPLES_DIR) \
	contrib

dist_doc_DATA = \
	README \
	INSTALL \
	COPYING \
	AUTHORS \
	ChangeLog

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = rohc.pc

# configure options for distcheck
DISTCHECK_CONFIGURE_FLAGS = \
	--enable-fail-on-warning \
	--enable-fortify-sources \
	--enable-rohc-tests \
	--disable-doc \
	--disable-examples

# extra files for releases
EXTRA_DIST = \
	autogen.sh \
	test/report_code_coverage.sh

# other extra files for releases
dist-hook:
	find $(distdir)/test/non_regression/inputs \
		-type f -and \
		-not -name source.pcap -and \
		-not -name rohc_wlsb4_smallcid.pcap -and \
		-not -name rohc_wlsb4_largecid.pcap -and \
		-not -name rohc_wlsb64_smallcid.pcap -and \
		-not -name rohc_wlsb64_largecid.pcap -and \
		-not -name description -and \
		-not -name rohc_sizes_wlsb4_smallcid -and \
		-not -name rohc_sizes_wlsb4_largecid -and \
		-not -name rohc_sizes_wlsb64_smallcid -and \
		-not -name rohc_sizes_wlsb64_largecid -and \
		-not -name README \
		-exec $(RM) \{\} \;


if CODE_COVERAGE
TESTS_CODE_COVERAGE = test/report_code_coverage.sh
endif
TESTS = $(TESTS_CODE_COVERAGE)

