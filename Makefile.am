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

SUBDIRS = src $(TESTS_DIR) $(STATS_DIR) app $(DOC_DIR) $(EXAMPLES_DIR) contrib

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
	--enable-rohc-tests \
	--disable-doc \
	--disable-examples

# extra files for releases
EXTRA_DIST = \
	autogen.sh

# other extra files for releases
dist-hook:
	find $(distdir)/test/non_regression/inputs \
		-type f -and \
		-not -name source.pcap -and \
		-not -name rohc_smallcid.pcap -and \
		-not -name rohc_largecid.pcap -and \
		-not -name description -and \
		-not -name rohc_sizes_smallcid -and \
		-not -name rohc_sizes_largecid -and \
		-not -name README \
		-exec $(RM) \{\} \;

