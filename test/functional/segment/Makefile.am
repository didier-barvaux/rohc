################################################################################
#	Name       : Makefile
#	Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#               Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check library features
################################################################################


TESTS = \
	test_segment.sh


check_PROGRAMS = \
	test_segment


test_segment_SOURCES = test_segment.c

test_segment_CFLAGS = \
	$(configure_cflags)

test_segment_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

test_segment_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

test_segment_LDADD = \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)


EXTRA_DIST = \
	$(TESTS)

