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
	$(configure_cflags) \
	-Wno-unused-parameter

test_segment_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

test_segment_LDFLAGS = \
	-L$(top_builddir)/src/.libs \
	$(configure_ldflags)

test_segment_LDADD = \
	-lrohc \
	$(additional_platform_libs)


EXTRA_DIST = \
	$(TESTS)

