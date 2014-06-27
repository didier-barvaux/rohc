################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check if decompressing feedback-only
#	             packets is supported
################################################################################


TESTS = \
	test_decompress_padding.sh


check_PROGRAMS = \
	test_decompress_padding


test_decompress_padding_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter

test_decompress_padding_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

test_decompress_padding_LDFLAGS = \
	-L$(top_builddir)/src/.libs \
	$(configure_ldflags)

test_decompress_padding_SOURCES = \
	test_decompress_padding.c

test_decompress_padding_LDADD = \
	-lrohc \
	$(additional_platform_libs)

EXTRA_DIST = \
	$(TESTS)

