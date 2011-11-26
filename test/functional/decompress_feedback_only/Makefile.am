################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check if decompressing feedback-only
#	             packets is supported
################################################################################


TESTS = \
	test_decompress_feedback_only.sh

XFAIL_TESTS = \
	test_decompress_feedback_only.sh


check_PROGRAMS = \
	test_decompress_feedback_only


INCLUDES = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/decomp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs


test_decompress_feedback_only_SOURCES = test_decompress_feedback_only.c
test_decompress_feedback_only_LDADD = \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	-lm

EXTRA_DIST = \
	$(TESTS)

