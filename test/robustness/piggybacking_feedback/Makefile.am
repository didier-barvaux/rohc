################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tool that checks how the compressor handles
#	             feedback piggybacking with compression failures.
################################################################################


TESTS = \
	test_piggybacking_feedback.sh


check_PROGRAMS = \
	test_piggybacking_feedback


INCLUDES = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs


test_piggybacking_feedback_SOURCES = test_piggybacking_feedback.c
test_piggybacking_feedback_LDADD = \
	-lpcap \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common

EXTRA_DIST = \
	$(TESTS)

