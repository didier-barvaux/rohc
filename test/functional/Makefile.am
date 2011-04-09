################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check library features
################################################################################


TESTS = \
	test_feedback2_ack_smallsn_crc.sh \
	test_feedback2_ack_largesn_sn_crc.sh


check_PROGRAMS = \
	test_feedback2


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


test_feedback2_SOURCES = test_feedback2.c
test_feedback2_LDADD = \
	-lpcap \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp \
	-lm

EXTRA_DIST = \
	test_feedback2.sh \
	$(TESTS) \
	inputs

