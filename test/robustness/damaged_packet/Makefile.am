################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tool that checks that the library correctly
#	             handle damaged packets
################################################################################


TESTS = \
	test_damaged_packet_7_uo0.sh

# the following tests fail with the current codebase
XFAIL_TESTS = \
	test_damaged_packet_7_uo0.sh


check_PROGRAMS = \
	test_damaged_packet


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


test_damaged_packet_SOURCES = test_damaged_packet.c
test_damaged_packet_LDADD = \
	-lpcap \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp \
	-lm

EXTRA_DIST = \
	test_damaged_packet.sh \
	$(TESTS) \
	inputs

