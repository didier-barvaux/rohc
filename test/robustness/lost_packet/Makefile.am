################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the test tool that checks that the library correctly
#	             handle lost packets
################################################################################


TESTS = \
	test_lost_packet_7_non_sequential_rtp_ts.sh


check_PROGRAMS = \
	test_lost_packet


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


test_lost_packet_SOURCES = test_lost_packet.c
test_lost_packet_LDADD = \
	-lpcap \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	-lm

EXTRA_DIST = \
	test_lost_packet.sh \
	$(TESTS) \
	inputs

