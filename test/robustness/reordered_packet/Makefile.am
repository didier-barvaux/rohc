################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tool that checks that the library correctly
#	             handle moderate reordered packets
################################################################################


TESTS = \
	test_reordered_packet_51_lossy_rtp.sh

check_PROGRAMS = \
	test_reordered_packet

test_reordered_packet_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_reordered_packet_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_reordered_packet_LDFLAGS = \
	$(configure_ldflags)

test_reordered_packet_SOURCES = \
	test_reordered_packet.c

test_reordered_packet_LDADD = \
	-l$(pcap_lib_name) \
	$(top_builddir)/src/librohc.la \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_reordered_packet.sh \
	$(TESTS) \
	inputs

