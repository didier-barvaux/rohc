################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the test tool that checks that the library correctly
#	             handle lost packets
################################################################################


TESTS = \
	test_lost_packet_7-7_7_non_sequential_rtp_ts.sh \
	test_lost_packet_102-105_125_rtp_with_sn_wrapround.sh \
	test_lost_packet_274-287_289_nominal_rtp.sh \
	test_lost_packet_13-16_16_nominal_tcp.sh

check_PROGRAMS = \
	test_lost_packet

test_lost_packet_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_lost_packet_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_lost_packet_LDFLAGS = \
	-L$(top_builddir)/src/.libs \
	$(configure_ldflags)

test_lost_packet_SOURCES = \
	test_lost_packet.c

test_lost_packet_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_lost_packet.sh \
	test_lost_packet_repair.sh \
	test_lost_packet_norepair.sh \
	$(TESTS) \
	inputs

