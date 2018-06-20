################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tool that checks that the library correctly
#	             handle damaged packets
################################################################################


TESTS = \
	test_damaged_packet_3_ir_with-tss-set.sh \
	test_damaged_packet_3_ir_with-tss-not-set.sh \
	test_damaged_packet_5_irdyn_with-tss-set.sh \
	test_damaged_packet_5_irdyn_with-tss-not-set.sh \
	test_damaged_packet_5_uo0.sh \
	test_damaged_packet_8_uo1id.sh \
	test_damaged_packet_8_uor2ts_without-ext3.sh \
	test_damaged_packet_8_uor2ts_with-ext3-and-ts-stride.sh \
	test_damaged_packet_8_uor2_with-ext3-but-not-ts-stride.sh \
	test_damaged_packet_273_uo0_repair.sh

XFAIL_TESTS = \
	test_damaged_packet_5_uo0.sh \
	test_damaged_packet_8_uo1id.sh

check_PROGRAMS = \
	test_damaged_packet


test_damaged_packet_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_damaged_packet_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_damaged_packet_LDFLAGS = \
	$(configure_ldflags)

test_damaged_packet_SOURCES = \
	test_damaged_packet.c

test_damaged_packet_LDADD = \
	-l$(pcap_lib_name) \
	$(top_builddir)/src/librohc.la \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_damaged_packet.sh \
	test_damaged_packet_repair.sh \
	test_damaged_packet_norepair.sh \
	$(TESTS) \
	inputs

