################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tool that checks that the library correctly
#	             handle damaged packets
################################################################################


TESTS = \
	test_damaged_packet_3_ir_with_tss_set.sh \
	test_damaged_packet_3_ir_with_tss_not_set.sh \
	test_damaged_packet_5_irdyn_with_tss_set.sh \
	test_damaged_packet_5_irdyn_with_tss_not_set.sh \
	test_damaged_packet_5_uo0.sh \
	test_damaged_packet_8_uo1id.sh \
	test_damaged_packet_8_uor2ts_without_ext3.sh \
	test_damaged_packet_8_uor2ts_with_ext3_and_ts_stride.sh \
	test_damaged_packet_8_uor2_with_ext3_but_not_ts_stride.sh


check_PROGRAMS = \
	test_damaged_packet


test_damaged_packet_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/compat \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

test_damaged_packet_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

test_damaged_packet_SOURCES = \
	test_damaged_packet.c

test_damaged_packet_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_damaged_packet.sh \
	$(TESTS) \
	inputs

