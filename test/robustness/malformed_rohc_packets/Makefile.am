################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tool that checks that decompression of malformed
#	             ROHC packets fails without crashing
################################################################################


TESTS = \
	test_malformed_rohc_packets_ir_1.sh \
	test_malformed_rohc_packets_ir_with_list_encoding_type1_1.sh \
	test_malformed_rohc_packets_truncated_uor2id_14.sh


check_PROGRAMS = \
	test_malformed_rohc_packets


test_malformed_rohc_packets_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_malformed_rohc_packets_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_malformed_rohc_packets_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

test_malformed_rohc_packets_SOURCES = \
	test_malformed_rohc_packets.c

test_malformed_rohc_packets_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_malformed_rohc_packets.sh \
	$(TESTS) \
	inputs

