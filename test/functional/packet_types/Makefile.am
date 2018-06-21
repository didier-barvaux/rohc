################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check library features
################################################################################


############# UO-1* packets #############

# IPv4
TESTS_UO1_ipv4rnd0 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd0_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd0_uo1ts.sh
TESTS_UO1_ipv4rnd1 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd1_uo1rtp.sh
TESTS_UO1_ipv4 = \
	$(TESTS_UO1_ipv4rnd0) \
	$(TESTS_UO1_ipv4rnd1)

# IPv4 + IPv4
TESTS_UO1_ipv4rnd0_ipv4rnd0 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uo1ts.sh
TESTS_UO1_ipv4rnd0_ipv4rnd1 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uo1ts.sh
TESTS_UO1_ipv4rnd1_ipv4rnd0 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uo1ts.sh
TESTS_UO1_ipv4rnd1_ipv4rnd1 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd1_uo1rtp.sh
TESTS_UO1_ipv4_ipv4 = \
	$(TESTS_UO1_ipv4rnd0_ipv4rnd0) \
	$(TESTS_UO1_ipv4rnd0_ipv4rnd1) \
	$(TESTS_UO1_ipv4rnd1_ipv4rnd0) \
	$(TESTS_UO1_ipv4rnd1_ipv4rnd1)

# IPv4 + IPv6
TESTS_UO1_ipv4rnd0_ipv6 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uo1ts.sh
TESTS_UO1_ipv4rnd1_ipv6 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd1ipv6_uo1rtp.sh
TESTS_UO1_ipv4_ipv6 = \
	$(TESTS_UO1_ipv4rnd0_ipv6) \
	$(TESTS_UO1_ipv4rnd1_ipv6)

# IPv6
TESTS_UO1_ipv6 = \
	test_packet_types_rtp_uo_disambiguation_ipv6_uo1rtp.sh

# IPv6 + IPv4
TESTS_UO1_ipv6_ipv4rnd0 = \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uo1ts.sh
TESTS_UO1_ipv6_ipv4rnd1 = \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd1_uo1rtp.sh
TESTS_UO1_ipv6_ipv4 = \
	$(TESTS_UO1_ipv6_ipv4rnd0) \
	$(TESTS_UO1_ipv6_ipv4rnd1)

# IPv6 + IPv6
TESTS_UO1_ipv6_ipv6 = \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv6_uo1rtp.sh

TESTS_UO1 = \
	$(TESTS_UO1_ipv4) \
	$(TESTS_UO1_ipv4_ipv4) \
	$(TESTS_UO1_ipv4_ipv6) \
	$(TESTS_UO1_ipv6) \
	$(TESTS_UO1_ipv6_ipv4) \
	$(TESTS_UO1_ipv6_ipv6)


############# UOR-2* packets #############

# IPv4
TESTS_UOR2_ipv4rnd0 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4rnd1 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4 = \
	$(TESTS_UOR2_ipv4rnd0) \
	$(TESTS_UOR2_ipv4rnd1)

# IPv4 + IPv4
TESTS_UOR2_ipv4rnd0_ipv4rnd0 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4rnd0_ipv4rnd1 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4rnd1_ipv4rnd0 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4rnd1_ipv4rnd1 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4_ipv4 = \
	$(TESTS_UOR2_ipv4rnd0_ipv4rnd0) \
	$(TESTS_UOR2_ipv4rnd0_ipv4rnd1) \
	$(TESTS_UOR2_ipv4rnd1_ipv4rnd0) \
	$(TESTS_UOR2_ipv4rnd1_ipv4rnd1)

# IPv4 + IPv6
TESTS_UOR2_ipv4rnd0_ipv6 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd1ipv6_uor2rtp.sh
TESTS_UOR2_ipv4rnd1_ipv6 = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd0ipv6_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd0ipv6_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd1ipv6_uor2rtp.sh
TESTS_UOR2_ipv4_ipv6 = \
	$(TESTS_UOR2_ipv4rnd0_ipv6) \
	$(TESTS_UOR2_ipv4rnd1_ipv6)

# IPv6
TESTS_UOR2_ipv6 = \
	test_packet_types_rtp_uo_disambiguation_ipv6_uor2rtp.sh

# IPv6 + IPv4
TESTS_UOR2_ipv6_ipv4rnd0 = \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv6_ipv4rnd1 = \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd0_uor2id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd0_uor2ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv6_ipv4 = \
	$(TESTS_UOR2_ipv6_ipv4rnd0) \
	$(TESTS_UOR2_ipv6_ipv4rnd1)

# IPv6 + IPv6
TESTS_UOR2_ipv6_ipv6 = \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv6_uor2rtp.sh

TESTS_UOR2 = \
	$(TESTS_UOR2_ipv4) \
	$(TESTS_UOR2_ipv4_ipv4) \
	$(TESTS_UOR2_ipv4_ipv6) \
	$(TESTS_UOR2_ipv6) \
	$(TESTS_UOR2_ipv6_ipv4) \
	$(TESTS_UOR2_ipv6_ipv6)


############# TCP packets #############

TESTS_TCP_SEQ = \
	test_packet_types_ipv4rnd_tcp_ir.sh \
	test_packet_types_ipv4rnd_tcp_irdyn.sh \
	test_packet_types_ipv4rnd_tcp_tcp-co-common.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-1.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-2.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-3.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-4.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-5.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-6.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-7.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-8.sh

TESTS_TCP_RND = \
	test_packet_types_ipv4seq_tcp_ir.sh \
	test_packet_types_ipv4seq_tcp_irdyn.sh \
	test_packet_types_ipv4seq_tcp_tcp-co-common.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-1.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-2.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-3.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-4.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-5.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-6.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-7.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-8.sh

TESTS_TCP = \
	$(TESTS_TCP_SEQ) \
	$(TESTS_TCP_RND)


TESTS = \
	$(TESTS_UO1) \
	$(TESTS_UOR2) \
	$(TESTS_TCP)

XFAIL_TESTS = \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd1_uo1rtp.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uo1ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uo1id.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uo1ts.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd1_uo1rtp.sh \
	test_packet_types_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd1ipv6_uo1rtp.sh \
	test_packet_types_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd1_uo1rtp.sh \
	test_packet_types_ipv4rnd_tcp_irdyn.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-1.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-2.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-3.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-4.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-5.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-6.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-7.sh \
	test_packet_types_ipv4seq_tcp_irdyn.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-1.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-2.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-3.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-4.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-5.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-6.sh \
	test_packet_types_ipv4seq_tcp_tcp-seq-7.sh \
	test_packet_types_ipv4rnd_tcp_tcp-rnd-8.sh

check_PROGRAMS = \
	test_packet_types


test_packet_types_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_packet_types_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_packet_types_LDFLAGS = \
	$(configure_ldflags)

test_packet_types_SOURCES = test_packet_types.c
test_packet_types_LDADD = \
	-l$(pcap_lib_name) \
	$(top_builddir)/src/librohc.la \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_packet_types.sh \
	$(TESTS) \
	inputs

