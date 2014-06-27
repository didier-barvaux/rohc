################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check library features
################################################################################


############# UO-1* packets #############

# IPv4
TESTS_UO1_ipv4rnd0 = \
	test_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd0_uo1id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd0_uo1ts.sh
TESTS_UO1_ipv4rnd1 = \
	test_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd1_uo1rtp.sh
TESTS_UO1_ipv4 = \
	$(TESTS_UO1_ipv4rnd0) \
	$(TESTS_UO1_ipv4rnd1)

# IPv4 + IPv4
TESTS_UO1_ipv4rnd0_ipv4rnd0 = \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uo1id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uo1ts.sh
TESTS_UO1_ipv4rnd0_ipv4rnd1 = \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uo1id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uo1ts.sh
TESTS_UO1_ipv4rnd1_ipv4rnd0 = \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uo1id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uo1ts.sh
TESTS_UO1_ipv4rnd1_ipv4rnd1 = \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd1_uo1rtp.sh
TESTS_UO1_ipv4_ipv4 = \
	$(TESTS_UO1_ipv4rnd0_ipv4rnd0) \
	$(TESTS_UO1_ipv4rnd0_ipv4rnd1) \
	$(TESTS_UO1_ipv4rnd1_ipv4rnd0) \
	$(TESTS_UO1_ipv4rnd1_ipv4rnd1)

# IPv4 + IPv6
TESTS_UO1_ipv4rnd0_ipv6 = \
	test_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uo1id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uo1ts.sh
TESTS_UO1_ipv4rnd1_ipv6 = \
	test_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd1ipv6_uo1rtp.sh
TESTS_UO1_ipv4_ipv6 = \
	$(TESTS_UO1_ipv4rnd0_ipv6) \
	$(TESTS_UO1_ipv4rnd1_ipv6)

# IPv6
TESTS_UO1_ipv6 = \
	test_rtp_uo_disambiguation_ipv6_uo1rtp.sh

# IPv6 + IPv4
TESTS_UO1_ipv6_ipv4rnd0 = \
	test_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uo1id.sh \
	test_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uo1ts.sh
TESTS_UO1_ipv6_ipv4rnd1 = \
	test_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd1_uo1rtp.sh
TESTS_UO1_ipv6_ipv4 = \
	$(TESTS_UO1_ipv6_ipv4rnd0) \
	$(TESTS_UO1_ipv6_ipv4rnd1)

# IPv6 + IPv6
TESTS_UO1_ipv6_ipv6 = \
	test_rtp_uo_disambiguation_ipv6ipv6_uo1rtp.sh

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
	test_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd0_ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4rnd1 = \
	test_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd1_ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4 = \
	$(TESTS_UOR2_ipv4rnd0) \
	$(TESTS_UOR2_ipv4rnd1)

# IPv4 + IPv4
TESTS_UOR2_ipv4rnd0_ipv4rnd0 = \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uo1id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4rnd0_ipv4rnd1 = \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4rnd1_ipv4rnd0 = \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4rnd1_ipv4rnd1 = \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv4_ipv4 = \
	$(TESTS_UOR2_ipv4rnd0_ipv4rnd0) \
	$(TESTS_UOR2_ipv4rnd0_ipv4rnd1) \
	$(TESTS_UOR2_ipv4rnd1_ipv4rnd0) \
	$(TESTS_UOR2_ipv4rnd1_ipv4rnd1)

# IPv4 + IPv6
TESTS_UOR2_ipv4rnd0_ipv6 = \
	test_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd0ipv6_ipv4rnd1ipv6_uor2rtp.sh
TESTS_UOR2_ipv4rnd1_ipv6 = \
	test_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd0ipv6_uor2id.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd0ipv6_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv4rnd1ipv6_ipv4rnd1ipv6_uor2rtp.sh
TESTS_UOR2_ipv4_ipv6 = \
	$(TESTS_UOR2_ipv4rnd0_ipv6) \
	$(TESTS_UOR2_ipv4rnd1_ipv6)

# IPv6
TESTS_UOR2_ipv6 = \
	test_rtp_uo_disambiguation_ipv6_uor2rtp.sh

# IPv6 + IPv4
TESTS_UOR2_ipv6_ipv4rnd0 = \
	test_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv6_ipv4rnd1 = \
	test_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd0_uor2id.sh \
	test_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd0_uor2ts.sh \
	test_rtp_uo_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd1_uor2rtp.sh
TESTS_UOR2_ipv6_ipv4 = \
	$(TESTS_UOR2_ipv6_ipv4rnd0) \
	$(TESTS_UOR2_ipv6_ipv4rnd1)

# IPv6 + IPv6
TESTS_UOR2_ipv6_ipv6 = \
	test_rtp_uo_disambiguation_ipv6ipv6_uor2rtp.sh

TESTS_UOR2 = \
	$(TESTS_UOR2_ipv4) \
	$(TESTS_UOR2_ipv4_ipv4) \
	$(TESTS_UOR2_ipv4_ipv6) \
	$(TESTS_UOR2_ipv6) \
	$(TESTS_UOR2_ipv6_ipv4) \
	$(TESTS_UOR2_ipv6_ipv6)


TESTS = \
	$(TESTS_UO1) \
	$(TESTS_UOR2)

check_PROGRAMS = \
	test_rtp_uo_disambiguation


test_rtp_uo_disambiguation_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_rtp_uo_disambiguation_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_rtp_uo_disambiguation_LDFLAGS = \
	-L$(top_builddir)/src/.libs \
	$(configure_ldflags)

test_rtp_uo_disambiguation_SOURCES = test_rtp_uo_disambiguation.c
test_rtp_uo_disambiguation_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_rtp_uo_disambiguation.sh \
	$(TESTS) \
	inputs

