################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check library features
################################################################################

# IPv4
TESTS_ipv4rnd0 = \
	test_rtp_uor2_disambiguation_ipv4rnd0_ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0_ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0_ipv4rnd1_uor2rtp.sh
TESTS_ipv4rnd1 = \
	test_rtp_uor2_disambiguation_ipv4rnd1_ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1_ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1_ipv4rnd1_uor2rtp.sh
TESTS_ipv4 = \
	$(TESTS_ipv4rnd0) \
	$(TESTS_ipv4rnd1)

# IPv4 + IPv4
TESTS_ipv4rnd0_ipv4rnd0 = \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd0_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_ipv4rnd0_ipv4rnd1 = \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv4rnd1_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_ipv4rnd1_ipv4rnd0 = \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd0_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_ipv4rnd1_ipv4rnd1 = \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd1_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd0ipv4rnd1_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv4rnd1_ipv4rnd1ipv4rnd1_uor2rtp.sh
TESTS_ipv4_ipv4 = \
	$(TESTS_ipv4rnd0_ipv4rnd0) \
	$(TESTS_ipv4rnd0_ipv4rnd1) \
	$(TESTS_ipv4rnd1_ipv4rnd0) \
	$(TESTS_ipv4rnd1_ipv4rnd1)

# IPv4 + IPv6
TESTS_ipv4rnd0_ipv6 = \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv6_ipv4rnd0ipv6_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd0ipv6_ipv4rnd1ipv6_uor2rtp.sh
TESTS_ipv4rnd1_ipv6 = \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv6_ipv4rnd0ipv6_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv6_ipv4rnd0ipv6_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv4rnd1ipv6_ipv4rnd1ipv6_uor2rtp.sh
TESTS_ipv4_ipv6 = \
	$(TESTS_ipv4rnd0_ipv6) \
	$(TESTS_ipv4rnd1_ipv6)

# IPv6
TESTS_ipv6 = \
	test_rtp_uor2_disambiguation_ipv6_uor2rtp.sh

# IPv6 + IPv4
TESTS_ipv6_ipv4rnd0 = \
	test_rtp_uor2_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv6ipv4rnd0_ipv6ipv4rnd1_uor2rtp.sh
TESTS_ipv6_ipv4rnd1 = \
	test_rtp_uor2_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd0_uor2id.sh \
	test_rtp_uor2_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd0_uor2ts.sh \
	test_rtp_uor2_disambiguation_ipv6ipv4rnd1_ipv6ipv4rnd1_uor2rtp.sh
TESTS_ipv6_ipv4 = \
	$(TESTS_ipv6_ipv4rnd0) \
	$(TESTS_ipv6_ipv4rnd1)

# IPv6 + IPv6
TESTS_ipv6_ipv6 = \
	test_rtp_uor2_disambiguation_ipv6ipv6_uor2rtp.sh


TESTS = \
	$(TESTS_ipv4) \
	$(TESTS_ipv4_ipv4) \
	$(TESTS_ipv4_ipv6) \
	$(TESTS_ipv6) \
	$(TESTS_ipv6_ipv4) \
	$(TESTS_ipv6_ipv6)


check_PROGRAMS = \
	test_rtp_uor2_disambiguation


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


test_rtp_uor2_disambiguation_SOURCES = test_rtp_uor2_disambiguation.c
test_rtp_uor2_disambiguation_LDADD = \
	-lpcap \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common

EXTRA_DIST = \
	test_rtp_uor2_disambiguation.sh \
	$(TESTS) \
	inputs

