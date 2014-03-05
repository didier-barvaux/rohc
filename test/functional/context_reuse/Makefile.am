################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check library features
################################################################################

TESTS_IPv4 = \
	test_context_reuse_many_ipv4_icmp_then_ipv4_ipv4_icmp.sh \
	test_context_reuse_many_ipv4_icmp_then_ipv4_ipv6_icmp.sh \
	test_context_reuse_many_ipv4_icmp_then_ipv6_icmp.sh \
	test_context_reuse_many_ipv4_icmp_then_ipv6_ipv4_icmp.sh \
	test_context_reuse_many_ipv4_icmp_then_ipv6_ipv6_icmp.sh

TESTS_IPv4_IPv4 = \
	test_context_reuse_many_ipv4_ipv4_icmp_then_ipv4_icmp.sh \
	test_context_reuse_many_ipv4_ipv4_icmp_then_ipv4_ipv6_icmp.sh \
	test_context_reuse_many_ipv4_ipv4_icmp_then_ipv6_icmp.sh \
	test_context_reuse_many_ipv4_ipv4_icmp_then_ipv6_ipv4_icmp.sh \
	test_context_reuse_many_ipv4_ipv4_icmp_then_ipv6_ipv6_icmp.sh

TESTS_IPv4_IPv6 = \
	test_context_reuse_many_ipv4_ipv6_icmp_then_ipv4_icmp.sh \
	test_context_reuse_many_ipv4_ipv6_icmp_then_ipv4_ipv4_icmp.sh \
	test_context_reuse_many_ipv4_ipv6_icmp_then_ipv6_icmp.sh \
	test_context_reuse_many_ipv4_ipv6_icmp_then_ipv6_ipv4_icmp.sh \
	test_context_reuse_many_ipv4_ipv6_icmp_then_ipv6_ipv6_icmp.sh

TESTS_IPv6 = \
	test_context_reuse_many_ipv6_icmp_then_ipv4_icmp.sh \
	test_context_reuse_many_ipv6_icmp_then_ipv4_ipv4_icmp.sh \
	test_context_reuse_many_ipv6_icmp_then_ipv4_ipv6_icmp.sh \
	test_context_reuse_many_ipv6_icmp_then_ipv6_ipv4_icmp.sh \
	test_context_reuse_many_ipv6_icmp_then_ipv6_ipv6_icmp.sh

TESTS_IPv6_IPv4 = \
	test_context_reuse_many_ipv6_ipv4_icmp_then_ipv4_icmp.sh \
	test_context_reuse_many_ipv6_ipv4_icmp_then_ipv4_ipv4_icmp.sh \
	test_context_reuse_many_ipv6_ipv4_icmp_then_ipv4_ipv6_icmp.sh \
	test_context_reuse_many_ipv6_ipv4_icmp_then_ipv6_icmp.sh \
	test_context_reuse_many_ipv6_ipv4_icmp_then_ipv6_ipv6_icmp.sh

TESTS_IPv6_IPv6 = \
	test_context_reuse_many_ipv6_ipv6_icmp_then_ipv4_icmp.sh \
	test_context_reuse_many_ipv6_ipv6_icmp_then_ipv4_ipv4_icmp.sh \
	test_context_reuse_many_ipv6_ipv6_icmp_then_ipv4_ipv6_icmp.sh \
	test_context_reuse_many_ipv6_ipv6_icmp_then_ipv6_icmp.sh \
	test_context_reuse_many_ipv6_ipv6_icmp_then_ipv6_ipv4_icmp.sh

TESTS_PROFILE_CHANGE = \
	test_context_reuse_many_ipv4_icmp_then_ipv4_udp.sh \
	test_context_reuse_many_ipv4_icmp_then_ipv4_udp_rtp.sh \
	test_context_reuse_many_ipv4_udp_rtp_then_ipv6_icmp.sh \
	test_context_reuse_many_ipv4_udp_rtp_then_ipv6_udp.sh \
	test_context_reuse_many_ipv4_icmp_then_ipv4_tcp.sh

TESTS_PROTOCOL_CHANGE = \
	test_context_reuse_ipv4_icmp_then_ipv4_tcp.sh \
	test_context_reuse_ipv4_tcp_then_ipv4_udp.sh

TESTS = \
	test_context_reuse_ipv4_icmp_then_ipv6_icmp.sh \
	test_context_reuse_ipv4_icmp_then_ipv4_ipv4_icmp.sh \
	$(TESTS_IPv4) \
	$(TESTS_IPv4_IPv4) \
	$(TESTS_IPv4_IPv6) \
	$(TESTS_IPv6) \
	$(TESTS_IPv6_IPv4) \
	$(TESTS_IPv6_IPv6) \
	$(TESTS_PROFILE_CHANGE) \
	$(TESTS_PROTOCOL_CHANGE)


check_PROGRAMS = \
	test_context_reuse


test_context_reuse_SOURCES = test_context_reuse.c

test_context_reuse_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_context_reuse_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_context_reuse_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

test_context_reuse_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_context_reuse.sh \
	$(TESTS) \
	inputs

