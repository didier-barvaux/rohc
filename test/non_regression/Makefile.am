################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create and run the ROHC non-regression tests
################################################################################

TESTS_BUG804552_SMALLCID = \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_smallcid.sh \
	test_non_regression_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_smallcid.sh

TESTS_ESP_SMALLCID = \
	test_non_regression_ipv4_esp_smallcid.sh \
	test_non_regression_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_smallcid.sh \
	test_non_regression_ipv6_esp_smallcid.sh

TESTS_SMALLCID = \
	test_non_regression_malformed-too-short_smallcid.sh \
	test_non_regression_unknown_smallcid.sh \
	test_non_regression_ipvx_smallcid.sh \
	test_non_regression_ipv4fragmented_smallcid.sh \
	test_non_regression_ipv4-with-options_smallcid.sh \
	test_non_regression_ipv4_icmp_smallcid.sh \
	test_non_regression_ipv4_icmp_bug580491_smallcid.sh \
	test_non_regression_ipv4_icmp+tcp_smallcid.sh \
	test_non_regression_ipv4_ipv4_icmp_smallcid.sh \
	test_non_regression_ipv4_ipv4_udplite_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video1_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video2_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_smallcid.sh \
	test_non_regression_ipv4_ipv6ext_udp_rtp_video1_smallcid.sh \
	test_non_regression_ipv4_ipv6_icmp_smallcid.sh \
	test_non_regression_ipv4_ipv6_udplite_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video1_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video2_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_smallcid.sh \
	test_non_regression_ipv4_udplite_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_h323_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_misc_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_mp3_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_rtp+rtp+icmp_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video2_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video3_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video1_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip-large-ts-stride_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip+video_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_more-than-14-bits-of-sn_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_lsb-interval-wraparound_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1001614-zero-ts-stride_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1080055_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1092660-rtp-padding-bit_smallcid.sh \
	test_non_regression_ipv4_udp_smallcid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_rtp_smallcid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_smallcid.sh \
	test_non_regression_ipv6ext_icmp_smallcid.sh \
	test_non_regression_ipv6ext_icmp-large-ipv6-ext_smallcid.sh \
	test_non_regression_ipv6ext_icmp-variable-ipv6ext_smallcid.sh \
	test_non_regression_ipv6ext_ipv6ext_icmp_smallcid.sh \
	test_non_regression_ipv6ext_udp_rtp_audio-vlc_smallcid.sh \
	test_non_regression_ipv6ext_udp_smallcid.sh \
	test_non_regression_ipv6_icmp_smallcid.sh \
	test_non_regression_ipv6_ipv6_icmp_smallcid.sh \
	test_non_regression_ipv6_ipv6_udplite_smallcid.sh \
	test_non_regression_ipv6_ipv6_udp_smallcid.sh \
	test_non_regression_ipv6_udplite_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_audio-vlc_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_video2_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_video1_smallcid.sh \
	test_non_regression_ipv6_udp_smallcid.sh \
	$(TESTS_BUG804552_SMALLCID) \
	$(TESTS_ESP_SMALLCID)


TESTS_BUG804552_LARGECID = \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_largecid.sh \
	test_non_regression_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_largecid.sh

TESTS_ESP_LARGECID = \
	test_non_regression_ipv4_esp_largecid.sh \
	test_non_regression_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_largecid.sh \
	test_non_regression_ipv6_esp_largecid.sh

TESTS_LARGECID = \
	test_non_regression_malformed-too-short_largecid.sh \
	test_non_regression_unknown_largecid.sh \
	test_non_regression_ipvx_largecid.sh \
	test_non_regression_ipv4fragmented_largecid.sh \
	test_non_regression_ipv4-with-options_largecid.sh \
	test_non_regression_ipv4_icmp_largecid.sh \
	test_non_regression_ipv4_icmp_bug580491_largecid.sh \
	test_non_regression_ipv4_icmp+tcp_largecid.sh \
	test_non_regression_ipv4_ipv4_icmp_largecid.sh \
	test_non_regression_ipv4_ipv4_udplite_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video1_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video2_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_largecid.sh \
	test_non_regression_ipv4_ipv6ext_udp_rtp_video1_largecid.sh \
	test_non_regression_ipv4_ipv6_icmp_largecid.sh \
	test_non_regression_ipv4_ipv6_udplite_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video1_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video2_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_largecid.sh \
	test_non_regression_ipv4_udplite_largecid.sh \
	test_non_regression_ipv4_udp_rtp_h323_largecid.sh \
	test_non_regression_ipv4_udp_rtp_misc_largecid.sh \
	test_non_regression_ipv4_udp_rtp_mp3_largecid.sh \
	test_non_regression_ipv4_udp_rtp_rtp+rtp+icmp_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video2_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video3_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video1_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip-large-ts-stride_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip+video_largecid.sh \
	test_non_regression_ipv4_udp_rtp_more-than-14-bits-of-sn_largecid.sh \
	test_non_regression_ipv4_udp_rtp_lsb-interval-wraparound_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1001614-zero-ts-stride_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1080055_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1092660-rtp-padding-bit_largecid.sh \
	test_non_regression_ipv4_udp_largecid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_rtp_largecid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_largecid.sh \
	test_non_regression_ipv6ext_icmp_largecid.sh \
	test_non_regression_ipv6ext_icmp-large-ipv6-ext_largecid.sh \
	test_non_regression_ipv6ext_icmp-variable-ipv6ext_largecid.sh \
	test_non_regression_ipv6ext_ipv6ext_icmp_largecid.sh \
	test_non_regression_ipv6ext_udp_rtp_audio-vlc_largecid.sh \
	test_non_regression_ipv6ext_udp_largecid.sh \
	test_non_regression_ipv6_icmp_largecid.sh \
	test_non_regression_ipv6_ipv6_icmp_largecid.sh \
	test_non_regression_ipv6_ipv6_udplite_largecid.sh \
	test_non_regression_ipv6_ipv6_udp_largecid.sh \
	test_non_regression_ipv6_udplite_largecid.sh \
	test_non_regression_ipv6_udp_rtp_audio-vlc_largecid.sh \
	test_non_regression_ipv6_udp_rtp_video2_largecid.sh \
	test_non_regression_ipv6_udp_rtp_video1_largecid.sh \
	test_non_regression_ipv6_udp_largecid.sh \
	test_non_regression_ipv6_udp_largecid.sh \
	$(TESTS_BUG804552_LARGECID) \
	$(TESTS_ESP_LARGECID)


TESTS = \
	$(TESTS_SMALLCID) \
	$(TESTS_LARGECID)


check_PROGRAMS = \
	test_non_regression \
	test_non_regression_kernel


test_non_regression_CFLAGS = \
	$(configure_cflags)

test_non_regression_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_non_regression_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

test_non_regression_SOURCES = \
	test_non_regression.c

test_non_regression_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)


test_non_regression_kernel_CFLAGS = \
	$(configure_cflags)

test_non_regression_kernel_CPPFLAGS = \
	-I$(top_srcdir)/test \
	$(libpcap_includes)

test_non_regression_kernel_LDFLAGS = \
	$(configure_ldflags)

test_non_regression_kernel_SOURCES = \
	test_non_regression_kernel.c

test_non_regression_kernel_LDADD = \
	-l$(pcap_lib_name) \
	$(additional_platform_libs)


EXTRA_DIST = \
	test_non_regression.sh \
	$(TESTS_SMALLCID) \
	$(TESTS_LARGECID) \
	inputs

