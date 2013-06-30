################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create and run the ROHC non-regression tests
################################################################################


#
# WLSB width 4 + small CID
#

TESTS_WLSB4_SMALLCID_MISC = \
	test_non_regression_malformed-too-short_wlsb4_smallcid.sh \
	test_non_regression_unknown_wlsb4_smallcid.sh \
	test_non_regression_ipvx_wlsb4_smallcid.sh \
	test_non_regression_ipv4fragmented_wlsb4_smallcid.sh \
	test_non_regression_ipv4-with-options_wlsb4_smallcid.sh

TESTS_WLSB4_SMALLCID_IPONLY = \
	test_non_regression_ipv4_icmp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_icmp_bug580491_wlsb4_smallcid.sh \
	test_non_regression_ipv4_icmp+tcp_wlsb4_smallcid.sh \
	test_non_regression_ipv6_icmp_wlsb4_smallcid.sh \
	test_non_regression_ipv6ext_icmp_wlsb4_smallcid.sh \
	test_non_regression_ipv6ext_icmp-large-ipv6-ext_wlsb4_smallcid.sh \
	test_non_regression_ipv6ext_icmp-variable-ipv6ext_wlsb4_smallcid.sh \
	test_non_regression_ipv6ext_ipv6ext_icmp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_icmp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6_icmp_wlsb4_smallcid.sh \
	test_non_regression_ipv6_ipv6_icmp_wlsb4_smallcid.sh

TESTS_WLSB4_SMALLCID_IP_UDP = \
	test_non_regression_ipv4_udp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_wlsb4_smallcid.sh \
	test_non_regression_ipv6_udp_wlsb4_smallcid.sh \
	test_non_regression_ipv6_udp_bug1166618_wlsb4_smallcid.sh \
	test_non_regression_ipv6ext_udp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_wlsb4_smallcid.sh \
	test_non_regression_ipv6_ipv6_udp_wlsb4_smallcid.sh

TESTS_WLSB4_SMALLCID_IP_UDPLITE = \
	test_non_regression_ipv4_udplite_wlsb4_smallcid.sh \
	test_non_regression_ipv6_udplite_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udplite_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6_udplite_wlsb4_smallcid.sh \
	test_non_regression_ipv6_ipv6_udplite_wlsb4_smallcid.sh

TESTS_WLSB4_SMALLCID_IP_UDP_RTP = \
	test_non_regression_ipv4_udp_rtp_h323_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_misc_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_mp3_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_rtp+rtp+icmp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video2_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video3_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video1_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip-large-ts-stride_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip+video_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_more-than-14-bits-of-sn_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_lsb-interval-wraparound_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1001614-zero-ts-stride_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1080055_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1092660-rtp-padding-bit_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1038637_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_rtp_wlsb4_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_audio-vlc_wlsb4_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_video2_wlsb4_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_video1_wlsb4_smallcid.sh \
	test_non_regression_ipv6ext_udp_rtp_audio-vlc_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video1_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video2_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video1_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video2_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6ext_udp_rtp_video1_wlsb4_smallcid.sh

TESTS_WLSB4_SMALLCID_ESP = \
	test_non_regression_ipv4_esp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_esp_large-sn-and-nonrnd-ip-id_wlsb4_smallcid.sh \
	test_non_regression_ipv4_esp_large-sn-and-rnd-ip-id_wlsb4_smallcid.sh \
	test_non_regression_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_esp_wlsb4_smallcid.sh \
	test_non_regression_ipv6_esp_wlsb4_smallcid.sh

TESTS_WLSB4_SMALLCID_BUG804552 = \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_smallcid.sh \
	test_non_regression_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_smallcid.sh

TESTS_WLSB4_SMALLCID_TCP = \
	test_non_regression_ipv4_tcp_wlsb4_smallcid.sh \
	test_non_regression_ipv4_tcp_sack-opt-with-duplicate-ack_wlsb4_smallcid.sh \
	test_non_regression_ipv6_tcp_wlsb4_smallcid.sh \
	test_non_regression_ipv6_tcp_non-zero-dscp_wlsb4_smallcid.sh

TESTS_WLSB4_SMALLCID = \
	$(TESTS_WLSB4_SMALLCID_MISC) \
	$(TESTS_WLSB4_SMALLCID_IPONLY) \
	$(TESTS_WLSB4_SMALLCID_IP_UDP) \
	$(TESTS_WLSB4_SMALLCID_IP_UDPLITE) \
	$(TESTS_WLSB4_SMALLCID_IP_UDP_RTP) \
	$(TESTS_WLSB4_SMALLCID_ESP) \
	$(TESTS_WLSB4_SMALLCID_BUG804552) \
	$(TESTS_WLSB4_SMALLCID_TCP)


#
# WLSB width 64 + small CID
#

TESTS_WLSB64_SMALLCID_MISC = \
	test_non_regression_malformed-too-short_wlsb64_smallcid.sh \
	test_non_regression_unknown_wlsb64_smallcid.sh \
	test_non_regression_ipvx_wlsb64_smallcid.sh \
	test_non_regression_ipv4fragmented_wlsb64_smallcid.sh \
	test_non_regression_ipv4-with-options_wlsb64_smallcid.sh

TESTS_WLSB64_SMALLCID_IPONLY = \
	test_non_regression_ipv4_icmp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_icmp_bug580491_wlsb64_smallcid.sh \
	test_non_regression_ipv4_icmp+tcp_wlsb64_smallcid.sh \
	test_non_regression_ipv6_icmp_wlsb64_smallcid.sh \
	test_non_regression_ipv6ext_icmp_wlsb64_smallcid.sh \
	test_non_regression_ipv6ext_icmp-large-ipv6-ext_wlsb64_smallcid.sh \
	test_non_regression_ipv6ext_icmp-variable-ipv6ext_wlsb64_smallcid.sh \
	test_non_regression_ipv6ext_ipv6ext_icmp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_icmp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6_icmp_wlsb64_smallcid.sh \
	test_non_regression_ipv6_ipv6_icmp_wlsb64_smallcid.sh

TESTS_WLSB64_SMALLCID_IP_UDP = \
	test_non_regression_ipv4_udp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_wlsb64_smallcid.sh \
	test_non_regression_ipv6_udp_wlsb64_smallcid.sh \
	test_non_regression_ipv6_udp_bug1166618_wlsb64_smallcid.sh \
	test_non_regression_ipv6ext_udp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_wlsb64_smallcid.sh \
	test_non_regression_ipv6_ipv6_udp_wlsb64_smallcid.sh

TESTS_WLSB64_SMALLCID_IP_UDPLITE = \
	test_non_regression_ipv4_udplite_wlsb64_smallcid.sh \
	test_non_regression_ipv6_udplite_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udplite_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6_udplite_wlsb64_smallcid.sh \
	test_non_regression_ipv6_ipv6_udplite_wlsb64_smallcid.sh

TESTS_WLSB64_SMALLCID_IP_UDP_RTP = \
	test_non_regression_ipv4_udp_rtp_h323_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_misc_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_mp3_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_rtp+rtp+icmp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video2_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video3_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_video1_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip-large-ts-stride_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_voip+video_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_more-than-14-bits-of-sn_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_lsb-interval-wraparound_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1001614-zero-ts-stride_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1080055_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1092660-rtp-padding-bit_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug1038637_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_rtp_wlsb64_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_audio-vlc_wlsb64_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_video2_wlsb64_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_video1_wlsb64_smallcid.sh \
	test_non_regression_ipv6ext_udp_rtp_audio-vlc_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video1_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video2_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video1_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video2_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6ext_udp_rtp_video1_wlsb64_smallcid.sh

TESTS_WLSB64_SMALLCID_ESP = \
	test_non_regression_ipv4_esp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_esp_large-sn-and-nonrnd-ip-id_wlsb64_smallcid.sh \
	test_non_regression_ipv4_esp_large-sn-and-rnd-ip-id_wlsb64_smallcid.sh \
	test_non_regression_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_esp_wlsb64_smallcid.sh \
	test_non_regression_ipv6_esp_wlsb64_smallcid.sh

TESTS_WLSB64_SMALLCID_BUG804552 = \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_smallcid.sh \
	test_non_regression_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_smallcid.sh

TESTS_WLSB64_SMALLCID_TCP = \
	test_non_regression_ipv4_tcp_wlsb64_smallcid.sh \
	test_non_regression_ipv4_tcp_sack-opt-with-duplicate-ack_wlsb64_smallcid.sh \
	test_non_regression_ipv6_tcp_wlsb64_smallcid.sh \
	test_non_regression_ipv6_tcp_non-zero-dscp_wlsb64_smallcid.sh

TESTS_WLSB64_SMALLCID = \
	$(TESTS_WLSB64_SMALLCID_MISC) \
	$(TESTS_WLSB64_SMALLCID_IPONLY) \
	$(TESTS_WLSB64_SMALLCID_IP_UDP) \
	$(TESTS_WLSB64_SMALLCID_IP_UDPLITE) \
	$(TESTS_WLSB64_SMALLCID_IP_UDP_RTP) \
	$(TESTS_WLSB64_SMALLCID_ESP) \
	$(TESTS_WLSB64_SMALLCID_BUG804552) \
	$(TESTS_WLSB64_SMALLCID_TCP)


TESTS_SMALLCID = \
	$(TESTS_WLSB4_SMALLCID) \
	$(TESTS_WLSB64_SMALLCID)



#
# WLSB width 4 + large CID
#

TESTS_WLSB4_LARGECID_MISC = \
	test_non_regression_malformed-too-short_wlsb4_largecid.sh \
	test_non_regression_unknown_wlsb4_largecid.sh \
	test_non_regression_ipvx_wlsb4_largecid.sh \
	test_non_regression_ipv4fragmented_wlsb4_largecid.sh \
	test_non_regression_ipv4-with-options_wlsb4_largecid.sh

TESTS_WLSB4_LARGECID_IPONLY = \
	test_non_regression_ipv4_icmp_wlsb4_largecid.sh \
	test_non_regression_ipv4_icmp_bug580491_wlsb4_largecid.sh \
	test_non_regression_ipv4_icmp+tcp_wlsb4_largecid.sh \
	test_non_regression_ipv6_icmp_wlsb4_largecid.sh \
	test_non_regression_ipv6ext_icmp_wlsb4_largecid.sh \
	test_non_regression_ipv6ext_icmp-large-ipv6-ext_wlsb4_largecid.sh \
	test_non_regression_ipv6ext_icmp-variable-ipv6ext_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_icmp_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6_icmp_wlsb4_largecid.sh \
	test_non_regression_ipv6_ipv6_icmp_wlsb4_largecid.sh \
	test_non_regression_ipv6ext_ipv6ext_icmp_wlsb4_largecid.sh

TESTS_WLSB4_LARGECID_IP_UDP = \
	test_non_regression_ipv4_udp_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_wlsb4_largecid.sh \
	test_non_regression_ipv6_udp_wlsb4_largecid.sh \
	test_non_regression_ipv6_udp_bug1166618_wlsb4_largecid.sh \
	test_non_regression_ipv6ext_udp_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_wlsb4_largecid.sh \
	test_non_regression_ipv6_ipv6_udp_wlsb4_largecid.sh

TESTS_WLSB4_LARGECID_IP_UDPLITE = \
	test_non_regression_ipv4_udplite_wlsb4_largecid.sh \
	test_non_regression_ipv6_udplite_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udplite_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6_udplite_wlsb4_largecid.sh \
	test_non_regression_ipv6_ipv6_udplite_wlsb4_largecid.sh

TESTS_WLSB4_LARGECID_IP_UDP_RTP = \
	test_non_regression_ipv4_udp_rtp_h323_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_misc_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_mp3_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_rtp+rtp+icmp_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video2_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video3_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video1_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip-large-ts-stride_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip+video_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_more-than-14-bits-of-sn_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_lsb-interval-wraparound_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1001614-zero-ts-stride_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1080055_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1092660-rtp-padding-bit_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1038637_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_rtp_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video1_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video2_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video1_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video2_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6ext_udp_rtp_video1_wlsb4_largecid.sh \
	test_non_regression_ipv6ext_udp_rtp_audio-vlc_wlsb4_largecid.sh \
	test_non_regression_ipv6_udp_rtp_audio-vlc_wlsb4_largecid.sh \
	test_non_regression_ipv6_udp_rtp_video2_wlsb4_largecid.sh \
	test_non_regression_ipv6_udp_rtp_video1_wlsb4_largecid.sh

TESTS_WLSB4_LARGECID_ESP = \
	test_non_regression_ipv4_esp_wlsb4_largecid.sh \
	test_non_regression_ipv4_esp_large-sn-and-nonrnd-ip-id_wlsb4_largecid.sh \
	test_non_regression_ipv4_esp_large-sn-and-rnd-ip-id_wlsb4_largecid.sh \
	test_non_regression_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv6_esp_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_esp_wlsb4_largecid.sh

TESTS_WLSB4_LARGECID_BUG804552 = \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_largecid.sh \
	test_non_regression_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb4_largecid.sh

TESTS_WLSB4_LARGECID_TCP = \
	test_non_regression_ipv4_tcp_wlsb4_largecid.sh \
	test_non_regression_ipv4_tcp_sack-opt-with-duplicate-ack_wlsb4_largecid.sh \
	test_non_regression_ipv6_tcp_wlsb4_largecid.sh \
	test_non_regression_ipv6_tcp_non-zero-dscp_wlsb4_largecid.sh

TESTS_WLSB4_LARGECID = \
	$(TESTS_WLSB4_LARGECID_MISC) \
	$(TESTS_WLSB4_LARGECID_IPONLY) \
	$(TESTS_WLSB4_LARGECID_IP_UDP) \
	$(TESTS_WLSB4_LARGECID_IP_UDPLITE) \
	$(TESTS_WLSB4_LARGECID_IP_UDP_RTP) \
	$(TESTS_WLSB4_LARGECID_ESP) \
	$(TESTS_WLSB4_LARGECID_BUG804552) \
	$(TESTS_WLSB4_LARGECID_TCP)


#
# WLSB width 64 + large CID
#

TESTS_WLSB64_LARGECID_MISC = \
	test_non_regression_malformed-too-short_wlsb64_largecid.sh \
	test_non_regression_unknown_wlsb64_largecid.sh \
	test_non_regression_ipvx_wlsb64_largecid.sh \
	test_non_regression_ipv4fragmented_wlsb64_largecid.sh \
	test_non_regression_ipv4-with-options_wlsb64_largecid.sh

TESTS_WLSB64_LARGECID_IPONLY = \
	test_non_regression_ipv4_icmp_wlsb64_largecid.sh \
	test_non_regression_ipv4_icmp_bug580491_wlsb64_largecid.sh \
	test_non_regression_ipv4_icmp+tcp_wlsb64_largecid.sh \
	test_non_regression_ipv6_icmp_wlsb64_largecid.sh \
	test_non_regression_ipv6ext_icmp_wlsb64_largecid.sh \
	test_non_regression_ipv6ext_icmp-large-ipv6-ext_wlsb64_largecid.sh \
	test_non_regression_ipv6ext_icmp-variable-ipv6ext_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_icmp_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6_icmp_wlsb64_largecid.sh \
	test_non_regression_ipv6_ipv6_icmp_wlsb64_largecid.sh \
	test_non_regression_ipv6ext_ipv6ext_icmp_wlsb64_largecid.sh

TESTS_WLSB64_LARGECID_IP_UDP = \
	test_non_regression_ipv4_udp_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_wlsb64_largecid.sh \
	test_non_regression_ipv6_udp_wlsb64_largecid.sh \
	test_non_regression_ipv6_udp_bug1166618_wlsb64_largecid.sh \
	test_non_regression_ipv6ext_udp_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_wlsb64_largecid.sh \
	test_non_regression_ipv6_ipv6_udp_wlsb64_largecid.sh

TESTS_WLSB64_LARGECID_IP_UDPLITE = \
	test_non_regression_ipv4_udplite_wlsb64_largecid.sh \
	test_non_regression_ipv6_udplite_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udplite_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6_udplite_wlsb64_largecid.sh \
	test_non_regression_ipv6_ipv6_udplite_wlsb64_largecid.sh

TESTS_WLSB64_LARGECID_IP_UDP_RTP = \
	test_non_regression_ipv4_udp_rtp_h323_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_misc_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_mp3_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_rtp+rtp+icmp_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video2_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video3_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_video1_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip-large-ts-stride_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_voip+video_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_more-than-14-bits-of-sn_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_lsb-interval-wraparound_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1001614-zero-ts-stride_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1080055_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1092660-rtp-padding-bit_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug1038637_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp-with-changing-checksum-behaviour_rtp_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video1_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_video2_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video1_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_video2_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6ext_udp_rtp_video1_wlsb64_largecid.sh \
	test_non_regression_ipv6ext_udp_rtp_audio-vlc_wlsb64_largecid.sh \
	test_non_regression_ipv6_udp_rtp_audio-vlc_wlsb64_largecid.sh \
	test_non_regression_ipv6_udp_rtp_video2_wlsb64_largecid.sh \
	test_non_regression_ipv6_udp_rtp_video1_wlsb64_largecid.sh

TESTS_WLSB64_LARGECID_ESP = \
	test_non_regression_ipv4_esp_wlsb64_largecid.sh \
	test_non_regression_ipv4_esp_large-sn-and-nonrnd-ip-id_wlsb64_largecid.sh \
	test_non_regression_ipv4_esp_large-sn-and-rnd-ip-id_wlsb64_largecid.sh \
	test_non_regression_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv6_esp_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_esp_wlsb64_largecid.sh

TESTS_WLSB64_LARGECID_BUG804552 = \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_largecid.sh \
	test_non_regression_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_wlsb64_largecid.sh

TESTS_WLSB64_LARGECID_TCP = \
	test_non_regression_ipv4_tcp_wlsb64_largecid.sh \
	test_non_regression_ipv4_tcp_sack-opt-with-duplicate-ack_wlsb64_largecid.sh \
	test_non_regression_ipv6_tcp_wlsb64_largecid.sh \
	test_non_regression_ipv6_tcp_non-zero-dscp_wlsb64_largecid.sh

TESTS_WLSB64_LARGECID = \
	$(TESTS_WLSB64_LARGECID_MISC) \
	$(TESTS_WLSB64_LARGECID_IPONLY) \
	$(TESTS_WLSB64_LARGECID_IP_UDP) \
	$(TESTS_WLSB64_LARGECID_IP_UDPLITE) \
	$(TESTS_WLSB64_LARGECID_IP_UDP_RTP) \
	$(TESTS_WLSB64_LARGECID_ESP) \
	$(TESTS_WLSB64_LARGECID_BUG804552) \
	$(TESTS_WLSB64_LARGECID_TCP)


TESTS_LARGECID = \
	$(TESTS_WLSB4_LARGECID) \
	$(TESTS_WLSB64_LARGECID)



TESTS = \
	$(TESTS_SMALLCID) \
	$(TESTS_LARGECID)



check_PROGRAMS = \
	test_non_regression

if ROHC_LINUX_MODULE
check_PROGRAMS += test_non_regression_kernel
endif


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
	-I$(top_srcdir)/src/common \
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

