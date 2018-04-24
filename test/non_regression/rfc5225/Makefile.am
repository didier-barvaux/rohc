################################################################################
# Name       : Makefile
# Author     : Valentin Boutonné <vboutonne@toulouse.viveris.fr>
#              Didier Barvaux <didier.barvaux@toulouse.viveris.com>
# Description: create and run the ROHC RFC5225 non-regression tests
################################################################################


#
# max contexts + WLSB width 4 + small CID
#

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_MISC = \
	scripts/test_non_reg_malformed-too-short_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_unknown_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipvx_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4fragmented_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4-with-options_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4-with-options_ipv4-empty-afl25_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_afl39-empty-ipv4-header_mc0_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_IPONLY = \
	scripts/test_non_reg_ipv4_icmp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp_ip-id-is-seq-but-not-inferred_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp_bug580491_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp+tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_icmp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-large-ipv6-ext_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-variable-ipv6ext_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-same-ipv6ext-different-content_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_icmp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_icmp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_icmp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_icmp_mc0_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_IP_UDP = \
	scripts/test_non_reg_ipv4_udp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_bug1166618_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp-torture-test-for-list-comp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_two-ipv6-dst-exts_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_mc0_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_IP_UDPLITE = \
	scripts/test_non_reg_ipv4_udplite_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udplite_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udplite_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udplite_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udplite_mc0_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_IP_UDP_RTP = \
	scripts/test_non_reg_ipv4_udp_rtp_h323_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_misc_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_mp3_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_rtp+rtp+icmp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video2_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video3_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video1_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip-large-ts-stride_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip+video_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_more-than-14-bits-of-sn_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_lsb-interval-wraparound_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1001614-zero-ts-stride_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1080055_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1092660-rtp-padding-bit_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1038637_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_rtp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1210498-ip-id-little-endian_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1265304_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_audio-vlc_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video2_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video1_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_rtp_audio-vlc_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video1_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video2_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video1_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video2_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6ext_udp_rtp_video1_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl31-variable-udp-checksum-behavior_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl35-rtp-version-changing_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl36-rtp-scaled-ts-0-bit-not-deducible_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl37-non-empty-csrc-list_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl38-rtp-version-changing-2_mc0_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_ESP = \
	scripts/test_non_reg_ipv4_esp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-nonrnd-ip-id_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-rnd-ip-id_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_esp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_esp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_esp_afl53-variable-sn_mc0_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_BUG804552 = \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID = \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_MISC) \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_IPONLY) \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_IP_UDP) \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_IP_UDPLITE) \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_IP_UDP_RTP) \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_ESP) \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID_BUG804552)


#
# max contexts + WLSB width 64 + small CID
#

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_MISC = \
	scripts/test_non_reg_malformed-too-short_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_unknown_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipvx_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4fragmented_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4-with-options_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4-with-options_ipv4-empty-afl25_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_afl39-empty-ipv4-header_mc0_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_IPONLY = \
	scripts/test_non_reg_ipv4_icmp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp_ip-id-is-seq-but-not-inferred_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp_bug580491_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp+tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_icmp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-large-ipv6-ext_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-variable-ipv6ext_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-same-ipv6ext-different-content_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_icmp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_icmp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_icmp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_icmp_mc0_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_IP_UDP = \
	scripts/test_non_reg_ipv4_udp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_bug1166618_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp-torture-test-for-list-comp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_two-ipv6-dst-exts_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_mc0_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_IP_UDPLITE = \
	scripts/test_non_reg_ipv4_udplite_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udplite_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udplite_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udplite_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udplite_mc0_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_IP_UDP_RTP = \
	scripts/test_non_reg_ipv4_udp_rtp_h323_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_misc_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_mp3_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_rtp+rtp+icmp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video2_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video3_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video1_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip-large-ts-stride_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip+video_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_more-than-14-bits-of-sn_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_lsb-interval-wraparound_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1001614-zero-ts-stride_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1080055_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1092660-rtp-padding-bit_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1038637_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_rtp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1210498-ip-id-little-endian_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1265304_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_audio-vlc_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video2_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video1_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_rtp_audio-vlc_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video1_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video2_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video1_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video2_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6ext_udp_rtp_video1_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl31-variable-udp-checksum-behavior_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl35-rtp-version-changing_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl36-rtp-scaled-ts-0-bit-not-deducible_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl37-non-empty-csrc-list_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl38-rtp-version-changing-2_mc0_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_ESP = \
	scripts/test_non_reg_ipv4_esp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-nonrnd-ip-id_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-rnd-ip-id_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_esp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_esp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_esp_afl53-variable-sn_mc0_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_BUG804552 = \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID = \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_MISC) \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_IPONLY) \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_IP_UDP) \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_IP_UDPLITE) \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_IP_UDP_RTP) \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_ESP) \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID_BUG804552)


TESTS_MAXCONTEXTS0_SMALLCID = \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID) \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID)


#
# max contexts 1 + WLSB width 4 + small CID
#

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_MISC = \
	scripts/test_non_reg_malformed-too-short_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_unknown_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipvx_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4fragmented_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4-with-options_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4-with-options_ipv4-empty-afl25_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_afl39-empty-ipv4-header_mc1_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_IPONLY = \
	scripts/test_non_reg_ipv4_icmp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp_ip-id-is-seq-but-not-inferred_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp_bug580491_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp+tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_icmp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-large-ipv6-ext_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-variable-ipv6ext_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-same-ipv6ext-different-content_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_icmp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_icmp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_icmp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_icmp_mc1_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_IP_UDP = \
	scripts/test_non_reg_ipv4_udp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_bug1166618_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp-torture-test-for-list-comp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_two-ipv6-dst-exts_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_mc1_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_IP_UDPLITE = \
	scripts/test_non_reg_ipv4_udplite_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udplite_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udplite_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udplite_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udplite_mc1_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_IP_UDP_RTP = \
	scripts/test_non_reg_ipv4_udp_rtp_h323_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_misc_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_mp3_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_rtp+rtp+icmp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video2_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video3_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video1_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip-large-ts-stride_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip+video_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_more-than-14-bits-of-sn_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_lsb-interval-wraparound_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1001614-zero-ts-stride_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1080055_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1092660-rtp-padding-bit_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1038637_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_rtp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1210498-ip-id-little-endian_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1265304_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_audio-vlc_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video2_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video1_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_rtp_audio-vlc_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video1_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video2_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video1_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video2_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6ext_udp_rtp_video1_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl31-variable-udp-checksum-behavior_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl35-rtp-version-changing_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl36-rtp-scaled-ts-0-bit-not-deducible_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl37-non-empty-csrc-list_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl38-rtp-version-changing-2_mc1_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_ESP = \
	scripts/test_non_reg_ipv4_esp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-nonrnd-ip-id_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-rnd-ip-id_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_esp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_esp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_esp_afl53-variable-sn_mc1_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_BUG804552 = \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID = \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_MISC) \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_IPONLY) \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_IP_UDP) \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_IP_UDPLITE) \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_IP_UDP_RTP) \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_ESP) \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID_BUG804552)


#
# max contexts 1 + WLSB width 64 + small CID
#

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_MISC = \
	scripts/test_non_reg_malformed-too-short_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_unknown_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipvx_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4fragmented_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4-with-options_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4-with-options_ipv4-empty-afl25_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_afl39-empty-ipv4-header_mc1_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_IPONLY = \
	scripts/test_non_reg_ipv4_icmp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp_ip-id-is-seq-but-not-inferred_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp_bug580491_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_icmp+tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_icmp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-large-ipv6-ext_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-variable-ipv6ext_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_icmp-same-ipv6ext-different-content_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_icmp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_icmp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_icmp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_icmp_mc1_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_IP_UDP = \
	scripts/test_non_reg_ipv4_udp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_bug1166618_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp-torture-test-for-list-comp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_two-ipv6-dst-exts_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_mc1_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_IP_UDPLITE = \
	scripts/test_non_reg_ipv4_udplite_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udplite_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udplite_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udplite_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udplite_mc1_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_IP_UDP_RTP = \
	scripts/test_non_reg_ipv4_udp_rtp_h323_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_misc_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_mp3_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_rtp+rtp+icmp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video2_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video3_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video1_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip-large-ts-stride_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip+video_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_more-than-14-bits-of-sn_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_lsb-interval-wraparound_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1001614-zero-ts-stride_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1080055_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1092660-rtp-padding-bit_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1038637_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_rtp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1210498-ip-id-little-endian_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1265304_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_audio-vlc_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video2_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video1_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_udp_rtp_audio-vlc_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video1_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video2_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video1_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video2_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6ext_udp_rtp_video1_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl31-variable-udp-checksum-behavior_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl35-rtp-version-changing_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl36-rtp-scaled-ts-0-bit-not-deducible_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl37-non-empty-csrc-list_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl38-rtp-version-changing-2_mc1_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_ESP = \
	scripts/test_non_reg_ipv4_esp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-nonrnd-ip-id_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-rnd-ip-id_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_esp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_esp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_esp_afl53-variable-sn_mc1_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_BUG804552 = \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_smallcid.sh

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID = \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_MISC) \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_IPONLY) \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_IP_UDP) \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_IP_UDPLITE) \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_IP_UDP_RTP) \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_ESP) \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID_BUG804552)


TESTS_MAXCONTEXTS1_SMALLCID = \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID) \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID)


TESTS_SMALLCID = \
	$(TESTS_MAXCONTEXTS0_SMALLCID) \
	$(TESTS_MAXCONTEXTS1_SMALLCID)


#
# max contexts + WLSB width 4 + large CID
#

TESTS_MAXCONTEXTS0_WLSB4_LARGECID_MISC = \
	scripts/test_non_reg_malformed-too-short_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_unknown_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipvx_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4fragmented_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4-with-options_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4-with-options_ipv4-empty-afl25_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_afl39-empty-ipv4-header_mc0_wlsb4_largecid.sh

TESTS_MAXCONTEXTS0_WLSB4_LARGECID_IPONLY = \
	scripts/test_non_reg_ipv4_icmp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_icmp_ip-id-is-seq-but-not-inferred_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_icmp_bug580491_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_icmp+tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_icmp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-large-ipv6-ext_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-variable-ipv6ext_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-same-ipv6ext-different-content_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_icmp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_icmp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_icmp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_icmp_mc0_wlsb4_largecid.sh

TESTS_MAXCONTEXTS0_WLSB4_LARGECID_IP_UDP = \
	scripts/test_non_reg_ipv4_udp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_bug1166618_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp-torture-test-for-list-comp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_two-ipv6-dst-exts_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_mc0_wlsb4_largecid.sh

TESTS_MAXCONTEXTS0_WLSB4_LARGECID_IP_UDPLITE = \
	scripts/test_non_reg_ipv4_udplite_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udplite_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udplite_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udplite_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udplite_mc0_wlsb4_largecid.sh

TESTS_MAXCONTEXTS0_WLSB4_LARGECID_IP_UDP_RTP = \
	scripts/test_non_reg_ipv4_udp_rtp_h323_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_misc_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_mp3_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_rtp+rtp+icmp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video2_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video3_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video1_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip-large-ts-stride_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip+video_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_more-than-14-bits-of-sn_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_lsb-interval-wraparound_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1001614-zero-ts-stride_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1080055_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1092660-rtp-padding-bit_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1038637_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_rtp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1210498-ip-id-little-endian_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1265304_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video1_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video2_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video1_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video2_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6ext_udp_rtp_video1_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_rtp_audio-vlc_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_audio-vlc_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video2_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video1_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl31-variable-udp-checksum-behavior_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl35-rtp-version-changing_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl36-rtp-scaled-ts-0-bit-not-deducible_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl37-non-empty-csrc-list_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl38-rtp-version-changing-2_mc0_wlsb4_largecid.sh

TESTS_MAXCONTEXTS0_WLSB4_LARGECID_ESP = \
	scripts/test_non_reg_ipv4_esp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-nonrnd-ip-id_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-rnd-ip-id_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_esp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_esp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_esp_afl53-variable-sn_mc0_wlsb4_largecid.sh

TESTS_MAXCONTEXTS0_WLSB4_LARGECID_BUG804552 = \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb4_largecid.sh

TESTS_MAXCONTEXTS0_WLSB4_LARGECID = \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID_MISC) \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID_IPONLY) \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID_IP_UDP) \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID_IP_UDPLITE) \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID_IP_UDP_RTP) \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID_ESP) \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID_BUG804552)


#
# max contexts + WLSB width 64 + large CID
#

TESTS_MAXCONTEXTS0_WLSB64_LARGECID_MISC = \
	scripts/test_non_reg_malformed-too-short_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_unknown_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipvx_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4fragmented_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4-with-options_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4-with-options_ipv4-empty-afl25_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_afl39-empty-ipv4-header_mc0_wlsb64_largecid.sh

TESTS_MAXCONTEXTS0_WLSB64_LARGECID_IPONLY = \
	scripts/test_non_reg_ipv4_icmp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_icmp_ip-id-is-seq-but-not-inferred_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_icmp_bug580491_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_icmp+tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_icmp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-large-ipv6-ext_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-variable-ipv6ext_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-same-ipv6ext-different-content_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_icmp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_icmp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_icmp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_icmp_mc0_wlsb64_largecid.sh

TESTS_MAXCONTEXTS0_WLSB64_LARGECID_IP_UDP = \
	scripts/test_non_reg_ipv4_udp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_bug1166618_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp-torture-test-for-list-comp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_two-ipv6-dst-exts_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_mc0_wlsb64_largecid.sh

TESTS_MAXCONTEXTS0_WLSB64_LARGECID_IP_UDPLITE = \
	scripts/test_non_reg_ipv4_udplite_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udplite_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udplite_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udplite_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udplite_mc0_wlsb64_largecid.sh

TESTS_MAXCONTEXTS0_WLSB64_LARGECID_IP_UDP_RTP = \
	scripts/test_non_reg_ipv4_udp_rtp_h323_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_misc_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_mp3_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_rtp+rtp+icmp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video2_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video3_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video1_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip-large-ts-stride_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip+video_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_more-than-14-bits-of-sn_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_lsb-interval-wraparound_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1001614-zero-ts-stride_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1080055_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1092660-rtp-padding-bit_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1038637_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_rtp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1210498-ip-id-little-endian_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1265304_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video1_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video2_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video1_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video2_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6ext_udp_rtp_video1_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_rtp_audio-vlc_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_audio-vlc_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video2_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video1_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl31-variable-udp-checksum-behavior_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl35-rtp-version-changing_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl36-rtp-scaled-ts-0-bit-not-deducible_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl37-non-empty-csrc-list_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl38-rtp-version-changing-2_mc0_wlsb64_largecid.sh

TESTS_MAXCONTEXTS0_WLSB64_LARGECID_ESP = \
	scripts/test_non_reg_ipv4_esp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-nonrnd-ip-id_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-rnd-ip-id_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_esp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_esp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_esp_afl53-variable-sn_mc0_wlsb64_largecid.sh

TESTS_MAXCONTEXTS0_WLSB64_LARGECID_BUG804552 = \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc0_wlsb64_largecid.sh

TESTS_MAXCONTEXTS0_WLSB64_LARGECID = \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID_MISC) \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID_IPONLY) \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID_IP_UDP) \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID_IP_UDPLITE) \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID_IP_UDP_RTP) \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID_ESP) \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID_BUG804552)


TESTS_MAXCONTEXTS0_LARGECID = \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID) \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID)


#
# max contexts 1 + WLSB width 4 + large CID
#

TESTS_MAXCONTEXTS1_WLSB4_LARGECID_MISC = \
	scripts/test_non_reg_malformed-too-short_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_unknown_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipvx_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4fragmented_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4-with-options_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4-with-options_ipv4-empty-afl25_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_afl39-empty-ipv4-header_mc1_wlsb4_largecid.sh

TESTS_MAXCONTEXTS1_WLSB4_LARGECID_IPONLY = \
	scripts/test_non_reg_ipv4_icmp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_icmp_ip-id-is-seq-but-not-inferred_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_icmp_bug580491_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_icmp+tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_icmp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-large-ipv6-ext_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-variable-ipv6ext_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-same-ipv6ext-different-content_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_icmp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_icmp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_icmp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_icmp_mc1_wlsb4_largecid.sh

TESTS_MAXCONTEXTS1_WLSB4_LARGECID_IP_UDP = \
	scripts/test_non_reg_ipv4_udp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_bug1166618_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp-torture-test-for-list-comp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_two-ipv6-dst-exts_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_mc1_wlsb4_largecid.sh

TESTS_MAXCONTEXTS1_WLSB4_LARGECID_IP_UDPLITE = \
	scripts/test_non_reg_ipv4_udplite_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udplite_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udplite_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udplite_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udplite_mc1_wlsb4_largecid.sh

TESTS_MAXCONTEXTS1_WLSB4_LARGECID_IP_UDP_RTP = \
	scripts/test_non_reg_ipv4_udp_rtp_h323_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_misc_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_mp3_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_rtp+rtp+icmp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video2_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video3_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video1_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip-large-ts-stride_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip+video_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_more-than-14-bits-of-sn_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_lsb-interval-wraparound_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1001614-zero-ts-stride_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1080055_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1092660-rtp-padding-bit_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1038637_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_rtp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1210498-ip-id-little-endian_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1265304_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video1_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video2_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video1_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video2_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6ext_udp_rtp_video1_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_rtp_audio-vlc_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_audio-vlc_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video2_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video1_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl31-variable-udp-checksum-behavior_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl35-rtp-version-changing_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl36-rtp-scaled-ts-0-bit-not-deducible_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl37-non-empty-csrc-list_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl38-rtp-version-changing-2_mc1_wlsb4_largecid.sh

TESTS_MAXCONTEXTS1_WLSB4_LARGECID_ESP = \
	scripts/test_non_reg_ipv4_esp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-nonrnd-ip-id_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-rnd-ip-id_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_esp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_esp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_esp_afl53-variable-sn_mc1_wlsb4_largecid.sh

TESTS_MAXCONTEXTS1_WLSB4_LARGECID_BUG804552 = \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb4_largecid.sh

TESTS_MAXCONTEXTS1_WLSB4_LARGECID = \
	$(TESTS_MAXCONTEXTS1_WLSB4_LARGECID_MISC) \
	$(TESTS_MAXCONTEXTS1_WLSB4_LARGECID_IPONLY) \
	$(TESTS_MAXCONTEXTS1_WLSB4_LARGECID_IP_UDP) \
	$(TESTS_MAXCONTEXTS1_WLSB4_LARGECID_IP_UDPLITE) \
	$(TESTS_MAXCONTEXTS1_WLSB4_LARGECID_IP_UDP_RTP) \
	$(TESTS_MAXCONTEXTS1_WLSB4_LARGECID_ESP) \
	$(TESTS_MAXCONTEXTS1_WLSB4_LARGECID_BUG804552)


#
# max contexts 1 + WLSB width 64 + large CID
#

TESTS_MAXCONTEXTS1_WLSB64_LARGECID_MISC = \
	scripts/test_non_reg_malformed-too-short_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_unknown_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipvx_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4fragmented_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4-with-options_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4-with-options_ipv4-empty-afl25_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_afl39-empty-ipv4-header_mc1_wlsb64_largecid.sh

TESTS_MAXCONTEXTS1_WLSB64_LARGECID_IPONLY = \
	scripts/test_non_reg_ipv4_icmp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_icmp_ip-id-is-seq-but-not-inferred_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_icmp_bug580491_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_icmp+tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_icmp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-large-ipv6-ext_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-variable-ipv6ext_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_icmp-same-ipv6ext-different-content_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_icmp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_icmp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_icmp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_icmp_mc1_wlsb64_largecid.sh

TESTS_MAXCONTEXTS1_WLSB64_LARGECID_IP_UDP = \
	scripts/test_non_reg_ipv4_udp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_bug1166618_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp-torture-test-for-list-comp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_two-ipv6-dst-exts_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_mc1_wlsb64_largecid.sh

TESTS_MAXCONTEXTS1_WLSB64_LARGECID_IP_UDPLITE = \
	scripts/test_non_reg_ipv4_udplite_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udplite_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udplite_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udplite_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udplite_mc1_wlsb64_largecid.sh

TESTS_MAXCONTEXTS1_WLSB64_LARGECID_IP_UDP_RTP = \
	scripts/test_non_reg_ipv4_udp_rtp_h323_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_misc_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_mp3_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_rtp+rtp+icmp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video2_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video3_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_video1_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip-large-ts-stride_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_voip+video_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_more-than-14-bits-of-sn_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_lsb-interval-wraparound_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1001614-zero-ts-stride_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1080055_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1083294-uor2ts-disambiguation-with-too-many-ts-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1088004-uor2id-with-too-many-ipid-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1092660-rtp-padding-bit_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1038637_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp-with-changing-checksum-behaviour_rtp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1210498-ip-id-little-endian_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug1265304_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_mp3-variable-pt-and-rnd-outer-ip-id_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video1_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_video2_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_SO-state-double-ipv4-non-rnd-without-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_innermost-ipid-bits-in-ext3_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video1_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_video2_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6ext_udp_rtp_video1_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_udp_rtp_audio-vlc_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_audio-vlc_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video2_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_video1_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl31-variable-udp-checksum-behavior_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl35-rtp-version-changing_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl36-rtp-scaled-ts-0-bit-not-deducible_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl37-non-empty-csrc-list_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_afl38-rtp-version-changing-2_mc1_wlsb64_largecid.sh

TESTS_MAXCONTEXTS1_WLSB64_LARGECID_ESP = \
	scripts/test_non_reg_ipv4_esp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-nonrnd-ip-id_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_esp_large-sn-and-rnd-ip-id_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_esp_bug1089106-non-rtp-with-14-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_esp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_esp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_esp_afl53-variable-sn_mc1_wlsb64_largecid.sh

TESTS_MAXCONTEXTS1_WLSB64_LARGECID_BUG804552 = \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2id-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2ts-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_udp_rtp_bug804552-uor2rtp-with-too-many-sn-bits_mc1_wlsb64_largecid.sh

TESTS_MAXCONTEXTS1_WLSB64_LARGECID = \
	$(TESTS_MAXCONTEXTS1_WLSB64_LARGECID_MISC) \
	$(TESTS_MAXCONTEXTS1_WLSB64_LARGECID_IPONLY) \
	$(TESTS_MAXCONTEXTS1_WLSB64_LARGECID_IP_UDP) \
	$(TESTS_MAXCONTEXTS1_WLSB64_LARGECID_IP_UDPLITE) \
	$(TESTS_MAXCONTEXTS1_WLSB64_LARGECID_IP_UDP_RTP) \
	$(TESTS_MAXCONTEXTS1_WLSB64_LARGECID_ESP) \
	$(TESTS_MAXCONTEXTS1_WLSB64_LARGECID_BUG804552)


TESTS_MAXCONTEXTS1_LARGECID = \
	$(TESTS_MAXCONTEXTS1_WLSB4_LARGECID) \
	$(TESTS_MAXCONTEXTS1_WLSB64_LARGECID)


TESTS_LARGECID = \
	$(TESTS_MAXCONTEXTS0_LARGECID) \
	$(TESTS_MAXCONTEXTS1_LARGECID)


TESTS = \
	$(TESTS_SMALLCID) \
	$(TESTS_LARGECID)


EXTRA_DIST = \
	$(TESTS) \
	inputs

