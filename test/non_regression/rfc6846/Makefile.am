################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create and run the ROHC RFC6846 non-regression tests
################################################################################


#
# max contexts + WLSB width 4 + small CID
#

TESTS_MAXCONTEXTS0_WLSB4_SMALLCID = \
	scripts/test_non_reg_ipv4_tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_syn-ack-dup_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_malformed-mss-opt_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_bad-ipv4-chksum_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_4-byte-sack-field_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_swapped-ip-id_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-opt-with-duplicate-ack_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_Aeroflex-TM500-LTE_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_unknown-multipath-opt_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_more-than-8-options_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_40-nop-options_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_non-zero-dscp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl0_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl1_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl2_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl3_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl4_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl5_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl6_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl7_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl8_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl9_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl10_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl11_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl12_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl13_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl14-recycle-indexes_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl15-recycle-indexes_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl16-recycle-indexes_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl17-bad-ip-length_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_afl18-bad-urg-data-ptr_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl19-bad-tcp-data-offset_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl20-many-exts_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl21-many-exts_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl22-many-exts_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl23-many-exts_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl24-duplicated-tcp-options_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl26-generic-option_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl27-christmas-tree-packet_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl28-reserved-flags_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl29-urg-ptr_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl30-mss-or-ws-opts-in-irregular-chain_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl32-irregular-generic-option_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl33-reserved-flags-changing_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl34-eol-option-changing_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl40-changing-ipv6-flow-label_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl41-changing-ecn-used_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl42-changing-urg-ptr-with-urg-flag-not-set_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-1_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-2_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl44-variable-generic-opt-length_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl45-christmas-tree-packet_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl46-bad-rnd7-choice_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl47-static-urg-ptr_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl48-changing-ipv4-ttl_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl49-changing-opt-ws_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl50-changing-opt-mss_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl51-changing-opt-eol_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl52-changing-opt-ws-rnd7_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl54-changing-opt-ws-rnd7-2_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl55-recycle-opts-indexes_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-2_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-3_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-4_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl57-recycle-opts_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl58-changing-opt-eol_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl59-rsf-flags_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl60-ack-not-changed_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl61-large-ts-in-opt_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_afl62-flowid-changing-and-context-recycling_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_generic-stable-irregular_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-unchanged-irregular_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_many-eol-opts_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_many-nop-opts_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-id-swapped_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_uk6x_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_ipv4_tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-10-times_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-11-times_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp-id-rnd_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode-id-rnd_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-ttl-variable_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-dscp-variable_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_tcp_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-assignment-1_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-rtmpt_mc0_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_snaketrap-hptcp_mc0_wlsb4_smallcid.sh


#
# max contexts + WLSB width 64 + small CID
#

TESTS_MAXCONTEXTS0_WLSB64_SMALLCID = \
	scripts/test_non_reg_ipv4_tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_syn-ack-dup_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_malformed-mss-opt_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_bad-ipv4-chksum_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_4-byte-sack-field_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_swapped-ip-id_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-opt-with-duplicate-ack_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_Aeroflex-TM500-LTE_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_unknown-multipath-opt_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_more-than-8-options_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_40-nop-options_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_non-zero-dscp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl0_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl1_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl2_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl3_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl4_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl5_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl6_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl7_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl8_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl9_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl10_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl11_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl12_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl13_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl14-recycle-indexes_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl15-recycle-indexes_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl16-recycle-indexes_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl17-bad-ip-length_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_afl18-bad-urg-data-ptr_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl19-bad-tcp-data-offset_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl20-many-exts_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl21-many-exts_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl22-many-exts_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl23-many-exts_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl24-duplicated-tcp-options_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl26-generic-option_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl27-christmas-tree-packet_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl28-reserved-flags_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl29-urg-ptr_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl30-mss-or-ws-opts-in-irregular-chain_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl32-irregular-generic-option_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl33-reserved-flags-changing_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl34-eol-option-changing_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl40-changing-ipv6-flow-label_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl41-changing-ecn-used_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl42-changing-urg-ptr-with-urg-flag-not-set_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-1_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-2_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl44-variable-generic-opt-length_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl45-christmas-tree-packet_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl46-bad-rnd7-choice_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl47-static-urg-ptr_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl48-changing-ipv4-ttl_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl49-changing-opt-ws_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl50-changing-opt-mss_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl51-changing-opt-eol_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl52-changing-opt-ws-rnd7_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl54-changing-opt-ws-rnd7-2_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl55-recycle-opts-indexes_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-2_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-3_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-4_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl57-recycle-opts_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl58-changing-opt-eol_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl59-rsf-flags_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl60-ack-not-changed_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl61-large-ts-in-opt_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_afl62-flowid-changing-and-context-recycling_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_generic-stable-irregular_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-unchanged-irregular_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_many-eol-opts_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_many-nop-opts_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-id-swapped_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_uk6x_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_ipv4_tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-10-times_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-11-times_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp-id-rnd_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode-id-rnd_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-ttl-variable_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-dscp-variable_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_tcp_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-assignment-1_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-rtmpt_mc0_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_snaketrap-hptcp_mc0_wlsb64_smallcid.sh


TESTS_MAXCONTEXTS0_SMALLCID = \
	$(TESTS_MAXCONTEXTS0_WLSB4_SMALLCID) \
	$(TESTS_MAXCONTEXTS0_WLSB64_SMALLCID)


#
# max contexts 1 + WLSB width 4 + small CID
#

TESTS_MAXCONTEXTS1_WLSB4_SMALLCID = \
	scripts/test_non_reg_ipv4_tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_syn-ack-dup_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_malformed-mss-opt_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_bad-ipv4-chksum_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_4-byte-sack-field_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_swapped-ip-id_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-opt-with-duplicate-ack_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_Aeroflex-TM500-LTE_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_unknown-multipath-opt_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_more-than-8-options_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_40-nop-options_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_non-zero-dscp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl0_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl1_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl2_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl3_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl4_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl5_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl6_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl7_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl8_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl9_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl10_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl11_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl12_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl13_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl14-recycle-indexes_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl15-recycle-indexes_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl16-recycle-indexes_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl17-bad-ip-length_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_afl18-bad-urg-data-ptr_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl19-bad-tcp-data-offset_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl20-many-exts_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl21-many-exts_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl22-many-exts_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl23-many-exts_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl24-duplicated-tcp-options_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl26-generic-option_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl27-christmas-tree-packet_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl28-reserved-flags_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl29-urg-ptr_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl30-mss-or-ws-opts-in-irregular-chain_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl32-irregular-generic-option_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl33-reserved-flags-changing_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl34-eol-option-changing_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl40-changing-ipv6-flow-label_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl41-changing-ecn-used_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl42-changing-urg-ptr-with-urg-flag-not-set_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-1_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-2_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl44-variable-generic-opt-length_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl45-christmas-tree-packet_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl46-bad-rnd7-choice_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl47-static-urg-ptr_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl48-changing-ipv4-ttl_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl49-changing-opt-ws_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl50-changing-opt-mss_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl51-changing-opt-eol_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl52-changing-opt-ws-rnd7_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl54-changing-opt-ws-rnd7-2_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl55-recycle-opts-indexes_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-2_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-3_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-4_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl57-recycle-opts_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl58-changing-opt-eol_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl59-rsf-flags_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl60-ack-not-changed_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl61-large-ts-in-opt_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_afl62-flowid-changing-and-context-recycling_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_generic-stable-irregular_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-unchanged-irregular_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_many-eol-opts_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_many-nop-opts_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-id-swapped_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_uk6x_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_ipv4_tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-10-times_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-11-times_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp-id-rnd_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode-id-rnd_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-ttl-variable_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-dscp-variable_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_tcp_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-assignment-1_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-rtmpt_mc1_wlsb4_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_snaketrap-hptcp_mc1_wlsb4_smallcid.sh


#
# max contexts 1 + WLSB width 64 + small CID
#

TESTS_MAXCONTEXTS1_WLSB64_SMALLCID = \
	scripts/test_non_reg_ipv4_tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_syn-ack-dup_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_malformed-mss-opt_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_bad-ipv4-chksum_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_4-byte-sack-field_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_swapped-ip-id_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-opt-with-duplicate-ack_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_Aeroflex-TM500-LTE_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_unknown-multipath-opt_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_more-than-8-options_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_40-nop-options_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_non-zero-dscp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl0_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl1_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl2_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl3_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl4_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl5_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl6_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl7_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl8_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl9_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl10_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl11_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl12_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl13_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl14-recycle-indexes_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl15-recycle-indexes_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl16-recycle-indexes_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl17-bad-ip-length_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_afl18-bad-urg-data-ptr_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl19-bad-tcp-data-offset_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl20-many-exts_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl21-many-exts_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl22-many-exts_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl23-many-exts_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl24-duplicated-tcp-options_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl26-generic-option_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl27-christmas-tree-packet_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl28-reserved-flags_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl29-urg-ptr_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl30-mss-or-ws-opts-in-irregular-chain_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl32-irregular-generic-option_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl33-reserved-flags-changing_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl34-eol-option-changing_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl40-changing-ipv6-flow-label_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl41-changing-ecn-used_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl42-changing-urg-ptr-with-urg-flag-not-set_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-1_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-2_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl44-variable-generic-opt-length_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl45-christmas-tree-packet_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl46-bad-rnd7-choice_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl47-static-urg-ptr_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl48-changing-ipv4-ttl_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl49-changing-opt-ws_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl50-changing-opt-mss_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl51-changing-opt-eol_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl52-changing-opt-ws-rnd7_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl54-changing-opt-ws-rnd7-2_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl55-recycle-opts-indexes_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-2_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-3_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-4_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl57-recycle-opts_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl58-changing-opt-eol_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl59-rsf-flags_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl60-ack-not-changed_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_afl61-large-ts-in-opt_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_afl62-flowid-changing-and-context-recycling_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_generic-stable-irregular_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-unchanged-irregular_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_many-eol-opts_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_many-nop-opts_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-id-swapped_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_tcp_uk6x_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_ipv4_tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv6_tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv4_tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6_ipv6_tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-10-times_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-11-times_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp-id-rnd_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode-id-rnd_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-ttl-variable_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-dscp-variable_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_tcp_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-assignment-1_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-rtmpt_mc1_wlsb64_smallcid.sh \
	scripts/test_non_reg_ipv4_tcp_snaketrap-hptcp_mc1_wlsb64_smallcid.sh


TESTS_MAXCONTEXTS1_SMALLCID = \
	$(TESTS_MAXCONTEXTS1_WLSB4_SMALLCID) \
	$(TESTS_MAXCONTEXTS1_WLSB64_SMALLCID)


TESTS_SMALLCID = \
	$(TESTS_MAXCONTEXTS0_SMALLCID) \
	$(TESTS_MAXCONTEXTS1_SMALLCID)


#
# max contexts + WLSB width 4 + large CID
#

TESTS_MAXCONTEXTS0_WLSB4_LARGECID = \
	scripts/test_non_reg_ipv4_tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_syn-ack-dup_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_malformed-mss-opt_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_bad-ipv4-chksum_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_4-byte-sack-field_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_swapped-ip-id_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-opt-with-duplicate-ack_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_Aeroflex-TM500-LTE_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_unknown-multipath-opt_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_more-than-8-options_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_40-nop-options_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_non-zero-dscp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl0_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl1_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl2_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl3_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl4_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl5_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl6_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl7_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl8_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl9_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl10_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl11_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl12_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl13_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl14-recycle-indexes_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl15-recycle-indexes_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl16-recycle-indexes_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl17-bad-ip-length_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_afl18-bad-urg-data-ptr_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl19-bad-tcp-data-offset_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl20-many-exts_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl21-many-exts_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl22-many-exts_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl23-many-exts_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl24-duplicated-tcp-options_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl26-generic-option_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl27-christmas-tree-packet_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl28-reserved-flags_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl29-urg-ptr_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl30-mss-or-ws-opts-in-irregular-chain_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl32-irregular-generic-option_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl33-reserved-flags-changing_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl34-eol-option-changing_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl40-changing-ipv6-flow-label_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl41-changing-ecn-used_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl42-changing-urg-ptr-with-urg-flag-not-set_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-1_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-2_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl44-variable-generic-opt-length_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl45-christmas-tree-packet_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl46-bad-rnd7-choice_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl47-static-urg-ptr_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl48-changing-ipv4-ttl_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl49-changing-opt-ws_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl50-changing-opt-mss_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl51-changing-opt-eol_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl52-changing-opt-ws-rnd7_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl54-changing-opt-ws-rnd7-2_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl55-recycle-opts-indexes_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-2_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-3_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-4_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl57-recycle-opts_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl58-changing-opt-eol_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl59-rsf-flags_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl60-ack-not-changed_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl61-large-ts-in-opt_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_afl62-flowid-changing-and-context-recycling_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_generic-stable-irregular_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-unchanged-irregular_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_many-eol-opts_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_many-nop-opts_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-id-swapped_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_uk6x_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_ipv4_tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-10-times_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-11-times_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp-id-rnd_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode-id-rnd_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-ttl-variable_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-dscp-variable_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_tcp_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-assignment-1_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-rtmpt_mc0_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_snaketrap-hptcp_mc0_wlsb4_largecid.sh


#
# max contexts + WLSB width 64 + large CID
#

TESTS_MAXCONTEXTS0_WLSB64_LARGECID = \
	scripts/test_non_reg_ipv4_tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_syn-ack-dup_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_malformed-mss-opt_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_bad-ipv4-chksum_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_4-byte-sack-field_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_swapped-ip-id_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-opt-with-duplicate-ack_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_Aeroflex-TM500-LTE_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_unknown-multipath-opt_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_more-than-8-options_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_40-nop-options_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_non-zero-dscp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl0_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl1_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl2_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl3_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl4_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl5_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl6_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl7_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl8_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl9_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl10_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl11_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl12_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl13_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl14-recycle-indexes_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl15-recycle-indexes_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl16-recycle-indexes_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl17-bad-ip-length_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_afl18-bad-urg-data-ptr_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl19-bad-tcp-data-offset_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl20-many-exts_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl21-many-exts_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl22-many-exts_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl23-many-exts_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl24-duplicated-tcp-options_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl26-generic-option_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl27-christmas-tree-packet_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl28-reserved-flags_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl29-urg-ptr_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl30-mss-or-ws-opts-in-irregular-chain_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl32-irregular-generic-option_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl33-reserved-flags-changing_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl34-eol-option-changing_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl40-changing-ipv6-flow-label_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl41-changing-ecn-used_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl42-changing-urg-ptr-with-urg-flag-not-set_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-1_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-2_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl44-variable-generic-opt-length_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl45-christmas-tree-packet_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl46-bad-rnd7-choice_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl47-static-urg-ptr_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl48-changing-ipv4-ttl_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl49-changing-opt-ws_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl50-changing-opt-mss_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl51-changing-opt-eol_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl52-changing-opt-ws-rnd7_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl54-changing-opt-ws-rnd7-2_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl55-recycle-opts-indexes_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-2_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-3_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-4_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl57-recycle-opts_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl58-changing-opt-eol_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl59-rsf-flags_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl60-ack-not-changed_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl61-large-ts-in-opt_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_afl62-flowid-changing-and-context-recycling_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_generic-stable-irregular_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-unchanged-irregular_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_many-eol-opts_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_many-nop-opts_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-id-swapped_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_uk6x_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_ipv4_tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-10-times_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-11-times_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp-id-rnd_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode-id-rnd_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-ttl-variable_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-dscp-variable_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_tcp_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-assignment-1_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-rtmpt_mc0_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_snaketrap-hptcp_mc0_wlsb64_largecid.sh


TESTS_MAXCONTEXTS0_LARGECID = \
	$(TESTS_MAXCONTEXTS0_WLSB4_LARGECID) \
	$(TESTS_MAXCONTEXTS0_WLSB64_LARGECID)


#
# max contexts 1 + WLSB width 4 + large CID
#

TESTS_MAXCONTEXTS1_WLSB4_LARGECID = \
	scripts/test_non_reg_ipv4_tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_syn-ack-dup_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_malformed-mss-opt_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_bad-ipv4-chksum_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_4-byte-sack-field_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_swapped-ip-id_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-opt-with-duplicate-ack_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_Aeroflex-TM500-LTE_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_unknown-multipath-opt_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_more-than-8-options_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_40-nop-options_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_non-zero-dscp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl0_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl1_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl2_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl3_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl4_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl5_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl6_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl7_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl8_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl9_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl10_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl11_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl12_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl13_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl14-recycle-indexes_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl15-recycle-indexes_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl16-recycle-indexes_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl17-bad-ip-length_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_afl18-bad-urg-data-ptr_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl19-bad-tcp-data-offset_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl20-many-exts_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl21-many-exts_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl22-many-exts_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl23-many-exts_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl24-duplicated-tcp-options_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl26-generic-option_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl27-christmas-tree-packet_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl28-reserved-flags_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl29-urg-ptr_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl30-mss-or-ws-opts-in-irregular-chain_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl32-irregular-generic-option_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl33-reserved-flags-changing_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl34-eol-option-changing_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl40-changing-ipv6-flow-label_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl41-changing-ecn-used_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl42-changing-urg-ptr-with-urg-flag-not-set_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-1_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-2_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl44-variable-generic-opt-length_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl45-christmas-tree-packet_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl46-bad-rnd7-choice_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl47-static-urg-ptr_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl48-changing-ipv4-ttl_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl49-changing-opt-ws_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl50-changing-opt-mss_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl51-changing-opt-eol_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl52-changing-opt-ws-rnd7_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl54-changing-opt-ws-rnd7-2_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl55-recycle-opts-indexes_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-2_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-3_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-4_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl57-recycle-opts_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl58-changing-opt-eol_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl59-rsf-flags_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl60-ack-not-changed_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl61-large-ts-in-opt_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_afl62-flowid-changing-and-context-recycling_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_generic-stable-irregular_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-unchanged-irregular_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_many-eol-opts_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_many-nop-opts_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-id-swapped_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_uk6x_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_ipv4_tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-10-times_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-11-times_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp-id-rnd_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode-id-rnd_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-ttl-variable_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-dscp-variable_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_tcp_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-assignment-1_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-rtmpt_mc1_wlsb4_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_snaketrap-hptcp_mc1_wlsb4_largecid.sh


#
# max contexts 1 + WLSB width 64 + large CID
#

TESTS_MAXCONTEXTS1_WLSB64_LARGECID = \
	scripts/test_non_reg_ipv4_tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_syn-ack-dup_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_malformed-mss-opt_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_bad-ipv4-chksum_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_4-byte-sack-field_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_swapped-ip-id_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-opt-with-duplicate-ack_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_Aeroflex-TM500-LTE_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_unknown-multipath-opt_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_more-than-8-options_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_40-nop-options_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_non-zero-dscp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl0_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl1_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl2_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl3_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl4_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl5_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl6_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl7_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl8_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl9_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl10_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl11_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl12_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl13_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl14-recycle-indexes_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl15-recycle-indexes_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl16-recycle-indexes_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl17-bad-ip-length_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_afl18-bad-urg-data-ptr_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl19-bad-tcp-data-offset_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl20-many-exts_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl21-many-exts_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl22-many-exts_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl23-many-exts_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl24-duplicated-tcp-options_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl26-generic-option_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl27-christmas-tree-packet_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl28-reserved-flags_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl29-urg-ptr_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl30-mss-or-ws-opts-in-irregular-chain_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl32-irregular-generic-option_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl33-reserved-flags-changing_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl34-eol-option-changing_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_tcp_afl40-changing-ipv6-flow-label_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl41-changing-ecn-used_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl42-changing-urg-ptr-with-urg-flag-not-set_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-1_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl43-variable-eol-opt-length-2_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl44-variable-generic-opt-length_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl45-christmas-tree-packet_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl46-bad-rnd7-choice_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl47-static-urg-ptr_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl48-changing-ipv4-ttl_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl49-changing-opt-ws_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl50-changing-opt-mss_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl51-changing-opt-eol_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl52-changing-opt-ws-rnd7_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl54-changing-opt-ws-rnd7-2_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl55-recycle-opts-indexes_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-2_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-3_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl56-changing-ecn-used-4_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl57-recycle-opts_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl58-changing-opt-eol_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl59-rsf-flags_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl60-ack-not-changed_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_afl61-large-ts-in-opt_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_afl62-flowid-changing-and-context-recycling_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_generic-stable-irregular_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_sack-unchanged-irregular_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_many-eol-opts_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_many-nop-opts_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-id-swapped_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_tcp_uk6x_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_ipv4_tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv6_tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv4_tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6_ipv6_tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-9-times_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-10-times_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ip-11-times_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_ssh-dscp-id-rnd_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wlsb-ack-only-for-r-mode-id-rnd_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-ttl-variable_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_ipv4_tcp_outer-ip-dscp-variable_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv6ext_ipv6ext_tcp_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-assignment-1_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_wiki-wireshark-rtmpt_mc1_wlsb64_largecid.sh \
	scripts/test_non_reg_ipv4_tcp_snaketrap-hptcp_mc1_wlsb64_largecid.sh


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

