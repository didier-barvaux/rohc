/*
 * Copyright 2017,2018 Didier Barvaux
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file   /comp/test/print_struct_sizes.c
 * @brief  Print the sizes of main compression structures
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include <rohc_comp_rfc3095.h>
#include <c_tcp_defines.h>

#include <stdio.h>


/**
 * @brief Print the sizes of main compression structures
 *
 * @return The unix return code: always return 0
 */
int main(void)
{
	/* general */
	printf("sizeof(size_t) = %zu\n", sizeof(size_t));
	printf("sizeof(bool) = %zu\n", sizeof(bool));
	printf("sizeof(bits_nr_t) = %zu\n", sizeof(bits_nr_t));
	printf("sizeof(rohc_lsb_shift_t) = %zu\n", sizeof(rohc_lsb_shift_t));
	printf("sizeof(c_wlsb) = %zu\n", sizeof(struct c_wlsb));
	printf("sizeof(rohc_ip_id_behavior_t) = %zu\n", sizeof(rohc_ip_id_behavior_t));

	/* compressor */
	printf("\n");
	printf("sizeof(struct rohc_comp) = %zu\n", sizeof(struct rohc_comp));
	printf("\tsizeof(struct rohc_medium) = %zu\n", sizeof(struct rohc_medium));
	printf("\tsizeof(rohc_comp_features_t) = %zu\n", sizeof(rohc_comp_features_t));

	/* context */
	printf("\n");
	printf("sizeof(struct rohc_comp_ctxt) = %zu\n", sizeof(struct rohc_comp_ctxt));
	printf("\tsizeof(struct rohc_fingerprint) = %zu\n", sizeof(struct rohc_fingerprint));
	printf("\t\tsizeof(struct rohc_fingerprint_base) = %zu\n", sizeof(struct rohc_fingerprint_base));
	printf("\t\t\tsizeof(struct rohc_fingerprint_ip) = %zu\n", sizeof(struct rohc_fingerprint_ip));
	printf("sizeof(struct rohc_pkt_hdrs) = %zu\n", sizeof(struct rohc_pkt_hdrs));
	printf("\tsizeof(struct rohc_pkt_ip_hdr) = %zu\n", sizeof(struct rohc_pkt_ip_hdr));

	/* RFC3095 */
	printf("\n");
	printf("sizeof(struct rohc_comp_rfc3095_ctxt) = %zu\n",
	       sizeof(struct rohc_comp_rfc3095_ctxt));
	printf("\tsizeof(struct rfc3095_tmp_state) = %zu\n", sizeof(struct rfc3095_tmp_state));
	printf("\tsizeof(struct ip_header_info) = %zu\n", sizeof(struct ip_header_info));
	printf("\t\tsizeof(struct ipv4_header_info) = %zu\n", sizeof(struct ipv4_header_info));
	printf("\t\tsizeof(struct ipv6_header_info) = %zu\n", sizeof(struct ipv6_header_info));
	printf("\t\t\tsizeof(struct list_comp) = %zu\n", sizeof(struct list_comp));
	printf("\t\t\t\tsizeof(struct rohc_list) = %zu\n", sizeof(struct rohc_list));
	printf("\t\t\t\tsizeof(struct rohc_list_item) = %zu\n", sizeof(struct rohc_list_item));

	/* RFC6846 / TCP */
	printf("\n");
	printf("sizeof(struct sc_tcp_context) = %zu\n", sizeof(struct sc_tcp_context));
	printf("\tsizeof(ip_context_t) = %zu\n", sizeof(ip_context_t));
	printf("\t\tsizeof(ip_option_context_t) = %zu\n", sizeof(ip_option_context_t));
	printf("\t\t\tsizeof(ipv6_generic_option_context_t) = %zu\n",
	       sizeof(ipv6_generic_option_context_t));
	printf("\tsizeof(struct c_tcp_opts_ctxt) = %zu\n", sizeof(struct c_tcp_opts_ctxt));
	printf("\t\tsizeof(struct c_tcp_opt_ctxt) = %zu\n", sizeof(struct c_tcp_opt_ctxt));
	printf("sizeof(struct c_tcp_opts_ctxt_tmp) = %zu\n", sizeof(struct c_tcp_opts_ctxt_tmp));
	printf("sizeof(struct tcp_tmp_variables) = %zu\n", sizeof(struct tcp_tmp_variables));

	return 0;
}

