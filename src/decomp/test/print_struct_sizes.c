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
 * @file   decomp/test/print_struct_sizes.c
 * @brief  Print the sizes of main decompression structures
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include <rohc_decomp_rfc3095.h>
#include <d_tcp_defines.h>

#include <stdio.h>


/**
 * @brief Print the sizes of main decompression structures
 *
 * @return The unix return code: always return 0
 */
int main(void)
{
	/* general */
	printf("sizeof(size_t) = %zu\n", sizeof(size_t));
	printf("sizeof(bool) = %zu\n", sizeof(bool));
	printf("sizeof(rohc_lsb_shift_t) = %zu\n", sizeof(rohc_lsb_shift_t));
	printf("sizeof(rohc_lsb_decode) = %zu\n", sizeof(struct rohc_lsb_decode));
	printf("sizeof(rohc_ip_id_behavior_t) = %zu\n", sizeof(rohc_ip_id_behavior_t));

	/* decompressor */
	printf("\n");
	printf("sizeof(struct rohc_decomp) = %zu\n", sizeof(struct rohc_decomp));
	printf("\tsizeof(struct rohc_medium) = %zu\n", sizeof(struct rohc_medium));
	printf("\tsizeof(rohc_decomp_features_t) = %zu\n", sizeof(rohc_decomp_features_t));
	printf("\tsizeof(rohc_mode_t) = %zu\n", sizeof(rohc_mode_t));

	/* context */
	printf("\n");
	printf("sizeof(struct rohc_decomp_ctxt) = %zu\n", sizeof(struct rohc_decomp_ctxt));
	printf("\tsizeof(struct d_statistics) = %zu\n", sizeof(struct d_statistics));

	/* RFC3095 */
	printf("\n");
	printf("sizeof(struct rohc_decomp_rfc3095_changes) = %zu\n",
	       sizeof(struct rohc_decomp_rfc3095_changes));
	printf("sizeof(struct rohc_decomp_rfc3095_ctxt) = %zu\n",
	       sizeof(struct rohc_decomp_rfc3095_ctxt));
	printf("\tsizeof(struct ip_id_offset_decode) = %zu\n",
	       sizeof(struct ip_id_offset_decode));
	printf("\tsizeof(struct list_decomp) = %zu\n", sizeof(struct list_decomp));
	printf("\t\tsizeof(struct rohc_list) = %zu\n", sizeof(struct rohc_list));
	printf("\t\tsizeof(struct rohc_list_item) = %zu\n", sizeof(struct rohc_list_item));

	/* RFC6846 / TCP */
	printf("\n");
	printf("sizeof(struct d_tcp_context) = %zu\n", sizeof(struct d_tcp_context));
	printf("\tsizeof(ip_context_t) = %zu\n", sizeof(ip_context_t));
	printf("\t\tsizeof(ipvx_context_t) = %zu\n", sizeof(ipvx_context_t));
	printf("\t\tsizeof(ipv4_context_t) = %zu\n", sizeof(ipv4_context_t));
	printf("\t\tsizeof(ipv6_context_t) = %zu\n", sizeof(ipv6_context_t));
	printf("\t\tsizeof(ip_option_context_t) = %zu\n", sizeof(ip_option_context_t));
	printf("\t\t\tsizeof(ipv6_generic_option_context_t) = %zu\n",
	       sizeof(ipv6_generic_option_context_t));
	printf("\tsizeof(struct d_tcp_opts_ctxt) = %zu\n", sizeof(struct d_tcp_opts_ctxt));
	printf("\t\tsizeof(struct d_tcp_opt_ctxt) = %zu\n", sizeof(struct d_tcp_opt_ctxt));
	printf("\t\tsizeof(struct d_tcp_opt_sack) = %zu\n", sizeof(struct d_tcp_opt_sack));

	printf("\n");
	printf("sizeof(struct rohc_tcp_extr_bits) = %zu\n",
	       sizeof(struct rohc_tcp_extr_bits));
	printf("\tsizeof(struct rohc_tcp_extr_ip_bits) = %zu\n",
	       sizeof(struct rohc_tcp_extr_ip_bits));
	printf("\t\tsizeof(ip_option_context_t) = %zu\n", sizeof(ip_option_context_t));
	printf("\tsizeof(d_tcp_opts_ctxt) = %zu\n", sizeof(struct d_tcp_opts_ctxt));
	printf("\tsizeof(rohc_lsb_field32) = %zu\n", sizeof(struct rohc_lsb_field32));
	printf("\tsizeof(rohc_lsb_field16) = %zu\n", sizeof(struct rohc_lsb_field16));
	printf("\tsizeof(rohc_lsb_field8) = %zu\n", sizeof(struct rohc_lsb_field8));

	printf("\n");
	printf("sizeof(struct rohc_tcp_decoded_values) = %zu\n",
	       sizeof(struct rohc_tcp_decoded_values));
	printf("\tsizeof(struct rohc_tcp_decoded_ip_values) = %zu\n",
	       sizeof(struct rohc_tcp_decoded_ip_values));
	printf("\t\tsizeof(ip_option_context_t) = %zu\n", sizeof(ip_option_context_t));
	printf("\tsizeof(d_tcp_opts_ctxt) = %zu\n", sizeof(struct d_tcp_opts_ctxt));
	printf("\tsizeof(d_tcp_opt_sack) = %zu\n", sizeof(struct d_tcp_opt_sack));

	return 0;
}

