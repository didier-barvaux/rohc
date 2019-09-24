/*
 * Copyright 2016 Didier Barvaux
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
 * @file   c_tcp_replicate.c
 * @brief  Handle the replicate chain of the TCP compression profile
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "c_tcp_replicate.h"

#include "c_tcp_defines.h"
#include "schemes/rfc4996.h"
#include "protocols/ip_numbers.h"
#include "protocols/ip.h"

#include <assert.h>

static int tcp_code_replicate_ipv4_part(const struct rohc_comp_ctxt *const context,
                                        const ip_context_t *const ip_context,
                                        const struct ipv4_hdr *const ipv4,
                                        const rohc_ip_id_behavior_t ip_id_behavior,
                                        const bool ttl_changed,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));

static int tcp_code_replicate_ipv6_part(const struct rohc_comp_ctxt *const context,
                                        const ip_context_t *const ip_context,
                                        const struct ipv6_hdr *const ipv6,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

static int tcp_code_replicate_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                            const struct rohc_pkt_ip_ext_hdr *const ext,
                                            uint8_t *const rohc_data,
                                            const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int tcp_code_replicate_tcp_part(const struct rohc_comp_ctxt *const context,
                                       const struct rohc_comp_ctxt *const ref_ctxt,
                                       const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                       const struct tcp_tmp_variables *const tmp,
                                       uint8_t *const rohc_data,
                                       const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));


/**
 * @brief Code the replicate chain of an IR packet
 *
 * @param context           The real compression context for traces and update
 * @param ref_ctxt          The reference compression context to detect changes
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for the compressed packet
 * @param[out] rohc_pkt     The ROHC packet being built
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
int tcp_code_replicate_chain(const struct rohc_comp_ctxt *const context,
                             const struct rohc_comp_ctxt *const ref_ctxt,
                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                             const struct tcp_tmp_variables *const tmp,
                             uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len)
{
	const struct sc_tcp_context *const tcp_context = ref_ctxt->specific;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	size_t ip_hdr_pos;
	int ret;

	/* add IP parts of replicate chain */
	for(ip_hdr_pos = 0; ip_hdr_pos < uncomp_pkt_hdrs->ip_hdrs_nr; ip_hdr_pos++)
	{
		const struct rohc_pkt_ip_hdr *const ip_hdr =
			&(uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos]);
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);

		if(ip_hdr->version == IPV4)
		{
			const rohc_ip_id_behavior_t ip_id_behavior =
				tmp->changes[ip_hdr_pos].ip_id_behavior;
			const bool ttl_hopl_changed = tmp->changes[ip_hdr_pos].ttl_hopl_changed;

			ret = tcp_code_replicate_ipv4_part(context, ip_context, ip_hdr->ipv4,
			                                   ip_id_behavior, ttl_hopl_changed,
			                                   rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv4 base header part "
				               "of the replicate chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
		}
		else /* IPv6 */
		{
			uint8_t ip_ext_pos;

			ret = tcp_code_replicate_ipv6_part(context, ip_context, ip_hdr->ipv6,
			                                   rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv6 base header part "
				               "of the replicate chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			for(ip_ext_pos = 0; ip_ext_pos < ip_hdr->exts_nr; ip_ext_pos++)
			{
				const struct rohc_pkt_ip_ext_hdr *const ext =
					&(ip_hdr->exts[ip_ext_pos]);

				rohc_comp_debug(context, "IPv6 option #%u: type %u / length %u",
				                ip_ext_pos + 1, ext->type, ext->len);
				ret = tcp_code_replicate_ipv6_opt_part(context, ext,
				                                       rohc_remain_data, rohc_remain_len);
				if(ret < 0)
				{
					rohc_comp_warn(context, "failed to build the IPv6 extension header "
					               "part of the replicate chain");
					goto error;
				}
				rohc_remain_data += ret;
				rohc_remain_len -= ret;
			}
		}
	}

	/* add TCP replicate part */
	ret = tcp_code_replicate_tcp_part(context, ref_ctxt, uncomp_pkt_hdrs, tmp,
	                                  rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the TCP header part of the "
		               "replicate chain");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the replicate part of the IPv4 header
 *
 * @param context         The real compression context for traces and update
 * @param ip_context      The specific IP compression context
 * @param ipv4            The IPv4 header
 * @param ip_id_behavior  The IP-ID behavior of the IPv4 header
 * @param ttl_changed     Whether the IP TTL changed
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_replicate_ipv4_part(const struct rohc_comp_ctxt *const context,
                                        const ip_context_t *const ip_context,
                                        const struct ipv4_hdr *const ipv4,
                                        const rohc_ip_id_behavior_t ip_id_behavior,
                                        const bool ttl_changed,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
{
	ipv4_replicate_t *const ipv4_replicate = (ipv4_replicate_t *) rohc_data;
	size_t ipv4_replicate_len = sizeof(ipv4_replicate_t);
	int ttl_hopl_indicator;
	int ret;

	assert(ip_context->version == IPV4);

	if(rohc_max_len < ipv4_replicate_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv4 replicate part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv4_replicate_len, rohc_max_len);
		goto error;
	}

	ipv4_replicate->reserved = 0;

	/* IP-ID behavior: cf. RFC6846 §6.1.2 and ip_id_enc_dyn() */
	ipv4_replicate->ip_id_behavior = ip_id_behavior;
	ipv4_replicate->df = ipv4->df;
	ipv4_replicate->dscp = ipv4->dscp;
	ipv4_replicate->ip_ecn_flags = ipv4->ecn;

	/* IP-ID itself: cf. RFC6846 ip_id_enc_dyn() */
	if(ipv4_replicate->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_ZERO)
	{
		rohc_comp_debug(context, "ip_id_behavior = %d", ipv4_replicate->ip_id_behavior);
	}
	else
	{
		uint16_t *const ipv4_replicate_ip_id = (uint16_t *) (rohc_data + ipv4_replicate_len);

		ipv4_replicate_len += sizeof(uint16_t);
		if(rohc_max_len < ipv4_replicate_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv4 replicate part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv4_replicate_len, rohc_max_len);
			goto error;
		}

		*ipv4_replicate_ip_id = ipv4->id;
		rohc_comp_debug(context, "ip_id_behavior = %d, IP-ID = 0x%04x",
		                ipv4_replicate->ip_id_behavior, rohc_ntoh16(ipv4->id));
	}

	/* ttl_hopl */
	ret = c_static_or_irreg8(ipv4->ttl, !ttl_changed,
	                         rohc_data + ipv4_replicate_len,
	                         rohc_max_len - ipv4_replicate_len, &ttl_hopl_indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(ttl_hopl)");
		goto error;
	}
	ipv4_replicate_len += ret;
	rohc_comp_debug(context, "TTL = 0x%02x -> 0x%02x",
	                ip_context->ttl_hopl, ipv4->ttl);
	ipv4_replicate->ttl_flag = ttl_hopl_indicator;

	rohc_comp_dump_buf(context, "IPv4 replicate part", rohc_data, ipv4_replicate_len);

	return ipv4_replicate_len;

error:
	return -1;
}


/**
 * @brief Build the replicate part of the IPv6 header
 *
 * @param context         The real compression context for traces and update
 * @param ip_context      The specific IP compression context
 * @param ipv6            The IPv6 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_replicate_ipv6_part(const struct rohc_comp_ctxt *const context,
                                        const ip_context_t *const ip_context,
                                        const struct ipv6_hdr *const ipv6,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
{
	const uint8_t dscp = ipv6_get_dscp(ipv6);
	size_t ipv6_replicate_len;

	assert(ip_context->version == IPV6);

	if(ipv6->flow1 == 0 && ipv6->flow2 == 0)
	{
		ipv6_replicate1_t *const ipv6_replicate1 = (ipv6_replicate1_t *) rohc_data;

		ipv6_replicate_len = sizeof(ipv6_replicate1_t);
		if(rohc_max_len < ipv6_replicate_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv6 replicate part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv6_replicate_len, rohc_max_len);
			goto error;
		}

		ipv6_replicate1->dscp = dscp;
		ipv6_replicate1->ip_ecn_flags = ipv6->ecn;
		ipv6_replicate1->reserved1 = 0;
		ipv6_replicate1->fl_enc_flag = 0;
		ipv6_replicate1->reserved2 = 0;
	}
	else
	{
		ipv6_replicate2_t *const ipv6_replicate2 = (ipv6_replicate2_t *) rohc_data;

		ipv6_replicate_len = sizeof(ipv6_replicate2_t);
		if(rohc_max_len < ipv6_replicate_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv6 replicate part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv6_replicate_len, rohc_max_len);
			goto error;
		}

		ipv6_replicate2->dscp = dscp;
		ipv6_replicate2->ip_ecn_flags = ipv6->ecn;
		ipv6_replicate2->reserved = 0;
		ipv6_replicate2->fl_enc_flag = 1;
		ipv6_replicate2->flow_label1 = ipv6->flow1;
		ipv6_replicate2->flow_label2 = ipv6->flow2;
	}

	rohc_comp_dump_buf(context, "IPv6 replicate part", rohc_data, ipv6_replicate_len);

	return ipv6_replicate_len;

error:
	return -1;
}


/**
 * @brief Build the replicate part of the IPv6 option header
 *
 * @param context         The real compression context for traces and update
 * @param ext             The IPv6 extension header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_replicate_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                            const struct rohc_pkt_ip_ext_hdr *const ext,
                                            uint8_t *const rohc_data,
                                            const size_t rohc_max_len)
{
	size_t ipv6_opt_replicate_len = 0;

	switch(ext->type)
	{
		case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop option */
		case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination option */
		case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
		{
			const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) ext->data;

			ipv6_opt_replicate_len = 2 + ext->len - 2;
			if(rohc_max_len < ipv6_opt_replicate_len)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv6 extension "
				               "header replicate part: %zu bytes required, but only %zu "
				               "bytes available", ipv6_opt_replicate_len, rohc_max_len);
				goto error;
			}
			rohc_data[0] = 0x80; /* discriminator */ /* TODO: avoid sending??? */
			rohc_data[1] = ipv6_opt->length;
			memcpy(rohc_data + 2, ipv6_opt->value, ipv6_opt_replicate_len - 2);
			break;
		}
		case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
		case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
		case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
		default:
		{
			assert(0);
			goto error;
		}
	}

	rohc_comp_dump_buf(context, "IPv6 option replicate part",
	                   rohc_data, ipv6_opt_replicate_len);

	return ipv6_opt_replicate_len;

error:
	return -1;
}


/**
 * @brief Build the replicate part of the TCP header
 *
 * @param context         The real compression context for traces and update
 * @param ref_ctxt        The reference compression context to detect changes
 * @param uncomp_pkt_hdrs The uncompressed headers to encode
 * @param tmp             The temporary state for the compressed packet
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_replicate_tcp_part(const struct rohc_comp_ctxt *const context,
                                       const struct rohc_comp_ctxt *const ref_ctxt,
                                       const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                       const struct tcp_tmp_variables *const tmp,
                                       uint8_t *const rohc_data,
                                       const size_t rohc_max_len)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	const struct sc_tcp_context *const tcp_context = ref_ctxt->specific;
	const struct tcphdr *const tcp = (struct tcphdr *) uncomp_pkt_hdrs->tcp;

	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	tcp_replicate_t *const tcp_replicate = (tcp_replicate_t *) rohc_data;
	const size_t tcp_replicate_len = sizeof(tcp_replicate_t);

	int indicator;
	int ret;

	rohc_comp_dump_buf(context, "TCP header", (uint8_t *) tcp, sizeof(struct tcphdr));

	if(rohc_max_len < tcp_replicate_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP replicate part: "
		               "%zu bytes required, but only %zu bytes available",
		               tcp_replicate_len, rohc_max_len);
		goto error;
	}

	/* TCP flags */
	tcp_replicate->reserved = 0;
	tcp_replicate->urg_flag = tcp->urg_flag;
	tcp_replicate->ack_flag = tcp->ack_flag;
	tcp_replicate->psh_flag = tcp->psh_flag;
	tcp_replicate->rsf_flags = rsf_index_enc(tcp->rsf_flags);
	tcp_replicate->ecn_used = tmp->ecn_used;

	/* MSN */
	tcp_replicate->msn = rohc_hton16(tmp->new_msn);
	rohc_comp_debug(context, "MSN 0x%02x present", tmp->new_msn);

	/* TCP sequence number */
	tcp_replicate->seq_num = tcp->seq_num;
	rohc_comp_debug(context, "TCP sequence number 0x%08x present",
	                rohc_hton32(tcp_replicate->seq_num));

	rohc_remain_data += sizeof(tcp_replicate_t);
	rohc_remain_len -= sizeof(tcp_replicate_t);

	/* source port */
	/* TODO: better compression */
	if(rohc_remain_len < sizeof(uint16_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP replicate part: "
		               "%zu bytes required for TCP source port, but only %zu bytes available",
		               sizeof(uint16_t), rohc_remain_len);
		goto error;
	}
	tcp_replicate->src_port_presence = ROHC_TCP_PORT_IRREGULAR; /* TODO */
	memcpy(rohc_remain_data, &tcp->src_port, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);
	rohc_comp_debug(context, "TCP source port %spresent",
	                tcp_replicate->src_port_presence ? "" : "not ");

	/* destination port */
	/* TODO: better compression */
	if(rohc_remain_len < sizeof(uint16_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP replicate part: "
		               "%zu bytes required for TCP destination port, but only %zu bytes available",
		               sizeof(uint16_t), rohc_remain_len);
		goto error;
	}
	tcp_replicate->dst_port_presence = ROHC_TCP_PORT_IRREGULAR; /* TODO */
	memcpy(rohc_remain_data, &tcp->dst_port, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);
	rohc_comp_debug(context, "TCP destination port %spresent",
	                tcp_replicate->dst_port_presence ? "" : "not ");

	/* window */
	{
		const bool cr_tcp_window_needed =
			(tmp->tcp_window_changed ||
			 tcp_context->tcp_window_change_count < oa_repetitions_nr);
		ret = c_static_or_irreg16(tcp->window, !cr_tcp_window_needed,
		                          rohc_remain_data, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(window)");
			goto error;
		}
		tcp_replicate->window_presence = indicator;
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "window_indicator = %d, window = 0x%x on %d bytes",
		                tcp_replicate->window_presence, rohc_ntoh16(tcp->window), ret);
	}

	/* urp_presence flag and URG pointer: always check for the URG pointer value
	 * even if the URG flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those
	 * bits will be ignored at reception */
	{
		const bool cr_tcp_urg_ptr_needed =
			(tmp->tcp_urg_ptr_changed ||
			 tcp_context->tcp_urg_ptr_trans_nr < oa_repetitions_nr);
		ret = c_static_or_irreg16(tcp->urg_ptr, !cr_tcp_urg_ptr_needed,
		                          rohc_remain_data, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode zero_or_irreg(urg_ptr)");
			goto error;
		}
		tcp_replicate->urp_presence = indicator;
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "urg_ptr_present = %d (URG pointer encoded on %d "
		                "bytes)", tcp_replicate->urp_presence, ret);
	}

	/* ack_presence flag and ACK number: always check for the ACK number value even
	 * if the ACK flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those bits
	 * will be ignored at reception */
	{
		const bool cr_tcp_ack_num_needed =
			(!tmp->tcp_ack_num_unchanged ||
			 tcp_context->tcp_ack_num_trans_nr < oa_repetitions_nr);
		ret = c_static_or_irreg32(tcp->ack_num, !cr_tcp_ack_num_needed,
		                          rohc_remain_data, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode zero_or_irreg(ack_number)");
			goto error;
		}
		tcp_replicate->ack_presence = indicator;
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "TCP ack_number %spresent",
		                tcp_replicate->ack_presence ? "" : "not ");
	}

	/* ecn_padding + tcp_res_flags + tcp_ecn_flags */
	if(tmp->ecn_used)
	{
		if(rohc_remain_len < sizeof(uint16_t))
		{
			rohc_comp_warn(context, "ROHC buffer too small for the TCP replicate part: "
			               "%zu bytes required for ecn_padding + tcp_res_flags + tcp_ecn_flags, "
			               "but only %zu bytes available", sizeof(uint8_t), rohc_remain_len);
			goto error;
		}
		rohc_remain_data[0] = ((tcp->res_flags << 2) & 0x3c) | (tcp->ecn_flags & 0x03);
		rohc_remain_data++;
		rohc_remain_len--;
	}
	rohc_comp_debug(context, "TCP RES and ECM flags %spresent",
	                tcp_replicate->ecn_used ? "" : "not ");

	/* checksum */
	if(rohc_remain_len < (sizeof(uint16_t) + sizeof(uint16_t)))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP replicate part: "
		               "%zu bytes required for TCP checksum, but only %zu bytes available",
		               sizeof(uint16_t), rohc_remain_len);
		goto error;
	}
	memcpy(rohc_remain_data, &tcp->checksum, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);
	rohc_comp_debug(context, "TCP checksum 0x%04x present",
	                rohc_ntoh16(tcp->checksum));

	/* ack_stride */
	{
		const bool is_ack_stride_static = !tmp->ack_num_scaling_changed;
		ret = c_static_or_irreg16(rohc_hton16(tmp->ack_stride),
		                          is_ack_stride_static,
		                          rohc_remain_data, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ack_stride)");
			goto error;
		}
		tcp_replicate->ack_stride_flag = indicator;
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "TCP ack_stride %spresent (ack_stride = %u)",
		                tcp_replicate->ack_stride_flag ? "" : "not ",
		                tmp->ack_stride);
	}

	/* RFC6846 section 6.3.7: The entire table of TCP options items is always
	 * replicated when using the IR-CR packet */
	{
		bool all_items_needed[MAX_TCP_OPTION_INDEX + 1] =
			{ true, true, true, true, true, true, true, true,
			  true, true, true, true, true, true, true, true };

		rohc_comp_debug(context, "compressed list of TCP options: list present");
		tcp_replicate->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, uncomp_pkt_hdrs,
		                                    &tmp->tcp_opts, all_items_needed,
		                                    rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
#endif
		rohc_remain_len -= ret;
	}

	rohc_comp_dump_buf(context, "TCP replicate part", rohc_data,
	                   rohc_max_len - rohc_remain_len);

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
}

