/*
 * Copyright 2012,2013,2014,2015,2016 Didier Barvaux
 * Copyright 2013,2014 Viveris Technologies
 * Copyright 2012 WBX
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
 * @file   c_tcp_dynamic.c
 * @brief  Handle the dynamic chain of the TCP compression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "c_tcp_dynamic.h"

#include "c_tcp_defines.h"
#include "schemes/rfc4996.h"
#include "protocols/ip_numbers.h"
#include "protocols/ip.h"

#include <assert.h>

static int tcp_code_dynamic_ipv4_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv4_hdr *const ipv4,
                                      const bool is_innermost,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int tcp_code_dynamic_ipv6_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv6_hdr *const ipv6,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

static int tcp_code_dynamic_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                          const struct ipv6_opt *const ipv6_opt,
                                          const uint8_t protocol,
                                          uint8_t *const rohc_data,
                                          const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int tcp_code_dynamic_tcp_part(const struct rohc_comp_ctxt *const context,
                                     const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                     struct tcp_tmp_variables *const tmp,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));


/**
 * @brief Code the dynamic part of an IR or IR-DYN packet
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param tmp               The temporary state for compressed packet
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
int tcp_code_dyn_part(struct rohc_comp_ctxt *const context,
                      const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                      struct tcp_tmp_variables *const tmp,
                      uint8_t *const rohc_pkt,
                      const size_t rohc_pkt_max_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	ip_context_t *const inner_ip_context =
		&(tcp_context->ip_contexts[uncomp_pkt_hdrs->ip_hdrs_nr - 1]);
	const struct ip_hdr *inner_ip_hdr = uncomp_pkt_hdrs->innermost_ip_hdr->ip;

	size_t ip_hdr_pos;
	int ret;

	/* add dynamic chain for both IR and IR-DYN packet */
	for(ip_hdr_pos = 0; ip_hdr_pos < uncomp_pkt_hdrs->ip_hdrs_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip = uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos].ip;
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const bool is_inner = !!(ip_hdr_pos + 1 == tcp_context->ip_contexts_nr);

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) ip;

			ret = tcp_code_dynamic_ipv4_part(context, ip_context, ipv4, is_inner,
			                                 rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv4 base header part "
				               "of the dynamic chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
		}
		else /* IPv6 */
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) ip;
			const uint8_t *remain_data = (const uint8_t *) (ipv6 + 1);
			size_t remain_len =
				uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos].tot_len - sizeof(struct ipv6_hdr);
			uint8_t protocol = ipv6->nh;
			size_t ip_ext_pos;

			ret = tcp_code_dynamic_ipv6_part(context, ip_context, ipv6,
			                                 rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv6 base header part "
				               "of the dynamic chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			for(ip_ext_pos = 0;
			    ip_ext_pos < uncomp_pkt_hdrs->ip_hdrs[ip_hdr_pos].exts_nr;
			    ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				const size_t opt_len = ipv6_opt_get_length(ipv6_opt);

				rohc_comp_debug(context, "IPv6 option %u", protocol);
				ret = tcp_code_dynamic_ipv6_opt_part(context, ipv6_opt, protocol,
				                                     rohc_remain_data, rohc_remain_len);
				if(ret < 0)
				{
					rohc_comp_warn(context, "failed to build the IPv6 extension "
					               "header part of the dynamic chain");
					goto error;
				}
				rohc_remain_data += ret;
				rohc_remain_len -= ret;

				protocol = ipv6_opt->next_header;
				remain_data += opt_len;
				remain_len -= opt_len;
			}
		}
	}

	/* add TCP dynamic part */
	ret = tcp_code_dynamic_tcp_part(context, uncomp_pkt_hdrs, tmp,
	                                rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the TCP header part of the "
		               "dynamic chain");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		inner_ip_context->last_ip_id_behavior =
			inner_ip_context->ip_id_behavior;
		inner_ip_context->last_ip_id = rohc_ntoh16(inner_ipv4->id);
		inner_ip_context->df = inner_ipv4->df;
		inner_ip_context->dscp = inner_ipv4->dscp;
	}
	else if(inner_ip_hdr->version == IPV6)
	{
		const struct ipv6_hdr *const inner_ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		inner_ip_context->dscp = ipv6_get_dscp(inner_ipv6);
	}
	else
	{
		rohc_comp_warn(context, "unexpected IP version %u", inner_ip_hdr->version);
		assert(0);
		goto error;
	}
	inner_ip_context->ttl_hopl = uncomp_pkt_hdrs->innermost_ip_hdr->ttl_hl;

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv4 header
 *
 * @param context         The compression context
 * @param ip_context      The specific IP compression context
 * @param ipv4            The IPv4 header
 * @param is_innermost    true if the IP header is the innermost of the packet,
 *                        false otherwise
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_ipv4_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv4_hdr *const ipv4,
                                      const bool is_innermost,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
{
	ipv4_dynamic1_t *const ipv4_dynamic1 = (ipv4_dynamic1_t *) rohc_data;
	size_t ipv4_dynamic_len = sizeof(ipv4_dynamic1_t);
	uint16_t ip_id;

	assert(ip_context->version == IPV4);

	if(rohc_max_len < ipv4_dynamic_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv4 dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv4_dynamic_len, rohc_max_len);
		goto error;
	}

	/* IP-ID */
	ip_id = rohc_ntoh16(ipv4->id);
	rohc_comp_debug(context, "ip_id_behavior = %d, last IP-ID = 0x%04x, "
	                "IP-ID = 0x%04x", ip_context->ip_id_behavior,
	                ip_context->last_ip_id, ip_id);

	ipv4_dynamic1->reserved = 0;
	ipv4_dynamic1->df = ipv4->df;

	/* IP-ID behavior
	 * cf. RFC4996 page 60/61 ip_id_behavior_choice() and ip_id_enc_dyn() */
	if(is_innermost)
	{
		/* all behavior values possible */
		ipv4_dynamic1->ip_id_behavior = ip_context->ip_id_behavior;
	}
	else
	{
		/* only ROHC_IP_ID_BEHAVIOR_RAND or ROHC_IP_ID_BEHAVIOR_ZERO */
		if(ipv4->id == 0)
		{
			ipv4_dynamic1->ip_id_behavior = ROHC_IP_ID_BEHAVIOR_ZERO;
		}
		else
		{
			ipv4_dynamic1->ip_id_behavior = ROHC_IP_ID_BEHAVIOR_RAND;
		}
		/* TODO: should not update context there */
		ip_context->ip_id_behavior = ipv4_dynamic1->ip_id_behavior;
	}
	/* TODO: should not update context there */
	ip_context->last_ip_id_behavior = ip_context->ip_id_behavior;

	ipv4_dynamic1->dscp = ipv4->dscp;
	ipv4_dynamic1->ip_ecn_flags = ipv4->ecn;
	ipv4_dynamic1->ttl_hopl = ipv4->ttl;

	/* IP-ID itself
	 * cf. RFC4996 page 60/61 ip_id_enc_dyn() */
	if(ipv4_dynamic1->ip_id_behavior == ROHC_IP_ID_BEHAVIOR_ZERO)
	{
		rohc_comp_debug(context, "ip_id_behavior = %d", ipv4_dynamic1->ip_id_behavior);
	}
	else
	{
		ipv4_dynamic2_t *const ipv4_dynamic2 = (ipv4_dynamic2_t *) rohc_data;

		ipv4_dynamic_len = sizeof(ipv4_dynamic2_t);
		if(rohc_max_len < ipv4_dynamic_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv4 dynamic part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv4_dynamic_len, rohc_max_len);
			goto error;
		}

		ipv4_dynamic2->ip_id = ipv4->id;
		rohc_comp_debug(context, "ip_id_behavior = %d, IP-ID = 0x%04x",
		                ipv4_dynamic1->ip_id_behavior, rohc_ntoh16(ipv4->id));
	}

	/* TODO: should not update context there */
	ip_context->dscp = ipv4->dscp;
	ip_context->ttl_hopl = ipv4->ttl;
	ip_context->df = ipv4->df;
	ip_context->last_ip_id = rohc_ntoh16(ipv4->id);

	rohc_comp_dump_buf(context, "IPv4 dynamic part", rohc_data, ipv4_dynamic_len);

	return ipv4_dynamic_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv6 header
 *
 * @param context         The compression context
 * @param ip_context      The specific IP compression context
 * @param ipv6            The IPv6 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_ipv6_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv6_hdr *const ipv6,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
{
	ipv6_dynamic_t *const ipv6_dynamic = (ipv6_dynamic_t *) rohc_data;
	const size_t ipv6_dynamic_len = sizeof(ipv6_dynamic_t);
	const uint8_t dscp = ipv6_get_dscp(ipv6);

	assert(ip_context->version == IPV6);

	if(rohc_max_len < ipv6_dynamic_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv6 dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv6_dynamic_len, rohc_max_len);
		goto error;
	}

	ipv6_dynamic->dscp = dscp;
	ipv6_dynamic->ip_ecn_flags = ipv6->ecn;
	ipv6_dynamic->ttl_hopl = ipv6->hl;

	/* TODO: should not update context there */
	ip_context->dscp = dscp;
	ip_context->ttl_hopl = ipv6->hl;

	rohc_comp_dump_buf(context, "IP dynamic part", rohc_data, ipv6_dynamic_len);

	return ipv6_dynamic_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv6 option header
 *
 * @param context         The compression context
 * @param ipv6_opt        The IPv6 extension header
 * @param protocol        The protocol of the IPv6 extension header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                          const struct ipv6_opt *const ipv6_opt,
                                          const uint8_t protocol,
                                          uint8_t *const rohc_data,
                                          const size_t rohc_max_len)
{
	size_t ipv6_opt_dynamic_len;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop option */
		case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination option */
		{
			ipv6_opt_dynamic_len = ipv6_opt_get_length(ipv6_opt) - 2;
			if(rohc_max_len < ipv6_opt_dynamic_len)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv6 extension "
				               "header dynamic part: %zu bytes required, but only %zu "
				               "bytes available", ipv6_opt_dynamic_len, rohc_max_len);
				goto error;
			}
			memcpy(rohc_data, ipv6_opt->value, ipv6_opt_dynamic_len);
			break;
		}
		case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
		{
			/* the dynamic part of the routing header is empty */
			ipv6_opt_dynamic_len = 0;
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

	rohc_comp_dump_buf(context, "IPv6 option dynamic part",
	                   rohc_data, ipv6_opt_dynamic_len);

	return ipv6_opt_dynamic_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the TCP header.
 *
 * \verbatim

 Dynamic part of TCP header:

TODO

\endverbatim
 *
 * @param context         The compression context
 * @param uncomp_pkt_hdrs The uncompressed headers to encode
 * @param tmp             The temporary state for compressed packet
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_tcp_part(const struct rohc_comp_ctxt *const context,
                                     const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                     struct tcp_tmp_variables *const tmp,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	struct sc_tcp_context *const tcp_context = context->specific;
	const struct tcphdr *const tcp = (struct tcphdr *) uncomp_pkt_hdrs->tcp;

	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	tcp_dynamic_t *const tcp_dynamic = (tcp_dynamic_t *) rohc_remain_data;
	size_t tcp_dynamic_len = sizeof(tcp_dynamic_t);

	int indicator;
	int ret;

	rohc_comp_debug(context, "TCP dynamic part (minimal length = %zd)",
	                tcp_dynamic_len);

	if(rohc_remain_len < tcp_dynamic_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
		               "%zu bytes required at minimum, but only %zu bytes available",
		               tcp_dynamic_len, rohc_remain_len);
		goto error;
	}

	rohc_comp_debug(context, "TCP seq = 0x%04x, ack_seq = 0x%04x",
	                rohc_ntoh32(tcp->seq_num), rohc_ntoh32(tcp->ack_num));
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d",
	                *(uint16_t*)(((uint8_t*)tcp) + 12),
	                tcp->res_flags, tcp->data_offset, tcp->rsf_flags,
	                tcp->ecn_flags, tcp->urg_flag, tcp->ack_flag,
	                tcp->psh_flag);
	rohc_comp_debug(context, "TCP window = 0x%04x, check = 0x%x, "
	                "urg_ptr = %d", rohc_ntoh16(tcp->window),
	                rohc_ntoh16(tcp->checksum), rohc_ntoh16(tcp->urg_ptr));

	tcp_dynamic->ecn_used = tcp_context->ecn_used;
	tcp_dynamic->tcp_res_flags = tcp->res_flags;
	tcp_dynamic->tcp_ecn_flags = tcp->ecn_flags;
	tcp_dynamic->urg_flag = tcp->urg_flag;
	tcp_dynamic->ack_flag = tcp->ack_flag;
	tcp_dynamic->psh_flag = tcp->psh_flag;
	tcp_dynamic->rsf_flags = tcp->rsf_flags;
	tcp_dynamic->msn = rohc_hton16(tcp_context->msn);
	tcp_dynamic->seq_num = tcp->seq_num;

	rohc_remain_data += sizeof(tcp_dynamic_t);
	rohc_remain_len -= sizeof(tcp_dynamic_t);

	/* ack_zero flag and ACK number: always check for the ACK number value even
	 * if the ACK flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those bits
	 * will be ignored at reception */
	ret = c_zero_or_irreg32(tcp->ack_num, rohc_remain_data, rohc_remain_len,
	                        &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode zero_or_irreg(ack_number)");
		goto error;
	}
	tcp_dynamic->ack_zero = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "TCP ack_number %spresent",
	                tcp_dynamic->ack_zero ? "not " : "");

	/* enough room for encoded window and checksum? */
	if(rohc_remain_len < (sizeof(uint16_t) + sizeof(uint16_t)))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
		               "%zu bytes required for TCP window and checksum, but only "
		               "%zu bytes available", sizeof(uint16_t) + sizeof(uint16_t),
		               rohc_remain_len);
		goto error;
	}

	/* window */
	memcpy(rohc_remain_data, &tcp->window, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	/* checksum */
	memcpy(rohc_remain_data, &tcp->checksum, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	/* urp_zero flag and URG pointer: always check for the URG pointer value
	 * even if the URG flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those
	 * bits will be ignored at reception */
	ret = c_zero_or_irreg16(tcp->urg_ptr, rohc_remain_data, rohc_remain_len,
	                        &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode zero_or_irreg(urg_ptr)");
		goto error;
	}
	tcp_dynamic->urp_zero = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "TCP urg_ptr %spresent",
	                tcp_dynamic->urp_zero ? "not " : "");

	/* ack_stride */
	{
		const bool is_ack_stride_static =
			tcp_is_ack_stride_static(tcp_context->ack_stride,
			                         tcp_context->ack_num_scaling_nr,
			                         oa_repetitions_nr);
		ret = c_static_or_irreg16(rohc_hton16(tcp_context->ack_stride),
		                          is_ack_stride_static,
		                          rohc_remain_data, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ack_stride)");
			goto error;
		}
		tcp_dynamic->ack_stride_flag = indicator;
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "TCP ack_stride %spresent",
		                tcp_dynamic->ack_stride_flag ? "" : "not ");
	}

	/* list of TCP options */
	if(uncomp_pkt_hdrs->tcp_opts.nr == 0)
	{
		rohc_comp_debug(context, "TCP no options!");

		/* see RFC4996, §6.3.3 : no XI items, PS = 0, m = 0 */
		if(rohc_remain_len < 1)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
			               "1 byte required for empty list of TCP option, but only "
			               "%zu bytes available", rohc_remain_len);
			goto error;
		}
		rohc_remain_data[0] = 0x00;
		rohc_remain_data++;
		rohc_remain_len--;
	}
	else
	{
		bool no_item_needed;

		ret = c_tcp_code_tcp_opts_list_item(context, uncomp_pkt_hdrs,
		                                    ROHC_CHAIN_DYNAMIC,
		                                    &tcp_context->tcp_opts, &tmp->tcp_opts,
		                                    rohc_remain_data, rohc_remain_len,
		                                    &no_item_needed);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode the list of TCP options "
			               "in the dynamic chain");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
#endif
		rohc_remain_len -= ret;
	}

	rohc_comp_dump_buf(context, "TCP dynamic part", rohc_data,
	                   rohc_max_len - rohc_remain_len);

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
}

