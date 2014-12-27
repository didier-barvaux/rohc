/*
 * Copyright 2012,2013,2014 Didier Barvaux
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
 * @file   d_tcp_dynamic.c
 * @brief  Handle the dynamic chain of the TCP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "d_tcp_dynamic.h"

#include "d_tcp_defines.h"
#include "rohc_utils.h"
#include "protocols/ip_numbers.h"
#include "schemes/decomp_wlsb.h" /* TODO: set ref later */
#include "schemes/tcp_sack.h"

#ifndef __KERNEL__
#  include <string.h>
#endif

static int tcp_parse_dynamic_ip(struct rohc_decomp_ctxt *const context,
                                ip_context_t *const ip_context,
                                const unsigned char *const rohc_packet,
										  const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int tcp_parse_dynamic_ipv6_option(struct rohc_decomp_ctxt *const context,
                                         ipv6_option_context_t *const opt_context,
                                         const uint8_t protocol,
                                         const unsigned char *const rohc_packet,
                                         const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int tcp_parse_dynamic_tcp(struct rohc_decomp_ctxt *const context,
                                 const unsigned char *const rohc_packet,
                                 const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2)));


/**
 * @brief Parse the dynamic chain of the IR/IR-DYN packet
 *
 * @param context          The decompression context
 * @param rohc_packet      The remaining part of the ROHC packet
 * @param rohc_length      The remaining length (in bytes) of the ROHC packet
 * @param[out] parsed_len  The length (in bytes) of static chain in case of success
 * @return                 true in the dynamic chain was successfully parsed,
 *                         false if the ROHC packet was malformed
 */
bool tcp_parse_dyn_chain(struct rohc_decomp_ctxt *const context,
                         const uint8_t *const rohc_packet,
                         const size_t rohc_length,
                         size_t *const parsed_len)
{
	struct d_tcp_context *tcp_context = context->specific;
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t ip_contexts_nr;
	int ret;

	(*parsed_len) = 0;

	/* parse dynamic IP part (IPv4/IPv6 headers and extension headers) */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_contexts_nr]);

		ret = tcp_parse_dynamic_ip(context, ip_context, remain_data, remain_len);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
			                 "dynamic part");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%u dynamic part is %d-byte length",
								ip_context->version, ret);
		assert(remain_len >= ((size_t) ret));
		remain_data += ret;
		remain_len -= ret;
		(*parsed_len) += ret;
	}

	/* parse TCP dynamic part */
	ret = tcp_parse_dynamic_tcp(context, remain_data, remain_len);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP "
		                 "dynamic part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP dynamic part is %d-byte length", ret);
	assert(remain_len >= ((size_t) ret));
	remain_data += ret;
	remain_len -= ret;
	(*parsed_len) += ret;

	return true;

error:
	return false;
}


/**
 * @brief Decode the dynamic IP header of the rohc packet.
 *
 * @param context        The decompression context
 * @param ip_context     The specific IP decompression context
 * @param rohc_packet    The remaining part of the ROHC packet
 * @param rohc_length    The remaining length (in bytes) of the ROHC packet
 * @return               The length of dynamic IP header in case of success,
 *                       -1 if an error occurs
 */
static int tcp_parse_dynamic_ip(struct rohc_decomp_ctxt *const context,
                                ip_context_t *const ip_context,
                                const unsigned char *const rohc_packet,
                                const size_t rohc_length)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t size = 0;
	int ret;

	rohc_decomp_debug(context, "parse IP dynamic part");

	if(ip_context->ctxt.vx.version == IPV4)
	{
		const ipv4_dynamic1_t *const ipv4_dynamic1 =
			(ipv4_dynamic1_t *) remain_data;

		if(remain_len < sizeof(ipv4_dynamic1_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv4 dynamic part");
			goto error;
		}

		ip_context->ctxt.v4.df = ipv4_dynamic1->df;
		ip_context->ctxt.v4.ip_id_behavior = ipv4_dynamic1->ip_id_behavior;
		rohc_decomp_debug(context, "ip_id_behavior = %d",
		                  ip_context->ctxt.v4.ip_id_behavior);
		ip_context->ctxt.v4.dscp = ipv4_dynamic1->dscp;
		ip_context->ctxt.v4.ip_ecn_flags = ipv4_dynamic1->ip_ecn_flags;
		ip_context->ctxt.v4.ttl_hopl = ipv4_dynamic1->ttl_hopl;
		rohc_decomp_debug(context, "DSCP = 0x%x, ip_ecn_flags = %d, "
		                  "ttl_hopl = 0x%x", ip_context->ctxt.v4.dscp,
		                  ip_context->ctxt.v4.ip_ecn_flags,
		                  ip_context->ctxt.v4.ttl_hopl);
		// cf RFC4996 page 60/61 ip_id_enc_dyn()
		if(ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
		{
			ip_context->ctxt.v4.ip_id = 0;
			rohc_decomp_debug(context, "new last IP-ID = 0x%04x",
			                  ip_context->ctxt.v4.ip_id);
			size += sizeof(ipv4_dynamic1_t);
			remain_data += sizeof(ipv4_dynamic1_t);
			remain_len -= sizeof(ipv4_dynamic1_t);
		}
		else
		{
			const ipv4_dynamic2_t *const ipv4_dynamic2 =
				(ipv4_dynamic2_t *) remain_data;
			uint16_t ip_id;

			if(remain_len < sizeof(ipv4_dynamic2_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "IPv4 dynamic part");
				goto error;
			}

			if(ipv4_dynamic2->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
			{
				ip_id = swab16(ipv4_dynamic2->ip_id);
			}
			else
			{
				ip_id = ipv4_dynamic2->ip_id;
			}
			ip_context->ctxt.v4.ip_id = rohc_ntoh16(ip_id);
			rohc_decomp_debug(context, "new last IP-ID = 0x%04x",
			                  ip_context->ctxt.v4.ip_id);

			size += sizeof(ipv4_dynamic2_t);
			remain_data += sizeof(ipv4_dynamic2_t);
			remain_len -= sizeof(ipv4_dynamic2_t);
		}
		rohc_decomp_debug(context, "IP-ID = 0x%04x", ip_context->ctxt.v4.ip_id);
	}
	else
	{
		const ipv6_dynamic_t *const ipv6_dynamic =
			(ipv6_dynamic_t *) remain_data;
		uint8_t protocol;
		size_t opts_nr;

		if(remain_len < sizeof(ipv6_dynamic_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv6 dynamic part");
			goto error;
		}

		ip_context->ctxt.v6.dscp = ipv6_dynamic->dscp;
		ip_context->ctxt.v6.ip_ecn_flags = ipv6_dynamic->ip_ecn_flags;
		ip_context->ctxt.v6.ttl_hopl = ipv6_dynamic->ttl_hopl;
		ip_context->ctxt.v6.ip_id_behavior = IP_ID_BEHAVIOR_RAND;

		size += sizeof(ipv6_dynamic_t);
		remain_data += sizeof(ipv6_dynamic_t);
		remain_len -= sizeof(ipv6_dynamic_t);

		protocol = ip_context->ctxt.v6.next_header;
		for(opts_nr = 0; opts_nr < ip_context->ctxt.v6.opts_nr; opts_nr++)
		{
			ipv6_option_context_t *const opt =
				&(ip_context->ctxt.v6.opts[ip_context->ctxt.v6.opts_nr]);

			ret = tcp_parse_dynamic_ipv6_option(context, opt, protocol,
			                                    remain_data, remain_len);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: malformed "
				                 "IPv6 dynamic option part");
				goto error;
			}
			rohc_decomp_debug(context, "IPv6 dynamic option part is %d-byte "
									"length", ret);
			assert(remain_len >= ((size_t) ret));
			size += ret;
			remain_data += ret;
			remain_len -= ret;

			protocol = opt->generic.next_header;
		}
	}

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IP dynamic part", rohc_packet, size);

	return size;

error:
	return -1;
}


/**
 * @brief Decode the dynamic IPv6 option header of the rohc packet.
 *
 * @param context        The decompression context
 * @param opt_context    The specific IPv6 option decompression context
 * @param protocol       The IPv6 protocol option
 * @param rohc_packet    The remaining part of the ROHC packet
 * @param rohc_length    The remaining length (in bytes) of the ROHC packet
 * @return               The length of dynamic IP header
 *                       0 if an error occurs
 */
static int tcp_parse_dynamic_ipv6_option(struct rohc_decomp_ctxt *const context,
                                         ipv6_option_context_t *const opt_context,
                                         const uint8_t protocol,
                                         const unsigned char *const rohc_packet,
                                         const size_t rohc_length)
{
	size_t remain_len = rohc_length;
	size_t size = 0;
#if 0
	int ret;
#endif

	assert(context != NULL);
	assert(rohc_packet != NULL);

	rohc_decomp_debug(context, "parse dynamic part of IPv6 extension header");

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
		{
			size += ((opt_context->generic.length + 1) << 3) - 2;
			if(remain_len < size)
			{
				rohc_decomp_warn(context, "malformed IPv6 option: malformed "
				                 "option %u: %zu bytes available while %zu bytes "
				                 "required", protocol, remain_len, size);
				goto error;
			}
			if(size > 6)
			{
				rohc_decomp_warn(context, "static part of the IPv6 %u too "
				                 "large for implementation: %zu bytes required "
				                 "while only %u bytes available", protocol,
				                 size, 6U);
				goto error;
			}
			memcpy(opt_context->generic.data, rohc_packet, size);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_len -= size;
#endif
			break;
		}
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
		{
			break;
		}
		case ROHC_IPPROTO_GRE:
		{
			if(opt_context->gre.c_flag != 0)
			{
				if(remain_len < sizeof(uint32_t))
				{
					rohc_decomp_warn(context, "malformed IPv6 option: malformed "
					                 "option GRE: %zu bytes available while 4 "
					                 "bytes required", remain_len);
					goto error;
				}
#if 0 /* to be moved after parsing */
				memcpy(base_header.ip_gre_opt->datas, rohc_packet + size,
				       sizeof(uint32_t));
#endif
				size += sizeof(uint32_t);
				remain_len -= sizeof(uint32_t);
			}
#if 0 /* to be moved after parsing */
			ret = d_optional32(opt_context->gre.s_flag,
			                   rohc_packet + size, remain_len,
			                   base_header.ip_gre_opt->datas[opt_context->gre.c_flag],
			                   &base_header.ip_gre_opt->datas[opt_context->gre.c_flag]);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "malformed IPv6 option: malformed "
				                 "option GRE");
				goto error;
			}
			size += ret;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_len -= ret;
#endif
#endif
			break;
		}
		case ROHC_IPPROTO_MINE:
		{
			break;
		}
		case ROHC_IPPROTO_AH:
		{
			const ip_ah_opt_dynamic_t *const ip_ah_opt_dynamic =
				(ip_ah_opt_dynamic_t *) rohc_packet;

			size += opt_context->ah.length << 2;
			if(remain_len < size)
			{
				rohc_decomp_warn(context, "malformed IPv6 option: malformed "
				                 "option AH: %zu bytes available while %zu bytes "
				                 "required", remain_len, size);
				goto error;
			}
			opt_context->ah.sequence_number =
			   ip_ah_opt_dynamic->sequence_number;
			memcpy(opt_context->ah.auth_data,
			       ip_ah_opt_dynamic->auth_data, size - sizeof(uint32_t));
			break;
		}
		default:
		{
			break;
		}
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IPv6 option dynamic part", rohc_packet, size);
#endif

	return size;

error:
	return -1;
}


/**
 * @brief Decode the TCP dynamic part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param rohc_packet  The remaining part of the ROHC packet
 * @param rohc_length  The remaining length (in bytes) of the ROHC packet
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_parse_dynamic_tcp(struct rohc_decomp_ctxt *const context,
                                 const unsigned char *const rohc_packet,
                                 const size_t rohc_length)
{
	struct d_tcp_context *const tcp_context = context->specific;
	const tcp_dynamic_t *tcp_dynamic;
	const uint8_t *remain_data;
	size_t remain_len;
	uint16_t msn_decoded;
	uint16_t window_decoded;

	assert(rohc_packet != NULL);

	remain_data = rohc_packet;
	remain_len = rohc_length;

	rohc_decomp_debug(context, "parse TCP dynamic part");

	/* check the minimal length to decode the TCP dynamic part */
	if(remain_len < sizeof(tcp_dynamic_t))
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least %zu bytes required for "
		                 "mandatory fields of the TCP dynamic part",
		                 remain_len, sizeof(tcp_dynamic_t));
		goto error;
	}
	tcp_dynamic = (tcp_dynamic_t *) remain_data;
	remain_data += sizeof(tcp_dynamic_t);
	remain_len -= sizeof(tcp_dynamic_t);

	rohc_decomp_debug(context, "TCP res_flags = %d, ecn_flags = %d, "
	                  "rsf_flags = %d, URG = %d, ACK = %d, PSH = %d",
	                  tcp_dynamic->tcp_res_flags, tcp_dynamic->tcp_ecn_flags,
	                  tcp_dynamic->rsf_flags, tcp_dynamic->urg_flag,
	                  tcp_dynamic->ack_flag, tcp_dynamic->psh_flag);

	/* retrieve the TCP flags and sequence number from the ROHC packet */
	tcp_context->ecn_used = tcp_dynamic->ecn_used;
	tcp_context->res_flags = tcp_dynamic->tcp_res_flags;
	tcp_context->ecn_flags = tcp_dynamic->tcp_ecn_flags;
	tcp_context->urg_flag = tcp_dynamic->urg_flag;
	tcp_context->ack_flag = tcp_dynamic->ack_flag;
	tcp_context->psh_flag = tcp_dynamic->psh_flag;
	tcp_context->rsf_flags = tcp_dynamic->rsf_flags;
	tcp_context->seq_num = tcp_dynamic->seq_num;

	/* retrieve the MSN from the ROHC packet */
	msn_decoded = rohc_ntoh16(tcp_dynamic->msn);
	rohc_decomp_debug(context, "MSN = 0x%04x", msn_decoded);
	tcp_context->msn_tmp = msn_decoded;

	/* optional ACK number */
	if(tcp_dynamic->ack_zero == 1)
	{
		tcp_context->ack_num = 0;
	}
	else
	{
		if(remain_len < sizeof(uint32_t))
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu "
			                 "bytes available while at least %zu bytes required "
			                 "for the ACK number", remain_len, sizeof(uint32_t));
			goto error;
		}
		memcpy(&tcp_context->ack_num, remain_data, sizeof(uint32_t));
		remain_data += sizeof(uint32_t);
		remain_len -= sizeof(uint32_t);

		if(tcp_context->ack_flag == 0)
		{
			rohc_decomp_debug(context, "ACK flag not set, but ACK number was "
			                  "transmitted anyway");
		}
	}
	rohc_decomp_debug(context, "seq_number = 0x%x, ack_number = 0x%x",
	                  rohc_ntoh32(tcp_context->seq_num),
	                  rohc_ntoh32(tcp_context->ack_num));

	/* window */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "window", remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&window_decoded, remain_data, sizeof(uint16_t));
	window_decoded = rohc_ntoh16(window_decoded);
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP window = 0x%04x", window_decoded);
	tcp_context->window_tmp = window_decoded;

	/* checksum */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "checksum", remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&tcp_context->checksum, remain_data, sizeof(uint16_t));
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP checksum = 0x%04x",
	                  rohc_ntoh16(tcp_context->checksum));

	/* URG pointer */
	if(tcp_dynamic->urp_zero == 1)
	{
		tcp_context->urg_ptr = 0;
	}
	else
	{
		if(remain_len < sizeof(uint16_t))
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu "
			                 "bytes available while at least %zu bytes required "
			                 "for the URG pointer", remain_len, sizeof(uint16_t));
			goto error;
		}
		memcpy(&tcp_context->urg_ptr, remain_data, sizeof(uint16_t));
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	rohc_decomp_debug(context, "TCP urg_ptr = 0x%04x",
	                  rohc_ntoh16(tcp_context->urg_ptr));

	/* ACK stride */
	if(tcp_dynamic->ack_stride_flag == 0)
	{
		tcp_context->ack_stride = 0;
	}
	else
	{
		if(remain_len < sizeof(uint16_t))
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu "
			                 "bytes available while at least %zu bytes required "
			                 "for the ACK stride", remain_len, sizeof(uint16_t));
			goto error;
		}
		memcpy(&tcp_context->ack_stride, remain_data, sizeof(uint16_t));
		tcp_context->ack_stride = rohc_ntoh16(tcp_context->ack_stride);
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	if(tcp_context->ack_stride != 0)
	{
		// Calculate the Ack Number residue
		tcp_context->ack_num_residue =
			rohc_ntoh32(tcp_context->ack_num) % tcp_context->ack_stride;
	}
	rohc_decomp_debug(context, "TCP ack_stride = 0x%04x, ack_number_residue = "
	                  "0x%04x", tcp_context->ack_stride,
	                  tcp_context->ack_num_residue);

	/* we need at least one byte to check whether TCP options are present or
	 * not */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least 1 byte required for the "
		                 "first byte of TCP options", remain_len);
		goto error;
	}

	/* If TCP option list compression present */
	if((remain_data[0] & 0x0f) != 0)
	{
		const uint8_t *tcp_opts_indexes;
		uint8_t reserved;
		uint8_t PS;
		uint8_t present;
		uint8_t opt_idx;
		uint8_t m;
		uint8_t i;
		uint8_t *tcp_options = tcp_context->options;
		size_t opt_padding_len;
		size_t opts_full_len;
		size_t indexes_len;

		/* read number of XI item(s) in the compressed list */
		reserved = remain_data[0] & 0xe0;
		m = remain_data[0] & 0x0F;
		PS = remain_data[0] & 0x10;
		if(reserved != 0)
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: malformed "
			                 "compressed list of TCP options: reserved bits "
			                 "must be zero, but first byte is 0x%02x",
			                 remain_data[0]);
			goto error;
		}
		remain_data++;
		remain_len--;
		if(m >= MAX_TCP_OPTION_INDEX)
		{
			rohc_decomp_warn(context, "TCP dynamic part: compressed list of TCP "
			                 "options: too many options");
			goto error;
		}

		/* compute the length of the indexes, and the position of items */
		if(PS != 0)
		{
			indexes_len = m;
		}
		else
		{
			indexes_len = ((m + 1) >> 1);
		}
		rohc_decomp_debug(context, "TCP options list: %u %u-bit indexes "
		                  "transmitted on %zu bytes", m, (PS != 0 ? 8 : 4),
		                  indexes_len);

		/* enough remaining data for all indexes? */
		if(remain_len < indexes_len)
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu "
			                 "bytes available while at least %zu bytes required "
			                 "for the list indexes", remain_len, indexes_len);
			goto error;
		}
		tcp_opts_indexes = remain_data;
		remain_data += indexes_len;
		remain_len -= indexes_len;

		/* for all item(s) in the list */
		for(i = 0, opts_full_len = 0; i < m; ++i)
		{
			uint8_t opt_type;
			uint8_t opt_len;

			/* if PS=1 indicating 8-bit XI field */
			if(PS != 0)
			{
				present = tcp_opts_indexes[0] & 0x80;
				opt_idx = tcp_opts_indexes[0] & 0x0F;
				tcp_opts_indexes++;
			}
			else
			{
				/* if odd position */
				if(i & 1)
				{
					present = tcp_opts_indexes[0] & 0x08;
					opt_idx = tcp_opts_indexes[0] & 0x07;
					tcp_opts_indexes++;
				}
				else
				{
					present = tcp_opts_indexes[0] & 0x80;
					opt_idx = (tcp_opts_indexes[0] & 0x70) >> 4;
				}
			}
			rohc_decomp_debug(context, "  TCP options list: XI #%u:", i);
			rohc_decomp_debug(context, "    item for index %u is %s", opt_idx,
			                  (present ? "present" : "absent"));
			// item must present in dynamic part
			if(present == 0)
			{
				rohc_decomp_debug(context, "list item #%u not present: not "
				                  "allowed in dynamic part, packet is malformed", i);
				goto error;
			}
			tcp_context->is_tcp_opts_list_item_present[i] = true;

			rohc_decomp_debug(context, "    index %u is a known index", opt_idx);

			/* determine option type */ /* TODO: dedicated function */
			switch(opt_idx)
			{
				case TCP_INDEX_NOP:
				{
					rohc_decomp_debug(context, "    TCP option NOP");
					opt_type = TCP_OPT_NOP;
					opt_len = 1;
					if((opts_full_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte NOP option",
						                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_len);
						goto error;
					}
					break;
				}
				case TCP_INDEX_EOL:
				{
					rohc_decomp_debug(context, "    TCP option EOL");
					opt_type = TCP_OPT_EOL;
					if(remain_len < 1)
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least %zu bytes "
						                 "required for next option", remain_len,
						                 sizeof(uint8_t));
						goto error;
					}
					if(remain_data[0] > (0xff - 1))
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: TCP EOL option "
						                 "is (%u+1)-byte long according to ROHC packet, "
						                 "but maximum length is %u bytes", remain_data[0],
						                 0xff);
						goto error;
					}
					opt_len = remain_data[0] + 1;
					if((opts_full_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte EOL option",
						                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_len);
						goto error;
					}
					memset(tcp_options + opts_full_len + 1, TCP_OPT_EOL, opt_len - 1);
					remain_data++;
					remain_len--;
					break;
				}
				case TCP_INDEX_MAXSEG:
				{
					opt_type = TCP_OPT_MAXSEG;
					opt_len = TCP_OLEN_MAXSEG;
					if(remain_len < sizeof(uint16_t))
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least %zu bytes "
						                 "required for next option", remain_len,
						                 sizeof(uint16_t));
						goto error;
					}
					memcpy(&tcp_context->tcp_option_maxseg, remain_data,
					       sizeof(uint16_t));
					if((opts_full_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte MSS option",
						                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_len);
						goto error;
					}
					memcpy(tcp_options + opts_full_len + 2, remain_data,
					       sizeof(uint16_t));
					remain_data += sizeof(uint16_t);
					remain_len -= sizeof(uint16_t);
					rohc_decomp_debug(context, "    TCP option MAXSEG = %u (0x%x)",
					                  rohc_ntoh16(tcp_context->tcp_option_maxseg),
					                  rohc_ntoh16(tcp_context->tcp_option_maxseg));
					break;
				}
				case TCP_INDEX_WINDOW:
				{
					opt_type = TCP_OPT_WINDOW;
					opt_len = TCP_OLEN_WINDOW;
					if(remain_len < sizeof(uint8_t))
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least %zu bytes "
						                 "required for next option", remain_len,
						                 sizeof(uint8_t));
						goto error;
					}
					tcp_context->tcp_option_window = remain_data[0];
					if((opts_full_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte Window option",
						                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_len);
						goto error;
					}
					tcp_options[opts_full_len + 2] = remain_data[0];
					remain_data++;
					remain_len--;
					rohc_decomp_debug(context, "    TCP option WINDOW = %d",
					                  tcp_context->tcp_option_window);
					break;
				}
				case TCP_INDEX_TIMESTAMP:
				{
					const struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) remain_data;

					rohc_decomp_debug(context, "    TCP option TIMESTAMP");
					opt_type = TCP_OPT_TIMESTAMP;
					opt_len = TCP_OLEN_TIMESTAMP;

					if(remain_len < (sizeof(uint32_t) * 2))
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least %zu bytes "
						                 "required for next option", remain_len,
						                 sizeof(uint32_t) * 2);
						goto error;
					}
					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;
					/* TODO: set ref later */
					rohc_lsb_set_ref(tcp_context->opt_ts_req_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts), false);
					/* TODO: set ref later */
					rohc_lsb_set_ref(tcp_context->opt_ts_reply_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts_reply), false);
					if((opts_full_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte Timestamp option",
						                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_len);
						goto error;
					}
					memcpy(tcp_options + opts_full_len + 2, remain_data, sizeof(uint32_t) * 2);
					remain_data += sizeof(uint32_t) * 2;
					remain_len -= sizeof(uint32_t) * 2;
					break;
				}
				case TCP_INDEX_SACK_PERMITTED:
				{
					rohc_decomp_debug(context, "    TCP option SACK permitted");
					opt_type = TCP_OPT_SACK_PERMITTED;
					opt_len = TCP_OLEN_SACK_PERMITTED;
					if((opts_full_len + opt_len) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "malformed TCP options: more than "
						                 "%lu bytes of TCP options: %zu bytes already "
						                 "in + %u-byte SACK permitted option",
						                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_len);
						goto error;
					}
					break;
				}
				case TCP_INDEX_SACK:
				{
					uint8_t *const uncomp_sack_opt = tcp_options + opts_full_len;
					const size_t opt_remain_len = MAX_TCP_OPTIONS_LEN - opts_full_len;
					size_t sack_opt_len;
					int ret;

					ret = d_tcp_sack_decode(context, remain_data, remain_len,
					                        uncomp_sack_opt, &sack_opt_len,
					                        opt_remain_len,
					                        rohc_ntoh32(tcp_context->ack_num));
					if(ret < 0)
					{
						rohc_decomp_warn(context, "failed to decompress TCP SACK "
						                 "option");
						goto error;
					}
					remain_data += ret;
					remain_len -= ret;

					opt_type = TCP_OPT_SACK;
					if(sack_opt_len > 0xff)
					{
						rohc_decomp_warn(context, "malformed ROHC packet: TCP option "
						                 "is larger than maximum length of %u bytes", 0xff);
						goto error;
					}
					opt_len = sack_opt_len;

					tcp_context->tcp_option_sack_length = opt_len - 2;
					rohc_decomp_debug(context, "    TCP option SACK Length = 2 + %u",
					                  tcp_context->tcp_option_sack_length);
					if(tcp_context->tcp_option_sack_length > (8 * 4))
					{
						rohc_decomp_warn(context, "TCP dynamic part: unexpected "
						                 "large %u-byte SACK option",
						                 tcp_context->tcp_option_sack_length);
						goto error;
					}
					memcpy(tcp_context->tcp_option_sackblocks, uncomp_sack_opt + 2,
					       tcp_context->tcp_option_sack_length);
					break;
				}
				default: /* generic options */
				{
					uint8_t *save_opt;

					/* option type */
					if(remain_len < 1)
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least 1 byte "
						                 "required for next option", remain_len);
						goto error;
					}
					opt_type = remain_data[0];
					remain_data++;
					remain_len--;

					/* option length */
					if(remain_len < 1)
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: only %zu "
						                 "bytes available while at least 1 byte "
						                 "required for next option", remain_len);
						goto error;
					}
					opt_len = remain_data[0] & 0x7f;
					remain_data++;
					remain_len--;
					if(opt_len < 2)
					{
						rohc_decomp_warn(context, "malformed TCP dynamic part: "
						                 "malformed TCP option items: option "
						                 "length should be at least 2 bytes, but "
						                 "is only %u byte(s)", opt_len);
						goto error;
					}

					/* was index already used? */
					if(tcp_context->tcp_options_list[opt_idx] == 0xff)
					{
						/* index was never used before */
						tcp_context->tcp_options_offset[opt_idx] =
							tcp_context->tcp_options_free_offset;
						save_opt = tcp_context->tcp_options_values +
						           tcp_context->tcp_options_free_offset;
						/* save length (without option_static) */
						save_opt[0] = opt_len - 2;
						rohc_decomp_debug(context, "    %d-byte TCP option of type %d",
						                  save_opt[0], opt_type);
						/* enough data for last bytes of option? */
						if(remain_len < save_opt[0])
						{
							rohc_decomp_warn(context, "malformed TCP dynamic part: "
							                 "malformed TCP option items: only %zu "
							                 "bytes available while at least %u "
							                 "bytes required for next option",
							                 remain_len, save_opt[0]);
							goto error;
						}
						/* save value */
						if((tcp_context->tcp_options_free_offset + 1 + save_opt[0]) >
						   MAX_TCP_OPT_SIZE)
						{
							rohc_decomp_warn(context, "TCP options too large: "
							                 "%u bytes while only %u are accepted",
							                 tcp_context->tcp_options_free_offset + 1 +
							                 save_opt[0], MAX_TCP_OPT_SIZE);
							goto error;
						}
						memcpy(save_opt + 1, remain_data, save_opt[0]);
						if((opts_full_len + opt_len) > MAX_TCP_OPTIONS_LEN)
						{
							rohc_decomp_warn(context, "malformed TCP options: more than "
							                 "%lu bytes of TCP options: %zu bytes "
							                 "already in + %u-byte TCP option",
							                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_len);
							goto error;
						}
						memcpy(tcp_options + opts_full_len + 2, remain_data, save_opt[0]);
						remain_data += save_opt[0];
						remain_len -= save_opt[0];
						/* update first free offset */
						tcp_context->tcp_options_free_offset += 1 + save_opt[0];
					}
					else /* index already used */
					{
						/* verify the value with the recorded one */
						rohc_decomp_debug(context, "tcp_options_list[%u] = %d <=> %d",
						                  opt_idx, tcp_context->tcp_options_list[opt_idx],
						                  opt_type);
						if(tcp_context->tcp_options_list[opt_idx] != opt_type)
						{
							rohc_decomp_warn(context, "unexpected TCP option at "
							                 "index %u: 0x%02x received while "
							                 "0x%02x expected", opt_idx, opt_type,
							                 tcp_context->tcp_options_list[opt_idx]);
							goto error;
						}
						save_opt = tcp_context->tcp_options_values +
						           tcp_context->tcp_options_offset[opt_idx];
						if((opt_len - 2) != save_opt[0])
						{
							rohc_decomp_warn(context, "malformed TCP dynamic part: "
							                 "unexpected TCP option with index %u: "
							                 "option length in packet (%u) does not "
							                 "match option length in context (%u)",
							                 opt_idx, opt_len, save_opt[0] + 2);
							goto error;
						}
						if(memcmp(save_opt + 1, remain_data, save_opt[0]) != 0)
						{
							rohc_decomp_warn(context, "malformed TCP dynamic part: "
							                 "unexpected TCP option with index %u: "
							                 "option data in packet does not match "
							                 "option option data in context",
							                 opt_idx);
							goto error;
						}
						if((opts_full_len + opt_len) > MAX_TCP_OPTIONS_LEN)
						{
							rohc_decomp_warn(context, "malformed TCP options: more than "
							                 "%lu bytes of TCP options: %zu bytes "
							                 "already in + %u-byte TCP option",
							                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_len);
							goto error;
						}
						memcpy(tcp_options + opts_full_len + 2, remain_data, save_opt[0]);
						remain_data += save_opt[0];
						remain_len -= save_opt[0];
					}
					break;
				}
			}
			rohc_decomp_debug(context, "    TCP option type 0x%02x (%u)",
			                  opt_type, opt_type);
			tcp_options[opts_full_len] = opt_type;
			if(opt_type == TCP_OPT_EOL)
			{
				rohc_decomp_debug(context, "    TCP option is %u-byte long (type "
				                  "and padding fields included)", opt_len);
			}
			else if(opt_type == TCP_OPT_NOP)
			{
				if(opt_len != 1)
				{
					rohc_decomp_warn(context, "unexpected length for TCP option "
					                 "type %u: %u bytes advertized by ROHC packet, "
					                 "but only 1 byte expected", opt_type, opt_len);
					goto error;
				}
				rohc_decomp_debug(context, "    TCP option is 1-byte long");
			}
			else
			{
				if(opt_len < 2)
				{
					rohc_decomp_warn(context, "unexpected length for TCP option "
					                 "type %u: %u bytes advertized by ROHC packet, "
					                 "but at least 2 bytes expected", opt_type,
					                 opt_len);
					goto error;
				}
				rohc_decomp_debug(context, "    TCP option is %u-byte long (type "
				                  "and length fields included)", opt_len);
				tcp_options[opts_full_len + 1] = opt_len;
			}
			opts_full_len += opt_len;

			/* save TCP option for this index */
			tcp_context->tcp_opts_list_struct[i] = opt_type;
			tcp_context->tcp_options_list[opt_idx] = opt_type;
			tcp_context->tcp_opts_list_item_uncomp_length[i] = opt_len;
		}
		memset(tcp_context->tcp_opts_list_struct + m, 0xff,
		       ROHC_TCP_OPTS_MAX - m);

		rohc_decomp_debug(context, "  %zu bytes of TCP options appended to the "
		                  "TCP base header", opts_full_len);

		/* add padding after TCP options (they must be aligned on 32-bit words) */
		opt_padding_len = sizeof(uint32_t) - (opts_full_len % sizeof(uint32_t));
		opt_padding_len %= sizeof(uint32_t);
		if((opts_full_len + opt_padding_len) > MAX_TCP_OPTIONS_LEN)
		{
			rohc_decomp_warn(context, "malformed TCP options: more than %lu bytes "
			                 "of TCP options: %zu bytes already in + %zu-byte padding",
			                 MAX_TCP_OPTIONS_LEN, opts_full_len, opt_padding_len);
			goto error;
		}
		for(i = 0; i < opt_padding_len; i++)
		{
			rohc_decomp_debug(context, "  add missing TCP EOL option for padding");
			tcp_options[opts_full_len + i] = TCP_OPT_EOL;
		}
		opts_full_len += opt_padding_len;
		assert((opts_full_len % sizeof(uint32_t)) == 0);

		/* print TCP options */
		rohc_dump_buf(context->decompressor->trace_callback,
		              context->decompressor->trace_callback_priv,
		              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
		              "decompressed TCP options", tcp_options, opts_full_len);

		/* update context */
		tcp_context->options_len = opts_full_len;
	}
	else
	{
		tcp_context->options_len = 0;
		rohc_decomp_debug(context, "TCP no options!");
		remain_data++;
		remain_len--;
		memset(tcp_context->tcp_opts_list_struct, 0xff, ROHC_TCP_OPTS_MAX);
	}
	assert(tcp_context->options_len <= MAX_TCP_OPTIONS_LEN);

	assert(remain_len <= rohc_length);
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG, "TCP dynamic part",
	              (unsigned char *) tcp_dynamic, rohc_length - remain_len);

	return (rohc_length - remain_len);

error:
	return -1;
}

