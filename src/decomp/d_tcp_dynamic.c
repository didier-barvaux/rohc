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
#include "d_tcp_opts_list.h"
#include "rohc_utils.h"
#include "protocols/ip_numbers.h"
#include "schemes/rfc4996.h"

#include <string.h>

static int tcp_parse_dynamic_ip(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const rohc_packet,
                                const size_t rohc_length,
                                struct rohc_tcp_extr_ip_bits *const ip_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int tcp_parse_dynamic_ipv6_option(const struct rohc_decomp_ctxt *const context,
                                         ip_option_context_t *const opt_context,
                                         const uint8_t *const rohc_packet,
                                         const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int tcp_parse_dynamic_tcp(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const rohc_packet,
                                 const size_t rohc_length,
                                 struct rohc_tcp_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));


/**
 * @brief Parse the dynamic chain of the IR/IR-DYN packet
 *
 * @param context          The decompression context
 * @param rohc_packet      The remaining part of the ROHC packet
 * @param rohc_length      The remaining length (in bytes) of the ROHC packet
 * @param[out] parsed_len  The length (in bytes) of static chain in case of success
 * @param[out] bits        The bits extracted from the dynamic chain
 * @return                 true in the dynamic chain was successfully parsed,
 *                         false if the ROHC packet was malformed
 */
bool tcp_parse_dyn_chain(const struct rohc_decomp_ctxt *const context,
                         const uint8_t *const rohc_packet,
                         const size_t rohc_length,
                         struct rohc_tcp_extr_bits *const bits,
                         size_t *const parsed_len)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t ip_hdrs_nr;
	int ret;

	(*parsed_len) = 0;

	/* parse dynamic IP part (IPv4/IPv6 headers and extension headers) */
	for(ip_hdrs_nr = 0; ip_hdrs_nr < bits->ip_nr; ip_hdrs_nr++)
	{
		struct rohc_tcp_extr_ip_bits *const ip_bits = &(bits->ip[ip_hdrs_nr]);

		ret = tcp_parse_dynamic_ip(context, remain_data, remain_len, ip_bits);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
			                 "dynamic part");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%u dynamic part is %d-byte length",
		                  ip_bits->version, ret);
		assert(remain_len >= ((size_t) ret));
		remain_data += ret;
		remain_len -= ret;
		(*parsed_len) += ret;
	}

	/* TTL/HL values of outer IP headers are included in the dynamic chain */
	bits->ttl_dyn_chain_flag = true;

	/* parse TCP dynamic part */
	ret = tcp_parse_dynamic_tcp(context, remain_data, remain_len, bits);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP "
		                 "dynamic part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP dynamic part is %d-byte length", ret);
	assert(remain_len >= ((size_t) ret));
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += ret;
	remain_len -= ret;
#endif
	(*parsed_len) += ret;

	return true;

error:
	return false;
}


/**
 * @brief Decode the dynamic IP header of the rohc packet.
 *
 * @param context        The decompression context
 * @param rohc_packet    The remaining part of the ROHC packet
 * @param rohc_length    The remaining length (in bytes) of the ROHC packet
 * @param[out] ip_bits   The bits extracted from the IP part of the dynamic chain
 * @return               The length of dynamic IP header in case of success,
 *                       -1 if an error occurs
 */
static int tcp_parse_dynamic_ip(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const rohc_packet,
                                const size_t rohc_length,
                                struct rohc_tcp_extr_ip_bits *const ip_bits)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t size = 0;
	int ret;

	rohc_decomp_debug(context, "parse IP dynamic part");

	if(ip_bits->version == IPV4)
	{
		const ipv4_dynamic1_t *const ipv4_dynamic1 =
			(ipv4_dynamic1_t *) remain_data;

		if(remain_len < sizeof(ipv4_dynamic1_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv4 dynamic part");
			goto error;
		}

		ip_bits->df = ipv4_dynamic1->df;
		ip_bits->df_nr = 1;
		ip_bits->id_behavior = ipv4_dynamic1->ip_id_behavior;
		ip_bits->id_behavior_nr = 2;
		rohc_decomp_debug(context, "ip_id_behavior = %d", ip_bits->id_behavior);
		ip_bits->dscp_bits = ipv4_dynamic1->dscp;
		ip_bits->dscp_bits_nr = 6;
		ip_bits->ecn_flags_bits = ipv4_dynamic1->ip_ecn_flags;
		ip_bits->ecn_flags_bits_nr = 2;
		ip_bits->ttl_hl.bits = ipv4_dynamic1->ttl_hopl;
		ip_bits->ttl_hl.bits_nr = 8;
		rohc_decomp_debug(context, "DSCP = 0x%x, ip_ecn_flags = %d, "
		                  "ttl_hopl = 0x%x", ip_bits->dscp_bits,
		                  ip_bits->ecn_flags_bits, ip_bits->ttl_hl.bits);
		// cf RFC4996 page 60/61 ip_id_enc_dyn()
		if(ipv4_dynamic1->ip_id_behavior != IP_ID_BEHAVIOR_ZERO)
		{
			const ipv4_dynamic2_t *const ipv4_dynamic2 =
				(ipv4_dynamic2_t *) remain_data;

			if(remain_len < sizeof(ipv4_dynamic2_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "IPv4 dynamic part");
				goto error;
			}

			ip_bits->id.bits = rohc_ntoh16(ipv4_dynamic2->ip_id);
			ip_bits->id.bits_nr = 16;
			rohc_decomp_debug(context, "IP-ID = 0x%04x", ip_bits->id.bits);

			size += sizeof(ipv4_dynamic2_t);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_data += sizeof(ipv4_dynamic2_t);
			remain_len -= sizeof(ipv4_dynamic2_t);
#endif
		}
		else
		{
			size += sizeof(ipv4_dynamic1_t);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_data += sizeof(ipv4_dynamic1_t);
			remain_len -= sizeof(ipv4_dynamic1_t);
#endif
		}
	}
	else
	{
		const ipv6_dynamic_t *const ipv6_dynamic =
			(ipv6_dynamic_t *) remain_data;
		size_t opts_nr;

		if(remain_len < sizeof(ipv6_dynamic_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv6 dynamic part");
			goto error;
		}

		ip_bits->dscp_bits = ipv6_dynamic->dscp;
		ip_bits->dscp_bits_nr = 6;
		ip_bits->ecn_flags_bits = ipv6_dynamic->ip_ecn_flags;
		ip_bits->ecn_flags_bits_nr = 2;
		ip_bits->ttl_hl.bits = ipv6_dynamic->ttl_hopl;
		ip_bits->ttl_hl.bits_nr = 8;
		ip_bits->id_behavior = IP_ID_BEHAVIOR_RAND;
		ip_bits->id_behavior_nr = 2;

		size += sizeof(ipv6_dynamic_t);
		remain_data += sizeof(ipv6_dynamic_t);
		remain_len -= sizeof(ipv6_dynamic_t);

		rohc_decomp_debug(context, "parse the dynamic parts of the %zu IPv6 "
		                  "extension headers", ip_bits->opts_nr);

		assert(ip_bits->proto_nr == 8);
		for(opts_nr = 0; opts_nr < ip_bits->opts_nr; opts_nr++)
		{
			ip_option_context_t *const opt = &(ip_bits->opts[opts_nr]);

			ret = tcp_parse_dynamic_ipv6_option(context, opt, remain_data, remain_len);
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

		}
	}

	rohc_decomp_dump_buf(context, "IP dynamic part", rohc_packet, size);

	return size;

error:
	return -1;
}


/**
 * @brief Decode the dynamic IPv6 option header of the rohc packet.
 *
 * @param context        The decompression context
 * @param opt_context    The specific IPv6 option decompression context
 * @param rohc_packet    The remaining part of the ROHC packet
 * @param rohc_length    The remaining length (in bytes) of the ROHC packet
 * @return               The length of dynamic IP header
 *                       -1 if an error occurs
 */
static int tcp_parse_dynamic_ipv6_option(const struct rohc_decomp_ctxt *const context,
                                         ip_option_context_t *const opt_context,
                                         const uint8_t *const rohc_packet,
                                         const size_t rohc_length)
{
	size_t remain_len = rohc_length;
	size_t size;

	rohc_decomp_debug(context, "parse dynamic part of the %zu-byte IPv6 extension "
	                  "header '%s' (%u)", opt_context->len,
	                  rohc_get_ip_proto_descr(opt_context->proto), opt_context->proto);

	switch(opt_context->proto)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
		{
			size = opt_context->len - 2;
			if(remain_len < size)
			{
				rohc_decomp_warn(context, "malformed IPv6 option: malformed "
				                 "option %u: %zu bytes available while %zu bytes "
				                 "required", opt_context->proto, remain_len, size);
				goto error;
			}
			opt_context->generic.data_len = size;
			memcpy(&opt_context->generic.data, rohc_packet, size);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_len -= size;
#endif
			break;
		}
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
		{
			size = 0;
			break;
		}
		case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
		{
			rohc_decomp_warn(context, "GRE extension header not supported yet");
			goto error;
		}
		case ROHC_IPPROTO_MINE:  /* TODO: MINE not yet supported */
		{
			rohc_decomp_warn(context, "MINE extension header not supported yet");
			goto error;
		}
		case ROHC_IPPROTO_AH:  /* TODO: AH not yet supported */
		{
			rohc_decomp_warn(context, "AH extension header not supported yet");
			goto error;
		}
		default:
		{
			rohc_decomp_warn(context, "unknown extension header not supported yet");
			goto error;
		}
	}

	rohc_decomp_dump_buf(context, "IPv6 option dynamic part", rohc_packet, size);

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
 * @param[out] bits    The bits extracted from the TCP part of the dynamic chain
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_parse_dynamic_tcp(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const rohc_packet,
                                 const size_t rohc_length,
                                 struct rohc_tcp_extr_bits *const bits)
{
	const tcp_dynamic_t *tcp_dynamic;
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	int ret;

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
	                  "rsf_flags = %d, URG = %d, ACK = %d, PSH = %d, ack_zero = %u",
	                  tcp_dynamic->tcp_res_flags, tcp_dynamic->tcp_ecn_flags,
	                  tcp_dynamic->rsf_flags, tcp_dynamic->urg_flag,
	                  tcp_dynamic->ack_flag, tcp_dynamic->psh_flag,
	                  tcp_dynamic->ack_zero);

	/* retrieve the TCP flags from the ROHC packet */
	bits->ecn_used_bits = tcp_dynamic->ecn_used;
	bits->ecn_used_bits_nr = 1;
	bits->res_flags_bits = tcp_dynamic->tcp_res_flags;
	bits->res_flags_bits_nr = 4;
	bits->ecn_flags_bits = tcp_dynamic->tcp_ecn_flags;
	bits->ecn_flags_bits_nr = 2;
	bits->urg_flag_bits = tcp_dynamic->urg_flag;
	bits->urg_flag_bits_nr = 1;
	bits->ack_flag_bits = tcp_dynamic->ack_flag;
	bits->ack_flag_bits_nr = 1;
	bits->psh_flag_bits = tcp_dynamic->psh_flag;
	bits->psh_flag_bits_nr = 1;
	bits->rsf_flags_bits = tcp_dynamic->rsf_flags;
	bits->rsf_flags_bits_nr = 3;

	/* retrieve the TCP sequence number from the ROHC packet */
	bits->seq.bits = rohc_ntoh32(tcp_dynamic->seq_num);
	bits->seq.bits_nr = 32;
	rohc_decomp_debug(context, "%zu bits of TCP sequence number 0x%08x",
	                  bits->seq.bits_nr, bits->seq.bits);

	/* retrieve the MSN from the ROHC packet */
	bits->msn.bits = rohc_ntoh16(tcp_dynamic->msn);
	bits->msn.bits_nr = 16;
	rohc_decomp_debug(context, "%zu bits of MSN 0x%04x",
	                  bits->msn.bits_nr, bits->msn.bits);

	/* optional ACK number */
	if(tcp_dynamic->ack_zero == 1)
	{
		bits->ack.bits = 0;
		bits->ack.bits_nr = 32; /* TODO */
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
		memcpy(&(bits->ack.bits), remain_data, sizeof(uint32_t));
		bits->ack.bits = rohc_ntoh32(bits->ack.bits);
		bits->ack.bits_nr = 32;
		remain_data += sizeof(uint32_t);
		remain_len -= sizeof(uint32_t);

		if(bits->ack_flag_bits == 0)
		{
			rohc_decomp_debug(context, "ACK flag not set, but ACK number was "
			                  "transmitted anyway");
		}
	}
	rohc_decomp_debug(context, "seq_number = 0x%08x, ack_number = 0x%08x",
	                  bits->seq.bits, bits->ack.bits);

	/* window */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "window", remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&(bits->window.bits), remain_data, sizeof(uint16_t));
	bits->window.bits = rohc_ntoh16(bits->window.bits);
	bits->window.bits_nr = 16;
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP window = 0x%04x", bits->window.bits);

	/* checksum */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "checksum", remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&(bits->tcp_check), remain_data, sizeof(uint16_t));
	bits->tcp_check = rohc_ntoh16(bits->tcp_check);
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP checksum = 0x%04x", bits->tcp_check);

	/* URG pointer */
	if(tcp_dynamic->urp_zero == 1)
	{
		bits->urg_ptr.bits = 0;
		bits->urg_ptr.bits_nr = 16;
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
		memcpy(&(bits->urg_ptr.bits), remain_data, sizeof(uint16_t));
		bits->urg_ptr.bits = rohc_ntoh16(bits->urg_ptr.bits);
		bits->urg_ptr.bits_nr = 16;
		remain_data += sizeof(uint16_t);
		remain_len -= sizeof(uint16_t);
	}
	rohc_decomp_debug(context, "TCP urg_ptr = 0x%04x", bits->urg_ptr.bits);

	/* ACK stride */
	ret = d_static_or_irreg16(remain_data, remain_len, tcp_dynamic->ack_stride_flag,
	                          &bits->ack_stride);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: "
		                 "static_or_irreg(ack_stride) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %zu bits of ACK stride encoded on "
	                  "%d bytes", bits->ack_stride.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	/* parse the compressed list of TCP options */
	ret = d_tcp_parse_tcp_opts_list_item(context, remain_data, remain_len, true,
	                                     &bits->tcp_opts);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to parse optional compressed list "
		                 "of TCP options");
		goto error;
	}
	rohc_decomp_debug(context, "compressed list of TCP options = %d bytes", ret);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += ret;
#endif
	remain_len -= ret;

	assert(remain_len <= rohc_length);
	rohc_decomp_dump_buf(context, "TCP dynamic part",
	                     (const uint8_t *const ) tcp_dynamic,
	                     rohc_length - remain_len);

	return (rohc_length - remain_len);

error:
	return -1;
}

