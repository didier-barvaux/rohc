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
 * @file   d_tcp_static.c
 * @brief  Handle the static chain of the TCP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "d_tcp_static.h"

#include "config.h" /* for ROHC_EXTRA_DEBUG */

#include "d_tcp_defines.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "protocols/ip_numbers.h"

#ifndef __KERNEL__
#  include <string.h>
#endif


static int tcp_parse_static_ip(const struct rohc_decomp_ctxt *const context,
                               const unsigned char *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_tcp_extr_ip_bits *const ip_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int tcp_parse_static_ipv6_option(const struct rohc_decomp_ctxt *const context,
                                        struct rohc_tcp_extr_ip_bits *const ip_bits,
                                        ipv6_option_context_t *const opt_context,
                                        const uint8_t protocol,
                                        const unsigned char *const rohc_packet,
                                        const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int tcp_parse_static_tcp(const struct rohc_decomp_ctxt *const context,
                                const unsigned char *const rohc_packet,
                                const size_t rohc_length,
                                struct rohc_tcp_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));


/**
 * @brief Parse the static chain of the IR packet
 *
 * @param context          The decompression context
 * @param rohc_packet      The remaining part of the ROHC packet
 * @param rohc_length      The remaining length (in bytes) of the ROHC packet
 * @param[out] bits        The bits extracted from the static chain
 * @param[out] parsed_len  The length (in bytes) of static chain in case of success
 * @return                 true in the static chain was successfully parsed,
 *                         false if the ROHC packet was malformed
 */
bool tcp_parse_static_chain(const struct rohc_decomp_ctxt *const context,
                            const uint8_t *const rohc_packet,
                            const size_t rohc_length,
                            struct rohc_tcp_extr_bits *const bits,
                            size_t *const parsed_len)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t ip_hdrs_nr;
	uint8_t protocol;
	int ret;

	(*parsed_len) = 0;

	/* parse static IP part (IPv4/IPv6 headers and extension headers) */
	ip_hdrs_nr = 0;
	do
	{
		struct rohc_tcp_extr_ip_bits *const ip_bits = &(bits->ip[ip_hdrs_nr]);

		ret = tcp_parse_static_ip(context, remain_data, remain_len, ip_bits);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
			                 "static part");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%u static part is %d-byte length",
		                  ip_bits->version, ret);
		assert(remain_len >= ((size_t) ret));
		remain_data += ret;
		remain_len -= ret;
		(*parsed_len) += ret;

		assert(ip_bits->proto_nr == 8);
		protocol = ip_bits->proto;
		ip_hdrs_nr++;
	}
	while(rohc_is_tunneling(protocol) && ip_hdrs_nr < ROHC_TCP_MAX_IP_HDRS);

	if(rohc_is_tunneling(protocol) && ip_hdrs_nr >= ROHC_TCP_MAX_IP_HDRS)
	{
		rohc_decomp_warn(context, "too many IP headers to decompress");
		goto error;
	}
	bits->ip_nr = ip_hdrs_nr;

	/* parse TCP static part */
	ret = tcp_parse_static_tcp(context, remain_data, remain_len, bits);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP static "
		                 "part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP static part is %d-byte length", ret);
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
 * @brief Decode the static IP header of the rohc packet.
 *
 * @param context       The decompression context
 * @param rohc_packet   The remaining part of the ROHC packet
 * @param rohc_length   The remaining length (in bytes) of the ROHC packet
 * @param[out] ip_bits  The bits extracted from the IP part of the static chain
 * @return              The length of static IP header in case of success,
 *                      -1 if an error occurs
 */
static int tcp_parse_static_ip(const struct rohc_decomp_ctxt *const context,
                               const unsigned char *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_tcp_extr_ip_bits *const ip_bits)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t read = 0;
	int ret;

	rohc_decomp_debug(context, "parse IP static part");

	/* at least 1 byte required to read the version flag */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
		                 "version flag of the IP static part");
		goto error;
	}

	/* parse IPv4 static part or IPv6 static part? */
	if(GET_BIT_7(remain_data) == 0)
	{
		const ipv4_static_t *const ipv4_static = (ipv4_static_t *) remain_data;

		rohc_decomp_debug(context, "  IPv4 static part");
		ip_bits->version = IPV4;

		if(remain_len < sizeof(ipv4_static_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
			                 "IPv4 static part");
			goto error;
		}

		ip_bits->proto = ipv4_static->protocol;
		ip_bits->proto_nr = 8;
		memcpy(ip_bits->saddr, &ipv4_static->src_addr, sizeof(uint32_t));
		ip_bits->saddr_nr = 32;
		memcpy(ip_bits->daddr, &ipv4_static->dst_addr, sizeof(uint32_t));
		ip_bits->daddr_nr = 32;

		read += sizeof(ipv4_static_t);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		remain_data += sizeof(ipv4_static_t);
		remain_len -= sizeof(ipv4_static_t);
#endif
	}
	else
	{
		uint8_t protocol;

		rohc_decomp_debug(context, "  IPv6 static part");
		ip_bits->version = IPV6;

		/* static 1 or static 2 variant? */
		if(GET_BIT_4(remain_data) == 0)
		{
			const ipv6_static1_t *const ipv6_static1 =
				(ipv6_static1_t *) remain_data;

			if(remain_len < sizeof(ipv6_static1_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the IPv6 static part");
				goto error;
			}

			ip_bits->flowid = 0;
			ip_bits->flowid_nr = 20;
			ip_bits->proto = ipv6_static1->next_header;
			ip_bits->proto_nr = 8;
			memcpy(ip_bits->saddr, &ipv6_static1->src_addr, sizeof(uint32_t) * 4);
			ip_bits->saddr_nr = 128;
			memcpy(ip_bits->daddr, &ipv6_static1->dst_addr, sizeof(uint32_t) * 4);
			ip_bits->daddr_nr = 128;

			read += sizeof(ipv6_static1_t);
			remain_data += sizeof(ipv6_static1_t);
			remain_len -= sizeof(ipv6_static1_t);
		}
		else
		{
			const ipv6_static2_t *const ipv6_static2 =
				(ipv6_static2_t *) remain_data;

			if(remain_len < sizeof(ipv6_static2_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the IPv6 static part");
				goto error;
			}

			ip_bits->flowid = (ipv6_static2->flow_label1 << 16) | ipv6_static2->flow_label2;
			rohc_decomp_debug(context, "  IPv6 flow label = 0x%05x", ip_bits->flowid);
			ip_bits->flowid_nr = 20;
			ip_bits->proto = ipv6_static2->next_header;
			ip_bits->proto_nr = 8;
			memcpy(ip_bits->saddr, &ipv6_static2->src_addr, sizeof(uint32_t) * 4);
			ip_bits->saddr_nr = 128;
			memcpy(ip_bits->daddr, &ipv6_static2->dst_addr, sizeof(uint32_t) * 4);
			ip_bits->daddr_nr = 128;

			read += sizeof(ipv6_static2_t);
			remain_data += sizeof(ipv6_static2_t);
			remain_len -= sizeof(ipv6_static2_t);
		}

		protocol = ip_bits->proto;
		ip_bits->opts_nr = 0;
		ip_bits->opts_len = 0;
		while(rohc_is_ipv6_opt(protocol))
		{
			ipv6_option_context_t *opt;

			if(ip_bits->opts_nr >= ROHC_TCP_MAX_IPV6_EXT_HDRS)
			{
				rohc_decomp_warn(context, "too many IPv6 extension headers");
				goto error;
			}
			opt = &(ip_bits->opts[ip_bits->opts_nr]);

			ret = tcp_parse_static_ipv6_option(context, ip_bits, opt, protocol,
			                                   remain_data, remain_len);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: malformed "
				                 "IPv6 static option part");
				goto error;
			}
			rohc_decomp_debug(context, "IPv6 static option part is %d-byte length",
			                  ret);
			assert(remain_len >= ((size_t) ret));
			read += ret;
			remain_data += ret;
			remain_len -= ret;

			protocol = opt->generic.next_header;
			ip_bits->opts_nr++;
		}
		rohc_decomp_debug(context, "IPv6 header is followed by %zu extension "
		                  "headers", ip_bits->opts_nr);
	}
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IP static part", rohc_packet, read);

	return read;

error:
	return -1;
}


/**
 * @brief Decode the static IPv6 option header of the rohc packet.
 *
 * @param context           The decompression context
 * @param[out] ip_bits      The bits extracted from the IP part of the static chain
 * @param[out] opt_context  The specific IPv6 option decompression context
 * @param protocol          The IPv6 protocol option
 * @param rohc_packet       The remaining part of the ROHC packet
 * @param rohc_length       The remaining length (in bytes) of the ROHC packet
 * @return                  The length of static IP header in case of success,
 *                          -1 if an error occurs
 */
static int tcp_parse_static_ipv6_option(const struct rohc_decomp_ctxt *const context,
                                        struct rohc_tcp_extr_ip_bits *const ip_bits,
                                        ipv6_option_context_t *const opt_context,
                                        const uint8_t protocol,
                                        const unsigned char *const rohc_packet,
                                        const size_t rohc_length)
{
	const ip_opt_static_t *ip_opt_static;
	size_t size;
#if 0
	int ret;
#endif

	assert(context != NULL);
	assert(rohc_packet != NULL);

	rohc_decomp_debug(context, "  parse static part of IPv6 extension header %u",
	                  protocol);

	/* at least 1 byte required to read the next header and length */
	if(rohc_length < 2)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
		                 "version flag of the IP static part");
		goto error;
	}
	ip_opt_static = (ip_opt_static_t *) rohc_packet;
	opt_context->generic.next_header = ip_opt_static->next_header;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
		{
			size = sizeof(ip_hop_opt_static_t);
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Hop-by-Hop option");
				goto error;
			}
			opt_context->generic.option_length = (ip_opt_static->length + 1) << 3;
			rohc_decomp_debug(context, "  IPv6 option Hop-by-Hop: length = %d, "
			                  "option_length = %zu", ip_opt_static->length,
			                  opt_context->generic.option_length);
			opt_context->generic.length = ip_opt_static->length;
			break;
		}
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
		{
			const ip_rout_opt_static_t *const ip_rout_opt_static =
				(ip_rout_opt_static_t *) ip_opt_static;
			size = (ip_rout_opt_static->length + 1) << 3;
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Routing option");
				goto error;
			}
			opt_context->generic.option_length = size;
			memcpy(&opt_context->generic.length, &ip_rout_opt_static->length,
			       size - 1);
			rohc_decomp_debug(context, "  IPv6 option Routing: length = %u, "
			                  "option_length = %zu", ip_rout_opt_static->length,
			                  opt_context->generic.option_length);
			break;
		}
		case ROHC_IPPROTO_GRE:
		{
			const ip_gre_opt_static_t *const ip_gre_opt_static =
				(ip_gre_opt_static_t *) ip_opt_static;

			if(rohc_length < sizeof(ip_gre_opt_static_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 GRE option");
				goto error;
			}
#if 0 /* to be clarified */
			if((opt_context->gre.protocol ==
			    ip_gre_opt_static->protocol) == 0) // TODO: check that
			{
				base_header.ip_gre_opt->protocol = rohc_hton16(0x0800);
			}
			else
			{
				base_header.ip_gre_opt->protocol = rohc_hton16(0x86DD);
			}
#endif
			opt_context->gre.c_flag = ip_gre_opt_static->c_flag;
			opt_context->gre.s_flag = ip_gre_opt_static->s_flag;
			opt_context->gre.k_flag = ip_gre_opt_static->k_flag;
			size = sizeof(ip_gre_opt_static_t);

#if 0 /* to be moved after parsing */
			ret = d_optional32(ip_gre_opt_static->k_flag,
			                   ip_gre_opt_static->options,
			                   rohc_length - size,
			                   opt_context->gre.key,
			                   &(base_header.ip_gre_opt->datas[opt_context->gre.c_flag]));
			if(ret < 0)
			{
				rohc_decomp_warn(context, "ROHC packet too small for optional "
				                 "key field in GRE static part");
				goto error;
			}
			opt_context->gre.key =
				base_header.ip_gre_opt->datas[opt_context->gre.c_flag];
			size += ret;
#endif

			opt_context->generic.option_length = size << 3;

#if 0 /* to be moved after parsing */
			if(ip_gre_opt_static->k_flag != 0)
			{
				base_header.ip_gre_opt->datas[opt_context->gre.c_flag] =
				   opt_context->gre.key;
			}
#endif
			break;
		}
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
		{
			const ip_dest_opt_static_t *const ip_dest_opt_static =
				(ip_dest_opt_static_t *) ip_opt_static;
			size = sizeof(ip_dest_opt_static_t);
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Destination option");
				goto error;
			}
			opt_context->generic.option_length = (ip_opt_static->length + 1) << 3;
			rohc_decomp_debug(context, "  IPv6 option Destination: length = %d, "
			                  "option_length = %zu", ip_opt_static->length,
			                  opt_context->generic.option_length);
			opt_context->generic.length = ip_dest_opt_static->length;
			break;
		}
		case ROHC_IPPROTO_MINE:
		{
			const ip_mime_opt_static_t *const ip_mime_opt_static =
				(ip_mime_opt_static_t *) ip_opt_static;
			size = sizeof(ip_mime_opt_static_t) -
			       (ip_mime_opt_static->s_bit * sizeof(uint32_t));
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Destination option");
				goto error;
			}
			opt_context->generic.option_length = (2 + ip_mime_opt_static->s_bit) << 3;
			opt_context->mime.s_bit = ip_mime_opt_static->s_bit;
			opt_context->mime.res_bits = ip_mime_opt_static->res_bits;
			opt_context->mime.orig_dest = ip_mime_opt_static->orig_dest;
			if(opt_context->mime.s_bit != 0)
			{
				opt_context->mime.orig_src = ip_mime_opt_static->orig_src;
			}
			break;
		}
		case ROHC_IPPROTO_AH:
		{
			const ip_ah_opt_static_t *const ip_ah_opt_static =
				(ip_ah_opt_static_t *) ip_opt_static;
			size = sizeof(ip_ah_opt_static_t);
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Destination option");
				goto error;
			}
			opt_context->generic.option_length =
				sizeof(ip_ah_opt_t) - sizeof(uint32_t) +
				(ip_ah_opt_static->length << 4) - sizeof(int32_t);
			opt_context->ah.length = ip_ah_opt_static->length;
			opt_context->ah.spi = ip_ah_opt_static->spi;
			break;
		}
		default:
		{
			goto error;
		}
	}
	ip_bits->opts_len += opt_context->generic.option_length;

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IPv6 option static part", rohc_packet, size);
#endif

	return size;

error:
	return -1;
}


/**
 * @brief Decode the TCP static part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param rohc_packet  The remaining part of the ROHC packet
 * @param rohc_length  The remaining length (in bytes) of the ROHC packet
 * @param[out] bits    The bits extracted from the CO packet
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_parse_static_tcp(const struct rohc_decomp_ctxt *const context,
                                const unsigned char *const rohc_packet,
                                const size_t rohc_length,
                                struct rohc_tcp_extr_bits *const bits)
{
	const tcp_static_t *tcp_static;

	assert(rohc_packet != NULL);

	rohc_decomp_debug(context, "parse TCP static part");

	/* check the minimal length to decode the TCP static part */
	if(rohc_length < sizeof(tcp_static_t))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_length);
		goto error;
	}
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "TCP static part", rohc_packet, sizeof(tcp_static_t));
	tcp_static = (tcp_static_t *) rohc_packet;

	/* TCP source port */
	bits->src_port = rohc_ntoh16(tcp_static->src_port);
	bits->src_port_nr = 16;
	rohc_decomp_debug(context, "TCP source port = %u", bits->src_port);

	/* TCP destination port */
	bits->dst_port = rohc_ntoh16(tcp_static->dst_port);
	bits->dst_port_nr = 16;
	rohc_decomp_debug(context, "TCP dest port = %u", bits->dst_port);

	/* number of bytes read from the packet */
	rohc_decomp_debug(context, "TCP static part is %zu-byte long",
	                  sizeof(tcp_static_t));
	return sizeof(tcp_static_t);

error:
	return -1;
}

