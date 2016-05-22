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

#include "d_tcp_defines.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "protocols/ip_numbers.h"

#ifndef __KERNEL__
#  include <string.h>
#endif


static int tcp_parse_static_ip(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_tcp_extr_ip_bits *const ip_bits,
                               uint8_t *const nh_proto)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

static int tcp_parse_static_ipv6_option(const struct rohc_decomp_ctxt *const context,
                                        struct rohc_tcp_extr_ip_bits *const ip_bits,
                                        ip_option_context_t *const opt_context,
                                        const uint8_t protocol,
                                        const uint8_t *const rohc_packet,
                                        const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int tcp_parse_static_tcp(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const rohc_packet,
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

		ret = tcp_parse_static_ip(context, remain_data, remain_len, ip_bits,
		                          &protocol);
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
 * @param[out] nh_proto The next header protocol of the last extension header
 * @return              The length of static IP header in case of success,
 *                      -1 if an error occurs
 */
static int tcp_parse_static_ip(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_tcp_extr_ip_bits *const ip_bits,
                               uint8_t *const nh_proto)
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
		*nh_proto = ip_bits->proto;
		memcpy(ip_bits->saddr, &ipv4_static->src_addr, sizeof(uint32_t));
		ip_bits->saddr_nr = 32;
		memcpy(ip_bits->daddr, &ipv4_static->dst_addr, sizeof(uint32_t));
		ip_bits->daddr_nr = 32;

		/* IP extension headers not supported for IPv4 */
		ip_bits->opts_nr = 0;
		ip_bits->opts_len = 0;

		read += sizeof(ipv4_static_t);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		remain_data += sizeof(ipv4_static_t);
		remain_len -= sizeof(ipv4_static_t);
#endif
	}
	else
	{
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

			ip_bits->flowid = (ipv6_static2->flow_label1 << 16) |
			                  rohc_ntoh16(ipv6_static2->flow_label2);
			assert((ip_bits->flowid & 0xfffff) == ip_bits->flowid);
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

		*nh_proto = ip_bits->proto;
		ip_bits->opts_nr = 0;
		ip_bits->opts_len = 0;
		while(rohc_is_ipv6_opt(*nh_proto))
		{
			ip_option_context_t *opt;

			if(ip_bits->opts_nr >= ROHC_TCP_MAX_IP_EXT_HDRS)
			{
				rohc_decomp_warn(context, "too many IPv6 extension headers");
				goto error;
			}
			opt = &(ip_bits->opts[ip_bits->opts_nr]);

			ret = tcp_parse_static_ipv6_option(context, ip_bits, opt, *nh_proto,
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

			*nh_proto = opt->nh_proto;
			ip_bits->opts_nr++;
		}
		rohc_decomp_debug(context, "IPv6 header is followed by %zu extension "
		                  "headers", ip_bits->opts_nr);
	}
	rohc_decomp_dump_buf(context, "IP static part", rohc_packet, read);

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
 * @param protocol          The protocol of the IPv6 option
 * @param rohc_packet       The remaining part of the ROHC packet
 * @param rohc_length       The remaining length (in bytes) of the ROHC packet
 * @return                  The length of static IP header in case of success,
 *                          -1 if an error occurs
 */
static int tcp_parse_static_ipv6_option(const struct rohc_decomp_ctxt *const context,
                                        struct rohc_tcp_extr_ip_bits *const ip_bits,
                                        ip_option_context_t *const opt_context,
                                        const uint8_t protocol,
                                        const uint8_t *const rohc_packet,
                                        const size_t rohc_length)
{
	const ip_opt_static_t *ip_opt_static;
	size_t size;

	rohc_decomp_debug(context, "parse static part of the IPv6 extension header "
	                  "'%s' (%u)", rohc_get_ip_proto_descr(protocol), protocol);

	/* at least 2 bytes required to read the next header and length */
	if(rohc_length < sizeof(ip_opt_static_t))
	{
		rohc_decomp_warn(context, "malformed ROHC packet: too short for the "
		                 "IP extension header static part");
		goto error;
	}
	ip_opt_static = (ip_opt_static_t *) rohc_packet;
	opt_context->proto = protocol;
	opt_context->nh_proto = ip_opt_static->next_header;

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
			opt_context->len = ipv6_opt_get_length((struct ipv6_opt *) ip_opt_static);
			rohc_decomp_debug(context, "  IPv6 option Hop-by-Hop is %zu-byte long",
			                  opt_context->len);
			break;
		}
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
		{
			const ip_rout_opt_static_t *const ip_rout_opt_static =
				(ip_rout_opt_static_t *) ip_opt_static;
			size = ipv6_opt_get_length((struct ipv6_opt *) ip_rout_opt_static);
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Routing option");
				goto error;
			}
			opt_context->len = size;
			opt_context->generic.data_len = size - 2;
			memcpy(&opt_context->generic.data, &ip_rout_opt_static->value,
			       opt_context->generic.data_len);
			rohc_decomp_debug(context, "  IPv6 option Routing is %zu-byte long",
			                  opt_context->len);
			break;
		}
		case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
		{
			rohc_decomp_warn(context, "GRE extension header not supported yet");
			goto error;
		}
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
		{
			size = sizeof(ip_dest_opt_static_t);
			if(rohc_length < size)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "the static part of the IPv6 Destination option");
				goto error;
			}
			opt_context->len = ipv6_opt_get_length((struct ipv6_opt *) ip_opt_static);
			rohc_decomp_debug(context, "  IPv6 option Destination is %zu-byte long",
			                  opt_context->len);
			break;
		}
		case ROHC_IPPROTO_MINE:  /* TODO: MINE not yet supported */
		{
			rohc_decomp_warn(context, "GRE extension header not supported yet");
			goto error;
		}
		case ROHC_IPPROTO_AH:  /* TODO: AH not yet supported */
		{
			rohc_decomp_warn(context, "GRE extension header not supported yet");
			goto error;
		}
		default:
		{
			goto error;
		}
	}
	ip_bits->opts_len += opt_context->len;

	rohc_decomp_dump_buf(context, "IPv6 option static part", rohc_packet, size);

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
                                const uint8_t *const rohc_packet,
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
	rohc_decomp_dump_buf(context, "TCP static part", rohc_packet,
	                     sizeof(tcp_static_t));
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

