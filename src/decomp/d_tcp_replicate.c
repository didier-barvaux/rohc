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
 * @file   d_tcp_replicate.c
 * @brief  Handle the replicate chain of the TCP decompression profile
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_tcp_replicate.h"

#include "d_tcp_defines.h"
#include "d_tcp_opts_list.h"
#include "schemes/rfc4996.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "protocols/ip_numbers.h"

#ifndef __KERNEL__
#  include <string.h>
#endif


static int tcp_parse_replicate_ip(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *const rohc_packet,
                                  const size_t rohc_length,
                                  struct rohc_tcp_extr_ip_bits *const ip_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int tcp_parse_replicate_ipv6_option(const struct rohc_decomp_ctxt *const context,
                                           ip_option_context_t *const opt_context,
                                           const uint8_t *const rohc_packet,
                                           const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static bool tcp_parse_replicate_tcp_port(const struct rohc_decomp_ctxt *const context,
                                         const rohc_tcp_port_type_t port_presence,
                                         const uint8_t *const rohc_packet,
                                         const size_t rohc_length,
                                         uint16_t *const bits,
                                         bits_nr_t *const bits_nr)
	__attribute__((warn_unused_result, nonnull(1, 3, 5, 6)));

static int tcp_parse_replicate_tcp(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const rohc_packet,
                                   const size_t rohc_length,
                                   struct rohc_tcp_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));


/**
 * @brief Parse the replicate chain of the IR-CR packet
 *
 * @param context          The decompression context
 * @param rohc_packet      The remaining part of the ROHC packet
 * @param rohc_length      The remaining length (in bytes) of the ROHC packet
 * @param[out] bits        The bits extracted from the replicate chain
 * @param[out] parsed_len  The length (in bytes) of replicate chain in case of success
 * @return                 true in the replicate chain was successfully parsed,
 *                         false if the ROHC packet was malformed
 */
bool tcp_parse_replicate_chain(const struct rohc_decomp_ctxt *const context,
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

	/* parse replicate IP part (IPv4/IPv6 headers and extension headers) */
	assert(bits->ip_nr > 0);
	for(ip_hdrs_nr = 0; ip_hdrs_nr < bits->ip_nr; ip_hdrs_nr++)
	{
		struct rohc_tcp_extr_ip_bits *const ip_bits = &(bits->ip[ip_hdrs_nr]);

		ret = tcp_parse_replicate_ip(context, remain_data, remain_len, ip_bits);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: malformed IP "
			                 "replicate part");
			goto error;
		}
		rohc_decomp_debug(context, "IPv%u replicate part is %d-byte length",
		                  ip_bits->version, ret);
		assert(remain_len >= ((size_t) ret));
		remain_data += ret;
		remain_len -= ret;
		(*parsed_len) += ret;
	}

	/* parse TCP replicate part */
	ret = tcp_parse_replicate_tcp(context, remain_data, remain_len, bits);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP replicate "
		                 "part");
		goto error;
	}
	rohc_decomp_debug(context, "TCP replicate part is %d-byte length", ret);
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
 * @brief Decode the replicate IP header of the rohc packet.
 *
 * @param context       The decompression context
 * @param rohc_packet   The remaining part of the ROHC packet
 * @param rohc_length   The remaining length (in bytes) of the ROHC packet
 * @param[out] ip_bits  The bits extracted from the IP part of the replicate chain
 * @return              The length of replicate IP header in case of success,
 *                      -1 if an error occurs
 */
static int tcp_parse_replicate_ip(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *const rohc_packet,
                                  const size_t rohc_length,
                                  struct rohc_tcp_extr_ip_bits *const ip_bits)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t size = 0;
	int ret;

	rohc_decomp_debug(context, "parse IP replicate part");

	if(ip_bits->version == IPV4)
	{
		const ipv4_replicate_t *const ipv4_replicate =
			(ipv4_replicate_t *) remain_data;

		if(remain_len < sizeof(ipv4_replicate_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv4 replicate part");
			goto error;
		}

		if(ipv4_replicate->reserved != 0)
		{
			rohc_decomp_debug(context, "IPv4 replicate part: reserved field is 0x%x"
			                  "instead of 0x0", ipv4_replicate->reserved);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}

		ip_bits->id_behavior = ipv4_replicate->ip_id_behavior;
		ip_bits->id_behavior_nr = 2;
		rohc_decomp_debug(context, "ip_id_behavior = %d", ip_bits->id_behavior);
		ip_bits->df = ipv4_replicate->df;
		ip_bits->df_nr = 1;
		ip_bits->dscp_bits = ipv4_replicate->dscp;
		ip_bits->dscp_bits_nr = 6;
		ip_bits->ecn_flags_bits = ipv4_replicate->ip_ecn_flags;
		ip_bits->ecn_flags_bits_nr = 2;
		rohc_decomp_debug(context, "DF = %d, DSCP = 0x%x, ip_ecn_flags = %d",
		                  ip_bits->df, ip_bits->dscp_bits, ip_bits->ecn_flags_bits);
		size += sizeof(ipv4_replicate_t);
		remain_data += sizeof(ipv4_replicate_t);
		remain_len -= sizeof(ipv4_replicate_t);

		/* IP-ID: cf RFC6846 ip_id_enc_dyn() */
		if(ipv4_replicate->ip_id_behavior != ROHC_IP_ID_BEHAVIOR_ZERO)
		{
			const uint16_t *const replicate_ip_id = (uint16_t *) remain_data;

			if(remain_len < sizeof(uint16_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "IP-ID in IPv4 replicate part");
				goto error;
			}

			ip_bits->id.bits = rohc_ntoh16(*replicate_ip_id);
			ip_bits->id.bits_nr = 16;
			rohc_decomp_debug(context, "IP-ID = 0x%04x", ip_bits->id.bits);

			size += sizeof(uint16_t);
			remain_data += sizeof(uint16_t);
			remain_len -= sizeof(uint16_t);
		}

		/* TTL/HL */
		if(ipv4_replicate->ttl_flag == 1)
		{
			if(remain_len < sizeof(uint8_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "TTL/HL in IPv4 replicate part");
				goto error;
			}

			ip_bits->ttl_hl.bits = remain_data[0];
			ip_bits->ttl_hl.bits_nr = 8;
			rohc_decomp_debug(context, "ttl_hopl = 0x%x", ip_bits->ttl_hl.bits);

			size += sizeof(uint8_t);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
			remain_data += sizeof(uint8_t);
			remain_len -= sizeof(uint8_t);
#endif
		}
	}
	else
	{
		const ipv6_replicate1_t *const ipv6_replicate1 =
			(ipv6_replicate1_t *) remain_data;
		size_t opts_nr;

		if(remain_len < sizeof(ipv6_replicate1_t))
		{
			rohc_decomp_warn(context, "malformed ROHC packet: too short for "
			                 "IPv6 replicate part");
			goto error;
		}

		/* DSCP and ECN flags */
		ip_bits->dscp_bits = ipv6_replicate1->dscp;
		ip_bits->dscp_bits_nr = 6;
		ip_bits->ecn_flags_bits = ipv6_replicate1->ip_ecn_flags;
		ip_bits->ecn_flags_bits_nr = 2;

		if(ipv6_replicate1->reserved1 != 0)
		{
			rohc_decomp_debug(context, "IPv6 replicate part: reserved field is 0x%x "
			                  "instead of 0x0", ipv6_replicate1->reserved1);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}

		/* Flow Label if any */
		if(ipv6_replicate1->fl_enc_flag == 0)
		{
			/* no Flow Label: reserved field should be 0 */
			if(ipv6_replicate1->reserved2 != 0)
			{
				rohc_decomp_debug(context, "IPv6 replicate part: reserved field is 0x%x "
				                  "instead of 0x0", ipv6_replicate1->reserved2);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
				goto error;
#endif
			}

			/* skip IPv6 replicate part without Flow Label */
			size += sizeof(ipv6_replicate1_t);
			remain_data += sizeof(ipv6_replicate1_t);
			remain_len -= sizeof(ipv6_replicate1_t);
		}
		else
		{
			/* FLow Label is present */
			const ipv6_replicate2_t *const ipv6_replicate2 =
				(ipv6_replicate2_t *) remain_data;

			if(remain_len < sizeof(ipv6_replicate2_t))
			{
				rohc_decomp_warn(context, "malformed ROHC packet: too short for "
				                 "IPv6 replicate part");
				goto error;
			}

			ip_bits->flowid = (ipv6_replicate2->flow_label1 << 16) |
			                  rohc_ntoh16(ipv6_replicate2->flow_label2);
			assert((ip_bits->flowid & 0xfffff) == ip_bits->flowid);
			rohc_decomp_debug(context, "  IPv6 flow label = 0x%05x", ip_bits->flowid);
			ip_bits->flowid_nr = 20;

			/* skip IPv6 replicate part with Flow Label */
			size += sizeof(ipv6_replicate2_t);
			remain_data += sizeof(ipv6_replicate2_t);
			remain_len -= sizeof(ipv6_replicate2_t);
		}

		/* no IP-ID for IPv6, simulate random behavior to be generic with IPv4 code */
		ip_bits->id_behavior = ROHC_IP_ID_BEHAVIOR_RAND;
		ip_bits->id_behavior_nr = 2;

		/* parse IPv6 extension headers */
		rohc_decomp_debug(context, "parse the replicate parts of the %u IPv6 "
		                  "extension headers", ip_bits->opts_nr);

		assert(ip_bits->proto_nr == 8);
		for(opts_nr = 0; opts_nr < ip_bits->opts_nr; opts_nr++)
		{
			ip_option_context_t *const opt = &(ip_bits->opts[opts_nr]);

			ret = tcp_parse_replicate_ipv6_option(context, opt, remain_data, remain_len);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: malformed "
				                 "IPv6 replicate option part");
				goto error;
			}
			rohc_decomp_debug(context, "IPv6 replicate option part is %d-byte "
			                  "length", ret);
			assert(remain_len >= ((size_t) ret));
			size += ret;
			remain_data += ret;
			remain_len -= ret;
		}
	}

	rohc_decomp_dump_buf(context, "IP replicate part", rohc_packet, size);

	return size;

error:
	return -1;
}


/**
 * @brief Decode the replicate IPv6 option header of the rohc packet.
 *
 * @param context           The decompression context
 * @param[out] opt_context  The specific IPv6 option decompression context
 * @param rohc_packet       The remaining part of the ROHC packet
 * @param rohc_length       The remaining length (in bytes) of the ROHC packet
 * @return                  The length of replicate IP header in case of success,
 *                          -1 if an error occurs
 */
static int tcp_parse_replicate_ipv6_option(const struct rohc_decomp_ctxt *const context,
                                           ip_option_context_t *const opt_context,
                                           const uint8_t *const rohc_packet,
                                           const size_t rohc_length)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t size = 0;

	rohc_decomp_debug(context, "parse replicate part of the %u-byte IPv6 extension "
	                  "header '%s' (%u)", opt_context->len,
	                  rohc_get_ip_proto_descr(opt_context->proto), opt_context->proto);

	switch(opt_context->proto)
	{
		case ROHC_IPPROTO_HOPOPTS:  /* IPv6 Hop-by-Hop options */
		case ROHC_IPPROTO_DSTOPTS:  /* IPv6 destination options */
		case ROHC_IPPROTO_ROUTING:  /* IPv6 routing header */
		{
			uint8_t discriminator;

			/* parse option discriminator */
			if(remain_len < sizeof(uint8_t))
			{
				rohc_decomp_warn(context, "malformed IPv6 option: malformed option "
				                 "%u: at least 1 byte required for discriminator",
				                 opt_context->proto);
				goto error;
			}
			discriminator = remain_data[0];
			size++;
			remain_data++;
			remain_len--;

			/* is option present or not? */
			if(discriminator == 0x80)
			{
				/* option is present: parse option length, then option data */
				uint8_t opt_len;

				/* option length */
				if(remain_len < sizeof(uint8_t))
				{
					rohc_decomp_warn(context, "malformed IPv6 option: malformed option "
					                 "%u: at least 1 byte required for option length",
					                 opt_context->proto);
					goto error;
				}
				opt_len = (remain_data[0] + 1) * 8;
				size++;
				remain_data++;
				remain_len--;

				/* option data */
				if(remain_len < opt_len)
				{
					rohc_decomp_warn(context, "malformed IPv6 option: malformed "
					                 "option %u: %zu bytes available while %u bytes "
					                 "required", opt_context->proto, remain_len, opt_len);
					goto error;
				}
				opt_context->len = opt_len;
				opt_context->generic.data_len = opt_len - 2;
				memcpy(&opt_context->generic.data, remain_data,
				       opt_context->generic.data_len);
				size += opt_context->generic.data_len;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
				remain_data += opt_context->generic.data_len;
				remain_len -= opt_context->generic.data_len;
#endif
			}
			else if(discriminator != 0x00)
			{
				/* malformed packet: discriminator shall be 0x00 or 0x80 */
				rohc_decomp_warn(context, "IPv6 option replicate part: discriminator "
				                 "is 0x%02x instead of 0x80 or 0x00", discriminator);
				goto error;
			}

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

	rohc_decomp_dump_buf(context, "IPv6 option replicate part", rohc_packet, size);

	return size;

error:
	return -1;
}


/**
 * @brief Decode the TCP port_replicate() encoding scheme of the ROHC packet
 *
 * @param context        The decompression context
 * @param port_presence  The type of encoding used for the TCP port
 * @param rohc_packet    The remaining part of the ROHC packet
 * @param rohc_length    The remaining length (in bytes) of the ROHC packet
 * @param[out] bits      The bits extracted for the TCP port
 * @param[out] bits_nr   The number of bits extracted for the TCP port
 * @return               true if parsing was successful, false if not
 */
static bool tcp_parse_replicate_tcp_port(const struct rohc_decomp_ctxt *const context,
                                         const rohc_tcp_port_type_t port_presence,
                                         const uint8_t *const rohc_packet,
                                         const size_t rohc_length,
                                         uint16_t *const bits,
                                         bits_nr_t *const bits_nr)
{
	if(port_presence < ROHC_TCP_PORT_RESERVED && rohc_length < port_presence)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
		                 "available while at least %u bytes required for the "
		                 "irregular TCP port", rohc_length, port_presence);
		goto error;
	}

	if(port_presence == ROHC_TCP_PORT_IRREGULAR)
	{
		const uint16_t *const tcp_replicate_src_port = (uint16_t *) rohc_packet;
		*bits = rohc_ntoh16(*tcp_replicate_src_port);
		*bits_nr = 16;
	}
	else if(port_presence == ROHC_TCP_PORT_LSB8)
	{
		/* TODO: handle LSB8 encoding for port_replicate() */
		rohc_decomp_warn(context, "LSB8 encoding is not supported yet for port_replicate()");
		goto error;
	}
	else if(port_presence == ROHC_TCP_PORT_STATIC)
	{
		*bits = 0;
		*bits_nr = 0;
	}
	else
	{
		rohc_decomp_warn(context, "port_presence is %u but only 0, 1 and 2 are "
		                 "allowed for the flags of port_replicate()", port_presence);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Decode the TCP replicate part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param rohc_packet  The remaining part of the ROHC packet
 * @param rohc_length  The remaining length (in bytes) of the ROHC packet
 * @param[out] bits    The bits extracted from the CO packet
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_parse_replicate_tcp(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const rohc_packet,
                                   const size_t rohc_length,
                                   struct rohc_tcp_extr_bits *const bits)
{
	const struct d_tcp_context *const tcp_context = context->persist_ctxt;
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	const tcp_replicate_t *tcp_replicate;
	int ret;

	rohc_decomp_debug(context, "parse TCP replicate part");

	/* check the minimal length to decode the TCP replicate part */
	if(remain_len < sizeof(tcp_replicate_t))
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "fixed-size TCP replicate part", remain_len,
		                 sizeof(tcp_replicate_t));
		goto error;
	}
	rohc_decomp_dump_buf(context, "TCP replicate part", remain_data,
	                     sizeof(tcp_replicate_t));
	tcp_replicate = (tcp_replicate_t *) rohc_packet;
	remain_data += sizeof(tcp_replicate_t);
	remain_len -= sizeof(tcp_replicate_t);

	/* check that reserved field is set to 0 */
	if(tcp_replicate->reserved != 0)
	{
		rohc_decomp_debug(context, "TCP replicate part: reserved field is %u"
		                  "instead of 0", tcp_replicate->reserved);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}

	/* retrieve the TCP flags from the TCP replicate part */
	rohc_decomp_debug(context, "TCP URG = %d, ACK = %u, PSH = %u, rsf_flags = %u, "
	                  "ecn_used = %u", tcp_replicate->urg_flag,
	                  tcp_replicate->ack_flag, tcp_replicate->psh_flag,
	                  tcp_replicate->rsf_flags, tcp_replicate->ecn_used);
	bits->urg_flag_bits = tcp_replicate->urg_flag;
	bits->urg_flag_bits_nr = 1;
	bits->ack_flag_bits = tcp_replicate->ack_flag;
	bits->ack_flag_bits_nr = 1;
	bits->psh_flag_bits = tcp_replicate->psh_flag;
	bits->psh_flag_bits_nr = 1;
	bits->rsf_flags_bits = tcp_replicate->rsf_flags;
	bits->rsf_flags_bits_nr = 2;
	bits->ecn_used_bits = tcp_replicate->ecn_used;
	bits->ecn_used_bits_nr = 1;

	/* retrieve the MSN from the TCP replicate part */
	bits->msn.bits = rohc_ntoh16(tcp_replicate->msn);
	bits->msn.bits_nr = 16;
	rohc_decomp_debug(context, "%u bits of MSN 0x%04x",
	                  bits->msn.bits_nr, bits->msn.bits);

	/* retrieve the TCP sequence number from the TCP replicate part */
	bits->seq.bits = rohc_ntoh32(tcp_replicate->seq_num);
	bits->seq.bits_nr = 32;
	rohc_decomp_debug(context, "%u bits of TCP sequence number 0x%08x",
	                  bits->seq.bits_nr, bits->seq.bits);

	/* TCP source port */
	if(!tcp_parse_replicate_tcp_port(context, tcp_replicate->src_port_presence,
	                                 remain_data, remain_len,
	                                 &(bits->src_port), &(bits->src_port_nr)))
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: malformed irregular "
		                 "TCP source port");
		goto error;
	}
	remain_data += tcp_replicate->src_port_presence;
	remain_len -= tcp_replicate->src_port_presence;
	rohc_decomp_debug(context, "%u-bit TCP source port = %u",
	                  bits->src_port_nr, bits->src_port);

	/* TCP destination port */
	if(!tcp_parse_replicate_tcp_port(context, tcp_replicate->dst_port_presence,
	                                 remain_data, remain_len,
	                                 &(bits->dst_port), &(bits->dst_port_nr)))
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: malformed irregular "
		                 "TCP destination port");
		goto error;
	}
	remain_data += tcp_replicate->dst_port_presence;
	remain_len -= tcp_replicate->dst_port_presence;
	rohc_decomp_debug(context, "%u-bit TCP destination port = %u",
	                  bits->dst_port_nr, bits->dst_port);

	/* window */
	ret = d_static_or_irreg16(remain_data, remain_len, tcp_replicate->window_presence,
	                          &bits->window);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: "
		                 "static_or_irreg(window) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %u bits of TCP window encoded on "
	                  "%d bytes", bits->window.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	/* URG pointer */
	ret = d_static_or_irreg16(remain_data, remain_len, tcp_replicate->urp_presence,
	                          &bits->urg_ptr);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: "
		                 "static_or_irreg(urg_ptr) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %u bits of TCP URG Pointer encoded on "
	                  "%d bytes", bits->urg_ptr.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	/* ACK number */
	ret = d_static_or_irreg32(remain_data, remain_len, tcp_replicate->ack_presence,
	                          &bits->ack);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: "
		                 "static_or_irreg(ack_number) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %u bits of TCP ACK number encoded on "
	                  "%d bytes", bits->ack.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	/* ecn_padding + tcp_res_flags + tcp_ecn_flags */
	if(tcp_replicate->ecn_used)
	{
		if(remain_len < sizeof(uint8_t))
		{
			rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
			                 "available while at least %zu bytes required for "
			                 "ecn_padding + tcp_res_flags + tcp_ecn_flags",
			                 remain_len, sizeof(uint8_t));
			goto error;
		}
		if(GET_BIT_6_7(remain_data) != 0)
		{
			rohc_decomp_debug(context, "TCP replicate part: reserved field along "
			                  "RES and ECN flags is %u instead of 0",
			                  GET_BIT_6_7(remain_data));
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}
		bits->res_flags_bits = GET_BIT_2_5(remain_data);
		bits->res_flags_bits_nr = 4;
		bits->ecn_flags_bits = GET_BIT_0_1(remain_data);
		bits->ecn_flags_bits_nr = 2;
		remain_data++;
		remain_len--;
		rohc_decomp_debug(context, "TCP RES and ECM flags %spresent",
		                  tcp_replicate->ecn_used ? "" : "not ");
	}

	/* checksum */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: only %zu bytes "
		                 "available while at least %zu bytes required for the "
		                 "checksum", remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&(bits->tcp_check), remain_data, sizeof(uint16_t));
	bits->tcp_check = rohc_ntoh16(bits->tcp_check);
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP checksum = 0x%04x", bits->tcp_check);

	/* ACK stride */
	ret = d_static_or_irreg16(remain_data, remain_len, tcp_replicate->ack_stride_flag,
	                          &bits->ack_stride);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed TCP replicate part: "
		                 "static_or_irreg(ack_stride) failed");
		goto error;
	}
	rohc_decomp_debug(context, "found %u bits of ACK stride encoded on "
	                  "%d bytes", bits->ack_stride.bits_nr, ret);
	remain_data += ret;
	remain_len -= ret;

	/* parse the compressed list of TCP options */
	if(tcp_replicate->list_present == 0)
	{
		/* same list as in base context */
		memcpy(&bits->tcp_opts, &tcp_context->tcp_opts, sizeof(struct d_tcp_opts_ctxt));
	}
	else
	{
		ret = d_tcp_parse_tcp_opts_list_item(context, remain_data, remain_len, false,
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
	}

	assert(remain_len <= rohc_length);
	rohc_decomp_dump_buf(context, "TCP replicate part",
	                     rohc_packet, rohc_length - remain_len);

	return (rohc_length - remain_len);

error:
	return -1;
}

