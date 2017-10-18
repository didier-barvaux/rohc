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
 * @file   c_tcp_static.c
 * @brief  Handle the static chain of the TCP compression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "c_tcp_static.h"

#include "c_tcp_defines.h"
#include "protocols/ip_numbers.h"
#include "protocols/ip.h"

#include <assert.h>

static int tcp_code_static_ipv4_part(const struct rohc_comp_ctxt *const context,
                                     const struct ipv4_hdr *const ipv4,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int tcp_code_static_ipv6_part(const struct rohc_comp_ctxt *const context,
                                     const struct ipv6_hdr *const ipv6,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int tcp_code_static_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                         const struct ipv6_opt *const ipv6_opt,
                                         const uint8_t protocol,
                                         uint8_t *const rohc_data,
                                         const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int tcp_code_static_tcp_part(const struct rohc_comp_ctxt *const context,
                                    const struct tcphdr *const tcp,
                                    uint8_t *const rohc_data,
                                    const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));


/**
 * @brief Code the static part of an IR packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
int tcp_code_static_part(struct rohc_comp_ctxt *const context,
                         const struct ip_packet *const ip,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const uint8_t *remain_data = ip->data;
	size_t remain_len = ip->size;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	size_t ip_hdr_pos;
	int ret;

	/* add IP parts of static chain */
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip_hdr = (struct ip_hdr *) remain_data;
		size_t ip_ext_pos;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip_hdr->version);

		if(ip_hdr->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			ret = tcp_code_static_ipv4_part(context, ipv4, rohc_remain_data,
			                                rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv4 base header part "
				               "of the static chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip_hdr->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			uint8_t protocol;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			ret = tcp_code_static_ipv6_part(context, ipv6, rohc_remain_data,
			                                rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv6 base header part "
				               "of the static chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			protocol = ipv6->nh;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			for(ip_ext_pos = 0;
			    ip_ext_pos < tcp_context->tmp.ip_exts_nr[ip_hdr_pos];
			    ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				const size_t opt_len = ipv6_opt_get_length(ipv6_opt);

				rohc_comp_debug(context, "IPv6 option #%zu: type %u / length %zu",
				                ip_ext_pos + 1, protocol, opt_len);
				ret = tcp_code_static_ipv6_opt_part(context, ipv6_opt, protocol,
				                                    rohc_remain_data, rohc_remain_len);
				if(ret < 0)
				{
					rohc_comp_warn(context, "failed to build the IPv6 extension header "
					               "part of the static chain");
					goto error;
				}
				rohc_remain_data += ret;
				rohc_remain_len -= ret;

				protocol = ipv6_opt->next_header;
				remain_data += opt_len;
				remain_len -= opt_len;
			}
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u", ip_hdr->version);
			assert(0);
			goto error;
		}
	}

	/* add TCP static part */
	{
		const struct tcphdr *const tcp = (struct tcphdr *) remain_data;

		assert(remain_len >= sizeof(struct tcphdr));

		ret = tcp_code_static_tcp_part(context, tcp, rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build the TCP header part of the "
			               "static chain");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
#endif
		rohc_remain_len -= ret;
	}

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv4 header
 *
 * @param context         The compression context
 * @param ipv4            The IPv4 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_static_ipv4_part(const struct rohc_comp_ctxt *const context,
                                     const struct ipv4_hdr *const ipv4,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
{
	ipv4_static_t *const ipv4_static = (ipv4_static_t *) rohc_data;
	const size_t ipv4_static_len = sizeof(ipv4_static_t);

	if(rohc_max_len < ipv4_static_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv4 static part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv4_static_len, rohc_max_len);
		goto error;
	}

	ipv4_static->version_flag = 0;
	ipv4_static->reserved = 0;
	ipv4_static->protocol = ipv4->protocol;
	rohc_comp_debug(context, "IPv4 protocol = %u", ipv4_static->protocol);
	ipv4_static->src_addr = ipv4->saddr;
	ipv4_static->dst_addr = ipv4->daddr;

	rohc_comp_dump_buf(context, "IPv4 static part", rohc_data, ipv4_static_len);

	return ipv4_static_len;

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv6 header
 *
 * @param context         The compression context
 * @param ipv6            The IPv6 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_static_ipv6_part(const struct rohc_comp_ctxt *const context,
                                     const struct ipv6_hdr *const ipv6,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
{
	size_t ipv6_static_len;

	if(ipv6->flow1 == 0 && ipv6->flow2 == 0)
	{
		ipv6_static1_t *const ipv6_static1 = (ipv6_static1_t *) rohc_data;

		ipv6_static_len = sizeof(ipv6_static1_t);
		if(rohc_max_len < ipv6_static_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv6 static part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv6_static_len, rohc_max_len);
			goto error;
		}

		ipv6_static1->version_flag = 1;
		ipv6_static1->reserved1 = 0;
		ipv6_static1->flow_label_enc_discriminator = 0;
		ipv6_static1->reserved2 = 0;
		ipv6_static1->next_header = ipv6->nh;
		memcpy(ipv6_static1->src_addr, &ipv6->saddr, sizeof(struct ipv6_addr));
		memcpy(ipv6_static1->dst_addr, &ipv6->daddr, sizeof(struct ipv6_addr));
	}
	else
	{
		ipv6_static2_t *const ipv6_static2 = (ipv6_static2_t *) rohc_data;

		ipv6_static_len = sizeof(ipv6_static2_t);
		if(rohc_max_len < ipv6_static_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv6 static part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv6_static_len, rohc_max_len);
			goto error;
		}

		ipv6_static2->version_flag = 1;
		ipv6_static2->reserved = 0;
		ipv6_static2->flow_label_enc_discriminator = 1;
		ipv6_static2->flow_label1 = ipv6->flow1;
		ipv6_static2->flow_label2 = ipv6->flow2;
		ipv6_static2->next_header = ipv6->nh;
		memcpy(ipv6_static2->src_addr, &ipv6->saddr, sizeof(struct ipv6_addr));
		memcpy(ipv6_static2->dst_addr, &ipv6->daddr, sizeof(struct ipv6_addr));
	}
	rohc_comp_debug(context, "IPv6 next header = %u", ipv6->nh);

	rohc_comp_dump_buf(context, "IPv6 static part", rohc_data, ipv6_static_len);

	return ipv6_static_len;

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv6 option header
 *
 * @param context         The compression context
 * @param ipv6_opt        The IPv6 extension header
 * @param protocol        The protocol of the IPv6 extension header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_static_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                         const struct ipv6_opt *const ipv6_opt,
                                         const uint8_t protocol,
                                         uint8_t *const rohc_data,
                                         const size_t rohc_max_len)
{
	ip_opt_static_t *const ip_opt_static = (ip_opt_static_t *) rohc_data;
	size_t ipv6_opt_static_len = sizeof(ip_opt_static_t);

	if(rohc_max_len < ipv6_opt_static_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv6 extension "
		               "header static part: %zu bytes required, but only %zu bytes "
		               "available", ipv6_opt_static_len, rohc_max_len);
		goto error;
	}

	/* next header and length are common to all options */
	ip_opt_static->next_header = ipv6_opt->next_header;
	ip_opt_static->length = ipv6_opt->length;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop option */
		case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination option */
		{
			/* no payload transmitted for those options, nothing to do */
			break;
		}
		case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
		{
			ip_rout_opt_static_t *const ip_rout_opt_static =
				(ip_rout_opt_static_t *) rohc_data;
			ipv6_opt_static_len = ipv6_opt_get_length(ipv6_opt);
			if(rohc_max_len < ipv6_opt_static_len)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv6 extension "
				               "header static part: %zu bytes required, but only %zu "
				               "bytes available", ipv6_opt_static_len, rohc_max_len);
				goto error;
			}
			memcpy(ip_rout_opt_static->value, ipv6_opt->value, ipv6_opt_static_len - 2);
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

	rohc_comp_dump_buf(context, "IPv6 option static part",
	                   rohc_data, ipv6_opt_static_len);

	return ipv6_opt_static_len;

error:
	return -1;
}


/**
 * @brief Build the static part of the TCP header
 *
 * \verbatim

 Static part of TCP header:

    +---+---+---+---+---+---+---+---+
 1  /  Source port                  /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /  Destination port             /   2 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context         The compression context
 * @param tcp             The TCP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_static_tcp_part(const struct rohc_comp_ctxt *const context,
                                    const struct tcphdr *const tcp,
                                    uint8_t *const rohc_data,
                                    const size_t rohc_max_len)
{
	tcp_static_t *const tcp_static = (tcp_static_t *) rohc_data;
	const size_t tcp_static_len = sizeof(tcp_static_t);

	rohc_comp_dump_buf(context, "TCP header", (uint8_t *) tcp, sizeof(struct tcphdr));

	if(rohc_max_len < tcp_static_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP static part: "
		               "%zu bytes required, but only %zu bytes available",
		               tcp_static_len, rohc_max_len);
		goto error;
	}

	tcp_static->src_port = tcp->src_port;
	rohc_comp_debug(context, "TCP source port = %d (0x%04x)",
	                rohc_ntoh16(tcp->src_port), rohc_ntoh16(tcp->src_port));

	tcp_static->dst_port = tcp->dst_port;
	rohc_comp_debug(context, "TCP destination port = %d (0x%04x)",
	                rohc_ntoh16(tcp->dst_port), rohc_ntoh16(tcp->dst_port));

	rohc_comp_dump_buf(context, "TCP static part", rohc_data, tcp_static_len);

	return tcp_static_len;

error:
	return -1;
}

