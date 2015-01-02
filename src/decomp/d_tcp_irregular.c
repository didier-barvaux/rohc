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
 * @file   d_tcp_irregular.c
 * @brief  Handle the irregular chain of the TCP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "d_tcp_irregular.h"

#include "config.h" /* for ROHC_EXTRA_DEBUG */

#include "d_tcp_defines.h"
#include "d_tcp_opts_list.h"
#include "rohc_utils.h"

#ifndef __KERNEL__
#  include <string.h>
#endif

static int tcp_parse_irregular_ip(const struct rohc_decomp_ctxt *const context,
                                  const ip_context_t *const ip_context,
                                  const uint8_t *rohc_data,
                                  const size_t rohc_data_len,
                                  const bool is_innermost,
                                  const tcp_ip_id_behavior_t ip_id_behavior,
                                  struct rohc_tcp_extr_bits *const bits,
                                  struct rohc_tcp_extr_ip_bits *const ip_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 7, 8)));

static int tcp_parse_irregular_ipv4(const struct rohc_decomp_ctxt *const context,
                                    const uint8_t *rohc_data,
                                    const size_t rohc_data_len,
                                    const bool is_innermost,
                                    const tcp_ip_id_behavior_t ip_id_behavior,
                                    struct rohc_tcp_extr_bits *const bits,
                                    struct rohc_tcp_extr_ip_bits *const ip_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 6, 7)));

static int tcp_parse_irregular_ipv6(const struct rohc_decomp_ctxt *const context,
                                    const uint8_t *rohc_data,
                                    const size_t rohc_data_len,
                                    const bool is_innermost,
                                    struct rohc_tcp_extr_bits *const bits,
                                    struct rohc_tcp_extr_ip_bits *const ip_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6)));

static int tcp_parse_irregular_tcp(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const rohc_data,
                                   const size_t rohc_data_len,
                                   struct rohc_tcp_extr_bits *const bits,
                                   struct rohc_tcp_extr_ip_bits *const ip_inner_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

static bool d_tcp_is_ecn_used(const struct d_tcp_context tcp_ctxt,
                              const struct rohc_tcp_extr_bits bits)
	__attribute__((warn_unused_result, const));


/**
 * @brief Parse the irregular chain of the ROHC packet
 *
 * @param context                   The decompression context
 * @param rohc_packet               The remaining part of the ROHC packet
 * @param rohc_length               The remaining length (in bytes) of ROHC packet
 * @param innermost_ip_id_behavior  The behavior of the innermost IP-ID
 * @param[out] bits                 The bits extracted from the irregular chain
 *                                  in case of success
 * @param[out] parsed_len           The length (in bytes) of irregular chain
 *                                  in case of success
 * @return                          true in the irregular chain was successfully
 *                                  parsed, false if the ROHC packet was malformed
 */
bool tcp_parse_irreg_chain(const struct rohc_decomp_ctxt *const context,
                           const uint8_t *const rohc_packet,
                           const size_t rohc_length,
                           const tcp_ip_id_behavior_t innermost_ip_id_behavior,
                           struct rohc_tcp_extr_bits *const bits,
                           size_t *const parsed_len)
{
	const struct d_tcp_context *const tcp_context = context->persist_ctxt;
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	const ip_context_t *ip_inner_context = NULL;
	struct rohc_tcp_extr_ip_bits *ip_inner_bits = NULL;
	size_t ip_contexts_nr;
	int ret;

	(*parsed_len) = 0;

	/* parse irregular IP part (IPv4/IPv6 headers and extension headers) */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		const ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[ip_contexts_nr]);
		struct rohc_tcp_extr_ip_bits *const ip_bits = &(bits->ip[ip_contexts_nr]);
		const bool is_inner_ip =
			(ip_contexts_nr == (tcp_context->ip_contexts_nr - 1));
		tcp_ip_id_behavior_t ip_id_behavior;

		if(is_inner_ip)
		{
			ip_id_behavior = innermost_ip_id_behavior;
		}
		else
		{
			ip_id_behavior = ip_context->ctxt.vx.ip_id_behavior;
		}

		ret = tcp_parse_irregular_ip(context, ip_context, remain_data, remain_len,
		                             is_inner_ip, ip_id_behavior, bits, ip_bits);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "failed to decode IP part of irregular chain");
			goto error;
		}
		assert(remain_len >= (size_t) ret);
		remain_data += ret;
		remain_len -= ret;
		(*parsed_len) += ret;

		ip_inner_context = ip_context;
		ip_inner_bits = ip_bits;
	}
	assert(ip_inner_context != NULL);

	/* parse irregular TCP part */
	ret = tcp_parse_irregular_tcp(context, remain_data, remain_len,
	                              bits, ip_inner_bits);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to decode TCP part of irregular chain");
		goto error;
	}
	assert(remain_len >= (size_t) ret);
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
 * @brief Decode the irregular IP header of the rohc packet.
 *
 * @param context         The decompression context
 * @param ip_context      The specific IP decompression context
 * @param rohc_data       The remaining part of the ROHC packet
 * @param rohc_data_len   The length of remaining part of the ROHC packet
 * @param is_innermost    True if the IP header is the innermost of the packet
 * @param ip_id_behavior  The IP-ID behavior of the IP header
 *                        (may be different from the context)
 * @param[out] bits       The bits extracted from the irregular chain
 *                        in case of success
 * @param[out] ip_bits    The bits extracted from the irregular chain for the
 *                        current IPv6 header in case of success
 * @return                The number of ROHC bytes parsed,
 *                        -1 if packet is malformed
 */
static int tcp_parse_irregular_ip(const struct rohc_decomp_ctxt *const context,
                                  const ip_context_t *const ip_context,
                                  const uint8_t *rohc_data,
                                  const size_t rohc_data_len,
                                  const bool is_innermost,
                                  const tcp_ip_id_behavior_t ip_id_behavior,
                                  struct rohc_tcp_extr_bits *const bits,
                                  struct rohc_tcp_extr_ip_bits *const ip_bits)
{
	int ret;

	rohc_decomp_debug(context, "is_innermost = %d, ttl_irregular_chain_flag = %d",
	                  is_innermost, bits->ttl_irregular_chain_flag ? 1 : 0);

	if(ip_context->ctxt.vx.version == IPV4)
	{
		ret = tcp_parse_irregular_ipv4(context, rohc_data, rohc_data_len,
		                               is_innermost, ip_id_behavior, bits, ip_bits);
	}
	else
	{
		ret = tcp_parse_irregular_ipv6(context, rohc_data, rohc_data_len,
		                               is_innermost, bits, ip_bits);
	}
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to parse the IP part of the irregular "
		                 "chain");
		goto error;
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IP irregular part", rohc_data, ret);
#endif

	return ret;

error:
	return -1;
}


/**
 * @brief Decode the irregular IPv4 header of the rohc packet.
 *
 * @param context         The decompression context
 * @param rohc_data       The remaining part of the ROHC packet
 * @param rohc_data_len   The length of remaining part of the ROHC packet
 * @param is_innermost    True if the IP header is the innermost of the packet
 * @param ip_id_behavior  The IP-ID behavior of the IP header
 *                        (may be different from the context)
 * @param[out] bits       The bits extracted from the irregular chain
 *                        in case of success
 * @param[out] ip_bits    The bits extracted from the irregular chain for the
 *                        current IPv6 header in case of success
 * @return                The number of ROHC bytes parsed,
 *                        -1 if packet is malformed
 */
static int tcp_parse_irregular_ipv4(const struct rohc_decomp_ctxt *const context,
                                    const uint8_t *rohc_data,
                                    const size_t rohc_data_len,
                                    const bool is_innermost,
                                    const tcp_ip_id_behavior_t ip_id_behavior,
                                    struct rohc_tcp_extr_bits *const bits,
                                    struct rohc_tcp_extr_ip_bits *const ip_bits)
{
	const struct d_tcp_context *const tcp_context = context->persist_ctxt;
	const uint8_t *remain_data;
	size_t remain_len;

	remain_data = rohc_data;
	remain_len = rohc_data_len;

	/* ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE ) */
	if(ip_id_behavior == IP_ID_BEHAVIOR_RAND)
	{
		uint16_t ip_id;

		if(remain_len < sizeof(uint16_t))
		{
			rohc_decomp_warn(context, "packet too short for random IP-ID: only "
			                 "%zu bytes available while at least %zu bytes "
			                 "required", remain_len, sizeof(uint16_t));
			goto error;
		}
		memcpy(&ip_id, remain_data, sizeof(uint16_t));
		remain_data += sizeof(uint16_t);
		rohc_decomp_debug(context, "read ip_id = 0x%04x (ip_id_behavior = %d)",
		                  ip_id, ip_id_behavior);
		ip_bits->id.bits = rohc_ntoh16(ip_id);
		ip_bits->id.bits_nr = 16;
		rohc_decomp_debug(context, "new IP-ID = 0x%04x", ip_bits->id.bits);
	}

	if(is_innermost)
	{
		/* ipv4_innermost_irregular: ip_inner_ecn is transmitted by the TCP part
		 * of the irregular chain */
		goto skip;
	}

	/* ipv4_outer_with_ttl_irregular or ipv4_outer_without_ttl_irregular */

	/* parse DSCP and ECN flags if present */
	if(d_tcp_is_ecn_used(*tcp_context, *bits))
	{
		if(remain_len < 1)
		{
			rohc_decomp_warn(context, "packet too short for DSCP/ECN: only %zu bytes "
			                 "available while at least 1 byte required", remain_len);
			goto error;
		}
		ip_bits->dscp_bits = (remain_data[0] >> 2) & 0x3f;
		ip_bits->dscp_bits_nr = 6;
		ip_bits->ecn_flags_bits = (remain_data[0] & 0x03);
		ip_bits->ecn_flags_bits_nr = 2;
		remain_data++;
		rohc_decomp_debug(context, "read DSCP = 0x%x, ip_ecn_flags = %d",
		                  ip_bits->dscp_bits, ip_bits->ecn_flags_bits);
	}

	/* parse TTL/HL if present */
	if(bits->ttl_irregular_chain_flag)
	{
		if(remain_len < 1)
		{
			rohc_decomp_warn(context, "packet too short for TTL/HL: only %zu bytes "
			                 "available while at least 1 byte required", remain_len);
			goto error;
		}
		ip_bits->ttl_hl.bits = remain_data[0];
		ip_bits->ttl_hl.bits_nr = 8;
		remain_data++;
		rohc_decomp_debug(context, "ttl_hopl = 0x%02x", ip_bits->ttl_hl.bits);
	}

skip:
	return (remain_data - rohc_data);

error:
	return -1;
}


/**
 * @brief Decode the irregular IPv6 header of the rohc packet.
 *
 * @param context         The decompression context
 * @param rohc_data       The remaining part of the ROHC packet
 * @param rohc_data_len   The length of remaining part of the ROHC packet
 * @param is_innermost    True if the IP header is the innermost of the packet
 * @param[out] bits       The bits extracted from the irregular chain
 *                        in case of success
 * @param[out] ip_bits    The bits extracted from the irregular chain for the
 *                        current IPv6 header in case of success
 * @return                The number of ROHC bytes parsed,
 *                        -1 if packet is malformed
 */
static int tcp_parse_irregular_ipv6(const struct rohc_decomp_ctxt *const context,
                                    const uint8_t *rohc_data,
                                    const size_t rohc_data_len,
                                    const bool is_innermost,
                                    struct rohc_tcp_extr_bits *const bits,
                                    struct rohc_tcp_extr_ip_bits *const ip_bits)
{
	const struct d_tcp_context *const tcp_context = context->persist_ctxt;
	const uint8_t *remain_data;
	size_t remain_len;

	remain_data = rohc_data;
	remain_len = rohc_data_len;

	if(is_innermost)
	{
		/* ipv6_innermost_irregular: ip_inner_ecn is transmitted by the TCP part
		 * of the irregular chain */
		goto skip;
	}

	/* ipv6_outer_without_ttl_irregular or ipv6_outer_with_ttl_irregular */

	/* parse DSCP and ECN flags if present */
	if(d_tcp_is_ecn_used(*tcp_context, *bits))
	{
		if(remain_len < 1)
		{
			rohc_decomp_warn(context, "packet too short for DSCP/ECN: only %zu bytes "
			                 "available while at least 1 byte required", remain_len);
			goto error;
		}
		ip_bits->dscp_bits = (remain_data[0] >> 2) & 0x3f;
		ip_bits->dscp_bits_nr = 6;
		ip_bits->ecn_flags_bits = (remain_data[0] & 0x03);
		ip_bits->ecn_flags_bits_nr = 2;
		remain_data++;
		rohc_decomp_debug(context, "read DSCP = 0x%x, ip_ecn_flags = %d",
		                  ip_bits->dscp_bits, ip_bits->ecn_flags_bits);
	}

	/* parse TTL/HL if present */
	if(bits->ttl_irregular_chain_flag)
	{
		if(remain_len < 1)
		{
			rohc_decomp_warn(context, "packet too short for TTL/HL: only %zu bytes "
			                 "available while at least 1 byte required", remain_len);
			goto error;
		}
		ip_bits->ttl_hl.bits = remain_data[0];
		ip_bits->ttl_hl.bits_nr = 8;
		remain_data++;
		rohc_decomp_debug(context, "ttl_hopl = 0x%02x", ip_bits->ttl_hl.bits);
	}

skip:
	return (remain_data - rohc_data);

error:
	return -1;
}


/**
 * @brief Decode the irregular TCP header of the rohc packet.
 *
 * See RFC4996 page 75
 *
 * @param context             The decompression context
 * @param rohc_data           The remain data of the rohc packet
 * @param rohc_data_len       The length of the remain data of the rohc packet
 * @param[out] bits           The bits extracted from the TCP part of the
 *                            irregular chain
 * @param[out] ip_inner_bits  The bits extracted from the innermost IP part of
 *                            the irregular chain
 * @return                    The number of ROHC bytes parsed,
 *                            -1 if packet is malformed
 */
static int tcp_parse_irregular_tcp(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const rohc_data,
                                   const size_t rohc_data_len,
                                   struct rohc_tcp_extr_bits *const bits,
                                   struct rohc_tcp_extr_ip_bits *const ip_inner_bits)
{
	const struct d_tcp_context *const tcp_context = context->persist_ctxt;
	const uint8_t *remain_data = rohc_data;
	size_t remain_len = rohc_data_len;
	int ret;

	rohc_decomp_debug(context, "decode TCP irregular chain");

	/* parse IP ECN flags, RES flags, and TCP ECN flags if present */
	if(d_tcp_is_ecn_used(*tcp_context, *bits))
	{
		if(remain_len < 1)
		{
			rohc_decomp_warn(context, "packet too short for ECN: only %zu bytes "
			                 "available while at least 1 byte required", remain_len);
			goto error;
		}
		/* innermost IP ECN flags */
		ip_inner_bits->ecn_flags_bits = (remain_data[0] >> 6) & 0x3;
		ip_inner_bits->ecn_flags_bits_nr = 2;
		rohc_decomp_debug(context, "inner IP ECN flags = 0x%x",
		                  ip_inner_bits->ecn_flags_bits);
		/* TCP RES flags */
		bits->res_flags_bits = (remain_data[0] >> 2) & 0x0f;
		bits->res_flags_bits_nr = 4;
		rohc_decomp_debug(context, "TCP RES flags = 0x%x", bits->res_flags_bits);
		/* TCP ECN flags */
		bits->ecn_flags_bits = remain_data[0] & 0x03;
		bits->ecn_flags_bits_nr = 2;
		rohc_decomp_debug(context, "TCP ECN flags = 0x%x", bits->ecn_flags_bits);
		remain_data++;
		remain_len--;
	}

	/* parse TCP checksum */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_decomp_warn(context, "packet too short for TCP checksum: only %zu "
		                 "bytes available while at least %zu bytes required",
		                 remain_len, sizeof(uint16_t));
		goto error;
	}
	memcpy(&bits->tcp_check, remain_data, sizeof(uint16_t));
	bits->tcp_check = rohc_ntoh16(bits->tcp_check);
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "TCP checksum = 0x%04x", bits->tcp_check);

	/* complete TCP options with the irregular part */
	ret = d_tcp_parse_tcp_opts_irreg(context, remain_data, remain_len,
	                                 &bits->tcp_opts);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to parse optional compressed list "
		                 "of TCP options");
		goto error;
	}
	rohc_decomp_debug(context, "compressed list of TCP options = %d bytes", ret);
	remain_data += ret;
	remain_len -= ret;

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "TCP irregular part", rohc_data, rohc_data_len - remain_len);

	return (rohc_data_len - remain_len);

error:
	return -1;
}


/**
 * @brief Determine whether the TCP ECN flags are used or not
 *
 * The bits extracted from the current ROHC packet are used if present. The
 * value recorded in the decompression context is used as fallback otherwise.
 *
 * @param tcp_ctxt   The TCP decompression context
 * @param bits       The bits extracted from the ROHC packet
 * @return           true if the TCP ECN flags are used by the compressed
 *                   TCP packet or not, false if they are not
 */
static bool d_tcp_is_ecn_used(const struct d_tcp_context tcp_ctxt,
                              const struct rohc_tcp_extr_bits bits)
{
	return ((bits.ecn_used_bits_nr > 0) ? (!!bits.ecn_used_bits) : tcp_ctxt.ecn_used);
}

