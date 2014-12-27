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

#include "d_tcp_defines.h"
#include "rohc_utils.h"
#include "schemes/decomp_wlsb.h"
#include "schemes/tcp_ts.h"
#include "schemes/tcp_sack.h"

#ifndef __KERNEL__
#  include <string.h>
#endif

static int tcp_parse_irregular_ip(struct rohc_decomp_ctxt *const context,
                                  ip_context_t *const ip_context,
                                  const uint8_t *rohc_data,
                                  const size_t rohc_data_len,
                                  const bool is_innermost,
                                  const bool ttl_irregular_chain_flag,
                                  const uint8_t ip_ecn_flags)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int tcp_parse_irregular_tcp(struct rohc_decomp_ctxt *const context,
                                   ip_context_t *const ip_inner_context,
                                   const uint8_t *const rohc_data,
                                   const size_t rohc_data_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));


/**
 * @brief Parse the irregular chain of the ROHC packet
 *
 * @param context                   The decompression context
 * @param rohc_packet               The remaining part of the ROHC packet
 * @param rohc_length               The remaining length (in bytes) of ROHC packet
 * @param ttl_irregular_chain_flag  true if one of the TTL value of header changed
 * @param[out] parsed_len           The length (in bytes) of static chain in case
 *                                  of success
 * @return                          true in the irregular chain was successfully
 *                                  parsed, false if the ROHC packet was malformed
 */
bool tcp_parse_irreg_chain(struct rohc_decomp_ctxt *const context,
                           const uint8_t *const rohc_packet,
                           const size_t rohc_length,
                           const bool ttl_irregular_chain_flag,
                           size_t *const parsed_len)
{
	struct d_tcp_context *tcp_context = context->specific;
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	ip_context_t *ip_inner_context = NULL;
	size_t ip_contexts_nr;
	int ret;

	(*parsed_len) = 0;

	/* parse irregular IP part (IPv4/IPv6 headers and extension headers) */
	for(ip_contexts_nr = 0; ip_contexts_nr < tcp_context->ip_contexts_nr;
	    ip_contexts_nr++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_contexts_nr]);
		const bool is_inner_ip =
			(ip_contexts_nr == (tcp_context->ip_contexts_nr - 1));
		const uint8_t ip_ecn_flags = ip_context->ctxt.vx.ip_ecn_flags;

		ret = tcp_parse_irregular_ip(context, ip_context, remain_data, remain_len,
		                             is_inner_ip, ttl_irregular_chain_flag,
		                             ip_ecn_flags);
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
	}
	assert(ip_inner_context != NULL);

	/* parse irregular TCP part */
	ret = tcp_parse_irregular_tcp(context, ip_inner_context, remain_data, remain_len);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to decode TCP part of irregular chain");
		goto error;
	}
	assert(remain_len >= (size_t) ret);
	remain_data += ret;
	remain_len -= ret;
	(*parsed_len) += ret;

	return true;

error:
	return false;
}


/**
 * @brief Decode the irregular IP header of the rohc packet.
 *
 * @param context                   The decompression context
 * @param ip_context                The specific IP decompression context
 * @param rohc_data                 The remaining part of the ROHC packet
 * @param rohc_data_len             The length of remaining part of the ROHC packet
 * @param is_innermost              True if the IP header is the innermost of the packet
 * @param ttl_irregular_chain_flag  true if one of the TTL value of header changed
 * @param ip_ecn_flags              The 2-bit ECN flags of the IP header
 * @return                          The number of ROHC bytes parsed,
 *                                  -1 if packet is malformed
 */
static int tcp_parse_irregular_ip(struct rohc_decomp_ctxt *const context,
                                  ip_context_t *const ip_context,
                                  const uint8_t *rohc_data,
                                  const size_t rohc_data_len,
                                  const bool is_innermost,
                                  const bool ttl_irregular_chain_flag,
                                  const uint8_t ip_ecn_flags)
{
	struct d_tcp_context *tcp_context = context->specific;
	const uint8_t *remain_data;
	size_t remain_len;

	assert((ip_ecn_flags & 0x3) == ip_ecn_flags);

	remain_data = rohc_data;
	remain_len = rohc_data_len;

	rohc_decomp_debug(context, "is_innermost = %d, ttl_irregular_chain_flag = %d, "
	                  "ip_ecn_flags = %d", is_innermost,
	                  ttl_irregular_chain_flag ? 1 : 0, ip_ecn_flags);

	if(ip_context->ctxt.vx.version == IPV4)
	{
		// ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE )
		if(ip_context->ctxt.v4.ip_id_behavior == IP_ID_BEHAVIOR_RAND)
		{
			uint16_t ip_id;

			if(remain_len < sizeof(uint16_t))
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
				             "packet too short for random IP-ID: only %zu bytes "
				             "available while at least %zu bytes required",
				             remain_len, sizeof(uint16_t));
				goto error;
			}
			memcpy(&ip_id, remain_data, sizeof(uint16_t));
			remain_data += sizeof(uint16_t);
			rohc_decomp_debug(context, "read ip_id = 0x%04x (ip_id_behavior = %d)",
			                  ip_id, ip_context->ctxt.v4.ip_id_behavior);
			ip_context->ctxt.v4.ip_id = rohc_ntoh16(ip_id);
			rohc_decomp_debug(context, "new IP-ID = 0x%04x",
			                  ip_context->ctxt.v4.ip_id);
		}
		if(is_innermost)
		{
			/* ipv4_innermost_irregular */
			ip_context->ctxt.v4.ip_ecn_flags = ip_ecn_flags;
		}
		else
		{
			/* ipv4_outer_with_ttl_irregular or ipv4_outer_without_ttl_irregular */
			if(tcp_context->ecn_used != 0)
			{
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
					             "packet too short for DSCP/ECN: only %zu bytes "
					             "available while at least 1 byte required", remain_len);
					goto error;
				}
				/* dscp =:= static_or_irreg(ecn_used.UVALUE) */
				ip_context->ctxt.v4.dscp = remain_data[0] >> 2;
				/* ip_ecn_flags =:= static_or_irreg(ecn_used.UVALUE) */
				ip_context->ctxt.v4.ip_ecn_flags = remain_data[0] & 0x03;
				remain_data++;
				rohc_decomp_debug(context, "read DSCP = 0x%x, ip_ecn_flags = %d",
				                  ip_context->ctxt.v4.dscp,
				                  ip_context->ctxt.v4.ip_ecn_flags);
			}
			if(ttl_irregular_chain_flag)
			{
				/* ipv4_outer_with_ttl_irregular only */
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
					             "packet too short for TTL/HL: only %zu bytes "
					             "available while at least 1 byte required", remain_len);
					goto error;
				}
				/* ttl_hopl =:= irregular(8) */
				ip_context->ctxt.v4.ttl_hopl = remain_data[0];
				remain_data++;
				rohc_decomp_debug(context, "read ttl_hopl = 0x%x",
				                  ip_context->ctxt.v4.ttl_hopl);
			}
		}
	}
	else
	{
		// IPv6
		if(!is_innermost)
		{
			// ipv6_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(tcp_context->ecn_used != 0)
			{
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
					             "packet too short for DSCP/ECN: only %zu bytes "
					             "available while at least 1 byte required", remain_len);
					goto error;
				}
				ip_context->ctxt.v6.dscp = (remain_data[0] >> 2) & 0x3f;
				ip_context->ctxt.v6.ip_ecn_flags = (remain_data[0] & 0x03);
				remain_data++;
			}
			if(ttl_irregular_chain_flag)
			{
				if(remain_len < 1)
				{
					rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
					             "packet too short for TTL/HL: only %zu bytes "
					             "available while at least 1 byte required", remain_len);
					goto error;
				}
				// ipv6_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				ip_context->ctxt.v6.ttl_hopl = remain_data[0];
				remain_data++;
				rohc_decomp_debug(context, "read ttl_hopl = 0x%x",
				                  ip_context->ctxt.v6.ttl_hopl);
			}
			/* else: ipv6_outer_without_ttl_irregular */
		}
		/* else: ipv6_innermost_irregular */
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "IP irregular part", rohc_data, remain_data - rohc_data);
#endif

	return (remain_data - rohc_data);

error:
	return -1;
}


/**
 * @brief Decode the irregular TCP header of the rohc packet.
 *
 * See RFC4996 page 75
 *
 * @param context           The decompression context
 * @param ip_inner_context  The context of the inner IP header
 * @param rohc_data         The remain data of the rohc packet
 * @param rohc_data_len     The length of the remain data of the rohc packet
 * @return                  The number of ROHC bytes parsed,
 *                          -1 if packet is malformed
 */
static int tcp_parse_irregular_tcp(struct rohc_decomp_ctxt *const context,
                                   ip_context_t *const ip_inner_context,
                                   const uint8_t *const rohc_data,
                                   const size_t rohc_data_len)
{
	struct d_tcp_context *const tcp_context = context->specific;
	const uint8_t *remain_data;
	size_t remain_len;
	uint8_t *tcp_options = tcp_context->options;
	size_t tcp_opts_len;
	size_t opt_padding_len;
	size_t i;
	int ret;

	rohc_decomp_debug(context, "decode TCP irregular chain");

	remain_data = rohc_data;
	remain_len = rohc_data_len;

	// ip_ecn_flags = := tcp_irreg_ip_ecn(ip_inner_ecn)
	// tcp_res_flags =:= static_or_irreg(ecn_used.CVALUE,4)
	// tcp_ecn_flags =:= static_or_irreg(ecn_used.CVALUE,2)
	if(tcp_context->ecn_used != 0)
	{
		// See RFC4996 page 71
		if(remain_len < 1)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
			             "packet too short for ECN: only %zu bytes available "
			             "while at least 1 byte required", remain_len);
			goto error;
		}
		if(ip_inner_context->ctxt.vx.version == IPV4)
		{
			ip_inner_context->ctxt.v4.ip_ecn_flags = (remain_data[0] >> 6);
			rohc_decomp_debug(context, "read ip_ecn_flags = %d",
			                  ip_inner_context->ctxt.v4.ip_ecn_flags);
		}
		else
		{
			ip_inner_context->ctxt.v6.ip_ecn_flags = (remain_data[0] >> 6);
			rohc_decomp_debug(context, "read ip_ecn_flags = %d",
			                  ip_inner_context->ctxt.v6.ip_ecn_flags);
		}
		tcp_context->ecn_flags = (remain_data[0] >> 4) & 0x03;
		tcp_context->res_flags = remain_data[0] & 0x0f;
		remain_data++;
		remain_len--;
		rohc_decomp_debug(context, "read TCP ecn_flags = %d, res_flags = %d",
		                  tcp_context->ecn_flags, tcp_context->res_flags);
	}
	else
	{
		// See RFC4996 page 71
		if(ip_inner_context->ctxt.vx.version == IPV4)
		{
			ip_inner_context->ctxt.v4.ip_ecn_flags = 0;
		}
		else
		{
			ip_inner_context->ctxt.v6.ip_ecn_flags = 0;
		}
		tcp_context->ecn_flags = 0;
		tcp_context->res_flags = 0;
		rohc_decomp_debug(context, "ip_ecn_flag = 0, tcp_ecn_flag = 0, and "
		                  "tcp_res_flag = 0");
	}

	// checksum =:= irregular(16)
	if(remain_len < sizeof(uint16_t))
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, ROHC_PROFILE_TCP,
		             "packet too short for TCP checksum: only %zu bytes available "
		             "while at least %zu bytes required", remain_len,
		             sizeof(uint16_t));
		goto error;
	}
	memcpy(&tcp_context->checksum, remain_data, sizeof(uint16_t));
	remain_data += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);
	rohc_decomp_debug(context, "read TCP checksum = 0x%04x",
	                  rohc_ntoh16(tcp_context->checksum));

	/* complete TCP options with the irregular part */
	tcp_opts_len = 0;
	for(i = 0;
	    i < ROHC_TCP_OPTS_MAX && tcp_context->tcp_opts_list_struct[i] != 0xff;
	    i++)
	{
		if(tcp_context->is_tcp_opts_list_item_present[i])
		{
			const uint8_t opt_type = tcp_context->tcp_opts_list_struct[i];
			const uint8_t opt_len = tcp_context->tcp_opts_list_item_uncomp_length[i];
			assert(tcp_context->tcp_opts_list_item_uncomp_length[i] <= 0xff);
			rohc_decomp_debug(context, "TCP irregular part: option %u is not present",
			                  opt_type);
			if((tcp_opts_len + opt_len) > MAX_TCP_OPTIONS_LEN)
			{
				rohc_decomp_warn(context, "not enough room in context to store "
				                 "the %u-byte option %u: room is only %lu "
				                 "bytes and %zu bytes of options are already in",
				                 opt_len, opt_type, MAX_TCP_OPTIONS_LEN, tcp_opts_len);
				goto error;
			}
			tcp_options += tcp_context->tcp_opts_list_item_uncomp_length[i];
			tcp_opts_len += tcp_context->tcp_opts_list_item_uncomp_length[i];
		}
		else
		{
			rohc_decomp_debug(context, "TCP irregular part: option %u is present",
			                  tcp_context->tcp_opts_list_struct[i]);
			if((tcp_opts_len + 1) > MAX_TCP_OPTIONS_LEN)
			{
				rohc_decomp_warn(context, "not enough room in context to store "
				                 "the option type: room is only %lu bytes and %zu "
				                 "bytes of options are already in",
				                 MAX_TCP_OPTIONS_LEN, tcp_opts_len);
				goto error;
			}
			tcp_options[0] = tcp_context->tcp_opts_list_struct[i];
			tcp_options++;
			tcp_opts_len++;

			switch(tcp_context->tcp_opts_list_struct[i])
			{
				case TCP_OPT_NOP:
				case TCP_OPT_EOL:
					break;
				case TCP_OPT_MAXSEG:
					if((tcp_opts_len + TCP_OLEN_MAXSEG - 1) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "not enough room in context to store "
						                 "the %u-byte MSS option: room is only %lu "
						                 "bytes and %zu bytes of options are already in",
						                 TCP_OLEN_MAXSEG - 1, MAX_TCP_OPTIONS_LEN,
						                 tcp_opts_len);
						goto error;
					}
					// Length
					tcp_options[0] = TCP_OLEN_MAXSEG;
					tcp_options++;
					tcp_opts_len++;
					// Max segment size value
					memcpy(tcp_options, &tcp_context->tcp_option_maxseg, 2);
					tcp_options += TCP_OLEN_MAXSEG - 2;
					tcp_opts_len += TCP_OLEN_MAXSEG - 2;
					break;
				case TCP_OPT_WINDOW:
					if((tcp_opts_len + TCP_OLEN_WINDOW - 1) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "not enough room in context to store "
						                 "the %u-byte Window option: room is only %lu "
						                 "bytes and %zu bytes of options are already in",
						                 TCP_OLEN_WINDOW - 1, MAX_TCP_OPTIONS_LEN,
						                 tcp_opts_len);
						goto error;
					}
					// Length
					tcp_options[0] = TCP_OLEN_WINDOW;
					tcp_options++;
					tcp_opts_len++;
					// Window scale value
					tcp_options[0] = tcp_context->tcp_option_window;
					tcp_options++;
					tcp_opts_len++;
					break;
				case TCP_OPT_TIMESTAMP:
				{
					struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (tcp_options + 1);

					if(!rohc_lsb_is_ready(tcp_context->opt_ts_req_lsb_ctxt) ||
					   !rohc_lsb_is_ready(tcp_context->opt_ts_reply_lsb_ctxt))
					{
						rohc_decomp_warn(context, "compressor sent a compressed TCP "
						                 "Timestamp option, but uncompressed value "
						                 "was not received yet");
						goto error;
					}

					if((tcp_opts_len + TCP_OLEN_TIMESTAMP - 1) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "not enough room in context to store "
						                 "the %u-byte Timestamp option: room is only "
						                 "%lu bytes and %zu bytes of options are "
						                 "already in", TCP_OLEN_TIMESTAMP - 1,
						                 MAX_TCP_OPTIONS_LEN, tcp_opts_len);
						goto error;
					}

					// Length
					tcp_options[0] = TCP_OLEN_TIMESTAMP;
					tcp_options++;
					tcp_opts_len++;

					/* decode TS echo request with method ts_lsb() */
					ret = d_tcp_ts_lsb_decode(context, tcp_context->opt_ts_req_lsb_ctxt,
					                          remain_data, remain_len,
					                          (uint32_t *) &opt_ts->ts);
					if(ret < 0)
					{
						rohc_decomp_warn(context, "TCP irregular part: failed to "
						                 "decompress TCP option Timestamp echo "
						                 "request");
						goto error;
					}
					remain_data += ret;
					remain_len -= ret;
					/* TODO: set ref later */
					rohc_lsb_set_ref(tcp_context->opt_ts_req_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts), false);

					/* decode TS echo reply with method ts_lsb() */
					ret = d_tcp_ts_lsb_decode(context, tcp_context->opt_ts_reply_lsb_ctxt,
					                          remain_data, remain_len,
					                          (uint32_t *) &opt_ts->ts_reply);
					if(ret < 0)
					{
						rohc_decomp_warn(context, "TCP irregular part: failed to "
						                 "decompress TCP option Timestamp echo "
						                 "reply");
						goto error;
					}
					remain_data += ret;
					remain_len -= ret;
					/* TODO: set ref later */
					rohc_lsb_set_ref(tcp_context->opt_ts_reply_lsb_ctxt,
					                 rohc_ntoh32(opt_ts->ts_reply), false);

					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;

					tcp_options += TCP_OLEN_TIMESTAMP - 2;
					tcp_opts_len += TCP_OLEN_TIMESTAMP - 2;
					break;
				}
				case TCP_OPT_SACK_PERMITTED:
					if((tcp_opts_len + TCP_OLEN_SACK_PERMITTED - 1) > MAX_TCP_OPTIONS_LEN)
					{
						rohc_decomp_warn(context, "not enough room in context to store "
						                 "the %u-byte SACK permitted option: room is "
						                 "only %lu bytes and %zu bytes of options are "
						                 "already in", TCP_OLEN_SACK_PERMITTED - 1,
						                 MAX_TCP_OPTIONS_LEN, tcp_opts_len);
						goto error;
					}
					// Length
					tcp_options[0] = TCP_OLEN_SACK_PERMITTED;
					tcp_options++;
					tcp_opts_len++;
					break;
				case TCP_OPT_SACK:
				{
					size_t opt_remain_len = MAX_TCP_OPTIONS_LEN - tcp_opts_len;
					size_t sack_opt_len;

					tcp_options--; /* remove option type */
					tcp_opts_len--;
					opt_remain_len++;
					ret = d_tcp_sack_decode(context, remain_data, remain_len,
					                        tcp_options, &sack_opt_len, opt_remain_len,
					                        rohc_ntoh32(tcp_context->ack_num));
					if(ret < 0)
					{
						rohc_decomp_warn(context, "failed to decompress TCP SACK "
						                 "option");
						goto error;
					}
					remain_data += ret;
					remain_len -= ret;
					tcp_options += sack_opt_len;
					tcp_opts_len += sack_opt_len;
					break;
				}
				default:  // Generic options
					rohc_decomp_debug(context, "TCP option %u not handled",
					                  tcp_context->tcp_opts_list_struct[i]);
					break;
			}
		}
	}
	assert(i <= ROHC_TCP_OPTS_MAX);
	assert(tcp_opts_len <= MAX_TCP_OPTIONS_LEN);

	/* add padding after TCP options (they must be aligned on 32-bit words) */
	opt_padding_len = sizeof(uint32_t) - (tcp_opts_len % sizeof(uint32_t));
	opt_padding_len %= sizeof(uint32_t);
	if((tcp_opts_len + opt_padding_len) > MAX_TCP_OPTIONS_LEN)
	{
		rohc_decomp_warn(context, "malformed TCP options: more than %lu bytes "
		                 "of TCP options: %zu bytes already in + %zu-byte padding",
		                 MAX_TCP_OPTIONS_LEN, tcp_opts_len, opt_padding_len);
		goto error;
	}
	for(i = 0; i < opt_padding_len; i++)
	{
		rohc_decomp_debug(context, "  add missing TCP EOL option for padding");
		tcp_options[0] = TCP_OPT_EOL;
		tcp_options++;
	}
	tcp_opts_len += opt_padding_len;
	assert((tcp_opts_len % sizeof(uint32_t)) == 0);

	rohc_dump_buf(context->decompressor->trace_callback,
	              context->decompressor->trace_callback_priv,
	              ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	              "TCP irregular part", rohc_data, rohc_data_len - remain_len);

	tcp_context->options_len = tcp_opts_len;
	return (rohc_data_len - remain_len);

error:
	return -1;
}

