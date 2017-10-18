/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2008,2009,2010,2012,2013 Viveris Technologies
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
 * @file d_udp_lite.c
 * @brief ROHC decompression context for the UDP-Lite profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_ip.h"
#include "d_udp.h"
#include "rohc_decomp_rfc3095.h"
#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "rohc_packets.h"
#include "crc.h"
#include "protocols/udp_lite.h"

#include <string.h>


/*
 * Private structures.
 */

/**
 * @brief Define the UDP-Lite part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context rohc_decomp_rfc3095_ctxt.
 *
 * @see rohc_decomp_rfc3095_ctxt
 */
struct d_udp_lite_context
{
	uint16_t sport;             /**< UDP source port */
	uint16_t dport;             /**< UDP destination port */

	/** Whether the UDP-Lite checksum coverage field is present or not */
	rohc_tristate_t cfp;
	/** Whether the UDP-Lite checksum coverage field can be inferred or not */
	rohc_tristate_t cfi;
	/** The Checksum Coverage (CC) */
	uint16_t cc;
};


/*
 * Private function prototypes.
 */

static bool d_udp_lite_create(const struct rohc_decomp_ctxt *const context,
                              struct rohc_decomp_rfc3095_ctxt **const persist_ctxt,
                              struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static void d_udp_lite_destroy(struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                               const struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((nonnull(1, 2)));

static rohc_packet_t udp_lite_detect_packet_type(const struct rohc_decomp_ctxt *const context,
                                                 const uint8_t *const rohc_packet,
                                                 const size_t rohc_length,
                                                 const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool d_udp_lite_parse(const struct rohc_decomp_ctxt *const context,
                             const struct rohc_buf rohc_packet,
                             const size_t large_cid_len,
                             rohc_packet_t *const packet_type,
                             struct rohc_decomp_crc *const extr_crc,
                             struct rohc_extr_bits *const bits,
                             size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 4, 5, 6, 7)));

static int udp_lite_parse_dynamic_udp(const struct rohc_decomp_ctxt *const context,
                                      const uint8_t *packet,
                                      const size_t length,
                                      struct rohc_extr_bits *const bits);

static int udp_lite_parse_uo_remainder(const struct rohc_decomp_ctxt *const context,
                                       const uint8_t *packet,
                                       unsigned int length,
                                       struct rohc_extr_bits *const bits);

static bool udp_lite_decode_values_from_bits(const struct rohc_decomp_ctxt *context,
                                             const struct rohc_extr_bits *const bits,
                                             struct rohc_decoded_values *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int udp_lite_build_uncomp_udp(const struct rohc_decomp_ctxt *const context,
                                     const struct rohc_decoded_values *const decoded,
                                     uint8_t *const dest,
                                     const unsigned int payload_len);

static void udp_lite_update_context(struct rohc_decomp_ctxt *const context,
                                    const struct rohc_decoded_values *const decoded)
	__attribute__((nonnull(1, 2)));


/*
 * Definitions of functions.
 */

/**
 * @brief Create the UDP-Lite decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context            The main decompression context
 * @param[out] persist_ctxt  The persistent part of the decompression context
 * @param[out] volat_ctxt    The volatile part of the decompression context
 * @return                   true if the UDP-Lite context was successfully created,
 *                           false if a problem occurred
 */
static bool d_udp_lite_create(const struct rohc_decomp_ctxt *const context,
                              struct rohc_decomp_rfc3095_ctxt **const persist_ctxt,
                              struct rohc_decomp_volat_ctxt *const volat_ctxt)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_udp_lite_context *udp_lite_context;

	assert(context != NULL);
	assert(context->decompressor != NULL);
	assert(context->profile != NULL);

	/* create the generic context */
	if(!rohc_decomp_rfc3095_create(context, persist_ctxt, volat_ctxt,
	                               context->decompressor->trace_callback,
	                               context->decompressor->trace_callback_priv,
	                               context->profile->id))
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the generic decompression context");
		goto quit;
	}
	rfc3095_ctxt = *persist_ctxt;

	/* create the UDP-Lite-specific part of the context */
	udp_lite_context = malloc(sizeof(struct d_udp_lite_context));
	if(udp_lite_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-Lite-specific context");
		goto destroy_context;
	}
	memset(udp_lite_context, 0, sizeof(struct d_udp_lite_context));
	rfc3095_ctxt->specific = udp_lite_context;

	/* create the LSB decoding context for SN */
	rfc3095_ctxt->sn_lsb_p = ROHC_LSB_SHIFT_SN;
	rfc3095_ctxt->sn_lsb_ctxt = rohc_lsb_new(16);
	if(rfc3095_ctxt->sn_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for SN");
		goto free_udp_context;
	}

	/* the UDP-Lite checksum coverage field present flag will be initialized
	 * with the IR or IR-DYN packets */
	udp_lite_context->cfp = ROHC_TRISTATE_NONE;
	udp_lite_context->cfi = ROHC_TRISTATE_NONE;

	/* some UDP-Lite-specific values and functions */
	rfc3095_ctxt->next_header_len = sizeof(struct udphdr);
	rfc3095_ctxt->parse_static_next_hdr = udp_parse_static_udp;
	rfc3095_ctxt->parse_dyn_next_hdr = udp_lite_parse_dynamic_udp;
	rfc3095_ctxt->parse_ext3 = ip_parse_ext3;
	rfc3095_ctxt->parse_uo_remainder = udp_lite_parse_uo_remainder;
	rfc3095_ctxt->decode_values_from_bits = udp_lite_decode_values_from_bits;
	rfc3095_ctxt->build_next_header = udp_lite_build_uncomp_udp;
	rfc3095_ctxt->compute_crc_static = udp_compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = udp_compute_crc_dynamic;
	rfc3095_ctxt->update_context = udp_lite_update_context;

	/* create the UDP-Lite-specific part of the header changes */
	rfc3095_ctxt->outer_ip_changes->next_header_len = sizeof(struct udphdr);
	rfc3095_ctxt->outer_ip_changes->next_header = malloc(sizeof(struct udphdr));
	if(rfc3095_ctxt->outer_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-Lite-specific part "
		           "of the outer IP header changes");
		goto free_lsb_sn;
	}
	memset(rfc3095_ctxt->outer_ip_changes->next_header, 0, sizeof(struct udphdr));

	rfc3095_ctxt->inner_ip_changes->next_header_len = sizeof(struct udphdr);
	rfc3095_ctxt->inner_ip_changes->next_header = malloc(sizeof(struct udphdr));
	if(rfc3095_ctxt->inner_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-Lite-specific part "
		           "of the inner IP header changes");
		goto free_outer_ip_changes_next_header;
	}
	memset(rfc3095_ctxt->inner_ip_changes->next_header, 0, sizeof(struct udphdr));

	/* set next header to UDP-Lite */
	rfc3095_ctxt->next_header_proto = ROHC_IPPROTO_UDPLITE;

	return true;

free_outer_ip_changes_next_header:
	zfree(rfc3095_ctxt->outer_ip_changes->next_header);
free_lsb_sn:
	rohc_lsb_free(rfc3095_ctxt->sn_lsb_ctxt);
free_udp_context:
	zfree(udp_lite_context);
destroy_context:
	rohc_decomp_rfc3095_destroy(rfc3095_ctxt, volat_ctxt);
quit:
	return false;
}


/**
 * @brief Destroy the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param rfc3095_ctxt  The persistent decompression context for the RFC3095 profiles
 * @param volat_ctxt    The volatile decompression context
 */
static void d_udp_lite_destroy(struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                               const struct rohc_decomp_volat_ctxt *const volat_ctxt)
{
	/* clean UDP-specific memory */
	assert(rfc3095_ctxt->outer_ip_changes != NULL);
	zfree(rfc3095_ctxt->outer_ip_changes->next_header);
	assert(rfc3095_ctxt->inner_ip_changes != NULL);
	zfree(rfc3095_ctxt->inner_ip_changes->next_header);

	/* destroy the LSB decoding context for SN */
	rohc_lsb_free(rfc3095_ctxt->sn_lsb_ctxt);

	/* destroy the resources of the generic context */
	rohc_decomp_rfc3095_destroy(rfc3095_ctxt, volat_ctxt);
}


/**
 * @brief Detect the type of ROHC packet for the UDP-Lite profile
 *
 * Parse optional CCE packet type, then normal packet type.
 *
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
static rohc_packet_t udp_lite_detect_packet_type(const struct rohc_decomp_ctxt *const context,
                                                 const uint8_t *const rohc_packet,
                                                 const size_t rohc_length,
                                                 const size_t large_cid_len)
{
	size_t new_large_cid_len;

	/* remaining ROHC data not parsed yet */
	const uint8_t *rohc_remain_data = rohc_packet;
	size_t rohc_remain_len = rohc_length;

	/* check if the ROHC packet is large enough to read the first byte */
	if(rohc_remain_len < (1 + large_cid_len))
	{
		rohc_decomp_warn(context, "ROHC packet too small to read the packet "
		                 "type (len = %zu)", rohc_remain_len);
		goto error;
	}

	/* find whether the IR packet owns an Coverage Checksum Extension or not */
	switch(rohc_remain_data[0])
	{
		case 0xf9: /* CCE() */
			rohc_decomp_debug(context, "CCE()");
			/* skip CCE byte (and optional large CID field) */
			rohc_remain_data += 1 + large_cid_len;
			rohc_remain_len -= 1 + large_cid_len;
			new_large_cid_len = 0;
			break;
		case 0xfa: /* CEC(ON) */
			rohc_decomp_debug(context, "CCE(ON)");
			/* skip CCE byte (and optional large CID field) */
			rohc_remain_data += 1 + large_cid_len;
			rohc_remain_len -= 1 + large_cid_len;
			new_large_cid_len = 0;
			break;
		case 0xfb: /* CCE(OFF) */
			rohc_decomp_debug(context, "CCE(OFF)");
			/* no CCE byte to skip */
			new_large_cid_len = large_cid_len;
			break;
		default:
			rohc_decomp_debug(context, "CCE not present");
			/* no CCE byte to skip */
			new_large_cid_len = large_cid_len;
			break;
	}

	/* CCE is now parsed, fallback on same detection scheme as other IP-based
	 * non-RTP profiles */
	return ip_detect_packet_type(context, rohc_remain_data, rohc_remain_len,
	                             new_large_cid_len);

error:
	return ROHC_PACKET_UNKNOWN;
}


/**
 * @brief Decode one IR, IR-DYN or UO* packet for UDP-Lite profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to decode
 * @param large_cid_len        The length of the optional large CID field
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] extr_crc        The CRC bits extracted from the ROHC header
 * @param[out] bits            The bits extracted from the ROHC header
 * @param[out] rohc_hdr_len    The length of the ROHC header (in bytes)
 * @return                     true if packet is successfully parsed,
 *                             false otherwise
 */
static bool d_udp_lite_parse(const struct rohc_decomp_ctxt *const context,
                             const struct rohc_buf rohc_packet,
                             const size_t large_cid_len,
                             rohc_packet_t *const packet_type,
                             struct rohc_decomp_crc *const extr_crc,
                             struct rohc_extr_bits *const bits,
                             size_t *const rohc_hdr_len)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	const struct d_udp_lite_context *const udp_lite_context = rfc3095_ctxt->specific;
	struct rohc_buf rohc_remain_data = rohc_packet;
	size_t new_large_cid_len;

	bits->cfp = udp_lite_context->cfp;
	bits->cfi = udp_lite_context->cfi;

	/* check if the ROHC packet is large enough to read the first byte */
	if(rohc_remain_data.len < (1 + large_cid_len))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu bytes)",
		                 rohc_remain_data.len);
		goto error_malformed;
	}

	/* find whether the packet owns an Coverage Checksum Extension or not */
	switch(rohc_buf_byte(rohc_remain_data))
	{
		case 0xf9: /* CCE() */
			rohc_decomp_debug(context, "CCE()");
			bits->cce_pkt = ROHC_PACKET_CCE;
			bits->cfp = ROHC_TRISTATE_YES;
			break;
		case 0xfa: /* CEC(ON) */
			rohc_decomp_debug(context, "CCE(ON)");
			bits->cce_pkt = ROHC_PACKET_CCE_ON;
			bits->cfp = ROHC_TRISTATE_YES;
			break;
		case 0xfb: /* CCE(OFF) */
			rohc_decomp_debug(context, "CCE(OFF)");
			bits->cce_pkt = ROHC_PACKET_CCE_OFF;
			bits->cfp = ROHC_TRISTATE_NO;
			break;
		default:
			rohc_decomp_debug(context, "CCE not present");
			bits->cce_pkt = ROHC_PACKET_CCE_OTHER;
			break;
	}

	/* if the CE extension is present, skip the CCE byte type (and the
	 * optional large CID field) */
	if(bits->cce_pkt != ROHC_PACKET_CCE_OTHER)
	{
		rohc_buf_pull(&rohc_remain_data, 1 + large_cid_len);
		new_large_cid_len = 0;
	}
	else
	{
		new_large_cid_len = large_cid_len;
	}

	/* decode the remaining part of the part as a normal IP-based packet
	 * (with a fake length for the large CID field eventually) */
	return rfc3095_decomp_parse_pkt(context, rohc_remain_data, new_large_cid_len,
	                                packet_type, extr_crc, bits, rohc_hdr_len);

error_malformed:
	return ROHC_STATUS_MALFORMED;
}


/**
 * @brief Parse the UDP-Lite dynamic part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int udp_lite_parse_dynamic_udp(const struct rohc_decomp_ctxt *const context,
                                      const uint8_t *packet,
                                      const size_t length,
                                      struct rohc_extr_bits *const bits)
{
	const size_t udplite_dyn_length = 4; /* checksum coverage + checksum */
	size_t udp_lite_length;
	int read = 0;
	int ret;

	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the UDP-Lite dynamic part */
	if(length < udplite_dyn_length)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* compute the length of the UDP-Lite packet: UDP-Lite dynamic chain
	 * contains a 2-byte checksum coverage, a 2-byte checksum and a 2-byte SN
	 * fields */
	udp_lite_length = sizeof(struct udphdr) + length - udplite_dyn_length - 2;

	/* retrieve the checksum coverage field from the ROHC packet */
	bits->udp_lite_cc = GET_NEXT_16_BITS(packet);
	bits->udp_lite_cc_nr = 16;
	rohc_decomp_debug(context, "checksum coverage = 0x%04x",
	                  rohc_ntoh16(bits->udp_lite_cc));
	read += 2;
	packet += 2;

	/* init the Coverage Field Present (CFP) (see 5.2.2 in RFC 4019) */
	/* init Coverage Field Inferred (CFI) (see 5.2.2 in RFC 4019) */
	if(udp_lite_length != rohc_ntoh16(bits->udp_lite_cc))
	{
		bits->cfp = ROHC_TRISTATE_YES;
		bits->cfi = ROHC_TRISTATE_NO;
	}
	else
	{
		bits->cfp = ROHC_TRISTATE_NO;
		bits->cfi = ROHC_TRISTATE_YES;
	}
	rohc_decomp_debug(context, "init CFP to %d (length = %zd, CC = %d)",
	                  bits->cfp, udp_lite_length, rohc_ntoh16(bits->udp_lite_cc));
	rohc_decomp_debug(context, "init CFI to %d (length = %zd, CC = %d)",
	                  bits->cfi, udp_lite_length, rohc_ntoh16(bits->udp_lite_cc));

	/* retrieve the checksum field from the ROHC packet */
	bits->udp_check = GET_NEXT_16_BITS(packet);
	bits->udp_check_nr = 16;
	rohc_decomp_debug(context, "checksum = 0x%04x",
	                  rohc_ntoh16(bits->udp_check));
	packet += 2;
	read += 2;

	/* SN field */
	ret = ip_parse_dynamic_ip(context, packet, length - read, bits);
	if(ret == -1)
	{
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += ret;
#endif
	read += ret;

	return read;

error:
	return -1;
}


/**
 * @brief Parse the UDP-Lite remainder of the UO* ROHC packets.
 *
 * @param context      The decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int udp_lite_parse_uo_remainder(const struct rohc_decomp_ctxt *const context,
                                       const uint8_t *packet,
                                       unsigned int length,
                                       struct rohc_extr_bits *const bits)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	const struct d_udp_lite_context *const udp_lite_context = rfc3095_ctxt->specific;
	size_t remainder_length; /* optional checksum coverage + checksum */
	size_t udp_lite_length;
	int read = 0; /* number of bytes read from the packet */

	assert(packet != NULL);
	assert(bits != NULL);

	rohc_decomp_debug(context, "CFP = %d, CFI = %d, CCE = %d",
	                  bits->cfp, bits->cfi, bits->cce_pkt);

	remainder_length = (bits->cfp == ROHC_TRISTATE_YES ? 2 : 0) + 2;

	/* check the minimal length to decode the tail of UO* packet */
	if(length < remainder_length)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %u)", length);
		goto error;
	}

	/* compute the length of the UDP-Lite packet: UDP-Lite UO remainder contains
	 * an optional 2-byte checksum coverage, a 2-byte checksum and a 2-byte SN
	 * fields */
	udp_lite_length = sizeof(struct udphdr) + length - remainder_length - 2;

	/* checksum coverage if present */
	if(bits->cfp == ROHC_TRISTATE_YES)
	{
		/* retrieve the checksum coverage field from the ROHC packet */
		bits->udp_lite_cc = GET_NEXT_16_BITS(packet);
		bits->udp_lite_cc_nr = 16;
		rohc_decomp_debug(context, "checksum coverage = 0x%04x",
		                  rohc_ntoh16(bits->udp_lite_cc));
		read += 2;
		packet += 2;
	}
	else if(bits->cfp == ROHC_TRISTATE_NONE)
	{
		rohc_decomp_warn(context, "CFP not initialized");
		goto error;
	}

	/* retrieve the checksum field from the ROHC packet */
	bits->udp_check = GET_NEXT_16_BITS(packet);
	bits->udp_check_nr = 16;
	rohc_decomp_debug(context, "checksum = 0x%04x",
	                  rohc_ntoh16(bits->udp_check));
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += 2;
#endif
	read += 2;

	/* CFI is updated by CCE(OFF) is CC equals packet length */
	if(bits->cce_pkt == ROHC_PACKET_CCE_OFF)
	{
		uint16_t cc;

		/* if present, packet(CC) has precedence over context(CC) */
		if(bits->cfp == ROHC_TRISTATE_YES)
		{
			cc = rohc_hton16(bits->udp_lite_cc);
		}
		else
		{
			cc = rohc_hton16(udp_lite_context->cc);
		}

		if(udp_lite_length == cc)
		{
			bits->cfi = ROHC_TRISTATE_YES;
		}
		else
		{
			bits->cfi = ROHC_TRISTATE_NO;
		}
		rohc_decomp_debug(context, "CFI updated to %d (length = %zu, CC = %u)",
		                  bits->cfi, udp_lite_length, cc);
	}

	return read;

error:
	return -1;
}


/**
 * @brief Decode UDP-Lite values from extracted bits
 *
 * The following values are decoded:
 *  - UDP-Lite source port
 *  - UDP-Lite destination port
 *  - UDP-Lite checksum
 *  - UDP-Lite Checksum Coverage (CC)
 *
 * @param context  The decompression context
 * @param bits     The extracted bits
 * @param decoded  OUT: The corresponding decoded values
 * @return         true if decoding is successful, false otherwise
 */
static bool udp_lite_decode_values_from_bits(const struct rohc_decomp_ctxt *context,
                                             const struct rohc_extr_bits *const bits,
                                             struct rohc_decoded_values *const decoded)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	const struct d_udp_lite_context *const udp_lite_context = rfc3095_ctxt->specific;
	struct udphdr *udp_lite;

	assert(decoded != NULL);

	udp_lite = (struct udphdr *) rfc3095_ctxt->outer_ip_changes->next_header;

	/* decode UDP-Lite source port */
	if(bits->udp_src_nr > 0)
	{
		/* take packet value */
		assert(bits->udp_src_nr == 16);
		decoded->udp_src = bits->udp_src;
	}
	else
	{
		/* keep context value */
		decoded->udp_src = udp_lite->source;
	}
	rohc_decomp_debug(context, "decoded UDP-Lite source port = 0x%04x",
	                  rohc_ntoh16(decoded->udp_src));

	/* decode UDP-Lite destination port */
	if(bits->udp_dst_nr > 0)
	{
		/* take packet value */
		assert(bits->udp_dst_nr == 16);
		decoded->udp_dst = bits->udp_dst;
	}
	else
	{
		/* keep context value */
		decoded->udp_dst = udp_lite->dest;
	}
	rohc_decomp_debug(context, "decoded UDP-Lite destination port = 0x%04x",
	                  rohc_ntoh16(decoded->udp_dst));

	/* decode UDP-Lite checksum */
	assert(bits->udp_check_nr == 16);
	decoded->udp_check = bits->udp_check;
	rohc_decomp_debug(context, "decoded UDP checksum = 0x%04x",
	                  rohc_ntoh16(decoded->udp_check));

	/* decode UDP-Lite Checksum Coverage (CC) */
	if(bits->udp_lite_cc_nr > 0)
	{
		/* take packet value */
		assert(bits->udp_lite_cc_nr == 16);
		decoded->udp_lite_cc = bits->udp_lite_cc;
	}
	else
	{
		/* keep context value, will be replaced if value is inferred */
		decoded->udp_lite_cc = udp_lite_context->cc;
	}

	/* CCE packet type and CFP/CFI flags */
	decoded->cce_pkt = bits->cce_pkt;
	decoded->cfp = bits->cfp;
	decoded->cfi = bits->cfi;

	return true;
}


/**
 * @brief Build an uncompressed UDP-Lite header.
 *
 * @todo check for dest size before writing into it
 *
 * @param context      The decompression context
 * @param decoded      The values decoded from the ROHC header
 * @param dest         The buffer to store the UDP-Lite header
 * @param payload_len  The length of the UDP-Lite payload
 * @return             The length of the next header (ie. the UDP-Lite header),
 *                     -1 in case of error
 */
static int udp_lite_build_uncomp_udp(const struct rohc_decomp_ctxt *const context,
                                     const struct rohc_decoded_values *const decoded,
                                     uint8_t *const dest,
                                     const unsigned int payload_len)
{
	struct udphdr *udp_lite;

	assert(dest != NULL);
	udp_lite = (struct udphdr *) dest;

	/* static fields */
	udp_lite->source = decoded->udp_src;
	udp_lite->dest = decoded->udp_dst;

	/* changing fields */
	udp_lite->check = decoded->udp_check;
	rohc_decomp_debug(context, "checksum = 0x%04x",
	                  rohc_ntoh16(udp_lite->check));

	/* set checksum coverage if inferred, get from packet otherwise */
	if(decoded->cfi == ROHC_TRISTATE_YES)
	{
		udp_lite->len = rohc_hton16(payload_len + sizeof(struct udphdr));
		rohc_decomp_debug(context, "checksum coverage (0x%04x) is inferred",
		                  udp_lite->len);
	}
	else if(decoded->cfi == ROHC_TRISTATE_NONE)
	{
		rohc_decomp_warn(context, "CFI not initialized");
		goto error;
	}
	else
	{
		udp_lite->len = decoded->udp_lite_cc;
		rohc_decomp_debug(context, "checksum coverage (0x%04x) is not inferred",
		                  udp_lite->len);
	}

	return sizeof(struct udphdr);

error:
	return -1;
}


/**
 * @brief Update context with decoded UDP-Lite values
 *
 * The following decoded values are updated in context:
 *  - UDP-Lite source port
 *  - UDP-Lite destination port
 *
 * @param context  The decompression context
 * @param decoded  The decoded values to update in the context
 */
static void udp_lite_update_context(struct rohc_decomp_ctxt *const context,
                                    const struct rohc_decoded_values *const decoded)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	struct d_udp_lite_context *const udp_lite_context = rfc3095_ctxt->specific;
	struct udphdr *udp;

	assert(rfc3095_ctxt->outer_ip_changes != NULL);
	assert(rfc3095_ctxt->outer_ip_changes->next_header != NULL);
	udp = (struct udphdr *) rfc3095_ctxt->outer_ip_changes->next_header;
	udp->source = decoded->udp_src;
	udp->dest = decoded->udp_dst;

	if(decoded->cce_pkt != ROHC_PACKET_CCE)
	{
		rohc_decomp_debug(context, "packet updates CFP to %d", decoded->cfp);
		udp_lite_context->cfp = decoded->cfp;
	}
	if(decoded->cce_pkt == ROHC_PACKET_CCE_OTHER ||
	   decoded->cce_pkt == ROHC_PACKET_CCE_OFF)
	{
		rohc_decomp_debug(context, "packet updates CFI to %d", decoded->cfi);
		udp_lite_context->cfi = decoded->cfi;
		rohc_decomp_debug(context, "packet updates CC to 0x%04x", decoded->udp_lite_cc);
		udp_lite_context->cc = decoded->udp_lite_cc;
	}
}


/**
 * @brief Define the decompression part of the UDP-Lite profile as described
 *        in the RFC 4019.
 */
const struct rohc_decomp_profile d_udplite_profile =
{
	.id              = ROHC_PROFILE_UDPLITE, /* profile ID (RFC 4019, §7) */
	.msn_max_bits    = 16,
	.new_context     = (rohc_decomp_new_context_t) d_udp_lite_create,
	.free_context    = (rohc_decomp_free_context_t) d_udp_lite_destroy,
	.detect_pkt_type = udp_lite_detect_packet_type,
	.parse_pkt       = (rohc_decomp_parse_pkt_t) d_udp_lite_parse,
	.decode_bits     = (rohc_decomp_decode_bits_t) rfc3095_decomp_decode_bits,
	.build_hdrs      = (rohc_decomp_build_hdrs_t) rfc3095_decomp_build_hdrs,
	.update_ctxt     = (rohc_decomp_update_ctxt_t) rfc3095_decomp_update_ctxt,
	.attempt_repair  = (rohc_decomp_attempt_repair_t) rfc3095_decomp_attempt_repair,
	.get_sn          = rohc_decomp_rfc3095_get_sn,
};

