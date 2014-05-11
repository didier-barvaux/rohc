/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2008,2009,2010,2012,2013 Viveris Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file d_udp_lite.c
 * @brief ROHC decompression context for the UDP-Lite profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_ip.h"
#include "d_udp.h"
#include "d_generic.h"
#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "rohc_packets.h"
#include "crc.h"
#include "protocols/udp_lite.h"

#ifndef __KERNEL__
#  include <string.h>
#endif


/*
 * Private structures.
 */

/**
 * @brief Define the UDP-Lite part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context d_generic_context.
 *
 * @see d_generic_context
 */
struct d_udp_lite_context
{
	/**
	 * @brief Whether the UDP-Lite checksum coverage field is present or not
	 *
	 * Possible values are:
	 *   -1 if not initialized
	 *    0 if not present
	 *    1 if present
	 */
	int cfp;

	/**
	 * @brief Whether the UDP-Lite checksum coverage field can be inferred
	 *        or not
	 *
	 * Possible values are:
	 *   -1 if not initialized
	 *    0 if not present
	 *    1 if present
	 */
	int cfi;

	/**
	 * @brief Checksum Coverage Extension
	 *
	 * Possible values are:
	 *  - 0 if not present
	 *  - ROHC_PACKET_CCE if present and ON
	 *  - ROHC_PACKET_CCE_OFF if present and OFF
	 */
	int cce_packet;
};


/*
 * Private function prototypes.
 */

static void d_udp_lite_destroy(void *const context)
	__attribute__((nonnull(1)));

static rohc_packet_t udp_lite_detect_packet_type(const struct rohc_decomp_ctxt *const context,
                                                 const uint8_t *const rohc_packet,
                                                 const size_t rohc_length,
                                                 const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int udp_lite_parse_dynamic_udp(const struct rohc_decomp_ctxt *const context,
                                      const uint8_t *packet,
                                      const size_t length,
                                      struct rohc_extr_bits *const bits);

static int udp_lite_parse_uo_remainder(const struct rohc_decomp_ctxt *const context,
                                       const unsigned char *packet,
                                       unsigned int length,
                                       struct rohc_extr_bits *const bits);

static bool udp_lite_decode_values_from_bits(const struct rohc_decomp_ctxt *context,
                                             const struct rohc_extr_bits bits,
                                             struct rohc_decoded_values *const decoded);

static int udp_lite_build_uncomp_udp(const struct rohc_decomp_ctxt *const context,
                                     const struct rohc_decoded_values decoded,
                                     unsigned char *dest,
                                     const unsigned int payload_len);


/*
 * Definitions of functions.
 */

/**
 * @brief Create the UDP-Lite decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The decompression context
 * @return         The newly-created UDP-Lite decompression context
 */
void * d_udp_lite_create(const struct rohc_decomp_ctxt *const context)
{
	struct d_generic_context *g_context;
	struct d_udp_lite_context *udp_lite_context;

	assert(context != NULL);
	assert(context->decompressor != NULL);
	assert(context->profile != NULL);

	/* create the generic context */
	g_context = d_generic_create(context,
	                             context->decompressor->trace_callback,
	                             context->profile->id);
	if(g_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the generic decompression context");
		goto quit;
	}

	/* create the UDP-Lite-specific part of the context */
	udp_lite_context = malloc(sizeof(struct d_udp_lite_context));
	if(udp_lite_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-Lite-specific context");
		goto destroy_context;
	}
	memset(udp_lite_context, 0, sizeof(struct d_udp_lite_context));
	g_context->specific = udp_lite_context;

	/* create the LSB decoding context for SN */
	g_context->sn_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_SN, 16);
	if(g_context->sn_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for SN");
		goto free_udp_context;
	}

	/* the UDP-Lite checksum coverage field present flag will be initialized
	 * with the IR or IR-DYN packets */
	udp_lite_context->cfp = -1;
	udp_lite_context->cfi = -1;

	/* some UDP-Lite-specific values and functions */
	g_context->next_header_len = sizeof(struct udphdr);
	g_context->parse_static_next_hdr = udp_parse_static_udp;
	g_context->parse_dyn_next_hdr = udp_lite_parse_dynamic_udp;
	g_context->parse_ext3 = ip_parse_ext3;
	g_context->parse_uo_remainder = udp_lite_parse_uo_remainder;
	g_context->decode_values_from_bits = udp_lite_decode_values_from_bits;
	g_context->build_next_header = udp_lite_build_uncomp_udp;
	g_context->compute_crc_static = udp_compute_crc_static;
	g_context->compute_crc_dynamic = udp_compute_crc_dynamic;
	g_context->update_context = udp_update_context;

	/* create the UDP-Lite-specific part of the header changes */
	g_context->outer_ip_changes->next_header_len = sizeof(struct udphdr);
	g_context->outer_ip_changes->next_header = malloc(sizeof(struct udphdr));
	if(g_context->outer_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-Lite-specific part "
		           "of the outer IP header changes");
		goto free_lsb_sn;
	}
	memset(g_context->outer_ip_changes->next_header, 0, sizeof(struct udphdr));

	g_context->inner_ip_changes->next_header_len = sizeof(struct udphdr);
	g_context->inner_ip_changes->next_header = malloc(sizeof(struct udphdr));
	if(g_context->inner_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-Lite-specific part "
		           "of the inner IP header changes");
		goto free_outer_ip_changes_next_header;
	}
	memset(g_context->inner_ip_changes->next_header, 0, sizeof(struct udphdr));

	/* set next header to UDP-Lite */
	g_context->next_header_proto = ROHC_IPPROTO_UDPLITE;

	return g_context;

free_outer_ip_changes_next_header:
	zfree(g_context->outer_ip_changes->next_header);
free_lsb_sn:
	rohc_lsb_free(g_context->sn_lsb_ctxt);
free_udp_context:
	zfree(udp_lite_context);
destroy_context:
	d_generic_destroy(g_context);
quit:
	return NULL;
}


/**
 * @brief Destroy the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
static void d_udp_lite_destroy(void *const context)
{
	struct d_generic_context *g_context;

	assert(context != NULL);
	g_context = (struct d_generic_context *) context;

	/* clean UDP-specific memory */
	assert(g_context->outer_ip_changes != NULL);
	assert(g_context->outer_ip_changes->next_header != NULL);
	zfree(g_context->outer_ip_changes->next_header);
	assert(g_context->inner_ip_changes != NULL);
	assert(g_context->inner_ip_changes->next_header != NULL);
	zfree(g_context->inner_ip_changes->next_header);

	/* destroy the LSB decoding context for SN */
	rohc_lsb_free(g_context->sn_lsb_ctxt);

	/* destroy the resources of the generic context */
	d_generic_destroy(context);
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
	struct d_generic_context *g_context = context->specific;
	struct d_udp_lite_context *udp_lite_context = g_context->specific;
	size_t new_large_cid_len;

	/* remaining ROHC data not parsed yet */
	const unsigned char *rohc_remain_data = rohc_packet;
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
			udp_lite_context->cce_packet = ROHC_PACKET_CCE;
			/* skip CCE byte (and optional large CID field) */
			rohc_remain_data += 1 + large_cid_len;
			rohc_remain_len -= 1 + large_cid_len;
			new_large_cid_len = 0;
			break;
		case 0xfa: /* CEC(ON) */
			rohc_decomp_debug(context, "CCE(ON)");
			udp_lite_context->cfp = 1;
			udp_lite_context->cce_packet = ROHC_PACKET_CCE;
			/* skip CCE byte (and optional large CID field) */
			rohc_remain_data += 1 + large_cid_len;
			rohc_remain_len -= 1 + large_cid_len;
			new_large_cid_len = 0;
			break;
		case 0xfb: /* CCE(OFF) */
			rohc_decomp_debug(context, "CCE(OFF)");
			udp_lite_context->cfp = 0;
			udp_lite_context->cce_packet = ROHC_PACKET_CCE_OFF;
			/* no CCE byte to skip */
			new_large_cid_len = large_cid_len;
			break;
		default:
			rohc_decomp_debug(context, "CCE not present");
			udp_lite_context->cce_packet = 0;
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
 * @param decomp                 The ROHC decompressor
 * @param context                The decompression context
 * @param arrival_time           The time at which packet was received (0 if
 *                               unknown, or to disable time-related features
 *                               in ROHC protocol)
 * @param rohc_packet            The ROHC packet to decode
 * @param rohc_length            The length of the ROHC packet
 * @param add_cid_len            The length of the optional Add-CID field
 * @param large_cid_len          The length of the optional large CID field
 * @param[out] dest              The uncompressed packet
 * @param uncomp_packet_max_len  The max length of the uncompressed packet
 * @param packet_type            IN:  The type of the ROHC packet to parse
 *                               OUT: The type of the parsed ROHC packet
 * @return                       The length of the uncompressed IP packet
 *                               or ROHC_ERROR_CRC if a CRC error occurs
 *                               or ROHC_ERROR if an error occurs
 */
static int d_udp_lite_decode(struct rohc_decomp *const decomp,
                             struct rohc_decomp_ctxt *const context,
                             const struct rohc_ts arrival_time,
                             const unsigned char *const rohc_packet,
                             const size_t rohc_length,
                             const size_t add_cid_len,
                             const size_t large_cid_len,
                             unsigned char *const dest,
                             const size_t uncomp_packet_max_len,
                             rohc_packet_t *const packet_type)
{
	struct d_generic_context *g_context = context->specific;
	struct d_udp_lite_context *udp_lite_context = g_context->specific;
	size_t new_large_cid_len;

	/* remaining ROHC data not parsed yet */
	const unsigned char *rohc_remain_data = rohc_packet;
	unsigned int rohc_remain_len = rohc_length;

	/* check if the ROHC packet is large enough to read the first byte */
	if(rohc_remain_len < (1 + large_cid_len))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %u)",
		                 rohc_remain_len);
		goto error;
	}

	/* if the CE extension is present, skip the CCE byte type (and the
	 * optional large CID field) */
	if(udp_lite_context->cce_packet)
	{
		rohc_remain_data += 1 + large_cid_len;
		rohc_remain_len -= 1 + large_cid_len;
		new_large_cid_len = 0;
	}
	else
	{
		new_large_cid_len = large_cid_len;
	}

	/* decode the remaining part of the part as a normal IP-based packet
	 * (with a fake length for the large CID field eventually) */
	return d_generic_decode(decomp, context, arrival_time,
	                        rohc_remain_data, rohc_remain_len,
	                        add_cid_len, new_large_cid_len,
	                        dest, uncomp_packet_max_len, packet_type);

error:
	return ROHC_ERROR;
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
	struct d_generic_context *g_context;
	struct d_udp_lite_context *udp_lite_context;
	const size_t udplite_dyn_length = 4; /* checksum coverage + checksum */
	size_t udp_lite_length;
	int read = 0;
	int ret;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	udp_lite_context = g_context->specific;
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
	udp_lite_context->cfp =
		(udp_lite_length != rohc_ntoh16(bits->udp_lite_cc));
	rohc_decomp_debug(context, "init CFP to %d (length = %zd, CC = %d)",
	                  udp_lite_context->cfp, udp_lite_length,
	                  rohc_ntoh16(bits->udp_lite_cc));

	/* init Coverage Field Inferred (CFI) (see 5.2.2 in RFC 4019) */
	udp_lite_context->cfi =
		(udp_lite_length == rohc_ntoh16(bits->udp_lite_cc));
	rohc_decomp_debug(context, "init CFI to %d (length = %zd, CC = %d)",
	                  udp_lite_context->cfi, udp_lite_length,
	                  rohc_ntoh16(bits->udp_lite_cc));

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
                                       const unsigned char *packet,
                                       unsigned int length,
                                       struct rohc_extr_bits *const bits)
{
	struct d_generic_context *g_context;
	struct d_udp_lite_context *udp_lite_context;
	size_t remainder_length; /* optional checksum coverage + checksum */
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	udp_lite_context = g_context->specific;
	assert(packet != NULL);
	assert(bits != NULL);

	rohc_decomp_debug(context, "CFP = %d, CFI = %d, cce_packet = %d",
	                  udp_lite_context->cfp, udp_lite_context->cfi,
	                  udp_lite_context->cce_packet);

	remainder_length = (udp_lite_context->cfp != 0 ? 2 : 0) + 2;

	/* check the minimal length to decode the tail of UO* packet */
	if(length < remainder_length)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %u)", length);
		goto error;
	}

	/* checksum coverage if present */
	if(udp_lite_context->cfp > 0)
	{
		/* retrieve the checksum coverage field from the ROHC packet */
		bits->udp_lite_cc = GET_NEXT_16_BITS(packet);
		bits->udp_lite_cc_nr = 16;
		rohc_decomp_debug(context, "checksum coverage = 0x%04x",
		                  rohc_ntoh16(bits->udp_lite_cc));
		read += 2;
		packet += 2;
	}
	else if(udp_lite_context->cfp < 0)
	{
		rohc_decomp_warn(context, "cfp not initialized and packet is not one "
		                 "IR packet");
		goto error;
	}

	/* check if Coverage Field Inferred (CFI) is uninitialized */
	if(udp_lite_context->cfi < 0)
	{
		rohc_decomp_warn(context, "cfi not initialized and packet is not one "
		                 "IR packet");
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
                                             const struct rohc_extr_bits bits,
                                             struct rohc_decoded_values *const decoded)
{
	struct d_generic_context *g_context;
	struct udphdr *udp_lite;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	assert(decoded != NULL);

	udp_lite = (struct udphdr *) g_context->outer_ip_changes->next_header;

	/* decode UDP-Lite source port */
	if(bits.udp_src_nr > 0)
	{
		/* take packet value */
		assert(bits.udp_src_nr == 16);
		decoded->udp_src = bits.udp_src;
	}
	else
	{
		/* keep context value */
		decoded->udp_src = udp_lite->source;
	}
	rohc_decomp_debug(context, "decoded UDP-Lite source port = 0x%04x",
	                  rohc_ntoh16(decoded->udp_src));

	/* decode UDP-Lite destination port */
	if(bits.udp_dst_nr > 0)
	{
		/* take packet value */
		assert(bits.udp_dst_nr == 16);
		decoded->udp_dst = bits.udp_dst;
	}
	else
	{
		/* keep context value */
		decoded->udp_dst = udp_lite->dest;
	}
	rohc_decomp_debug(context, "decoded UDP-Lite destination port = 0x%04x",
	                  rohc_ntoh16(decoded->udp_dst));

	/* decode UDP-Lite checksum */
	assert(bits.udp_check_nr == 16);
	decoded->udp_check = bits.udp_check;
	rohc_decomp_debug(context, "decoded UDP checksum = 0x%04x",
	                  rohc_ntoh16(decoded->udp_check));

	/* decode UDP-Lite Checksum Coverage (CC) */
	if(bits.udp_lite_cc_nr > 0)
	{
		/* take packet value */
		assert(bits.udp_lite_cc_nr == 16);
		decoded->udp_lite_cc = bits.udp_lite_cc;
	}
	else
	{
		/* keep context value, will be replaced if value is inferred */
		decoded->udp_lite_cc = udp_lite->len;
	}

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
                                     const struct rohc_decoded_values decoded,
                                     unsigned char *dest,
                                     const unsigned int payload_len)
{
	struct d_generic_context *g_context;
	struct d_udp_lite_context *udp_lite_context;
	struct udphdr *udp_lite;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	udp_lite_context = g_context->specific;
	assert(dest != NULL);
	udp_lite = (struct udphdr *) dest;

	/* static fields */
	udp_lite->source = decoded.udp_src;
	udp_lite->dest = decoded.udp_dst;

	/* changing fields */
	udp_lite->check = decoded.udp_check;
	rohc_decomp_debug(context, "checksum = 0x%04x",
	                  rohc_ntoh16(udp_lite->check));

	/* set checksum coverage if inferred, get from packet otherwise */
	if(udp_lite_context->cfi > 0)
	{
		udp_lite->len = rohc_hton16(payload_len + sizeof(struct udphdr));
		rohc_decomp_debug(context, "checksum coverage (0x%04x) is inferred",
		                  udp_lite->len);
	}
	else
	{
		udp_lite->len = decoded.udp_lite_cc;
		rohc_decomp_debug(context, "checksum coverage (0x%04x) is not inferred",
		                  udp_lite->len);
	}

	return sizeof(struct udphdr);
}


/**
 * @brief Define the decompression part of the UDP-Lite profile as described
 *        in the RFC 4019.
 */
const struct rohc_decomp_profile d_udplite_profile =
{
	.id              = ROHC_PROFILE_UDPLITE, /* profile ID (RFC 4019, §7) */
	.new_context     = d_udp_lite_create,
	.free_context    = d_udp_lite_destroy,
	.decode          = d_udp_lite_decode,
	.detect_pkt_type = udp_lite_detect_packet_type,
	.get_sn          = d_generic_get_sn,
};

