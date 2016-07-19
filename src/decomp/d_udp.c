/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
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
 * @file d_udp.c
 * @brief ROHC decompression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_udp.h"
#include "d_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_bit_ops.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "crc.h"
#include "protocols/udp.h"

#include <string.h>
#include <assert.h>


/**
 * @brief Define the UDP part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context rohc_decomp_rfc3095_ctxt.
 *
 * @see rohc_decomp_rfc3095_ctxt
 */
struct d_udp_context
{
	uint16_t sport;                    /**< UDP source port */
	uint16_t dport;                    /**< UDP destination port */
	rohc_tristate_t udp_check_present; /**< Whether the UDP checksum is used */
};


/*
 * Private function prototypes.
 */

static bool d_udp_create(const struct rohc_decomp_ctxt *const context,
                         struct rohc_decomp_rfc3095_ctxt **const persist_ctxt,
                         struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static void d_udp_destroy(struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                          const struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((nonnull(1, 2)));

static int udp_parse_dynamic_udp(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *packet,
                                 const size_t length,
                                 struct rohc_extr_bits *const bits);

static int udp_parse_uo_remainder(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *packet,
                                  unsigned int length,
                                  struct rohc_extr_bits *const bits);

static bool udp_decode_values_from_bits(const struct rohc_decomp_ctxt *context,
                                        const struct rohc_extr_bits *const bits,
                                        struct rohc_decoded_values *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int udp_build_uncomp_udp(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_decoded_values *const decoded,
                                uint8_t *const dest,
                                const unsigned int payload_len);

static void udp_update_context(struct rohc_decomp_ctxt *const context,
                               const struct rohc_decoded_values *const decoded)
	__attribute__((nonnull(1)));


/**
 * @brief Create the UDP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context            The main decompression context
 * @param[out] persist_ctxt  The persistent part of the decompression context
 * @param[out] volat_ctxt    The volatile part of the decompression context
 * @return                   true if the UDP context was successfully created,
 *                           false if a problem occurred
 */
static bool d_udp_create(const struct rohc_decomp_ctxt *const context,
                         struct rohc_decomp_rfc3095_ctxt **const persist_ctxt,
                         struct rohc_decomp_volat_ctxt *const volat_ctxt)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_udp_context *udp_context;

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

	/* create the UDP-specific part of the context */
	udp_context = calloc(1, sizeof(struct d_udp_context));
	if(udp_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-specific context");
		goto destroy_context;
	}
	rfc3095_ctxt->specific = udp_context;

	/* create the LSB decoding context for SN */
	rfc3095_ctxt->sn_lsb_p = ROHC_LSB_SHIFT_SN;
	rfc3095_ctxt->sn_lsb_ctxt = rohc_lsb_new(16);
	if(rfc3095_ctxt->sn_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for SN");
		goto free_udp_context;
	}

	/* the UDP checksum field present flag will be initialized
	 * with the IR packets */
	udp_context->udp_check_present = ROHC_TRISTATE_NONE;

	/* some UDP-specific values and functions */
	rfc3095_ctxt->next_header_len = sizeof(struct udphdr);
	rfc3095_ctxt->parse_static_next_hdr = udp_parse_static_udp;
	rfc3095_ctxt->parse_dyn_next_hdr = udp_parse_dynamic_udp;
	rfc3095_ctxt->parse_ext3 = ip_parse_ext3;
	rfc3095_ctxt->parse_uo_remainder = udp_parse_uo_remainder;
	rfc3095_ctxt->decode_values_from_bits = udp_decode_values_from_bits;
	rfc3095_ctxt->build_next_header = udp_build_uncomp_udp;
	rfc3095_ctxt->compute_crc_static = udp_compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = udp_compute_crc_dynamic;
	rfc3095_ctxt->update_context = udp_update_context;

	/* create the UDP-specific part of the header changes */
	rfc3095_ctxt->outer_ip_changes->next_header_len = sizeof(struct udphdr);
	rfc3095_ctxt->outer_ip_changes->next_header = calloc(1, sizeof(struct udphdr));
	if(rfc3095_ctxt->outer_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-specific part of the "
		           "outer IP header changes");
		goto free_lsb_sn;
	}

	rfc3095_ctxt->inner_ip_changes->next_header_len = sizeof(struct udphdr);
	rfc3095_ctxt->inner_ip_changes->next_header = calloc(1, sizeof(struct udphdr));
	if(rfc3095_ctxt->inner_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the UDP-specific part of the "
		           "inner IP header changes");
		goto free_outer_ip_changes_next_header;
	}

	/* set next header to UDP */
	rfc3095_ctxt->next_header_proto = ROHC_IPPROTO_UDP;

	return true;

free_outer_ip_changes_next_header:
	zfree(rfc3095_ctxt->outer_ip_changes->next_header);
free_lsb_sn:
	rohc_lsb_free(rfc3095_ctxt->sn_lsb_ctxt);
free_udp_context:
	zfree(udp_context);
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
static void d_udp_destroy(struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
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
 * @brief Parse the UDP static part of the ROHC packet.
 *
 * @param context The decompression context
 * @param packet  The ROHC packet to parse
 * @param length  The length of the ROHC packet
 * @param bits    OUT: The bits extracted from the ROHC header
 * @return        The number of bytes read in the ROHC packet,
 *                -1 in case of failure
 */
int udp_parse_static_udp(const struct rohc_decomp_ctxt *const context,
                         const uint8_t *packet,
                         size_t length,
                         struct rohc_extr_bits *const bits)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt =
		context->persist_ctxt;
	const struct d_udp_context *const udp_context = rfc3095_ctxt->specific;
	size_t read = 0; /* number of bytes read from the packet */

	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the UDP static part */
	if(length < 4)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* UDP source port */
	bits->udp_src = GET_NEXT_16_BITS(packet);
	bits->udp_src_nr = 16;
	rohc_decomp_debug(context, "UDP source port = 0x%04x (%u)",
	                  rohc_ntoh16(bits->udp_src), rohc_ntoh16(bits->udp_src));
	packet += 2;
	read += 2;

	/* UDP destination port */
	bits->udp_dst = GET_NEXT_16_BITS(packet);
	bits->udp_dst_nr = 16;
	rohc_decomp_debug(context, "UDP destination port = 0x%04x (%u)",
	                  rohc_ntoh16(bits->udp_dst), rohc_ntoh16(bits->udp_dst));
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += 2;
#endif
	read += 2;

	/* is context re-used? */
	if(context->num_recv_packets >= 1 && bits->udp_src != udp_context->sport)
	{
		rohc_decomp_debug(context, "UDP source port mismatch (packet = %u, "
		                  "context = %u) -> context is being reused",
		                  rohc_ntoh16(bits->udp_src),
		                  rohc_ntoh16(udp_context->sport));
		bits->is_context_reused = true;
	}
	if(context->num_recv_packets >= 1 && bits->udp_dst != udp_context->dport)
	{
		rohc_decomp_debug(context, "UDP destination port mismatch (packet = %u, "
		                  "context = %u) -> context is being reused",
		                  rohc_ntoh16(bits->udp_dst),
		                  rohc_ntoh16(udp_context->dport));
		bits->is_context_reused = true;
	}

	return read;

error:
	return -1;
}


/**
 * @brief Parse the UDP dynamic part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int udp_parse_dynamic_udp(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *packet,
                                 const size_t length,
                                 struct rohc_extr_bits *const bits)
{
	int read = 0; /* number of bytes read from the packet */
	int ret;

	assert(packet != NULL);
	assert(bits != NULL);

	/* UDP checksum */
	if(length < 2)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}
	bits->udp_check = GET_NEXT_16_BITS(packet);
	bits->udp_check_nr = 16;
	rohc_decomp_debug(context, "UDP checksum = 0x%04x",
	                  rohc_ntoh16(bits->udp_check));
	packet += 2;
	read += 2;

	/* determine whether the UDP checksum will be present in UO packets */
	bits->udp_check_present = (bits->udp_check > 0) ? ROHC_TRISTATE_YES : ROHC_TRISTATE_NO;

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
 * @brief Parse the UDP tail of the UO* ROHC packets.
 *
 * @param context      The decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int udp_parse_uo_remainder(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *packet,
                                  unsigned int length,
                                  struct rohc_extr_bits *const bits)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt =
		context->persist_ctxt;
	const struct d_udp_context *const udp_context = rfc3095_ctxt->specific;
	int read = 0; /* number of bytes read from the packet */

	assert(packet != NULL);
	assert(bits != NULL);

	/* parse extra UDP checksum if present */
	if(udp_context->udp_check_present == ROHC_TRISTATE_NONE)
	{
		rohc_decomp_warn(context, "the behavior of the UDP checksum is not yet "
		                 "known, but packet is not one IR packet");
		goto error;
	}
	else if(udp_context->udp_check_present == ROHC_TRISTATE_NO)
	{
		bits->udp_check_nr = 0;
		rohc_decomp_debug(context, "UDP checksum not present");
	}
	else
	{
		/* check the minimal length to decode the UDP checksum */
		if(length < 2)
		{
			rohc_decomp_warn(context, "ROHC packet too small (len = %u)",
			                 length);
			goto error;
		}

		/* retrieve the UDP checksum from the ROHC packet */
		bits->udp_check = GET_NEXT_16_BITS(packet);
		bits->udp_check_nr = 16;
		rohc_decomp_debug(context, "UDP checksum = 0x%04x",
		                  rohc_ntoh16(bits->udp_check));
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		packet += 2;
#endif
		read += 2;
	}

	return read;

error:
	return -1;
}


/**
 * @brief Decode UDP values from extracted bits
 *
 * The following values are decoded:
 *  - UDP source port
 *  - UDP destination port
 *  - UDP checksum
 *
 * @param context  The decompression context
 * @param bits     The extracted bits
 * @param decoded  OUT: The corresponding decoded values
 * @return         true if decoding is successful, false otherwise
 */
static bool udp_decode_values_from_bits(const struct rohc_decomp_ctxt *context,
                                        const struct rohc_extr_bits *const bits,
                                        struct rohc_decoded_values *const decoded)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt =
		context->persist_ctxt;
	const struct d_udp_context *const udp_context = rfc3095_ctxt->specific;
	struct udphdr *udp;

	assert(decoded != NULL);

	assert(rfc3095_ctxt->outer_ip_changes != NULL);
	assert(rfc3095_ctxt->outer_ip_changes->next_header != NULL);
	udp = (struct udphdr *) rfc3095_ctxt->outer_ip_changes->next_header;

	/* decode UDP source port */
	if(bits->udp_src_nr > 0)
	{
		/* take packet value */
		assert(bits->udp_src_nr == 16);
		decoded->udp_src = bits->udp_src;
	}
	else
	{
		/* keep context value */
		decoded->udp_src = udp->source;
	}
	rohc_decomp_debug(context, "decoded UDP source port = 0x%04x",
	                  rohc_ntoh16(decoded->udp_src));

	/* decode UDP destination port */
	if(bits->udp_dst_nr > 0)
	{
		/* take packet value */
		assert(bits->udp_dst_nr == 16);
		decoded->udp_dst = bits->udp_dst;
	}
	else
	{
		/* keep context value */
		decoded->udp_dst = udp->dest;
	}
	rohc_decomp_debug(context, "decoded UDP destination port = 0x%04x",
	                  rohc_ntoh16(decoded->udp_dst));

	/* take UDP checksum behavior from packet if present, otherwise from context */
	if(bits->udp_check_present != ROHC_TRISTATE_NONE)
	{
		decoded->udp_check_present = bits->udp_check_present;
	}
	else
	{
		decoded->udp_check_present = udp_context->udp_check_present;
	}

	/* UDP checksum:
	 *  - error if UDP checksum behavior is still unknown,
	 *  - copy from packet if checksum is present,
	 *  - set checksum to zero if checksum is not present */
	if(decoded->udp_check_present == ROHC_TRISTATE_NONE)
	{
		rohc_decomp_warn(context, "the behavior of the UDP checksum field is "
		                 "still not known");
		goto error;
	}
	else if(decoded->udp_check_present == ROHC_TRISTATE_YES)
	{
		assert(bits->udp_check_nr == 16);
		decoded->udp_check = bits->udp_check;
	}
	else
	{
		assert(bits->udp_check_nr == 16 || bits->udp_check_nr == 0);
		assert(bits->udp_check == 0);
		decoded->udp_check = 0;
	}
	rohc_decomp_debug(context, "decoded UDP checksum = 0x%04x (checksum "
	                  "present = %d)", rohc_ntoh16(decoded->udp_check),
	                  decoded->udp_check_present);

	return true;

error:
	return false;
}


/**
 * @brief Build an uncompressed UDP header.
 *
 * @param context      The decompression context
 * @param decoded      The values decoded from the ROHC header
 * @param dest         The buffer to store the UDP header (MUST be at least
 *                     of sizeof(struct udphdr) length)
 * @param payload_len  The length of the UDP payload
 * @return             The length of the next header (ie. the UDP header),
 *                     -1 in case of error
 */
static int udp_build_uncomp_udp(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_decoded_values *const decoded,
                                uint8_t *const dest,
                                const unsigned int payload_len)
{
	struct udphdr *udp;

	assert(context != NULL);
	assert(dest != NULL);
	udp = (struct udphdr *) dest;

	/* static fields */
	udp->source = decoded->udp_src;
	udp->dest = decoded->udp_dst;

	/* changing fields */
	udp->check = decoded->udp_check;
	rohc_decomp_debug(context, "UDP checksum = 0x%04x", rohc_ntoh16(udp->check));

	/* interfered fields */
	udp->len = rohc_hton16(payload_len + sizeof(struct udphdr));
	rohc_decomp_debug(context, "UDP length = 0x%04x", rohc_ntoh16(udp->len));

	return sizeof(struct udphdr);
}


/**
 * @brief Update context with decoded UDP values
 *
 * The following decoded values are updated in context:
 *  - UDP source port
 *  - UDP destination port
 *  - UDP checksum present flag
 *
 * @param context  The decompression context
 * @param decoded  The decoded values to update in the context
 */
static void udp_update_context(struct rohc_decomp_ctxt *const context,
                               const struct rohc_decoded_values *const decoded)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt =
		context->persist_ctxt;
	struct d_udp_context *const udp_context = rfc3095_ctxt->specific;
	struct udphdr *udp;

	assert(rfc3095_ctxt->outer_ip_changes != NULL);
	assert(rfc3095_ctxt->outer_ip_changes->next_header != NULL);
	udp = (struct udphdr *) rfc3095_ctxt->outer_ip_changes->next_header;
	udp->source = decoded->udp_src;
	udp->dest = decoded->udp_dst;

	/* determine whether the UDP checksum will be present in UO packets */
	udp_context->udp_check_present = decoded->udp_check_present;

	/* record source & destination ports into the context to be able to detect
	 * context re-use */
	udp_context->sport = decoded->udp_src;
	udp_context->dport = decoded->udp_dst;
}


/**
 * @brief Define the decompression part of the UDP profile as described
 *        in the RFC 3095.
 */
const struct rohc_decomp_profile d_udp_profile =
{
	.id              = ROHC_PROFILE_UDP, /* profile ID (see 8 in RFC3095) */
	.msn_max_bits    = 16,
	.new_context     = (rohc_decomp_new_context_t) d_udp_create,
	.free_context    = (rohc_decomp_free_context_t) d_udp_destroy,
	.detect_pkt_type = ip_detect_packet_type,
	.parse_pkt       = (rohc_decomp_parse_pkt_t) rfc3095_decomp_parse_pkt,
	.decode_bits     = (rohc_decomp_decode_bits_t) rfc3095_decomp_decode_bits,
	.build_hdrs      = (rohc_decomp_build_hdrs_t) rfc3095_decomp_build_hdrs,
	.update_ctxt     = (rohc_decomp_update_ctxt_t) rfc3095_decomp_update_ctxt,
	.attempt_repair  = (rohc_decomp_attempt_repair_t) rfc3095_decomp_attempt_repair,
	.get_sn          = rohc_decomp_rfc3095_get_sn,
};

