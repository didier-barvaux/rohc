/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2009,2010 Thales Communications
 * Copyright 2012,2013 Viveris Technologies
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
 * @file   d_esp.c
 * @brief  ROHC ESP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_decomp_rfc3095.h"
#include "d_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "crc.h"
#include "protocols/esp.h"
#include "schemes/decomp_wlsb.h"

#include <stdint.h>
#include <string.h>
#include <assert.h>


/**
 * @brief Define the ESP part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context rohc_decomp_rfc3095_ctxt.
 *
 * @see rohc_decomp_rfc3095_ctxt
 */
struct d_esp_context
{
	/** ESP SPI */
	uint32_t spi;
};



/*
 * Private function prototypes.
 */

static bool d_esp_create(const struct rohc_decomp_ctxt *const context,
                         struct rohc_decomp_rfc3095_ctxt **const persist_ctxt,
                         struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static void d_esp_destroy(struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                          const struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((nonnull(1, 2)));

static int esp_parse_static_esp(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *packet,
                                size_t length,
                                struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int esp_parse_dynamic_esp(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *packet,
                                 const size_t length,
                                 struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static bool esp_decode_values_from_bits(const struct rohc_decomp_ctxt *context,
                                        const struct rohc_extr_bits *const bits,
                                        struct rohc_decoded_values *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int esp_build_uncomp_esp(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_decoded_values *const decoded,
                                uint8_t *const dest,
                                const unsigned int payload_len);

static void esp_update_context(struct rohc_decomp_ctxt *const context,
                               const struct rohc_decoded_values *const decoded)
	__attribute__((nonnull(1, 2)));


/*
 * Private function definitions
 */

/**
 * @brief Create the ESP decompression context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context            The decompression context
 * @param[out] persist_ctxt  The persistent part of the decompression context
 * @param[out] volat_ctxt    The volatile part of the decompression context
 * @return                   true if the ESP context was successfully created,
 *                           false if a problem occurred
 */
static bool d_esp_create(const struct rohc_decomp_ctxt *const context,
                         struct rohc_decomp_rfc3095_ctxt **const persist_ctxt,
                         struct rohc_decomp_volat_ctxt *const volat_ctxt)
{
	struct rohc_decomp_rfc3095_ctxt *rfc3095_ctxt;
	struct d_esp_context *esp_context;

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

	/* create the ESP-specific part of the context */
	esp_context = calloc(1, sizeof(struct d_esp_context));
	if(esp_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the ESP-specific context");
		goto destroy_context;
	}
	rfc3095_ctxt->specific = esp_context;

	/* create the LSB decoding context for SN (same shift value as RTP) */
	rohc_lsb_init(&rfc3095_ctxt->sn_lsb_ctxt, 32);

	/* some ESP-specific values and functions */
	rfc3095_ctxt->next_header_len = sizeof(struct esphdr);
	rfc3095_ctxt->parse_static_next_hdr = esp_parse_static_esp;
	rfc3095_ctxt->parse_dyn_next_hdr = esp_parse_dynamic_esp;
	rfc3095_ctxt->parse_ext3 = ip_parse_ext3;
	rfc3095_ctxt->parse_uo_remainder = NULL;
	rfc3095_ctxt->decode_values_from_bits = esp_decode_values_from_bits;
	rfc3095_ctxt->build_next_header = esp_build_uncomp_esp;
	rfc3095_ctxt->compute_crc_static = esp_compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = esp_compute_crc_dynamic;
	rfc3095_ctxt->update_context = esp_update_context;

	/* create the ESP-specific part of the header changes */
	rfc3095_ctxt->outer_ip_changes->next_header_len = sizeof(struct esphdr);
	rfc3095_ctxt->outer_ip_changes->next_header = calloc(1, sizeof(struct esphdr));
	if(rfc3095_ctxt->outer_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the ESP-specific part of the "
		           "outer IP header changes");
		goto free_esp_context;
	}

	rfc3095_ctxt->inner_ip_changes->next_header_len = sizeof(struct esphdr);
	rfc3095_ctxt->inner_ip_changes->next_header = calloc(1, sizeof(struct esphdr));
	if(rfc3095_ctxt->inner_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the ESP-specific part of the "
		           "inner IP header changes");
		goto free_outer_ip_changes_next_header;
	}

	/* set next header to ESP */
	rfc3095_ctxt->next_header_proto = ROHC_IPPROTO_ESP;

	return true;

free_outer_ip_changes_next_header:
	zfree(rfc3095_ctxt->outer_ip_changes->next_header);
free_esp_context:
	zfree(esp_context);
destroy_context:
	rohc_decomp_rfc3095_destroy(rfc3095_ctxt, volat_ctxt);
quit:
	return false;
}


/**
 * @brief Destroy the context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param rfc3095_ctxt  The persistent decompression context for the RFC3095 profiles
 * @param volat_ctxt    The volatile decompression context
 */
static void d_esp_destroy(struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                          const struct rohc_decomp_volat_ctxt *const volat_ctxt)
{
	/* clean ESP-specific memory */
	assert(rfc3095_ctxt->outer_ip_changes != NULL);
	zfree(rfc3095_ctxt->outer_ip_changes->next_header);
	assert(rfc3095_ctxt->inner_ip_changes != NULL);
	zfree(rfc3095_ctxt->inner_ip_changes->next_header);

	/* destroy the resources of the generic context */
	rohc_decomp_rfc3095_destroy(rfc3095_ctxt, volat_ctxt);
}


/**
 * @brief Parse the ESP static part of the ROHC packet
 *
 * @param context The decompression context
 * @param packet  The ROHC packet to decode
 * @param length  The length of the ROHC packet
 * @param bits    OUT: The bits extracted from the ROHC header
 * @return        The number of bytes read in the ROHC packet,
 *                -1 in case of failure
 */
static int esp_parse_static_esp(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *packet,
                                size_t length,
                                struct rohc_extr_bits *const bits)
{
	const size_t spi_length = sizeof(uint32_t);
	size_t read = 0; /* number of bytes read from the packet */

	/* check the minimal length to parse the ESP static part */
	if(length < spi_length)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* SPI */
	memcpy(&bits->esp_spi, packet, spi_length);
	bits->esp_spi_nr = spi_length * 8;
	rohc_decomp_debug(context, "ESP SPI = 0x%08x", rohc_ntoh32(bits->esp_spi));
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += spi_length;
#endif
	read += spi_length;

#if 0 /* TODO */
	   /* is context re-used? */
	if(context->num_recv_packets >= 1 &&
	   memcmp(&bits->esp_spi, &esp_context->spi, spi_length) != 0)
	{
		rohc_decomp_debug(context, "ESP SPI mismatch (packet = 0x%08x, "
		                  "context = 0x%08x) -> context is being reused",
		                  bits->esp_spi, esp_context->spi);
		bits->is_context_reused = true;
	}
	memcpy(&esp_context->spi, &bits->esp_spi, spi_length);
#endif

	return read;

error:
	return -1;
}


/**
 * @brief Parse the ESP dynamic part of the ROHC packet
 *
 * @param context  The decompression context
 * @param packet   The ROHC packet to decode
 * @param length   The length of the ROHC packet
 * @param bits     OUT: The bits extracted from the ROHC header
 * @return         The number of bytes read in the ROHC packet,
 *                 -1 in case of failure
 */
static int esp_parse_dynamic_esp(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *packet,
                                 const size_t length,
                                 struct rohc_extr_bits *const bits)
{
	const size_t sn_length = sizeof(uint32_t);
	int read = 0; /* number of bytes read from the packet */
	uint32_t sn;

	/* check the minimal length to parse the ESP dynamic part */
	if(length < sn_length)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* retrieve the ESP sequence number from the ROHC packet */
	memcpy(&sn, packet, sn_length);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += sn_length;
#endif
	read += sn_length;
	bits->sn = rohc_ntoh32(sn);
	bits->sn_nr = sn_length * 8;
	bits->is_sn_enc = false;
	rohc_decomp_debug(context, "ESP SN = 0x%08x", bits->sn);

	return read;

error:
	return -1;
}


/**
 * @brief Decode ESP values from extracted bits
 *
 * The following values are decoded:
 *  - ESP SPI
 *
 * @param context  The decompression context
 * @param bits     The extracted bits
 * @param decoded  OUT: The corresponding decoded values
 * @return         true if decoding is successful, false otherwise
 */
static bool esp_decode_values_from_bits(const struct rohc_decomp_ctxt *context,
                                        const struct rohc_extr_bits *const bits,
                                        struct rohc_decoded_values *const decoded)
{
	const struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	const struct esphdr *const esp = rfc3095_ctxt->outer_ip_changes->next_header;
	const size_t spi_length = sizeof(uint32_t);

	/* decode ESP SPI */
	if(bits->esp_spi_nr > 0)
	{
		/* take packet value */
		assert(bits->esp_spi_nr == (spi_length * 8));
		memcpy(&decoded->esp_spi, &bits->esp_spi, spi_length);
	}
	else
	{
		/* keep context value */
		memcpy(&decoded->esp_spi, &esp->spi, spi_length);
	}
	rohc_decomp_debug(context, "decoded SPI = 0x%08x",
	                  rohc_ntoh32(decoded->esp_spi));

	return true;
}


/**
 * @brief Build an uncompressed ESP header
 *
 * @param context      The decompression context
 * @param decoded      The values decoded from the ROHC header
 * @param dest         The buffer to store the ESP header (MUST be at least
 *                     of sizeof(struct esphdr) length)
 * @param payload_len  The length of the ESP payload
 * @return             The length of the next header (ie. the ESP header),
 *                     -1 in case of error
 */
static int esp_build_uncomp_esp(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_decoded_values *const decoded,
                                uint8_t *const dest,
                                const unsigned int payload_len __attribute__((unused)))
{
	const size_t spi_length = sizeof(uint32_t);
	struct esphdr *const esp = (struct esphdr *) dest;

	/* static SPI field */
	memcpy(&esp->spi, &decoded->esp_spi, spi_length);
	rohc_decomp_debug(context, "SPI = 0x%08x", rohc_ntoh32(esp->spi));

	/* dynamic SN field */
	esp->sn = rohc_hton32(decoded->sn);
	rohc_decomp_debug(context, "SN = 0x%08x", rohc_ntoh32(esp->sn));

	return sizeof(struct esphdr);
}


/**
 * @brief Update context with decoded ESP values
 *
 * The following decoded values are updated in context:
 *  - ESP SPI
 *
 * @param context  The decompression context
 * @param decoded  The decoded values to update in the context
 */
static void esp_update_context(struct rohc_decomp_ctxt *const context,
                               const struct rohc_decoded_values *const decoded)
{
	struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt = context->persist_ctxt;
	struct esphdr *const esp =
		(struct esphdr *) rfc3095_ctxt->outer_ip_changes->next_header;

	memcpy(&esp->spi, &decoded->esp_spi, sizeof(uint32_t));
}


/**
 * @brief Define the decompression part of the ESP profile as described
 *        in the RFC 3095.
 */
const struct rohc_decomp_profile d_esp_profile =
{
	.id              = ROHC_PROFILE_ESP, /* profile ID (RFC 3095, §8) */
	.msn_max_bits    = 32,
	.new_context     = (rohc_decomp_new_context_t) d_esp_create,
	.free_context    = (rohc_decomp_free_context_t) d_esp_destroy,
	.detect_pkt_type = ip_detect_packet_type,
	.parse_pkt       = (rohc_decomp_parse_pkt_t) rfc3095_decomp_parse_pkt,
	.decode_bits     = (rohc_decomp_decode_bits_t) rfc3095_decomp_decode_bits,
	.build_hdrs      = (rohc_decomp_build_hdrs_t) rfc3095_decomp_build_hdrs,
	.update_ctxt     = (rohc_decomp_update_ctxt_t) rfc3095_decomp_update_ctxt,
	.attempt_repair  = (rohc_decomp_attempt_repair_t) rfc3095_decomp_attempt_repair,
	.get_sn          = rohc_decomp_rfc3095_get_sn,
};

