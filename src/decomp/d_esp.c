/*
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
 * @file   d_esp.c
 * @brief  ROHC ESP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_esp.h"
#include "d_generic.h"
#include "d_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "crc.h"
#include "protocols/esp.h"
#include "lsb_decode.h"
#include "rohc_decomp_internals.h"

#include <stdint.h>
#ifndef __KERNEL__
#	include <string.h>
#endif
#include <assert.h>


/**
 * @brief Define the ESP part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context d_generic_context.
 *
 * @see d_generic_context
 */
struct d_esp_context
{
	/** ESP SPI */
	uint32_t spi;
};



/*
 * Private function prototypes.
 */

static void * d_esp_create(const struct d_context *const context);
static void d_esp_destroy(void *const context)
	__attribute__((nonnull(1)));

static int esp_parse_static_esp(const struct d_context *const context,
                                const unsigned char *packet,
                                unsigned int length,
                                struct rohc_extr_bits *const bits);

static int esp_parse_dynamic_esp(const struct d_context *const context,
                                 const unsigned char *packet,
                                 unsigned int length,
                                 struct rohc_extr_bits *const bits);

static bool esp_decode_values_from_bits(const struct d_context *context,
                                        const struct rohc_extr_bits bits,
                                        struct rohc_decoded_values *const decoded);

static int esp_build_uncomp_esp(const struct d_context *const context,
                                const struct rohc_decoded_values decoded,
                                unsigned char *dest,
                                const unsigned int payload_len);

static void esp_update_context(const struct d_context *context,
                               const struct rohc_decoded_values decoded);


/*
 * Private function definitions
 */

/**
 * @brief Create the ESP decompression context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The decompression context
 * @return         The newly-created ESP decompression context
 */
static void * d_esp_create(const struct d_context *const context)
{
	struct d_generic_context *g_context;
	struct d_esp_context *esp_context;

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
		           "failed to create the generic decompression context\n");
		goto quit;
	}
	g_context->specific = NULL;

	/* create the ESP-specific part of the context */
	esp_context = malloc(sizeof(struct d_esp_context));
	if(esp_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the ESP-specific context\n");
		goto destroy_context;
	}
	memset(esp_context, 0, sizeof(struct d_esp_context));
	g_context->specific = esp_context;

	/* create the LSB decoding context for SN (same shift value as RTP) */
	g_context->sn_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_ESP_SN, 32);
	if(g_context->sn_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for SN\n");
		goto free_esp_context;
	}

	/* some ESP-specific values and functions */
	g_context->next_header_len = sizeof(struct esphdr);
	g_context->detect_packet_type = ip_detect_packet_type;
	g_context->parse_static_next_hdr = esp_parse_static_esp;
	g_context->parse_dyn_next_hdr = esp_parse_dynamic_esp;
	g_context->parse_uo_remainder = NULL;
	g_context->decode_values_from_bits = esp_decode_values_from_bits;
	g_context->build_next_header = esp_build_uncomp_esp;
	g_context->compute_crc_static = esp_compute_crc_static;
	g_context->compute_crc_dynamic = esp_compute_crc_dynamic;
	g_context->update_context = esp_update_context;

	/* create the ESP-specific part of the header changes */
	g_context->outer_ip_changes->next_header_len = sizeof(struct esphdr);
	g_context->outer_ip_changes->next_header =
		(unsigned char *) malloc(sizeof(struct esphdr));
	if(g_context->outer_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the ESP-specific part of the "
		           "outer IP header changes\n");
		goto free_lsb_sn;
	}
	memset(g_context->outer_ip_changes->next_header, 0, sizeof(struct esphdr));

	g_context->inner_ip_changes->next_header_len = sizeof(struct esphdr);
	g_context->inner_ip_changes->next_header =
		(unsigned char *) malloc(sizeof(struct esphdr));
	if(g_context->inner_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the ESP-specific part of the "
		           "inner IP header changes\n");
		goto free_outer_ip_changes_next_header;
	}
	memset(g_context->inner_ip_changes->next_header, 0, sizeof(struct esphdr));

	/* set next header to ESP */
	g_context->next_header_proto = ROHC_IPPROTO_ESP;

	return g_context;

free_outer_ip_changes_next_header:
	zfree(g_context->outer_ip_changes->next_header);
free_lsb_sn:
	rohc_lsb_free(g_context->sn_lsb_ctxt);
free_esp_context:
	zfree(esp_context);
destroy_context:
	d_generic_destroy(g_context);
quit:
	return NULL;
}


/**
 * @brief Destroy the context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
static void d_esp_destroy(void *const context)
{
	struct d_generic_context *g_context;

	assert(context != NULL);
	g_context = (struct d_generic_context *) context;

	/* clean ESP-specific memory */
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
 * @brief Parse the ESP static part of the ROHC packet
 *
 * @param context The decompression context
 * @param packet  The ROHC packet to decode
 * @param length  The length of the ROHC packet
 * @param bits    OUT: The bits extracted from the ROHC header
 * @return        The number of bytes read in the ROHC packet,
 *                -1 in case of failure
 */
static int esp_parse_static_esp(const struct d_context *const context,
                                const unsigned char *packet,
                                unsigned int length,
                                struct rohc_extr_bits *const bits)
{
	const size_t spi_length = sizeof(uint32_t);
	struct d_generic_context *g_context;
	struct d_esp_context *esp_context;
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	esp_context = g_context->specific;
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to parse the ESP static part */
	if(length < spi_length)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* SPI */
	memcpy(&bits->esp_spi, packet, spi_length);
	bits->esp_spi_nr = spi_length * 8;
	rohc_decomp_debug(context, "ESP SPI = 0x%08x\n", ntohl(bits->esp_spi));
	packet += spi_length;
	read += spi_length;

	/* is context re-used? */
	if(context->num_recv_packets > 1 &&
	   memcmp(&bits->esp_spi, &esp_context->spi, spi_length) != 0)
	{
		rohc_decomp_debug(context, "ESP SPI mismatch (packet = 0x%08x, "
		                  "context = 0x%08x) -> context is being reused\n",
		                  bits->esp_spi, esp_context->spi);
		bits->is_context_reused = true;
	}
	memcpy(&esp_context->spi, &bits->esp_spi, spi_length);

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
static int esp_parse_dynamic_esp(const struct d_context *const context,
                                 const unsigned char *packet,
                                 unsigned int length,
                                 struct rohc_extr_bits *const bits)
{
	const size_t sn_length = sizeof(uint32_t);
	int read = 0; /* number of bytes read from the packet */
	uint32_t sn;

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to parse the ESP dynamic part */
	if(length < sn_length)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* retrieve the ESP sequence number from the ROHC packet */
	memcpy(&sn, packet, sn_length);
	packet += sn_length;
	read += sn_length;
	bits->sn = ntohl(sn);
	bits->sn_nr = sn_length * 8;
	rohc_decomp_debug(context, "ESP SN = 0x%08x\n", bits->sn);

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
static bool esp_decode_values_from_bits(const struct d_context *context,
                                        const struct rohc_extr_bits bits,
                                        struct rohc_decoded_values *const decoded)
{
	const size_t spi_length = sizeof(uint32_t);
	struct d_generic_context *g_context;
	struct esphdr *esp;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(decoded != NULL);

	esp = (struct esphdr *) g_context->outer_ip_changes->next_header;

	/* decode ESP SPI */
	if(bits.esp_spi_nr > 0)
	{
		/* take packet value */
		assert(bits.esp_spi_nr == (spi_length * 8));
		memcpy(&decoded->esp_spi, &bits.esp_spi, spi_length);
	}
	else
	{
		/* keep context value */
		memcpy(&decoded->esp_spi, &esp->spi, spi_length);
	}
	rohc_decomp_debug(context, "decoded SPI = 0x%08x\n", ntohl(decoded->esp_spi));

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
static int esp_build_uncomp_esp(const struct d_context *const context,
                                const struct rohc_decoded_values decoded,
                                unsigned char *dest,
                                const unsigned int payload_len)
{
	const size_t spi_length = sizeof(uint32_t);
	struct esphdr *const esp = (struct esphdr *) dest;

	/* static SPI field */
	memcpy(&esp->spi, &decoded.esp_spi, spi_length);
	rohc_decomp_debug(context, "SPI = 0x%08x\n", ntohl(esp->spi));

	/* dynamic SN field */
	esp->sn = htonl(decoded.sn);
	rohc_decomp_debug(context, "SN = 0x%08x\n", ntohl(esp->sn));

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
static void esp_update_context(const struct d_context *context,
                               const struct rohc_decoded_values decoded)
{
	struct d_generic_context *g_context;
	struct esphdr *esp;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;

	esp = (struct esphdr *) g_context->outer_ip_changes->next_header;
	memcpy(&esp->spi, &decoded.esp_spi, sizeof(uint32_t));
}


/**
 * @brief Define the decompression part of the ESP profile as described
 *        in the RFC 3095.
 */
struct d_profile d_esp_profile =
{
	ROHC_PROFILE_ESP,       /* profile ID (see 8 in RFC 3095) */
	"ESP / Decompressor",   /* profile description */
	d_generic_decode,       /* profile handlers */
	d_esp_create,
	d_esp_destroy,
	d_generic_get_sn,
};

