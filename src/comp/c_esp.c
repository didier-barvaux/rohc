/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2009,2010 Thales Communications
 * Copyright 2012,2013,2014 Viveris Technologies
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
 * @file   c_esp.c
 * @brief  ROHC ESP compression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_comp_rfc3095.h"
#include "c_ip.h"
#include "rohc_traces_internal.h"
#include "crc.h"
#include "protocols/esp.h"
#include "rohc_utils.h"

#include <stdbool.h>
#include <string.h>
#include <assert.h>


/*
 * Private structures and types
 */

/**
 * @brief Define the ESP part of the profile decompression context
 *
 * This object must be used with the generic part of the decompression
 * context rohc_comp_rfc3095_ctxt.
 *
 * @see rohc_comp_rfc3095_ctxt
 */
struct sc_esp_context
{
	/// The previous ESP header
	struct esphdr old_esp;
};


/*
 * Private function prototypes
 */

static bool c_esp_create(struct rohc_comp_ctxt *const context,
                         const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int c_esp_encode(struct rohc_comp_ctxt *const context,
                        const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                        const struct rohc_buf *const packet,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 6)));

static uint32_t c_esp_get_next_sn(const struct rohc_comp_ctxt *const context,
                                  const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static size_t esp_code_static_esp_part(const struct rohc_comp_ctxt *const context,
                                       const uint8_t *const next_header,
                                       uint8_t *const dest,
                                       const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static size_t esp_code_dynamic_esp_part(const struct rohc_comp_ctxt *const context,
                                        const uint8_t *const next_header,
                                        uint8_t *const dest,
                                        const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));


/*
 * Private function definitions
 */

/**
 * @brief Create a new ESP context and initialize it thanks to the given IP/ESP
 *        packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context          The compression context
 * @param uncomp_pkt_hdrs  The uncompressed headers to initialize the new context
 * @return                 true if successful, false otherwise
 */
static bool c_esp_create(struct rohc_comp_ctxt *const context,
                         const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_esp_context *esp_context;

	assert(uncomp_pkt_hdrs->innermost_ip_hdr->next_proto == ROHC_IPPROTO_ESP);
	assert(uncomp_pkt_hdrs->esp != NULL);

	/* create and initialize the generic part of the profile context */
	if(!rohc_comp_rfc3095_create(context, uncomp_pkt_hdrs))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto quit;
	}
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* initialize SN with the SN found in the ESP header */
	rfc3095_ctxt->sn = rohc_ntoh32(uncomp_pkt_hdrs->esp->sn);
	rohc_comp_debug(context, "initialize context(SN) = hdr(SN) of first "
	                "packet = %u", rfc3095_ctxt->sn);

	/* create the ESP part of the profile context */
	esp_context = malloc(sizeof(struct sc_esp_context));
	if(esp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the ESP part of the profile context");
		goto clean;
	}
	rfc3095_ctxt->specific = esp_context;

	/* initialize the ESP part of the profile context */
	memcpy(&(esp_context->old_esp), uncomp_pkt_hdrs->esp, sizeof(struct esphdr));

	/* init the ESP-specific variables and functions */
	rfc3095_ctxt->next_header_len = sizeof(struct esphdr);
	rfc3095_ctxt->encode_uncomp_fields = NULL;
	rfc3095_ctxt->decide_state = rohc_comp_rfc3095_decide_state;
	rfc3095_ctxt->decide_FO_packet = c_ip_decide_FO_packet;
	rfc3095_ctxt->decide_SO_packet = c_ip_decide_SO_packet;
	rfc3095_ctxt->decide_extension = decide_extension;
	rfc3095_ctxt->init_at_IR = NULL;
	rfc3095_ctxt->get_next_sn = c_esp_get_next_sn;
	rfc3095_ctxt->code_static_part = esp_code_static_esp_part;
	rfc3095_ctxt->code_dynamic_part = esp_code_dynamic_esp_part;
	rfc3095_ctxt->code_ir_remainder = NULL;
	rfc3095_ctxt->code_UO_packet_head = NULL;
	rfc3095_ctxt->code_uo_remainder = NULL;
	rfc3095_ctxt->compute_crc_static = esp_compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = esp_compute_crc_dynamic;

	return true;

clean:
	rohc_comp_rfc3095_destroy(context);
quit:
	return false;
}


/**
 * @brief Encode an IP/ESP packet according to a pattern decided by several
 *        different factors.
 *
 * @param context           The compression context
 * @param uncomp_pkt_hdrs   The uncompressed headers to encode
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int c_esp_encode(struct rohc_comp_ctxt *const context,
                        const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                        const struct rohc_buf *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	struct sc_esp_context *const esp_context = rfc3095_ctxt->specific;
	const struct esphdr *esp;
	struct net_pkt ip_pkt;
	int size;

	/* parse the uncompressed packet */
	net_pkt_parse(&ip_pkt, *uncomp_pkt, context->compressor->trace_callback,
	              context->compressor->trace_callback_priv, ROHC_TRACE_COMP);

	/* retrieve the ESP header */
	assert(ip_pkt.transport->data != NULL);
	esp = (struct esphdr *) ip_pkt.transport->data;

	/* encode the IP packet */
	size = rohc_comp_rfc3095_encode(context, uncomp_pkt_hdrs, uncomp_pkt,
	                                rohc_pkt, rohc_pkt_max_len, packet_type);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new ESP header */
	if((*packet_type) == ROHC_PACKET_IR ||
	   (*packet_type) == ROHC_PACKET_IR_DYN)
	{
		memcpy(&(esp_context->old_esp), esp, sizeof(struct esphdr));
	}

quit:
	return size;
}


/**
 * @brief Determine the SN value for the next packet
 *
 * Profile SN is the ESP SN.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @return            The SN
 */
static uint32_t c_esp_get_next_sn(const struct rohc_comp_ctxt *const context __attribute__((unused)),
                                  const struct net_pkt *const uncomp_pkt)
{
	const struct esphdr *const esp = (struct esphdr *) uncomp_pkt->transport->data;

	return rohc_ntoh32(esp->sn);
}


/**
 * @brief Build the static part of the ESP header
 *
 * \verbatim

 Static part of ESP header (5.7.7.7):

    +---+---+---+---+---+---+---+---+
 1  /              SPI              /   4 octets
    +---+---+---+---+---+---+---+---+

 SPI = Security Parameters Index

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The ESP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t esp_code_static_esp_part(const struct rohc_comp_ctxt *const context,
                                       const uint8_t *const next_header,
                                       uint8_t *const dest,
                                       const size_t counter)
{
	const struct esphdr *const esp = (struct esphdr *) next_header;
	size_t nr_written = 0;

	/* part 1 */
	rohc_comp_debug(context, "ESP SPI = 0x%08x", rohc_ntoh32(esp->spi));
	memcpy(&dest[counter + nr_written], &esp->spi, sizeof(uint32_t));
	nr_written += sizeof(uint32_t);

	return counter + nr_written;
}


/**
 * @brief Build the dynamic part of the ESP header
 *
 * \verbatim

 Dynamic part of ESP header (5.7.7.7):

    +---+---+---+---+---+---+---+---+
 1  /       Sequence Number         /   4 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The ESP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t esp_code_dynamic_esp_part(const struct rohc_comp_ctxt *const context,
                                        const uint8_t *const next_header,
                                        uint8_t *const dest,
                                        const size_t counter)
{
	const struct esphdr *const esp = (struct esphdr *) next_header;
	size_t nr_written = 0;

	/* part 1 */
	rohc_comp_debug(context, "ESP SN = 0x%08x", rohc_ntoh32(esp->sn));
	memcpy(&dest[counter + nr_written], &esp->sn, sizeof(uint32_t));
	nr_written += sizeof(uint32_t);

	return counter + nr_written;
}


/**
 * @brief Define the compression part of the ESP profile as described
 *        in the RFC 3095.
 */
const struct rohc_comp_profile c_esp_profile =
{
	.id             = ROHC_PROFILE_ESP, /* profile ID (see 8 in RFC 3095) */
	.create         = c_esp_create,     /* profile handlers */
	.destroy        = rohc_comp_rfc3095_destroy,
	.encode         = c_esp_encode,
	.feedback       = rohc_comp_rfc3095_feedback,
};

