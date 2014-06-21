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

#include "c_generic.h"
#include "c_ip.h"
#include "rohc_traces_internal.h"
#include "crc.h"
#include "protocols/esp.h"
#include "rohc_utils.h"

#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif
#ifndef __KERNEL__
#	include <string.h>
#endif
#include <assert.h>


/*
 * Private structures and types
 */

/**
 * @brief Define the ESP part of the profile decompression context
 *
 * This object must be used with the generic part of the decompression
 * context c_generic_context.
 *
 * @see c_generic_context
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
                         const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool c_esp_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool c_esp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int c_esp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const packet,
                        unsigned char *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

static uint32_t c_esp_get_next_sn(const struct rohc_comp_ctxt *const context,
                                  const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static size_t esp_code_static_esp_part(const struct rohc_comp_ctxt *const context,
                                       const unsigned char *const next_header,
                                       unsigned char *const dest,
                                       const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static size_t esp_code_dynamic_esp_part(const struct rohc_comp_ctxt *const context,
                                        const unsigned char *const next_header,
                                        unsigned char *const dest,
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
 * @param context  The compression context
 * @param packet   The IP/ESP packet given to initialize the new context
 * @return         true if successful, false otherwise
 */
static bool c_esp_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
{
	struct c_generic_context *g_context;
	struct sc_esp_context *esp_context;
	const struct esphdr *esp;

	assert(context != NULL);
	assert(context->profile != NULL);
	assert(packet != NULL);

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_ESP_SN, packet))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto quit;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* check that transport protocol is ESP */
	assert(packet->transport->proto == ROHC_IPPROTO_ESP);
	assert(packet->transport->data != NULL);
	esp = (struct esphdr *) packet->transport->data;

	/* initialize SN with the SN found in the ESP header */
	g_context->sn = rohc_ntoh32(esp->sn);
	rohc_comp_debug(context, "initialize context(SN) = hdr(SN) of first "
	                "packet = %u", g_context->sn);

	/* create the ESP part of the profile context */
	esp_context = malloc(sizeof(struct sc_esp_context));
	if(esp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the ESP part of the profile context");
		goto clean;
	}
	g_context->specific = esp_context;

	/* initialize the ESP part of the profile context */
	memcpy(&(esp_context->old_esp), esp, sizeof(struct esphdr));

	/* init the ESP-specific variables and functions */
	g_context->next_header_len = sizeof(struct esphdr);
	g_context->encode_uncomp_fields = NULL;
	g_context->decide_state = decide_state;
	g_context->decide_FO_packet = c_ip_decide_FO_packet;
	g_context->decide_SO_packet = c_ip_decide_SO_packet;
	g_context->decide_extension = decide_extension;
	g_context->init_at_IR = NULL;
	g_context->get_next_sn = c_esp_get_next_sn;
	g_context->code_static_part = esp_code_static_esp_part;
	g_context->code_dynamic_part = esp_code_dynamic_esp_part;
	g_context->code_ir_remainder = NULL;
	g_context->code_UO_packet_head = NULL;
	g_context->code_uo_remainder = NULL;
	g_context->compute_crc_static = esp_compute_crc_static;
	g_context->compute_crc_dynamic = esp_compute_crc_dynamic;

	return true;

clean:
	c_generic_destroy(context);
quit:
	return false;
}


/**
 * @brief Check if the given packet corresponds to the ESP profile
 *
 * Conditions are:
 *  \li the transport protocol is ESP
 *  \li the version of the outer IP header is 4 or 6
 *  \li the outer IP header is not an IP fragment
 *  \li if there are at least 2 IP headers, the version of the inner IP header
 *      is 4 or 6
 *  \li if there are at least 2 IP headers, the inner IP header is not an IP
 *      fragment
 *
 * @see c_generic_check_profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param comp    The ROHC compressor
 * @param packet  The packet to check
 * @return        Whether the IP packet corresponds to the profile:
 *                  \li true if the IP packet corresponds to the profile,
 *                  \li false if the IP packet does not correspond to
 *                      the profile
 */
static bool c_esp_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
{
	bool ip_check;

	assert(comp != NULL);
	assert(packet != NULL);

	/* check that the the versions of outer and inner IP headers are 4 or 6
	   and that outer and inner IP headers are not IP fragments */
	ip_check = c_generic_check_profile(comp, packet);
	if(!ip_check)
	{
		goto bad_profile;
	}

	/* IP payload shall be large enough for ESP header */
	if(packet->transport->len < sizeof(struct esphdr))
	{
		goto bad_profile;
	}

	/* check that the transport protocol is ESP */
	if(packet->transport->data == NULL ||
	   packet->transport->proto != ROHC_IPPROTO_ESP)
	{
		goto bad_profile;
	}

	return true;

bad_profile:
	return false;
}


/**
 * @brief Check if the IP/ESP packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - the transport protocol must be ESP
 *  - the security parameters index of the ESP header must match the one in
 *    the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP/UDP packet to check
 * @return         true if the packet belongs to the context,
 *                 false if it does not belong to the context
 */
static bool c_esp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
{
	struct c_generic_context *g_context;
	struct sc_esp_context *esp_context;
	const struct esphdr *esp;

	assert(context != NULL);
	assert(packet != NULL);

	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	esp_context = (struct sc_esp_context *) g_context->specific;

	/* first, check the same parameters as for the IP-only profile */
	if(!c_ip_check_context(context, packet))
	{
		goto bad_context;
	}

	/* in addition, check Security parameters index (SPI) */
	assert(packet->transport->data != NULL);
	esp = (struct esphdr *) packet->transport->data;
	if(esp_context->old_esp.spi != esp->spi)
	{
		goto bad_context;
	}

	return true;

bad_context:
	return false;
}


/**
 * @brief Encode an IP/ESP packet according to a pattern decided by several
 *        different factors.
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int c_esp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        unsigned char *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_esp_context *esp_context;
	const struct esphdr *esp;
	int size;

	assert(context != NULL);
	assert(uncomp_pkt != NULL);
	assert(rohc_pkt != NULL);
	assert(packet_type != NULL);

	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	esp_context = (struct sc_esp_context *) g_context->specific;

	/* retrieve the ESP header */
	assert(uncomp_pkt->transport->data != NULL);
	esp = (struct esphdr *) uncomp_pkt->transport->data;

	/* encode the IP packet */
	size = c_generic_encode(context, uncomp_pkt, rohc_pkt, rohc_pkt_max_len,
	                        packet_type, payload_offset);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new ESP header */
	if(g_context->tmp.packet_type == ROHC_PACKET_IR ||
	   g_context->tmp.packet_type == ROHC_PACKET_IR_DYN)
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
	const struct esphdr *const esp =
		(struct esphdr *) uncomp_pkt->transport->data;

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
                                       const unsigned char *const next_header,
                                       unsigned char *const dest,
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
                                        const unsigned char *const next_header,
                                        unsigned char *const dest,
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
	.protocol       = ROHC_IPPROTO_ESP, /* IP protocol */
	.create         = c_esp_create,     /* profile handlers */
	.destroy        = c_generic_destroy,
	.check_profile  = c_esp_check_profile,
	.check_context  = c_esp_check_context,
	.encode         = c_esp_encode,
	.reinit_context = c_generic_reinit_context,
	.feedback       = c_generic_feedback,
	.use_udp_port   = c_generic_use_udp_port,
};

