/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010,2012,2013,2014 Viveris Technologies
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
 * @file c_udp.c
 * @brief ROHC compression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "c_udp.h"
#include "c_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "crc.h"
#include "rohc_comp_rfc3095.h"
#include "protocols/udp.h"

#include <stdlib.h>
#ifndef __KERNEL__
#  include <string.h>
#endif
#include <assert.h>


/**
 * @brief Define the UDP-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the UDP-specific decompression context
 * sc_udp_context.
 *
 * @see sc_udp_context
 */
struct udp_tmp_vars
{
	/** The number of UDP fields that changed in the UDP header */
	int send_udp_dynamic;
};


/**
 * @brief Define the UDP part of the profile decompression context.
 *
 * This object must be used with the generic part of the decompression
 * context rohc_comp_rfc3095_ctxt.
 *
 * @see rohc_comp_rfc3095_ctxt
 */
struct sc_udp_context
{
	/** @brief The number of times the checksum field was added to the
	 *         compressed header */
	size_t udp_checksum_change_count;

	/** The previous UDP header */
	struct udphdr old_udp;

	/** @brief UDP-specific temporary variables that are used during one single
	 *         compression of packet */
	struct udp_tmp_vars tmp;
};


/*
 * Private function prototypes.
 */

static bool c_udp_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void udp_decide_state(struct rohc_comp_ctxt *const context);

static int c_udp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

static size_t udp_code_dynamic_udp_part(const struct rohc_comp_ctxt *const context,
                                        const uint8_t *const next_header,
                                        uint8_t *const dest,
                                        const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int udp_changed_udp_dynamic(const struct rohc_comp_ctxt *context,
                                   const struct udphdr *udp);


/**
 * @brief Create a new UDP context and initialize it thanks to the given IP/UDP
 *        packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP/UDP packet given to initialize the new context
 * @return         true if successful, false otherwise
 */
static bool c_udp_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
{
	const struct rohc_comp *const comp = context->compressor;
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_context *udp_context;
	const struct udphdr *udp;

	/* create and initialize the generic part of the profile context */
	if(!rohc_comp_rfc3095_create(context, 16, ROHC_LSB_SHIFT_SN, packet))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto quit;
	}
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* initialize SN to a random value (RFC 3095, 5.11.1) */
	rfc3095_ctxt->sn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "initialize context(SN) = random() = %u",
	                rfc3095_ctxt->sn);

	/* check that transport protocol is UDP */
	assert(packet->transport->proto == ROHC_IPPROTO_UDP);
	assert(packet->transport->data != NULL);
	udp = (struct udphdr *) packet->transport->data;

	/* create the UDP part of the profile context */
	udp_context = malloc(sizeof(struct sc_udp_context));
	if(udp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the UDP part of the profile context");
		goto clean;
	}
	rfc3095_ctxt->specific = udp_context;

	/* initialize the UDP part of the profile context */
	udp_context->udp_checksum_change_count = 0;
	memcpy(&udp_context->old_udp, udp, sizeof(struct udphdr));

	/* init the UDP-specific temporary variables */
	udp_context->tmp.send_udp_dynamic = -1;

	/* init the UDP-specific variables and functions */
	rfc3095_ctxt->next_header_len = sizeof(struct udphdr);
	rfc3095_ctxt->decide_state = udp_decide_state;
	rfc3095_ctxt->decide_FO_packet = c_ip_decide_FO_packet;
	rfc3095_ctxt->decide_SO_packet = c_ip_decide_SO_packet;
	rfc3095_ctxt->decide_extension = decide_extension;
	rfc3095_ctxt->init_at_IR = NULL;
	rfc3095_ctxt->get_next_sn = c_ip_get_next_sn;
	rfc3095_ctxt->code_static_part = udp_code_static_udp_part;
	rfc3095_ctxt->code_dynamic_part = udp_code_dynamic_udp_part;
	rfc3095_ctxt->code_ir_remainder = c_ip_code_ir_remainder;
	rfc3095_ctxt->code_UO_packet_head = NULL;
	rfc3095_ctxt->code_uo_remainder = udp_code_uo_remainder;
	rfc3095_ctxt->compute_crc_static = udp_compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = udp_compute_crc_dynamic;

	return true;

clean:
	rohc_comp_rfc3095_destroy(context);
quit:
	return false;
}


/**
 * @brief Check if the given packet corresponds to the UDP profile
 *
 * Conditions are:
 *  \li the transport protocol is UDP
 *  \li the version of the outer IP header is 4 or 6
 *  \li the outer IP header is not an IP fragment
 *  \li if there are at least 2 IP headers, the version of the inner IP header
 *      is 4 or 6
 *  \li if there are at least 2 IP headers, the inner IP header is not an IP
 *      fragment
 *  \li the inner IP payload is at least 8-byte long for UDP header
 *  \li the UDP Length field and the UDP payload match
 *
 * @see rohc_comp_rfc3095_check_profile
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
bool c_udp_check_profile(const struct rohc_comp *const comp,
                         const struct net_pkt *const packet)
{
	const struct udphdr *udp_header;
	bool ip_check;

	assert(comp != NULL);
	assert(packet != NULL);

	/* check that the the versions of outer and inner IP headers are 4 or 6
	   and that outer and inner IP headers are not IP fragments */
	ip_check = rohc_comp_rfc3095_check_profile(comp, packet);
	if(!ip_check)
	{
		goto bad_profile;
	}

	/* IP payload shall be large enough for UDP header */
	if(packet->transport->len < sizeof(struct udphdr))
	{
		goto bad_profile;
	}

	/* check that the transport protocol is UDP */
	if(packet->transport->data == NULL ||
	   packet->transport->proto != ROHC_IPPROTO_UDP)
	{
		goto bad_profile;
	}

	/* retrieve the UDP header */
	udp_header = (const struct udphdr *) packet->transport->data;
	if(packet->transport->len != rohc_ntoh16(udp_header->len))
	{
		goto bad_profile;
	}

	return true;

bad_profile:
	return false;
}


/**
 * @brief Check if the IP/UDP packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - the transport protocol must be UDP
 *  - the source and destination ports of the UDP header must match the ones in
 *    the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP/UDP packet to check
 * @return         true if the IP/UDP packet belongs to the context
 *                 false if it does not belong to the context
 */
bool c_udp_check_context(const struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt =
		(struct rohc_comp_rfc3095_ctxt *) context->specific;
	const struct sc_udp_context *const udp_context =
		(struct sc_udp_context *) rfc3095_ctxt->specific;
	const struct udphdr *const udp = (struct udphdr *) packet->transport->data;

	/* first, check the same parameters as for the IP-only profile */
	if(!c_ip_check_context(context, packet))
	{
		goto bad_context;
	}

	/* in addition, check UDP ports */
	if(udp_context->old_udp.source != udp->source ||
	   udp_context->old_udp.dest != udp->dest)
	{
		goto bad_context;
	}

	return true;

bad_context:
	return false;
}


/**
 * @brief Encode an IP/UDP packet according to a pattern decided by several
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
static int c_udp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_context *udp_context;
	const struct udphdr *udp;
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	assert(rfc3095_ctxt->specific != NULL);
	udp_context = (struct sc_udp_context *) rfc3095_ctxt->specific;

	/* retrieve the UDP header */
	assert(uncomp_pkt->transport->data != NULL);
	udp = (struct udphdr *) uncomp_pkt->transport->data;

	/* check that UDP length is correct (we have to discard all packets with
	 * wrong UDP length fields, otherwise the ROHC decompressor will compute
	 * a different UDP length on its side) */
	if(rohc_ntoh16(udp->len) != uncomp_pkt->transport->len)
	{
		rohc_comp_warn(context, "wrong UDP Length field in UDP header: %u "
		               "found while %zu expected", rohc_ntoh16(udp->len),
		               uncomp_pkt->transport->len);
		return -1;
	}

	/* how many UDP fields changed? */
	udp_context->tmp.send_udp_dynamic = udp_changed_udp_dynamic(context, udp);

	/* encode the IP packet */
	size = rohc_comp_rfc3095_encode(context, uncomp_pkt, rohc_pkt, rohc_pkt_max_len,
	                                packet_type, payload_offset);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new UDP header */
	if(rfc3095_ctxt->tmp.packet_type == ROHC_PACKET_IR ||
	   rfc3095_ctxt->tmp.packet_type == ROHC_PACKET_IR_DYN)
	{
		memcpy(&udp_context->old_udp, udp, sizeof(struct udphdr));
	}

quit:
	return size;
}


/**
 * @brief Decide the state that should be used for the next packet compressed
 *        with the ROHC UDP profile.
 *
 * The three states are:
 *  - Initialization and Refresh (IR),
 *  - First Order (FO),
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
static void udp_decide_state(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_context *udp_context;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	udp_context = (struct sc_udp_context *) rfc3095_ctxt->specific;

	if(udp_context->tmp.send_udp_dynamic)
	{
		rohc_comp_debug(context, "go back to IR state because UDP checksum "
		                "behaviour changed in the last few packets");
		rohc_comp_change_state(context, ROHC_COMP_STATE_IR);
	}
	else
	{
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		rohc_comp_rfc3095_decide_state(context);
	}
}


/**
 * @brief Build UDP-related fields in the tail of the UO packets.
 *
 * \verbatim

     --- --- --- --- --- --- --- ---
    :                               :
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
size_t udp_code_uo_remainder(const struct rohc_comp_ctxt *const context,
                             const uint8_t *const next_header,
                             uint8_t *const dest,
                             const size_t counter)
{
	const struct udphdr *const udp = (struct udphdr *) next_header;
	size_t nr_written = 0;

	/* part 13 */
	if(udp->check != 0)
	{
		rohc_comp_debug(context, "UDP checksum = 0x%x", udp->check);
		memcpy(&dest[counter], &udp->check, 2);
		nr_written += 2;
	}

	return counter + nr_written;
}


/**
 * @brief Build the static part of the UDP header.
 *
 * \verbatim

 Static part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /          Source Port          /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /       Destination Port        /   2 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
size_t udp_code_static_udp_part(const struct rohc_comp_ctxt *const context,
                                const uint8_t *const next_header,
                                uint8_t *const dest,
                                const size_t counter)
{
	const struct udphdr *const udp = (struct udphdr *) next_header;
	size_t nr_written = 0;

	/* part 1 */
	rohc_comp_debug(context, "UDP source port = 0x%x", udp->source);
	memcpy(&dest[counter + nr_written], &udp->source, 2);
	nr_written += 2;

	/* part 2 */
	rohc_comp_debug(context, "UDP dest port = 0x%x", udp->dest);
	memcpy(&dest[counter + nr_written], &udp->dest, 2);
	nr_written += 2;

	return counter + nr_written;
}


/**
 * @brief Build the dynamic part of the UDP header.
 *
 * \verbatim

 Dynamic part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /           Checksum            /   2 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t udp_code_dynamic_udp_part(const struct rohc_comp_ctxt *const context,
                                        const uint8_t *const next_header,
                                        uint8_t *const dest,
                                        const size_t counter)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_context *udp_context;
	const struct udphdr *udp;
	size_t nr_written = 0;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	udp_context = (struct sc_udp_context *) rfc3095_ctxt->specific;

	udp = (struct udphdr *) next_header;

	/* part 1 */
	rohc_comp_debug(context, "UDP checksum = 0x%x", udp->check);
	memcpy(&dest[counter + nr_written], &udp->check, 2);
	nr_written += 2;
	udp_context->udp_checksum_change_count++;

	return counter + nr_written;
}


/**
 * @brief Check if the dynamic part of the UDP header changed.
 *
 * @param context The compression context
 * @param udp     The UDP header
 * @return        The number of UDP fields that changed
 */
static int udp_changed_udp_dynamic(const struct rohc_comp_ctxt *context,
                                   const struct udphdr *udp)
{
	const struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_context *udp_context;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	udp_context = (struct sc_udp_context *) rfc3095_ctxt->specific;

	if((udp->check != 0 && udp_context->old_udp.check == 0) ||
	   (udp->check == 0 && udp_context->old_udp.check != 0) ||
	   (udp_context->udp_checksum_change_count < MAX_IR_COUNT))
	{
		if((udp->check != 0 && udp_context->old_udp.check == 0) ||
		   (udp->check == 0 && udp_context->old_udp.check != 0))
		{
			udp_context->udp_checksum_change_count = 0;
		}
		return 1;
	}
	else
	{
		return 0;
	}
}


/**
 * @brief Define the compression part of the UDP profile as described
 *        in the RFC 3095.
 */
const struct rohc_comp_profile c_udp_profile =
{
	.id             = ROHC_PROFILE_UDP, /* profile ID (see 8 in RFC 3095) */
	.protocol       = ROHC_IPPROTO_UDP, /* IP protocol */
	.create         = c_udp_create,     /* profile handlers */
	.destroy        = rohc_comp_rfc3095_destroy,
	.check_profile  = c_udp_check_profile,
	.check_context  = c_udp_check_context,
	.encode         = c_udp_encode,
	.reinit_context = rohc_comp_reinit_context,
	.feedback       = rohc_comp_rfc3095_feedback,
};

