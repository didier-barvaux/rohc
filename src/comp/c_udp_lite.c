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
 * @file   c_udp_lite.c
 * @brief  ROHC compression context for the UDP-Lite profile.
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
#include "protocols/udp_lite.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


/// @brief The maximal number of times the checksum coverage dit not change
///        or may be inferred
#define MAX_LITE_COUNT 2


/**
 * @brief Define the UDP-Lite-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the UDP-specific compression context
 * sc_udp_lite_context.
 *
 * @see sc_udp_lite_context
 */
struct udp_lite_tmp_vars
{
	/// The size of the UDP-Lite packet (header + payload)
	int udp_size;
};


/**
 * @brief Define the UDP-Lite part of the profile compression context.
 *
 * This object must be used with the generic part of the compression
 * context rohc_comp_rfc3095_ctxt.
 *
 * @see rohc_comp_rfc3095_ctxt
 */
struct sc_udp_lite_context
{
	/// Whether the Coverage Field is Present or not
	int cfp;
	/// Whether the Coverage Field is Inferred or not
	int cfi;

	/// The F and K bits in the CCE packet (see appendix B in the RFC 4019)
	uint8_t FK;

	/// The number of times the checksum coverage field did not change
	size_t coverage_equal_count;
	/// The number of times the checksum coverage field may be inferred
	size_t coverage_inferred_count;
	/// Temporary variables related to the checksum coverage field
	int tmp_coverage;

	/// The number of CCE() packets sent by the compressor
	size_t sent_cce_only_count;
	/// The number of CCE(ON) packets sent by the compressor
	size_t sent_cce_on_count;
	/// The number of CCE(OFF) packets sent by the compressor
	size_t sent_cce_off_count;

	/// The previous UDP-Lite header
	struct udphdr old_udp_lite;

	/// @brief UDP-Lite-specific temporary variables that are used during one
	///        single compression of packet
	struct udp_lite_tmp_vars tmp;
};



/*
 * Private function prototypes.
 */

static bool c_udp_lite_create(struct rohc_comp_ctxt *const context,
                              const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int c_udp_lite_encode(struct rohc_comp_ctxt *const context,
                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                             const struct rohc_buf *const uncomp_pkt,
                             uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len,
                             rohc_packet_t *const packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 6)));

static size_t udp_lite_code_dynamic_udplite_part(const struct rohc_comp_ctxt *const context,
                                                 const uint8_t *const next_header,
                                                 uint8_t *const dest,
                                                 const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static size_t udp_lite_build_cce_packet(const struct rohc_comp_ctxt *const context,
                                        const uint8_t *const next_header,
                                        uint8_t *const dest,
                                        size_t counter,
                                        size_t *const first_position)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static bool udp_lite_send_cce_packet(const struct rohc_comp_ctxt *const context,
                                     const struct udphdr *const udp_lite)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static size_t udp_lite_code_uo_remainder(const struct rohc_comp_ctxt *const context,
                                         const uint8_t *const next_header,
                                         uint8_t *const dest,
                                         const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static void udp_lite_init_cc(struct rohc_comp_ctxt *const context,
                             const uint8_t *const next_header)
	__attribute__((nonnull(1, 2)));



/**
 * @brief Create a new UDP-Lite context and initialize it thanks to the given
 *        IP/UDP-Lite packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context          The compression context
 * @param uncomp_pkt_hdrs  The uncompressed headers to initialize the new context
 * @return                 true if successful, false otherwise
 */
static bool c_udp_lite_create(struct rohc_comp_ctxt *const context,
                              const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
{
	const struct rohc_comp *const comp = context->compressor;
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_lite_context *udp_lite_context;

	assert(uncomp_pkt_hdrs->innermost_ip_hdr->next_proto == ROHC_IPPROTO_UDPLITE);
	assert(uncomp_pkt_hdrs->udp_lite != NULL);

	/* create and initialize the generic part of the profile context */
	if(!rohc_comp_rfc3095_create(context, uncomp_pkt_hdrs))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto quit;
	}
	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;

	/* initialize SN to a random value (RFC 3095, 5.11.1) */
	rfc3095_ctxt->sn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "initialize context(SN) = random() = %u",
	                rfc3095_ctxt->sn);

	/* create the UDP-Lite part of the profile context */
	udp_lite_context = malloc(sizeof(struct sc_udp_lite_context));
	if(udp_lite_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the UDP-Lite part of the profile context");
		goto clean;
	}
	rfc3095_ctxt->specific = udp_lite_context;

	/* initialize the UDP-Lite part of the profile context */
	udp_lite_context->cfp = 0;
	udp_lite_context->cfi = 0;
	udp_lite_context->FK = 0;
	udp_lite_context->coverage_equal_count = 0;
	udp_lite_context->coverage_inferred_count = 0;
	udp_lite_context->sent_cce_only_count = 0;
	udp_lite_context->sent_cce_on_count = comp->oa_repetitions_nr;
	udp_lite_context->sent_cce_off_count = comp->oa_repetitions_nr;
	memcpy(&udp_lite_context->old_udp_lite, uncomp_pkt_hdrs->udp_lite,
	       sizeof(struct udphdr));

	/* init the UDP-Lite-specific temporary variables */
	udp_lite_context->tmp.udp_size = -1;

	/* init the UDP-Lite-specific variables and functions */
	rfc3095_ctxt->next_header_len = sizeof(struct udphdr);
	rfc3095_ctxt->decide_state = rohc_comp_rfc3095_decide_state;
	rfc3095_ctxt->decide_FO_packet = c_ip_decide_FO_packet;
	rfc3095_ctxt->decide_SO_packet = c_ip_decide_SO_packet;
	rfc3095_ctxt->decide_extension = decide_extension;
	rfc3095_ctxt->init_at_IR = udp_lite_init_cc;
	rfc3095_ctxt->get_next_sn = c_ip_get_next_sn;
	rfc3095_ctxt->code_static_part = udp_code_static_udp_part; /* same as UDP */
	rfc3095_ctxt->code_dynamic_part = udp_lite_code_dynamic_udplite_part;
	rfc3095_ctxt->code_ir_remainder = c_ip_code_ir_remainder;
	rfc3095_ctxt->code_UO_packet_head = udp_lite_build_cce_packet;
	rfc3095_ctxt->code_uo_remainder = udp_lite_code_uo_remainder;
	rfc3095_ctxt->compute_crc_static = udp_compute_crc_static;
	rfc3095_ctxt->compute_crc_dynamic = udp_compute_crc_dynamic;

	return true;

clean:
	rohc_comp_rfc3095_destroy(context);
quit:
	return false;
}


/**
 * @brief Encode an IP/UDP-lite packet according to a pattern decided by several
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
static int c_udp_lite_encode(struct rohc_comp_ctxt *const context,
                             const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                             const struct rohc_buf *const uncomp_pkt,
                             uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len,
                             rohc_packet_t *const packet_type)
{
	struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	struct sc_udp_lite_context *const udp_lite_context = rfc3095_ctxt->specific;
	const struct udphdr *udp_lite;
	struct net_pkt ip_pkt;
	int size;

	/* parse the uncompressed packet */
	net_pkt_parse(&ip_pkt, *uncomp_pkt, context->compressor->trace_callback,
	              context->compressor->trace_callback_priv, ROHC_TRACE_COMP);

	/* retrieve the UDP-Lite header */
	assert(ip_pkt.transport->data != NULL);
	udp_lite = (struct udphdr *) ip_pkt.transport->data;
	udp_lite_context->tmp.udp_size = ip_pkt.transport->len;

	/* encode the IP packet */
	size = rohc_comp_rfc3095_encode(context, uncomp_pkt_hdrs, uncomp_pkt,
	                                rohc_pkt, rohc_pkt_max_len, packet_type);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new UDP-Lite header */
	if((*packet_type) == ROHC_PACKET_IR ||
	   (*packet_type) == ROHC_PACKET_IR_DYN)
	{
		memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));
	}

quit:
	return size;
}


/**
 * @brief Build the Checksum Coverage Extension (CCE) packet.
 *
 * The Checksum Coverage Extension is located at the very start of the UO
 * packet (part 2 in the following figure).
 *
 * \verbatim

     0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :  If for small CIDs and CID 1 - 15
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   0   F | K |  Outer packet type identifier
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /  1 - 2 octets if large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
    :                               :
 4  /   UO-0, UO-1 or UO-2 packet   /
    :                               :
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 1, 3 and 4 are coded by the generic code_UO0_packet, code_UO1_packet
 * and code_UO2_packet functions. These functions call the code_UO_packet_head
 * function which in case of UDP-Lite profile is the udp_lite_build_cce_packet
 * function.
 *
 * When the udp_lite_build_cce_packet is called, the parameter first_position
 * points on the part 2 and the parameter counter points on the beginning of
 * the part 4.
 *
 * @param context        The compression context
 * @param next_header    The UDP header
 * @param dest           The rohc-packet-under-build buffer
 * @param counter        The current position in the rohc-packet-under-build buffer
 * @param first_position The position to place the first byte of packet
 * @return               The new position in the rohc-packet-under-build buffer
 */
static size_t udp_lite_build_cce_packet(const struct rohc_comp_ctxt *const context,
                                        const uint8_t *const next_header,
                                        uint8_t *const dest,
                                        const size_t counter,
                                        size_t *const first_position)
{
	struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	struct sc_udp_lite_context *udp_lite_context;
	const struct udphdr *const udp_lite = (struct udphdr *) next_header;
	size_t nr_written = 0;
	bool send_cce_packet;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) rfc3095_ctxt->specific;


	/* do we need to add the CCE packet? */
	send_cce_packet = udp_lite_send_cce_packet(context, udp_lite);
	if(send_cce_packet)
	{
		rohc_comp_debug(context, "adding CCE");

		/* part 2 */
		dest[*first_position] = (0xf8 | udp_lite_context->FK);

		/* now first_position must point on the first byte of the part 4
		 * and counter must point on the second byte of the part 4 */
		*first_position = counter;
		nr_written++;
	}
	else
	{
		rohc_comp_debug(context, "CCE not needed");
	}

	return counter + nr_written;
}


/**
 * @brief Build UDP-Lite-related fields in the tail of the UO packets.
 *
 * \verbatim

     --- --- --- --- --- --- --- ---
    :                               :  2 octets,
 1  +  UDP-Lite Checksum Coverage   +  if context(CFP) = 1 or
    :                               :  if packet type = CCE
     --- --- --- --- --- --- --- ---
    :                               :
 2  +       UDP-Lite Checksum       +  2 octets
    :                               :
     --- --- --- --- --- --- --- ---

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP-Lite header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t udp_lite_code_uo_remainder(const struct rohc_comp_ctxt *const context,
                                         const uint8_t *const next_header,
                                         uint8_t *const dest,
                                         const size_t counter)
{
	const struct rohc_comp_rfc3095_ctxt *rfc3095_ctxt;
	const struct sc_udp_lite_context *udp_lite_context;
	const struct udphdr *const udp_lite = (struct udphdr *) next_header;
	size_t nr_written = 0;

	rfc3095_ctxt = (struct rohc_comp_rfc3095_ctxt *) context->specific;
	udp_lite_context = (struct sc_udp_lite_context *) rfc3095_ctxt->specific;

	/* part 1 */
	if(udp_lite_context->cfp == 1 ||
	   udp_lite_send_cce_packet(context, udp_lite))
	{
		rohc_comp_debug(context, "UDP-Lite checksum coverage = 0x%04x",
		                rohc_ntoh16(udp_lite->len));
		memcpy(&dest[counter + nr_written], &udp_lite->len, 2);
		nr_written += 2;
	}

	/* part 2 */
	rohc_comp_debug(context, "UDP-Lite checksum = 0x%04x",
	                rohc_ntoh16(udp_lite->check));
	memcpy(&dest[counter + nr_written], &udp_lite->check, 2);
	nr_written += 2;

	return counter + nr_written;
}


/**
 * @brief Build the dynamic part of the UDP-Lite header.
 *
 * \verbatim

 Dynamic part of UDP-Lite header (5.2.1 of RFC 4019):

    +---+---+---+---+---+---+---+---+
 1  /       Checksum Coverage       /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /           Checksum            /   2 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The UDP-Lite header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t udp_lite_code_dynamic_udplite_part(const struct rohc_comp_ctxt *const context,
                                                 const uint8_t *const next_header,
                                                 uint8_t *const dest,
                                                 const size_t counter)
{
	const struct udphdr *const udp_lite = (struct udphdr *) next_header;
	size_t nr_written = 0;

	/* part 1 */
	rohc_comp_debug(context, "UDP-Lite checksum coverage = 0x%04x",
	                rohc_ntoh16(udp_lite->len));
	memcpy(&dest[counter + nr_written], &udp_lite->len, 2);
	nr_written += 2;

	/* part 2 */
	rohc_comp_debug(context, "UDP-Lite checksum = 0x%04x",
	                rohc_ntoh16(udp_lite->check));
	memcpy(&dest[counter + nr_written], &udp_lite->check, 2);
	nr_written += 2;

	return counter + nr_written;
}


/**
 * @brief Initialize checksum coverage in the compression context with the given
 *        UDP-Lite header.
 *
 * @param context     The compression context
 * @param next_header The UDP-Lite header
 */
static void udp_lite_init_cc(struct rohc_comp_ctxt *const context,
                             const uint8_t *const next_header)
{
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	struct sc_udp_lite_context *const udp_lite_context = rfc3095_ctxt->specific;
	const struct udphdr *const udp_lite = (struct udphdr *) next_header;
	int packet_length = udp_lite_context->tmp.udp_size;

	if(context->state_oa_repeat_nr == 1)
	{
		udp_lite_context->cfp = 0;
		udp_lite_context->cfi = 1;
	}

	rohc_comp_debug(context, "CFP = %d, CFI = %d (ir_count = %u)",
	                udp_lite_context->cfp, udp_lite_context->cfi,
	                context->state_oa_repeat_nr);

	udp_lite_context->cfp =
		(rohc_ntoh16(udp_lite->len) != packet_length) || udp_lite_context->cfp;
	udp_lite_context->cfi =
		(rohc_ntoh16(udp_lite->len) == packet_length) && udp_lite_context->cfi;

	rohc_comp_debug(context, "packet_length = %d", packet_length);
	rohc_comp_debug(context, "udp_lite length = %d",
	                rohc_ntoh16(udp_lite->len));
	rohc_comp_debug(context, "CFP = %d, CFI = %d", udp_lite_context->cfp,
	                udp_lite_context->cfi);

	udp_lite_context->tmp_coverage = udp_lite->len;
	memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));
}


/**
 * @brief Check whether a Checksum Coverage Extension (CCE) packet must be sent
 *        or not in order to compress the given UDP-Lite header.
 *
 * The function also updates the FK variable stored in the UDP-Lite context.
 *
 * @param context   The compression context
 * @param udp_lite  The UDP-Lite header
 * @return          true if a CCE packet must be sent, false if not
 */
static bool udp_lite_send_cce_packet(const struct rohc_comp_ctxt *const context,
                                     const struct udphdr *const udp_lite)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	const struct rohc_comp_rfc3095_ctxt *const rfc3095_ctxt = context->specific;
	struct sc_udp_lite_context *const udp_lite_context = rfc3095_ctxt->specific;
	int is_coverage_inferred;
	int is_coverage_same;

	rohc_comp_debug(context, "CFP = %d, CFI = %d", udp_lite_context->cfp,
	                udp_lite_context->cfi);

	/* may the checksum coverage be inferred from UDP-Lite length ? */
	is_coverage_inferred =
		(rohc_ntoh16(udp_lite->len) == udp_lite_context->tmp.udp_size);

	/* is the checksum coverage unchanged since last packet ? */
	if(udp_lite_context->sent_cce_only_count > 0)
	{
		is_coverage_same = (udp_lite_context->tmp_coverage == udp_lite->len);
	}
	else
	{
		is_coverage_same = (udp_lite_context->old_udp_lite.len == udp_lite->len);
	}

	udp_lite_context->tmp_coverage = udp_lite->len;

	if(is_coverage_same)
	{
		udp_lite_context->coverage_equal_count++;
		if(is_coverage_inferred)
		{
			udp_lite_context->coverage_inferred_count++;
		}
	}
	else
	{
		udp_lite_context->coverage_equal_count = 0;
		if(is_coverage_inferred)
		{
			udp_lite_context->coverage_inferred_count++;
		}
		else
		{
			udp_lite_context->coverage_inferred_count = 0;
		}
	}

	if(udp_lite_context->cfp == 0 && udp_lite_context->cfi == 1)
	{
		if(!is_coverage_inferred)
		{
			if(udp_lite_context->sent_cce_only_count < oa_repetitions_nr)
			{
				udp_lite_context->sent_cce_only_count++;
				udp_lite_context->FK = 0x01;
				return true;
			}
			else if(udp_lite_context->coverage_equal_count > MAX_LITE_COUNT)
			{
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->FK = 0x03;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
			else
			{
				udp_lite_context->cfp = 1;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_on_count = 1;
				udp_lite_context->FK = 0x02;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
		}
	}
	else if(udp_lite_context->cfp == 0 && udp_lite_context->cfi == 0)
	{
		if(is_coverage_inferred || !is_coverage_same)
		{
			if(udp_lite_context->sent_cce_only_count < oa_repetitions_nr)
			{
				udp_lite_context->sent_cce_only_count++;
				udp_lite_context->FK = 0x01;
				return true;
			}
			else if(udp_lite_context->coverage_inferred_count > MAX_LITE_COUNT)
			{
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 1;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->FK = 0x03;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
			else
			{
				udp_lite_context->cfp = 1;
				udp_lite_context->cfi = 0;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->sent_cce_on_count = 1;
				udp_lite_context->FK = 0x02;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
		}
	}
	else if(udp_lite_context->cfp == 1)
	{
		if(is_coverage_inferred || is_coverage_same)
		{
			if(udp_lite_context->coverage_equal_count > MAX_LITE_COUNT)
			{
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 0;
				udp_lite_context->FK = 0x03;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
			else if(udp_lite_context->coverage_inferred_count > MAX_LITE_COUNT)
			{
				udp_lite_context->sent_cce_off_count = 1;
				udp_lite_context->sent_cce_only_count = 0;
				udp_lite_context->cfp = 0;
				udp_lite_context->cfi = 1;
				udp_lite_context->FK = 0x03;
				memcpy(&udp_lite_context->old_udp_lite, udp_lite,
				       sizeof(struct udphdr));
				return true;
			}
		}
	}

	if(udp_lite_context->sent_cce_off_count < oa_repetitions_nr)
	{
		udp_lite_context->sent_cce_off_count++;
		udp_lite_context->sent_cce_only_count = 0;
		udp_lite_context->FK = 0x03;
		memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));
		return true;
	}
	else if(udp_lite_context->sent_cce_on_count < oa_repetitions_nr)
	{
		udp_lite_context->sent_cce_on_count++;
		udp_lite_context->sent_cce_only_count = 0;
		udp_lite_context->FK = 0x02;
		memcpy(&udp_lite_context->old_udp_lite, udp_lite, sizeof(struct udphdr));
		return true;
	}

	udp_lite_context->sent_cce_only_count = 0;

	return false;
}


/**
 * @brief Define the compression part of the UDP-Lite profile as described
 *        in the RFC 4019.
 */
const struct rohc_comp_profile c_udp_lite_profile =
{
	.id             = ROHC_PROFILE_UDPLITE, /* profile ID (see 7 in RFC4019) */
	.create         = c_udp_lite_create,    /* profile handlers */
	.destroy        = rohc_comp_rfc3095_destroy,
	.encode         = c_udp_lite_encode,
	.feedback       = rohc_comp_rfc3095_feedback,
};

