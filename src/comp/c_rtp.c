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
 * @file c_rtp.c
 * @brief ROHC compression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "c_rtp.h"
#include "c_udp.h"
#include "rohc_traces_internal.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "sdvl.h"
#include "crc.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


/*
 * Constants and macros
 */

/**
 * @brief The list of UDP ports associated with RTP streams
 *
 * The port numbers must be separated by a comma
 */
#define RTP_PORTS  1234, 36780, 33238, 5020, 5002


/*
 * Private function prototypes.
 */

static rohc_packet_t c_rtp_decide_FO_packet(const struct c_context *context);
static rohc_packet_t c_rtp_decide_SO_packet(const struct c_context *context);
static rohc_ext_t c_rtp_decide_extension(const struct c_context *context);

static uint32_t c_rtp_get_next_sn(const struct c_context *context,
                                  const struct ip_packet *outer_ip,
                                  const struct ip_packet *inner_ip);

static int rtp_encode_uncomp_fields(struct c_context *const context,
                                    const struct ip_packet *const ip,
                                    const struct ip_packet *const ip2,
                                    const unsigned char *const next_header);

int rtp_code_static_rtp_part(const struct c_context *context,
                             const unsigned char *next_header,
                             unsigned char *const dest,
                             int counter);

int rtp_code_dynamic_rtp_part(const struct c_context *context,
                              const unsigned char *next_header,
                              unsigned char *const dest,
                              int counter);

int rtp_changed_rtp_dynamic(const struct c_context *context,
                            const struct udphdr *udp);


/**
 * @brief Create a new RTP context and initialize it thanks to the given
 *        IP/UDP/RTP packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/UDP/RTP packet given to initialize the new context
 * @return        1 if successful, 0 otherwise
 */
int c_rtp_create(struct c_context *const context, const struct ip_packet *ip)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	unsigned int ip_proto;

	assert(context != NULL);
	assert(context->profile != NULL);

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_RTP_SN, ip))
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "generic context creation failed\n");
		goto quit;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* check if packet is IP/UDP/RTP or IP/IP/UDP/RTP */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP,
			             context->profile->id,
			             "cannot create the inner IP header\n");
			goto clean;
		}
		last_ip_header = &ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	if(ip_proto != ROHC_IPPROTO_UDP)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "next header is not UDP (%d), cannot use this profile\n",
		             ip_proto);
		goto clean;
	}

	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);
	rtp = (struct rtphdr *) (udp + 1);

	/* initialize SN with the SN found in the RTP header */
	g_context->sn = (uint32_t) ntohs(rtp->sn);
	assert(g_context->sn <= 0xffff);
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "initialize context(SN) = hdr(SN) of first packet = %u\n",
	           g_context->sn);

	/* create the RTP part of the profile context */
	rtp_context = malloc(sizeof(struct sc_rtp_context));
	if(rtp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the RTP part of the profile context\n");
		goto clean;
	}
	g_context->specific = rtp_context;

	/* initialize the RTP part of the profile context */
	rtp_context->udp_checksum_change_count = 0;
	memcpy(&rtp_context->old_udp, udp, sizeof(struct udphdr));
	rtp_context->rtp_pt_change_count = 0;
	memcpy(&rtp_context->old_rtp, rtp, sizeof(struct rtphdr));
	if(!c_create_sc(&rtp_context->ts_sc,
	                context->compressor->wlsb_window_width,
	                context->compressor->trace_callback))
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "cannot create scaled RTP Timestamp encoding\n");
		goto clean;
	}

	/* init the RTP-specific temporary variables */
	rtp_context->tmp.send_rtp_dynamic = -1;
	rtp_context->tmp.timestamp = 0;
	rtp_context->tmp.ts_send = 0;
	/* do not transmit any RTP TimeStamp (TS) bit by default */
	rtp_context->tmp.nr_ts_bits = 0;
	/* RTP Marker (M) bit is not set by default */
	rtp_context->tmp.m_set = 0;
	rtp_context->tmp.rtp_pt_changed = 0;

	/* init the RTP-specific variables and functions */
	g_context->next_header_proto = ROHC_IPPROTO_UDP;
	g_context->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	g_context->encode_uncomp_fields = rtp_encode_uncomp_fields;
	g_context->decide_state = rtp_decide_state;
	g_context->decide_FO_packet = c_rtp_decide_FO_packet;
	g_context->decide_SO_packet = c_rtp_decide_SO_packet;
	g_context->decide_extension = c_rtp_decide_extension;
	g_context->init_at_IR = NULL;
	g_context->get_next_sn = c_rtp_get_next_sn;
	g_context->code_static_part = rtp_code_static_rtp_part;
	g_context->code_dynamic_part = rtp_code_dynamic_rtp_part;
	g_context->code_ir_remainder = NULL;
	g_context->code_UO_packet_head = NULL;
	g_context->code_uo_remainder = udp_code_uo_remainder;
	g_context->compute_crc_static = rtp_compute_crc_static;
	g_context->compute_crc_dynamic = rtp_compute_crc_dynamic;

	return 1;

clean:
	c_generic_destroy(context);
quit:
	return 0;
}


/**
 * @brief Destroy the RTP context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The RTP compression context to destroy
 */
void c_rtp_destroy(struct c_context *const context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	c_destroy_sc(&rtp_context->ts_sc);
	c_generic_destroy(context);
}


/**
 * @brief Check if the IP/UDP/RTP packet belongs to the context
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
 *  - the SSRC field of the RTP header must match the one in the context
 *
 * All the context but the last one are done by the c_udp_check_context()
 * function.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/UDP/RTP packet to check
 * @return        1 if the IP/UDP/RTP packet belongs to the context,
 *                0 if it does not belong to the context and
 *                -1 if an error occurs
 *
 * @see c_udp_check_context
 */
int c_rtp_check_context(const struct c_context *context,
                        const struct ip_packet *ip)
{
	const struct c_generic_context *g_context;
	const struct sc_rtp_context *rtp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	unsigned int ip_proto;
	int udp_check;
	int is_rtp_same;

	/* check IP and UDP headers */
	udp_check = c_udp_check_context(context, ip);
	if(udp_check != 1)
	{
		goto quit;
	}

	/* get the last IP header */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* second IP header is last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "cannot create the inner IP header\n");
			goto error;
		}
		last_ip_header = &ip2;
	}
	else
	{
		/* first IP header is last IP header */
		last_ip_header = ip;
	}

	/* get UDP and RTP headers */
	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);
	rtp = (struct rtphdr *) (udp + 1);

	/* check the RTP SSRC field */
	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	is_rtp_same = (rtp_context->old_rtp.ssrc == rtp->ssrc);

	return is_rtp_same;

quit:
	return udp_check;
error:
	return -1;
}


/**
 * @brief Decide which packet to send when in First Order (FO) state.
 *
 * Packets that can be used are the IR-DYN and UO-2 packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among:
 *                 - PACKET_UOR_2_RTP
 *                 - PACKET_UOR_2_TS
 *                 - PACKET_UOR_2_ID
 *                 - PACKET_IR_DYN
 */
static rohc_packet_t c_rtp_decide_FO_packet(const struct c_context *context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	rohc_packet_t packet;
	size_t nr_of_ip_hdr;
	size_t nr_sn_bits;
	size_t nr_ts_bits;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	nr_of_ip_hdr = g_context->tmp.nr_of_ip_hdr;
	nr_sn_bits = g_context->tmp.nr_sn_bits;
	nr_ts_bits = rtp_context->tmp.nr_ts_bits;

	if(g_context->tmp.send_static)
	{
		packet = PACKET_UOR_2_RTP;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet UOR-2-RTP because at least one static "
		           "field changed\n");
	}
	else if(nr_of_ip_hdr == 1 && g_context->tmp.send_dynamic > 2)
	{
		packet = PACKET_IR_DYN;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet IR-DYN because %d > 2 dynamic fields changed "
		           "with a single IP header\n", g_context->tmp.send_dynamic);
	}
	else if(nr_of_ip_hdr > 1 && g_context->tmp.send_dynamic > 4)
	{
		packet = PACKET_IR_DYN;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet IR-DYN because %d > 4 dynamic fields changed "
		           "with double IP header\n", g_context->tmp.send_dynamic);
	}
	else if(nr_sn_bits <= 14)
	{
		/* UOR-2* packets can be used only if SN stand on <= 14 bits (6 bits
		 * in base header + 8 bits in extension 3): determine which UOR-2*
		 * packet to choose */

		const int is_ip_v4 = (g_context->ip_flags.version == IPV4);
		const int is_rnd = g_context->ip_flags.info.v4.rnd;
		const size_t nr_ip_id_bits = g_context->tmp.nr_ip_id_bits;
		const bool is_outer_ipv4_non_rnd = (is_ip_v4 && !is_rnd);
		size_t nr_ipv4_non_rnd;
		size_t nr_ipv4_non_rnd_with_bits;

		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose one UOR-2-* packet because %zd <= 14 SN "
		           "bits must be transmitted\n", nr_sn_bits);

		/* how many IP headers are IPv4 headers with non-random IP-IDs */
		nr_ipv4_non_rnd = 0;
		nr_ipv4_non_rnd_with_bits = 0;
		if(is_outer_ipv4_non_rnd)
		{
			nr_ipv4_non_rnd++;
			if(nr_ip_id_bits > 0)
			{
				nr_ipv4_non_rnd_with_bits++;
			}
		}
		if(nr_of_ip_hdr >= 1)
		{
			const int is_ip2_v4 = g_context->ip2_flags.version == IPV4;
			const int is_rnd2 = g_context->ip2_flags.info.v4.rnd;
			const size_t nr_ip_id_bits2 = g_context->tmp.nr_ip_id_bits2;
			const bool is_inner_ipv4_non_rnd = (is_ip2_v4 && !is_rnd2);

			if(is_inner_ipv4_non_rnd)
			{
				nr_ipv4_non_rnd++;
				if(nr_ip_id_bits2 > 0)
				{
					nr_ipv4_non_rnd_with_bits++;
				}
			}
		}

		/* what UOR-2* packet do we choose? */
		/* TODO: the 3 next if/else could be merged with the ones from
		 * c_rtp_decide_SO_packet */
		if(nr_ipv4_non_rnd == 0)
		{
			packet = PACKET_UOR_2_RTP;
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "choose packet UOR-2-RTP because neither of the %zd "
			           "IP header(s) are IPv4 with non-random IP-ID\n",
			           nr_of_ip_hdr);
		}
		else if(nr_ipv4_non_rnd_with_bits >= 1 &&
		        sdvl_can_length_be_encoded(nr_ts_bits))
		{
			packet = PACKET_UOR_2_ID;
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "choose packet UOR-2-ID because at least one of the "
			           "%zd IP header(s) is IPv4 with non-random IP-ID with at "
			           "least 1 bit of IP-ID to transmit, and %zd TS bits can "
			           "be SDVL-encoded\n", nr_of_ip_hdr, nr_ts_bits);
		}
		else
		{
			packet = PACKET_UOR_2_TS;
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "choose packet UOR-2-TS because at least one of the "
			           "%zd IP header(s) is IPv4 with non-random IP-ID\n",
			           nr_of_ip_hdr);
		}
	}
	else
	{
		/* UOR-2* packets can not be used, use IR-DYN instead */
		packet = PACKET_IR_DYN;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet IR-DYN because %zd > 14 SN bits must "
		           "be transmitted\n", nr_sn_bits);
	}

	return packet;
}


/**
 * @brief Decide which packet to send when in Second Order (SO) state.
 *
 * Packets that can be used are the UO-0, UO-1 and UO-2 (with or without
 * extensions) packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among:
 *                 - PACKET_UO_0
 *                 - PACKET_UO_1
 *                 - PACKET_UOR_2_RTP
 *                 - PACKET_UOR_2_TS
 *                 - PACKET_UOR_2_ID
 *                 - PACKET_IR_DYN
 */
static rohc_packet_t c_rtp_decide_SO_packet(const struct c_context *context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	size_t nr_of_ip_hdr;
	rohc_packet_t packet;
	unsigned int nr_ipv4_non_rnd;
	unsigned int nr_ipv4_non_rnd_with_bits;
	size_t nr_innermost_ip_id_bits;
	size_t nr_outermost_ip_id_bits;
	bool is_outer_ipv4_non_rnd;
	int is_rnd;
	int is_ip_v4;
	size_t nr_sn_bits;
	size_t nr_ts_bits;
	size_t nr_ip_id_bits;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	nr_of_ip_hdr = g_context->tmp.nr_of_ip_hdr;
	nr_sn_bits = g_context->tmp.nr_sn_bits;
	nr_ts_bits = rtp_context->tmp.nr_ts_bits;
	nr_ip_id_bits = g_context->tmp.nr_ip_id_bits;
	is_rnd = g_context->ip_flags.info.v4.rnd;
	is_ip_v4 = (g_context->ip_flags.version == IPV4);
	is_outer_ipv4_non_rnd = (is_ip_v4 && !is_rnd);

	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "nr_ip_bits = %zd, nr_sn_bits = %zd, nr_ts_bits = %zd, "
	           "m_set = %d, nr_of_ip_hdr = %zd, rnd = %d\n", nr_ip_id_bits,
	           nr_sn_bits, nr_ts_bits, rtp_context->tmp.m_set, nr_of_ip_hdr,
	           is_rnd);

	/* sanity check */
	assert(g_context->tmp.send_static == 0);
	assert(g_context->tmp.send_dynamic == 0);
	assert(rtp_context->tmp.send_rtp_dynamic == 0);

	/* find out how many IP headers are IPv4 headers with non-random IP-IDs */
	nr_ipv4_non_rnd = 0;
	nr_ipv4_non_rnd_with_bits = 0;
	if(is_outer_ipv4_non_rnd)
	{
		nr_ipv4_non_rnd++;
		if(nr_ip_id_bits > 0)
		{
			nr_ipv4_non_rnd_with_bits++;
		}
	}
	if(nr_of_ip_hdr >= 1)
	{
		const int is_ip2_v4 = (g_context->ip2_flags.version == IPV4);
		const int is_rnd2 = g_context->ip2_flags.info.v4.rnd;
		const size_t nr_ip_id_bits2 = g_context->tmp.nr_ip_id_bits2;
		const bool is_inner_ipv4_non_rnd = (is_ip2_v4 && !is_rnd2);

		if(is_inner_ipv4_non_rnd)
		{
			nr_ipv4_non_rnd++;
			if(nr_ip_id_bits2 > 0)
			{
				nr_ipv4_non_rnd_with_bits++;
			}
		}
	}
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "nr_ipv4_non_rnd = %u, nr_ipv4_non_rnd_with_bits = %u\n",
	           nr_ipv4_non_rnd, nr_ipv4_non_rnd_with_bits);

	/* determine the number of IP-ID bits and the IP-ID offset of the
	 * innermost IPv4 header with non-random IP-ID */
	rohc_get_ipid_bits(context, &nr_innermost_ip_id_bits,
	                   &nr_outermost_ip_id_bits);

	/* what packet type do we choose? */
	if(nr_sn_bits <= 4 &&
	   nr_ipv4_non_rnd_with_bits == 0 &&
	   nr_ts_bits == 0 &&
	   rtp_context->tmp.m_set == 0)
	{
		packet = PACKET_UO_0;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet UO-0 because %zd <= 4 SN bits must be "
		           "transmitted, neither of the %zd IP header(s) are IPv4 "
		           "with non-random IP-ID with some IP-ID bits to transmit, "
		           "%s, and RTP M bit is not set\n", nr_sn_bits, nr_of_ip_hdr,
		           (nr_ts_bits == 0 ? "0 TS bit must be transmitted" :
		            "TS bits are deductible"));
	}
	else if(nr_sn_bits <= 4 &&
	        nr_ipv4_non_rnd == 0 &&
	        nr_ts_bits <= 6)
	{
		packet = PACKET_UO_1_RTP;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet UO-1-RTP because neither of the %zd IP "
		           "header(s) are 'IPv4 with non-random IP-ID', %zd <= 4 SN "
		           "bits must be transmitted, %zd <= 6 TS bits must be "
		           "transmitted\n", nr_sn_bits, nr_of_ip_hdr, nr_ts_bits);
	}
	else if(nr_sn_bits <= 4 &&
	        nr_ipv4_non_rnd_with_bits == 1 && nr_innermost_ip_id_bits <= 5 &&
	        nr_ts_bits == 0 &&
	        rtp_context->tmp.m_set == 0)
	{
		/* TODO: when extensions are supported within the UO-1-ID packet,
		 * please check whether the "m_set == 0" condition could be
		 * removed or not, and whether nr_ipv4_non_rnd_with_bits == 1 should
		 * not be replaced by nr_ipv4_non_rnd_with_bits >= 1 */
		packet = PACKET_UO_1_ID;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet UO-1-ID because only one of the %zd IP "
		           "headers is IPv4 with non-random IP-ID with %zd <= 5 IP-ID "
		           "bits to transmit, %zd <= 4 SN bits must be transmitted, "
		           "%s, and RTP M bit is not set\n", nr_of_ip_hdr,
		           nr_innermost_ip_id_bits, nr_sn_bits,
		           (nr_ts_bits == 0 ? "0 TS bit must be transmitted" :
		            "TS bits are deductible"));
	}
	else if(nr_sn_bits <= 4 &&
	        nr_ipv4_non_rnd_with_bits == 0 &&
	        nr_ts_bits <= 5)
	{
		packet = PACKET_UO_1_TS;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet UO-1-TS because neither of the %zd IP "
		           "header(s) are IPv4 with non-random IP-ID with some IP-ID "
		           "bits to to transmit for that IP header, %zd <= 4 SN bits "
		           "must be transmitted, %zd <= 6 TS bits must be "
		           "transmitted\n", nr_of_ip_hdr, nr_sn_bits, nr_ts_bits);
	}
	else if(nr_sn_bits <= 14)
	{
		/* UOR-2* packets can be used only if SN stand on <= 14 bits (6 bits
		 * in base header + 8 bits in extension 3): determine which UOR-2*
		 * packet to choose */

		/* what UOR-2* packet do we choose? */
		/* TODO: the 3 next if/else could be merged with the ones from
		 * c_rtp_decide_FO_packet */
		if(nr_ipv4_non_rnd == 0)
		{
			packet = PACKET_UOR_2_RTP;
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "choose packet UOR-2-RTP because neither of the %zd "
			           "IP header(s) are IPv4 with non-random IP-ID\n",
			           nr_of_ip_hdr);
		}
		else if(nr_ipv4_non_rnd_with_bits >= 1 &&
		        sdvl_can_length_be_encoded(nr_ts_bits))
		{
			packet = PACKET_UOR_2_ID;
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "choose packet UOR-2-ID because at least one of the "
			           "%zd IP header(s) is IPv4 with non-random IP-ID with at "
			           "least 1 bit of IP-ID to transmit, and %zd TS bits can "
			           "be SDVL-encoded\n", nr_of_ip_hdr, nr_ts_bits);
		}
		else
		{
			packet = PACKET_UOR_2_TS;
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "choose packet UOR-2-TS because at least one of the "
			           "%zd IP header(s) is IPv4 with non-random IP-ID\n",
			           nr_of_ip_hdr);
		}
	}
	else
	{
		/* UOR-2* packets can not be used, use IR-DYN instead */
		packet = PACKET_IR_DYN;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "choose packet IR-DYN because %zd > 14 SN bits must "
		           "be transmitted\n", nr_sn_bits);
	}

	return packet;
}


/**
 * @brief Decide what extension shall be used in the UO-1/UO-2 packet.
 *
 * Extensions 0, 1 & 2 are IPv4 only because of the IP-ID.
 *
 * @param context The compression context
 * @return        The extension code among PACKET_NOEXT, PACKET_EXT_0,
 *                PACKET_EXT_1 and PACKET_EXT_3 if successful,
 *                PACKET_EXT_UNKNOWN otherwise
 */
static rohc_ext_t c_rtp_decide_extension(const struct c_context *context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	rohc_ext_t ext;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	/* force extension type 3 if at least one RTP dynamic field changed */
	if(rtp_context->tmp.send_rtp_dynamic > 0)
	{
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "force EXT-3 because at least one RTP dynamic field changed\n");
		ext = PACKET_EXT_3;
	}
	else
	{
		/* fallback on the algorithm shared by all IP-based profiles */
		ext = decide_extension(context);
	}

	return ext;
}


/**
 * @brief Encode an IP/UDP/RTP packet according to a pattern decided by several
 *        different factors.
 *
 * @param context        The compression context
 * @param ip             The IP packet to encode
 * @param packet_size    The length of the IP packet to encode
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param packet_type    OUT: The type of ROHC packet that is created
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 */
int c_rtp_encode(struct c_context *const context,
                 const struct ip_packet *ip,
                 const int packet_size,
                 unsigned char *const dest,
                 const int dest_size,
                 rohc_packet_t *const packet_type,
                 int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	unsigned int ip_proto;
	int size;

	g_context = (struct c_generic_context *) context->specific;
	if(g_context == NULL)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "generic context not valid\n");
		return -1;
	}

	rtp_context = (struct sc_rtp_context *) g_context->specific;
	if(rtp_context == NULL)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "RTP context not valid\n");
		return -1;
	}

	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "cannot create the inner IP header\n");
			return -1;
		}
		last_ip_header = &ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	if(ip_proto != ROHC_IPPROTO_UDP)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "packet is not an UDP packet\n");
		return -1;
	}
	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);
	rtp = (struct rtphdr *) (udp + 1);

	/* how many UDP/RTP fields changed? */
	rtp_context->tmp.send_rtp_dynamic = rtp_changed_rtp_dynamic(context, udp);

	/* encode the IP packet */
	size = c_generic_encode(context, ip, packet_size, dest, dest_size,
	                        packet_type, payload_offset);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new UDP/RTP headers */
	if(g_context->tmp.packet_type == PACKET_IR ||
	   g_context->tmp.packet_type == PACKET_IR_DYN)
	{
		memcpy(&rtp_context->old_udp, udp, sizeof(struct udphdr));
		memcpy(&rtp_context->old_rtp, rtp, sizeof(struct rtphdr));
	}

quit:
	return size;
}


/**
 * @brief Decide the state that should be used for the next packet compressed
 *        with the ROHC RTP profile.
 *
 * The three states are:
 *  - Initialization and Refresh (IR),
 *  - First Order (FO),
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
void rtp_decide_state(struct c_context *const context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	if(rtp_context->ts_sc.state == INIT_TS)
	{
		change_state(context, IR);
	}
	else if(rtp_context->udp_checksum_change_count < MAX_IR_COUNT)
	{
		/* TODO: could be optimized: IR state is not required, only IR or
		 * IR-DYN packet is */
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "go back to IR state because UDP checksum behaviour "
		           "changed in the last few packets\n");
		change_state(context, IR);
	}
	else if(rtp_context->tmp.send_rtp_dynamic)
	{
		if(context->state == IR)
		{
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "%d RTP dynamic fields changed, stay in IR state\n",
			           rtp_context->tmp.send_rtp_dynamic);
		}
		else
		{
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "%d RTP dynamic fields changed, go in FO state\n",
			           rtp_context->tmp.send_rtp_dynamic);
			change_state(context, FO);
		}
	}
	else
	{
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		decide_state(context);
	}
}


/**
 * @brief Determine the SN value for the next packet
 *
 * Profile SN is the 16-bit RTP SN.
 *
 * @param context   The compression context
 * @param outer_ip  The outer IP header
 * @param inner_ip  The inner IP header if it exists, NULL otherwise
 * @return          The SN
 */
static uint32_t c_rtp_get_next_sn(const struct c_context *context,
                                  const struct ip_packet *outer_ip,
                                  const struct ip_packet *inner_ip)
{
	struct c_generic_context *g_context;
	struct udphdr *udp;
	struct rtphdr *rtp;
	uint32_t next_sn;

	g_context = (struct c_generic_context *) context->specific;

	/* get UDP and RTP headers */
	if(g_context->tmp.nr_of_ip_hdr > 1)
	{
		udp = (struct udphdr *) ip_get_next_layer(inner_ip);
	}
	else
	{
		udp = (struct udphdr *) ip_get_next_layer(outer_ip);
	}
	rtp = (struct rtphdr *) (udp + 1);

	next_sn = (uint32_t) ntohs(rtp->sn);

	assert(next_sn <= 0xffff);
	return next_sn;
}


/**
 * @brief Encode uncompressed RTP fields
 *
 * Handle the RTP TS field.
 *
 * @param context      The compression context
 * @param ip           The outer IP header
 * @param ip2          The inner IP header
 * @param next_header  The next header
 * @return             ROHC_OK in case of success,
 *                     ROHC_ERROR otherwise
 */
static int rtp_encode_uncomp_fields(struct c_context *const context,
                                    const struct ip_packet *const ip,
                                    const struct ip_packet *const ip2,
                                    const unsigned char *const next_header)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct udphdr *udp;
	struct rtphdr *rtp;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	rtp_context = g_context->specific;
	assert(next_header != NULL);
	udp = (struct udphdr *)  next_header;
	rtp = (struct rtphdr *) (udp + 1);
	assert(ip != NULL);

	/* add new TS value to context */
	assert(g_context->sn <= 0xffff);
	c_add_ts(&rtp_context->ts_sc, rtp_context->tmp.timestamp, g_context->sn);

	/* determine the number of TS bits to send wrt compression state */
	if(rtp_context->ts_sc.state == INIT_TS)
	{
		/* TS_STRIDE cannot be computed yet (first packet or TS is constant),
		 * so send TS only */
		rtp_context->tmp.ts_send = ntohl(rtp->timestamp);
		rtp_context->tmp.nr_ts_bits = 32;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "cannot send TS scaled, send TS only\n");
	}
	else if(rtp_context->ts_sc.state == INIT_STRIDE)
	{
		/* TS and TS_STRIDE will be send */
		rtp_context->tmp.ts_send = ntohl(rtp->timestamp);
		rtp_context->tmp.nr_ts_bits = 32;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "cannot send TS scaled, send TS and TS_STRIDE\n");
	}
	else /* SEND_SCALED */
	{
		/* TS_SCALED value will be send */
		rtp_context->tmp.ts_send = get_ts_scaled(rtp_context->ts_sc);
		if(!nb_bits_scaled(rtp_context->ts_sc, &(rtp_context->tmp.nr_ts_bits)))
		{
			const uint32_t ts_send = rtp_context->tmp.ts_send;
			size_t nr_bits;
			uint32_t mask;

			/* this is the first TS scaled to be sent, we cannot code it with
			 * W-LSB and we must find its size (in bits) */
			for(nr_bits = 1, mask = 1;
			    nr_bits <= 32 && (ts_send & mask) != ts_send;
			    nr_bits++, mask |= (1 << (nr_bits - 1)))
			{
			}
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            (ts_send & mask) == ts_send, error, "size of TS scaled "
			            "(0x%x) not found, this should never happen!", ts_send);

			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "first TS scaled to be sent: ts_send = %u, mask = 0x%x, "
			           "nr_bits = %zd\n", ts_send, mask, nr_bits);
			rtp_context->tmp.nr_ts_bits = nr_bits;
		}

		/* save the new TS_SCALED value */
		assert(g_context->sn <= 0xffff);
		add_scaled(&rtp_context->ts_sc, g_context->sn);
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "ts_scaled = %u on %zd bits\n",
		           rtp_context->tmp.ts_send, rtp_context->tmp.nr_ts_bits);
	}

	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "%zd bits are required to encode new TS\n",
	           rtp_context->tmp.nr_ts_bits);

	return ROHC_OK;

error:
	return ROHC_ERROR;
}


/**
 * @brief Build the static part of the UDP/RTP headers.
 *
 * \verbatim

 Static part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /          Source Port          /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /       Destination Port        /   2 octets
    +---+---+---+---+---+---+---+---+

 Static part of RTP header (5.7.7.6):

    +---+---+---+---+---+---+---+---+
 3  /             SSRC              /   4 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 1 & 2 are done by the udp_code_static_udp_part() function. Part 3 is
 * done by this function.
 *
 * @param context     The compression context
 * @param next_header The UDP/RTP headers
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 *
 * @see udp_code_static_udp_part
 */
int rtp_code_static_rtp_part(const struct c_context *context,
                             const unsigned char *next_header,
                             unsigned char *const dest,
                             int counter)
{
	struct udphdr *udp = (struct udphdr *) next_header;
	struct rtphdr *rtp = (struct rtphdr *) (udp + 1);

	/* parts 1 & 2 */
	counter = udp_code_static_udp_part(context, next_header, dest, counter);

	/* part 3 */
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "RTP SSRC = 0x%x\n", rtp->ssrc);
	memcpy(&dest[counter], &rtp->ssrc, 4);
	counter += 4;

	return counter;
}


/**
 * @brief Build the dynamic part of the UDP/RTP headers.
 *
 * \verbatim

 Dynamic part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /           Checksum            /   2 octets
    +---+---+---+---+---+---+---+---+

 Dynamic part of RTP header (5.7.7.6):

    +---+---+---+---+---+---+---+---+
 2  |  V=2  | P | RX|      CC       |  (RX is NOT the RTP X bit)
    +---+---+---+---+---+---+---+---+
 3  | M |            PT             |
    +---+---+---+---+---+---+---+---+
 4  /      RTP Sequence Number      /  2 octets
    +---+---+---+---+---+---+---+---+
 5  /   RTP Timestamp (absolute)    /  4 octets
    +---+---+---+---+---+---+---+---+
 6  /      Generic CSRC list        /  variable length
    +---+---+---+---+---+---+---+---+
 7  : Reserved  | X |  Mode |TIS|TSS:  if RX = 1
    +---+---+---+---+---+---+---+---+
 8  :         TS_Stride             :  1-4 octets, if TSS = 1
    +---+---+---+---+---+---+---+---+
 9  :         Time_Stride           :  1-4 octets, if TIS = 1
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 6 & 9 are not supported yet. The TIS flag in part 7 is not supported.
 *
 * @param context     The compression context
 * @param next_header The UDP/RTP headers
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int rtp_code_dynamic_rtp_part(const struct c_context *context,
                              const unsigned char *next_header,
                              unsigned char *const dest,
                              int counter)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct udphdr *udp;
	struct rtphdr *rtp;
	unsigned char byte;
	unsigned int rx_byte = 0;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	udp = (struct udphdr *) next_header;
	rtp = (struct rtphdr *) (udp + 1);

	/* part 1 */
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "UDP checksum = 0x%04x\n", udp->check);
	memcpy(&dest[counter], &udp->check, 2);
	counter += 2;
	rtp_context->udp_checksum_change_count++;

	/* part 2 */
	byte = 0;
	if(rtp_context->ts_sc.state == INIT_STRIDE)
	{
		/* send ts_stride */
		rx_byte = 1;
		byte |= 1 << 4;
	}
	byte |= (rtp->version & 0x03) << 6;
	byte |= (rtp->padding & 0x01) << 5;
	byte |= rtp->cc & 0x0f;
	dest[counter] = byte;
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "part 2 = 0x%02x\n", dest[counter]);
	counter++;

	/* part 3 */
	byte = 0;
	byte |= (rtp->m & 0x01) << 7;
	byte |= rtp->pt & 0x7f;
	dest[counter] = byte;
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "part 3 = 0x%02x\n", dest[counter]);
	counter++;
	rtp_context->rtp_pt_change_count++;

	/* part 4 */
	memcpy(&dest[counter], &rtp->sn, 2);
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "part 4 = 0x%02x 0x%02x\n", dest[counter], dest[counter + 1]);
	counter += 2;

	/* part 5 */
	memcpy(&dest[counter], &rtp->timestamp, 4);
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "part 5 = 0x%02x 0x%02x 0x%02x 0x%02x\n", dest[counter],
	           dest[counter + 1], dest[counter + 2], dest[counter + 3]);
	counter += 4;

	/* part 6 not supported yet  but the field is mandatory,
	   so add a zero byte */
	dest[counter] = 0x00;
	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "Generic CSRC list not supported yet, put a 0x00 byte\n");
	counter++;

	/* parts 7, 8 & 9 */
	if(rx_byte)
	{
		int tis;
		int tss;

		/* part 7 */
		tis = 0; /* TIS flag not supported yet */
		tss = (rtp_context->ts_sc.state == INIT_STRIDE);

		byte = 0;
		byte |= (rtp->extension & 0x01) << 4;
		byte |= (context->mode & 0x03) << 2;
		byte |= (tis & 0x01) << 1;
		byte |= tss & 0x01;
		dest[counter] = byte;
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "part 7 = 0x%02x\n", dest[counter]);
		counter++;

		/* part 8 */
		if(tss)
		{
			uint32_t ts_stride;
			size_t ts_stride_sdvl_len;
			int ret;

			/* get the TS_STRIDE to send in packet */
			ts_stride = get_ts_stride(rtp_context->ts_sc);

			/* how many bytes are required by SDVL to encode TS_STRIDE ? */
			ts_stride_sdvl_len = c_bytesSdvl(ts_stride, 0 /* length detection */);
			if(ts_stride_sdvl_len <= 0 || ts_stride_sdvl_len > 4)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				             "failed to determine the number of bits required to "
				             "SDVL-encode TS_STRIDE %u (%zd)\n", ts_stride,
				             ts_stride_sdvl_len);
				/* TODO: should handle error gracefully */
				assert(0);
			}

			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "send ts_stride = 0x%08x encoded with SDVL on %zd bytes\n",
			           ts_stride, ts_stride_sdvl_len);

			/* encode TS_STRIDE in SDVL and write it to packet */
			ret = c_encodeSdvl(&dest[counter], ts_stride, 0 /* length detection */);
			if(ret != 1)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				             "failed to SDVL-encode TS_STRIDE %u\n", ts_stride);
				/* TODO: should handle error gracefully */
				assert(0);
			}

			/* skip the bytes used to encode TS_STRIDE in SDVL */
			counter += ts_stride_sdvl_len;

			/* do we transmit the scaled RTP Timestamp (TS) in the next packet ? */
			rtp_context->ts_sc.nr_init_stride_packets++;
			if(rtp_context->ts_sc.nr_init_stride_packets >= ROHC_INIT_TS_STRIDE_MIN)
			{
				rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				           "TS_STRIDE transmitted at least %u times, so change "
				           "from state INIT_STRIDE to SEND_SCALED\n",
				           ROHC_INIT_TS_STRIDE_MIN);
				rtp_context->ts_sc.state = SEND_SCALED;
			}
			else
			{
				rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				           "TS_STRIDE transmitted only %zd times, so stay in "
				           "state INIT_STRIDE (at least %u times are required "
				           "to change to state SEND_SCALED)\n",
				           rtp_context->ts_sc.nr_init_stride_packets,
				           ROHC_INIT_TS_STRIDE_MIN);
			}
		}

		/* part 9 not supported yet */
	}

	if(rtp_context->ts_sc.state == INIT_TS)
	{
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "change from state INIT_TS to INIT_STRIDE\n");
		rtp_context->ts_sc.state = INIT_STRIDE;
		rtp_context->ts_sc.nr_init_stride_packets = 0;
	}

	return counter;
}


/**
 * @brief Check if the dynamic part of the UDP/RTP headers changed.
 *
 * @param context The compression context
 * @param udp     The UDP/RTP headers
 * @return        The number of UDP/RTP fields that changed
 */
int rtp_changed_rtp_dynamic(const struct c_context *context,
                            const struct udphdr *udp)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct rtphdr *rtp;
	int fields = 0;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	rtp = (struct rtphdr *) (udp + 1);

	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "find changes in RTP dynamic fields\n");

	/* check UDP checksum field */
	if((udp->check != 0 && rtp_context->old_udp.check == 0) ||
	   (udp->check == 0 && rtp_context->old_udp.check != 0) ||
	   (rtp_context->udp_checksum_change_count < MAX_IR_COUNT))
	{
		if((udp->check != 0 && rtp_context->old_udp.check == 0) ||
		   (udp->check == 0 && rtp_context->old_udp.check != 0))
		{
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "UDP checksum field changed\n");
			rtp_context->udp_checksum_change_count = 0;
		}
		else
		{
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "UDP checksum field did not change but changed in the "
			           "last few packets\n");
		}

		/* do not count the UDP checksum change as other RTP dynamic fields
		 * because it requires a specific behaviour (IR or IR-DYN packet
		 * required). */
	}

	/* check RTP CSRC Counter and CSRC field */
	if(rtp->cc != rtp_context->old_rtp.cc)
	{
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "RTP CC field changed (0x%x -> 0x%x)\n",
		           rtp_context->old_rtp.cc, rtp->cc);
		fields += 2;
	}

	/* check SSRC field */
	if(rtp->ssrc != rtp_context->old_rtp.ssrc)
	{
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "RTP SSRC field changed (0x%08x -> 0x%08x)\n",
		           rtp_context->old_rtp.ssrc, rtp->ssrc);
		fields++;
	}

	/* check RTP Marker field: remember its value but do not count it
	 * as a changed field since it is not stored in the context */
	if(rtp->m != 0)
	{
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "RTP Marker (M) bit is set\n");
		rtp_context->tmp.m_set = 1;
	}
	else
	{
		rtp_context->tmp.m_set = 0;
	}

	/* check RTP Payload Type field */
	if(rtp->pt != rtp_context->old_rtp.pt ||
	   rtp_context->rtp_pt_change_count < MAX_IR_COUNT)
	{
		if(rtp->pt != rtp_context->old_rtp.pt)
		{
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "RTP Payload Type (PT) field changed (0x%x -> 0x%x)\n",
			           rtp_context->old_rtp.pt, rtp->pt);
			rtp_context->tmp.rtp_pt_changed = 1;
			rtp_context->rtp_pt_change_count = 0;
		}
		else
		{
			rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "RTP Payload Type (PT) field did not change "
			           "but changed in the last few packets\n");
		}

		fields++;
	}
	else
	{
		rtp_context->tmp.rtp_pt_changed = 0;
	}

	/* we verify if ts_stride changed */
	rtp_context->tmp.timestamp = ntohl(rtp->timestamp);
	if(rtp_context->ts_sc.state != SEND_SCALED)
	{
		rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "TS_STRIDE changed now or in the last few packets\n");
		fields++;
	}

	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "%d RTP dynamic fields changed\n", fields);

	return fields;
}


/// List of UDP ports which are associated with RTP streams
int rtp_ports[] = { RTP_PORTS, 0 };


/**
 * @brief Define the compression part of the RTP profile as described
 *        in the RFC 3095.
 */
struct c_profile c_rtp_profile =
{
	ROHC_IPPROTO_UDP,    /* IP protocol */
	rtp_ports,           /* list of UDP ports */
	ROHC_PROFILE_RTP,    /* profile ID */
	"RTP / Compressor",  /* profile description */
	c_rtp_create,        /* profile handlers */
	c_rtp_destroy,
	c_rtp_check_context,
	c_rtp_encode,
	c_generic_feedback,
};

