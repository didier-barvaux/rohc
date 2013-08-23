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
 * @file d_rtp.c
 * @brief ROHC decompression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_rtp.h"
#include "rohc_traces_internal.h"
#include "rohc_bit_ops.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "ts_sc_decomp.h"
#include "sdvl.h"
#include "crc.h"
#include "decode.h"
#include "protocols/udp.h"
#include "protocols/rtp.h"

#include <assert.h>


/*
 * Private function prototypes.
 */

static void d_rtp_destroy(void *const context)
	__attribute__((nonnull(1)));

static rohc_packet_t rtp_detect_packet_type(const struct rohc_decomp *const decomp,
                                            const struct d_context *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static rohc_packet_t rtp_choose_uo1_variant(const struct rohc_decomp *const decomp,
                                            const struct d_context *const context,
                                            const uint8_t *const packet,
                                            const size_t rohc_length)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static rohc_packet_t rtp_choose_uor2_variant(const struct rohc_decomp *const decomp,
                                             const struct d_context *const context,
                                             const uint8_t *const packet,
                                             const size_t rohc_length,
                                             const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rtp_parse_static_rtp(const struct d_context *const context,
                                const unsigned char *packet,
                                size_t length,
                                struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int rtp_parse_dynamic_rtp(const struct d_context *const context,
                                 const uint8_t *packet,
                                 const size_t length,
                                 struct rohc_extr_bits *const bits);

static int rtp_parse_extension3(const struct rohc_decomp *const decomp,
                                const struct d_context *const context,
                                const unsigned char *const rohc_data,
                                const size_t rohc_data_len,
                                const rohc_packet_t packet_type,
                                struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));

static inline bool is_uor2_reparse_required(const rohc_packet_t packet_type,
                                            const int are_all_ipv4_rnd)
	__attribute__((warn_unused_result, const));

static int rtp_parse_uo_remainder(const struct d_context *const context,
                                  const unsigned char *packet,
                                  unsigned int length,
                                  struct rohc_extr_bits *const bits);

static bool rtp_decode_values_from_bits(const struct d_context *context,
                                        const struct rohc_extr_bits bits,
                                        struct rohc_decoded_values *const decoded);

static int rtp_build_uncomp_rtp(const struct d_context *const context,
                                const struct rohc_decoded_values decoded,
                                unsigned char *dest,
                                const unsigned int payload_len);

static void rtp_update_context(const struct d_context *context,
                               const struct rohc_decoded_values decoded)
	__attribute__((nonnull(1)));


/*
 * Prototypes of private helper functions
 */

static inline bool is_outer_ipv4_ctxt(const struct d_generic_context *const ctxt);
static inline bool is_outer_ipv4_rnd_ctxt(const struct d_generic_context *const ctxt);
static inline bool is_inner_ipv4_ctxt(const struct d_generic_context *const ctxt);
static inline bool is_inner_ipv4_rnd_ctxt(const struct d_generic_context *const ctxt);


/*
 * Definitions of functions
 */

/**
 * @brief Create the RTP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return The newly-created RTP decompression context
 */
void * d_rtp_create(const struct d_context *const context)
{
	struct d_generic_context *g_context;
	struct d_rtp_context *rtp_context;
	const size_t nh_len = sizeof(struct udphdr) + sizeof(struct rtphdr);

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

	/* create the RTP-specific part of the context */
	rtp_context = malloc(sizeof(struct d_rtp_context));
	if(rtp_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the RTP-specific context\n");
		goto destroy_context;
	}
	memset(rtp_context, 0, sizeof(struct d_rtp_context));
	g_context->specific = rtp_context;

	/* create the LSB decoding context for SN */
	g_context->sn_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_RTP_SN, 16);
	if(g_context->sn_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for SN\n");
		goto free_rtp_context;
	}

	/* the UDP checksum field present flag will be initialized
	 * with the IR packets */
	rtp_context->udp_checksum_present = -1;

	/* some RTP-specific values and functions */
	g_context->next_header_len = nh_len;
	g_context->parse_static_next_hdr = rtp_parse_static_rtp;
	g_context->parse_dyn_next_hdr = rtp_parse_dynamic_rtp;
	g_context->parse_extension3 = rtp_parse_extension3;
	g_context->parse_uo_remainder = rtp_parse_uo_remainder;
	g_context->decode_values_from_bits = rtp_decode_values_from_bits;
	g_context->build_next_header = rtp_build_uncomp_rtp;
	g_context->compute_crc_static = rtp_compute_crc_static;
	g_context->compute_crc_dynamic = rtp_compute_crc_dynamic;
	g_context->update_context = rtp_update_context;

	/* create the UDP-specific part of the header changes */
	g_context->outer_ip_changes->next_header_len = nh_len;
	g_context->outer_ip_changes->next_header =
		(unsigned char *) malloc(nh_len);
	if(g_context->outer_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the RTP-specific part of the "
		           "outer IP header changes\n");
		goto free_lsb_sn;
	}
	memset(g_context->outer_ip_changes->next_header, 0, nh_len);

	g_context->inner_ip_changes->next_header_len = nh_len;
	g_context->inner_ip_changes->next_header =
		(unsigned char *) malloc(nh_len);
	if(g_context->inner_ip_changes->next_header == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the RTP-specific part of the "
		           "inner IP header changes\n");
		goto free_outer_ip_changes_next_header;
	}
	memset(g_context->inner_ip_changes->next_header, 0, nh_len);

	/* set next header to UDP */
	g_context->next_header_proto = ROHC_IPPROTO_UDP;

	/* create the scaled RTP Timestamp decoding context */
	rtp_context->ts_scaled_ctxt =
		d_create_sc(context->decompressor->trace_callback);
	if(rtp_context->ts_scaled_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot create the scaled RTP Timestamp decoding context\n");
		goto free_inner_ip_changes_next_header;
	}

	return g_context;

free_inner_ip_changes_next_header:
	zfree(g_context->inner_ip_changes->next_header);
free_outer_ip_changes_next_header:
	zfree(g_context->outer_ip_changes->next_header);
free_lsb_sn:
	rohc_lsb_free(g_context->sn_lsb_ctxt);
free_rtp_context:
	zfree(rtp_context);
destroy_context:
	d_generic_destroy(g_context);
quit:
	return NULL;
}


/**
 * @brief Destroy the given RTP context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The RTP compression context to destroy
 */
static void d_rtp_destroy(void *const context)
{
	struct d_generic_context *g_context;
	struct d_rtp_context *rtp_context;

	assert(context != NULL);
	g_context = (struct d_generic_context *) context;
	assert(g_context->specific != NULL);
	rtp_context = (struct d_rtp_context *) g_context->specific;

	/* destroy the scaled RTP Timestamp decoding object */
	rohc_ts_scaled_free(rtp_context->ts_scaled_ctxt);

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
 * @brief Detect the type of ROHC packet for RTP profile
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
static rohc_packet_t rtp_detect_packet_type(const struct rohc_decomp *const decomp,
                                            const struct d_context *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len)
{
	rohc_packet_t type;

	if(rohc_length < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small to read the first byte that "
		             "contains the packet type (len = %zd)\n", rohc_length);
		goto error;
	}

	if(d_is_uo0(rohc_packet, rohc_length))
	{
		/* UO-0 packet */
		type = PACKET_UO_0;
	}
	else if(d_is_uo1(rohc_packet, rohc_length))
	{
		/* choose between the UO-1-RTP, UO-1-ID, and UO-1-TS variants */
		type = rtp_choose_uo1_variant(decomp, context, rohc_packet, rohc_length);
	}
	else if(d_is_uor2(rohc_packet, rohc_length))
	{
		/* UOR-2* packet */

#if RTP_BIT_TYPE

		/* UOR-2-RTP or UOR-2-ID/TS packet, check the RTP disambiguation bit */
		if(d_is_uor2_rtp(rohc_packet, rohc_length, large_cid_len))
		{
			/* UOR-2-RTP packet */
			type = PACKET_UOR_2_RTP;
		}
		else if(d_is_uor2_ts(rohc_packet, rohc_length, large_cid_len))
		{
			/* UOR-2-TS packet */
			type = PACKET_UOR_2_TS;
		}
		else
		{
			/* UOR-2-ID packet */
			type = PACKET_UOR_2_ID;
		}

#else /* !RTP_BIT_TYPE */

		/* choose between the UOR-2-RTP, UOR-2-ID, and UOR-2-TS variants */
		type = rtp_choose_uor2_variant(decomp, context, rohc_packet, rohc_length,
		                               large_cid_len);

#endif /* RTP_BIT_TYPE */

	}
	else if(d_is_irdyn(rohc_packet, rohc_length))
	{
		/* IR-DYN packet */
		type = PACKET_IR_DYN;
	}
	else if(d_is_ir(rohc_packet, rohc_length))
	{
		/* IR packet */
		type = PACKET_IR;
	}
	else
	{
		/* unknown packet */
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to recognize the packet type in byte 0x%02x\n",
		             rohc_packet[0]);
		type = PACKET_UNKNOWN;
	}

	return type;

error:
	return PACKET_UNKNOWN;
}


/**
 * @brief Choose between UO-1-RTP, UO-1-TS, and UO-1-ID variants
 *
 * This function is useful to choose which packet type to try to parse in the
 * UO-1* families.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param packet         The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @return               The packet type
 */
static rohc_packet_t rtp_choose_uo1_variant(const struct rohc_decomp *const decomp,
                                            const struct d_context *const context,
                                            const uint8_t *const packet,
                                            const size_t rohc_length)
{
	struct d_generic_context *g_context = context->specific;
	rohc_packet_t type;
	size_t nr_ipv4_non_rnd;
	size_t nr_ipv4;

	/* compute the number of IPv4 headers, and IPv4 with context(RND) = 0 */
	nr_ipv4 = 0;
	nr_ipv4_non_rnd = 0;
	if(is_outer_ipv4_ctxt(g_context))
	{
		nr_ipv4++;
		if(!is_outer_ipv4_rnd_ctxt(g_context))
		{
			nr_ipv4_non_rnd++;
		}
	}
	if(is_inner_ipv4_ctxt(g_context))
	{
		nr_ipv4++;
		if(!is_inner_ipv4_rnd_ctxt(g_context))
		{
			nr_ipv4_non_rnd++;
		}
	}

	/* There is no easy way to disambiguate UO-1-ID/TS and UO-1-RTP
	 * packets. The following algorithm is based on notes you may
	 * read in RFC 3095, section 5.7.3:
	 *  - UO-1-RTP cannot be used if the context contains at least one
	 *    IPv4 header with value(RND) = 0. This disambiguates it from
	 *    UO-1-ID and UO-1-TS.
	 *  - UO-1-ID cannot be used if there is no IPv4 header in the
	 *    context or if value(RND) and value(RND2) are both 1.
	 *  - UO-1-TS cannot be used if there is no IPv4 header in the
	 *    context or if value(RND) and value(RND2) are both 1.
	 *  - T: T = 0 indicates format UO-1-ID;
	 *       T = 1 indicates format UO-1-TS.
	 */
	if(nr_ipv4 == 0)
	{
		/* no IPv4 header at all, so only UO-1-RTP packet can be used */
		rohc_decomp_debug(context, "UO-1* packet disambiguation: no IPv4 "
		                  "header at all, so parse as UO-1-RTP\n");
		type = PACKET_UO_1_RTP;
	}
	else if(nr_ipv4_non_rnd == 0)
	{
		/* there is no IPv4 header with context(RND) = 0, and UO-1* packets
		 * have either no value(RND) or value(RND) = context(RND) if they have
		 * one. So only UO-1-RTP packet can be used */
		rohc_decomp_debug(context, "UO-1* packet disambiguation: no IPv4 "
		                  "header with context(RND) = 0, so parse as "
		                  "UO-1-RTP\n");
		type = PACKET_UO_1_RTP;
	}
	else
	{
		/* there is at least one IPv4 header with context(RND) = 0, and UO-1*
		 * packets have either no value(RND) or value(RND) = context(RND) if
		 * they have one. So only UO-1-TS/ID are possible */
		rohc_decomp_debug(context, "UO-1* packet disambiguation: at least one "
		                  "IP header is IPv4 with context(RND) = 0, so parse "
		                  "as UO-1-ID or UO-1-TS\n");

		/* UO-1-ID or UO-1-TS packet, check the T field */
		if(d_is_uo1_ts(packet, rohc_length))
		{
			/* UO-1-TS packet */
			rohc_decomp_debug(context, "UO-1* packet disambiguation: T = 1, "
			                  "so parse as UO-1-TS\n");
			type = PACKET_UO_1_TS;
		}
		else
		{
			/* UO-1-ID packet */
			rohc_decomp_debug(context, "UO-1* packet disambiguation: T = 0, "
			                  "so parse as UO-1-ID\n");
			type = PACKET_UO_1_ID;
		}
	}

	return type;
}


/**
 * @brief Choose between UOR-2-RTP, UOR-2-TS, and UOR-2-ID variants
 *
 * This function is useful to choose which packet type to try to decode (may
 * change later, causing a packet reparse) in the UOR-2* family.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param packet         The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
static rohc_packet_t rtp_choose_uor2_variant(const struct rohc_decomp *const decomp,
                                             const struct d_context *const context,
                                             const uint8_t *const packet,
                                             const size_t rohc_length,
                                             const size_t large_cid_len)
{
	struct d_generic_context *g_context = context->specific;
	rohc_packet_t type;
	size_t nr_ipv4_non_rnd;
	size_t nr_ipv4;

	/* compute the number of IPv4 headers, and IPv4 with context(RND) = 0 */
	nr_ipv4 = 0;
	nr_ipv4_non_rnd = 0;
	if(is_outer_ipv4_ctxt(g_context))
	{
		nr_ipv4++;
		if(!is_outer_ipv4_rnd_ctxt(g_context))
		{
			nr_ipv4_non_rnd++;
		}
	}
	if(is_inner_ipv4_ctxt(g_context))
	{
		nr_ipv4++;
		if(!is_inner_ipv4_rnd_ctxt(g_context))
		{
			nr_ipv4_non_rnd++;
		}
	}

	/* There is no easy way to disambiguate UOR-2-ID/TS and UOR-2-RTP
	 * packets. The following algorithm is based on notes you may
	 * read in RFC 3095, section 5.7.4:
	 *  - UOR-2-RTP cannot be used if the context contains at least one
	 *    IPv4 header with value(RND) = 0. This disambiguates it from
	 *    UOR-2-ID and UOR-2-TS.
	 *  - UOR-2-ID cannot be used if there is no IPv4 header in the
	 *    context or if value(RND) and value(RND2) are both 1.
	 *  - UOR-2-TS cannot be used if there is no IPv4 header in the
	 *    context or if value(RND) and value(RND2) are both 1.
	 *  - T: T = 0 indicates format UOR-2-ID;
	 *       T = 1 indicates format UOR-2-TS.
	 */
	if(nr_ipv4 == 0)
	{
		/* no IPv4 header at all, so only *-RTP packet can be used */
		rohc_decomp_debug(context, "UOR-2* packet disambiguation: no IPv4 "
		                  "header at all, so parse as UOR-2-RTP\n");
		type = PACKET_UOR_2_RTP;
	}
	else if(nr_ipv4_non_rnd == 0)
	{
		/* there is no IPv4 header with context(RND) = 0, but maybe there is a
		 * IPv4 header with value(RND) = 0 (the ROHC packet may contain a RND
		 * field and update context). So try parsing UOR-2-RTP, and fallback
		 * on UOR-2-TS/ID if value(RND) = 0 is found. */
		rohc_decomp_debug(context, "UOR-2* packet disambiguation: no IPv4 "
		                  "header with context(RND) = 0, so try parsing as "
		                  "UOR-2-RTP, and fallback on UOR-2-ID/TS later if "
		                  "value(RND) = 0 in packet\n");
		type = PACKET_UOR_2_RTP;
	}
	else
	{
		/* there is at least one IPv4 header with context(RND) = 0, but maybe
		 * there is a IPv4 header with value(RND) = 1 (the ROHC packet may
		 * contain a RND field and update context), so try parsing UOR-2-TS/ID,
		 * and fallback on UOR-2-RTP if value(RND) = 1 is found */
		rohc_decomp_debug(context, "UOR-2* packet disambiguation: at least one "
		                  "IP header is IPv4 with context(RND) = 0, so try "
		                  "parsing as UOR-2-ID/TS, and fallback on UOR-2-RTP "
		                  "later if value(RND) = 1 in packet\n");

		/* UOR-2-ID or UOR-2-TS packet, check the T field */
		if(d_is_uor2_ts(packet, rohc_length, large_cid_len))
		{
			/* UOR-2-TS packet */
			rohc_decomp_debug(context, "UOR-2* packet disambiguation: T = 1, "
			                  "so try parsing as UOR-2-TS, and fallback on "
			                  "UOR-2-RTP later if value(RND) = 1 in packet\n");
			type = PACKET_UOR_2_TS;
		}
		else
		{
			/* UOR-2-ID packet */
			rohc_decomp_debug(context, "UOR-2* packet disambiguation: T = 0, "
			                  "so try parsing as UOR-2-ID, and fallback on "
			                  "UOR-2-RTP later if value(RND) = 1 in packet\n");
			type = PACKET_UOR_2_ID;
		}
	}

	return type;
}


/**
 * @brief Parse the UDP/RTP static part of the ROHC packet.
 *
 * @param context The decompression context
 * @param packet  The ROHC packet to parse
 * @param length  The length of the ROHC packet
 * @param bits    OUT: The bits extracted from the ROHC header
 * @return        The number of bytes read in the ROHC packet,
 *                -1 in case of failure
 */
static int rtp_parse_static_rtp(const struct d_context *const context,
                                const unsigned char *packet,
                                size_t length,
                                struct rohc_extr_bits *const bits)
{
	struct d_generic_context *g_context;
	struct d_rtp_context *rtp_context;
	int read; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	rtp_context = g_context->specific;
	assert(packet != NULL);
	assert(bits != NULL);

	/* decode UDP static part */
	read = udp_parse_static_udp(context, packet, length, bits);
	if(read == -1)
	{
		goto error;
	}
	packet += read;
	length -= read;

	/* check the minimal length to decode the RTP static part */
	if(length < sizeof(uint32_t))
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zu)\n", length);
		goto error;
	}

	/* decode RTP static part */
	memcpy(&(bits->rtp_ssrc), packet, sizeof(uint32_t));
	bits->rtp_ssrc_nr = 32;
	rohc_decomp_debug(context, "SSRC = 0x%08x\n", bits->rtp_ssrc);
	packet += sizeof(uint32_t);
	read += sizeof(uint32_t);

	/* is context re-used? */
	if(context->num_recv_packets > 1 &&
	   memcmp(&bits->rtp_ssrc, &rtp_context->ssrc, sizeof(uint32_t)) != 0)
	{
		rohc_decomp_debug(context, "RTP SSRC mismatch (packet = 0x%08x, "
		                  "context = 0x%08x) -> context is being reused\n",
		                  bits->rtp_ssrc, rtp_context->ssrc);
		bits->is_context_reused = true;
	}
	memcpy(&rtp_context->ssrc, &bits->rtp_ssrc, sizeof(uint32_t));

	return read;

error:
	return -1;
}


/**
 * @brief Parse the UDP/RTP dynamic part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int rtp_parse_dynamic_rtp(const struct d_context *const context,
                                 const uint8_t *packet,
                                 const size_t length,
                                 struct rohc_extr_bits *const bits)
{
	/* The size (in bytes) of the constant RTP dynamic part:
	 *
	 * According to RFC3095 section 5.7.7.6:
	 *   1 (flags V, P, RX, CC) + 1 (flags M, PT) + 2 (RTP SN) +
	 *   4 (RTP TS) + 1 (CSRC list) = 9 bytes
	 *
	 * The size of the Generic CSRC list field is considered constant because
	 * generic CSRC list is not supported yet and thus 1 byte of zero is used.
	 */
	const size_t rtp_dyn_size = 9;

	struct d_generic_context *g_context;
	struct d_rtp_context *rtp_context;
	size_t remain_len = length;
	int rx;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	rtp_context = g_context->specific;
	assert(packet != NULL);
	assert(bits != NULL);

	/* part 1: UDP checksum */
	if(remain_len < sizeof(uint16_t))
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zu)\n", remain_len);
		goto error;
	}
	bits->udp_check = GET_NEXT_16_BITS(packet);
	bits->udp_check_nr = 16;
	rohc_decomp_debug(context, "UDP checksum = 0x%04x\n",
	                  rohc_ntoh16(bits->udp_check));
	packet += sizeof(uint16_t);
	remain_len -= sizeof(uint16_t);

	/* determine whether the UDP checksum will be present in UO packets */
	rtp_context->udp_checksum_present = (bits->udp_check > 0);

	/* check the minimal length to decode the constant part of the RTP
	   dynamic part (parts 2-6) */
	if(remain_len < rtp_dyn_size)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zu)\n", remain_len);
		goto error;
	}

	/* part 2 */
	bits->rtp_version = GET_BIT_6_7(packet);
	bits->rtp_version_nr = 2;
	rohc_decomp_debug(context, "version = 0x%x\n", bits->rtp_version);
	bits->rtp_p = GET_REAL(GET_BIT_5(packet));
	bits->rtp_p_nr = 1;
	rohc_decomp_debug(context, "padding = 0x%x\n", bits->rtp_p);
	bits->rtp_cc = GET_BIT_0_3(packet);
	bits->rtp_cc_nr = 4;
	rohc_decomp_debug(context, "CSRC Count = 0x%x\n", bits->rtp_cc);
	rx = GET_REAL(GET_BIT_4(packet));
	rohc_decomp_debug(context, "RX = 0x%x\n", rx);
	packet++;
	remain_len--;

	/* part 3 */
	bits->rtp_m = GET_REAL(GET_BIT_7(packet));
	bits->rtp_m_nr = 1;
	rohc_decomp_debug(context, "M = 0x%x\n", bits->rtp_m);
	bits->rtp_pt = GET_BIT_0_6(packet);
	bits->rtp_pt_nr = 7;
	rohc_decomp_debug(context, "payload type = 0x%x\n", bits->rtp_pt);
	packet++;
	remain_len--;

	/* part 4: 16-bit RTP SN */
	bits->sn = rohc_ntoh16(GET_NEXT_16_BITS(packet));
	bits->sn_nr = 16;
	bits->is_sn_enc = false;
	packet += sizeof(uint16_t);
	remain_len-= sizeof(uint16_t);
	rohc_decomp_debug(context, "SN = %u (0x%04x)\n", bits->sn, bits->sn);

	/* part 5: 4-byte TimeStamp (TS) */
	memcpy(&bits->ts, packet, sizeof(uint32_t));
	bits->ts = rohc_ntoh32(bits->ts);
	bits->ts_nr = 32;
	bits->is_ts_scaled = false;
	packet += sizeof(uint32_t);
	remain_len -= sizeof(uint32_t);
	rohc_decomp_debug(context, "timestamp = 0x%08x\n", bits->ts);

	/* part 6 is not supported yet, ignore the byte which should be set to 0 */
	if(GET_BIT_0_7(packet) != 0x00)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "generic CSRC list not supported yet, but first CSRC "
		             "byte was set to 0x%02x\n", GET_BIT_0_7(packet));
		goto error;
	}
	packet++;
	remain_len--;

	/* part 7 */
	if(rx)
	{
		int mode, tis, tss;

		/* check the minimal length to decode the flags that are only present
		   if RX flag is set */
		if(remain_len < 1)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id,
			             "ROHC packet too small (len = %zu)\n", remain_len);
			goto error;
		}

		bits->rtp_x = GET_REAL(GET_BIT_4(packet));
		bits->rtp_x_nr = 1;
		mode = ((*packet) >> 2) & 0x03;
		tis = GET_REAL(GET_BIT_1(packet));
		tss = GET_REAL(GET_BIT_0(packet));
		rohc_decomp_debug(context, "X = %u, rohc_mode = %d, tis = %d, "
		                  "tss = %d\n", bits->rtp_x, mode, tis, tss);
		packet++;
		remain_len--;

		/* part 8 */
		if(tss)
		{
			size_t ts_stride_sdvl_len;
			uint32_t ts_stride;
			size_t ts_stride_bits_nr;

			/* decode the SDVL-encoded TS_STRIDE field */
			ts_stride_sdvl_len = sdvl_decode(packet, remain_len,
			                                 &ts_stride, &ts_stride_bits_nr);
			if(ts_stride_sdvl_len <= 0)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "failed to decode SDVL-encoded TS_STRIDE field\n");
				goto error;
			}
			rohc_decomp_debug(context, "TS_STRIDE read = %u / 0x%x\n",
			                  ts_stride, ts_stride);

			/* skip the SDVL-encoded TS_STRIDE field in packet */
			packet += ts_stride_sdvl_len;
			remain_len -= ts_stride_sdvl_len;

			/* temporarily store the decoded TS_STRIDE in context */
			d_record_ts_stride(rtp_context->ts_scaled_ctxt, ts_stride);
		}

		/* part 9 */
		if(tis)
		{
			/* check the minimal length to decode the SDVL-encoded TIME_STRIDE */
			if(remain_len < 1)
			{
				rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
				             context->profile->id,
				             "ROHC packet too small (len = %zu) for 1st byte "
				             "of SDVL-encoded TIME_STRIDE\n", remain_len);
				goto error;
			}

			/* not supported yet */
			rohc_decomp_debug(context, "TIME_STRIDE field not supported yet\n");
			goto error;
		}
	}

	assert(remain_len < length);

	return (length - remain_len);

error:
	return -1;
}


/**
 * @brief Parse the extension 3 of the UO-1-ID or UOR-2* packet
 *
 * \verbatim

 Extension 3 for RTP profile (5.7.5):

       0     1     2     3     4     5     6     7
    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |  1     1  |  S  |R-TS | Tsc |  I  | ip  | rtp |
    +-----+-----+-----+-----+-----+-----+-----+-----+
 2  |            Inner IP header flags        | ip2 |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 3  |            Outer IP header flags              |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 4  |                      SN                       |  if S = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
4.1 /                      TS                       / 1-4 octets, if R-TS = 1
    |                                               |
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 5  /            Inner IP header fields             /  variable,
    |                                               |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 6  |                     IP-ID                     |  2 octets, if I = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 7  /            Outer IP header fields             /  variable,
    |                                               |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |  variable,
 8  /          RTP Header flags and fields          /  if rtp = 1
    |                                               |
    +-----+-----+-----+-----+-----+-----+-----+-----+

\endverbatim
 *
 * @param decomp            The ROHC decompressor
 * @param context           The decompression context
 * @param rohc_data         The ROHC data to parse
 * @param rohc_data_len     The length of the ROHC data to parse
 * @param packet_type       The type of ROHC packet to parse
 * @param bits              IN: the bits already found in base header
 *                          OUT: the bits found in the extension header 3
 * @return                  The data length read from the ROHC packet,
 *                          -2 in case packet must be reparsed,
 *                          -1 in case of error
 */
static int rtp_parse_extension3(const struct rohc_decomp *const decomp,
                                const struct d_context *const context,
                                const unsigned char *const rohc_data,
                                const size_t rohc_data_len,
                                const rohc_packet_t packet_type,
                                struct rohc_extr_bits *const bits)
{
	struct d_generic_context *g_context;
	const unsigned char *ip_flags_pos = NULL;
	const unsigned char *ip2_flags_pos = NULL;
	int S, rts, I, ip, rtp, ip2;
	uint16_t I_bits;
	int size;

	/* remaining ROHC data */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* whether all RND values for outer and inner IP headers are set to 1 or
	 * not (use value(RND) if RND bits are present in the extension, use
	 * context(RND) = 1 otherwise) */
	int are_all_ipv4_rnd = 1;

	/* whether at least one RND flag changed in extension 3 */
	bool rnd_changed = false;

	/* sanity checks */
	assert(decomp != NULL);
	assert(context != NULL);
	assert(context->specific != NULL);
	assert(rohc_data != NULL);
	assert(bits != NULL);

	g_context = context->specific;

	rohc_decomp_debug(context, "decode extension 3\n");

	rohc_remain_data = rohc_data;
	rohc_remain_len = rohc_data_len;

	/* check the minimal length to decode the flags */
	if(rohc_remain_len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* decode the first byte of flags */
	S = GET_REAL(GET_BIT_5(rohc_remain_data));
	rts = GET_REAL(GET_BIT_4(rohc_remain_data));
	bits->is_ts_scaled = GET_BOOL(GET_BIT_3(rohc_remain_data));
	I = GET_REAL(GET_BIT_2(rohc_remain_data));
	ip = GET_REAL(GET_BIT_1(rohc_remain_data));
	rtp = GET_REAL(GET_BIT_0(rohc_remain_data));

	/* decode the optional ip2 flag */
	if(ip)
	{
		/* check the minimal length to decode the ip2 flag */
		if(rohc_remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
			goto error;
		}

		ip2 = GET_REAL(GET_BIT_0(rohc_remain_data + 1));
	}
	else
	{
		ip2 = 0;
	}
	rohc_decomp_debug(context, "S = %d, R-TS = %d, Tsc = %d, I = %d, ip = %d, "
	                  "rtp = %d, ip2 = %d\n", S, rts, bits->is_ts_scaled, I,
	                  ip, rtp, ip2);
	rohc_remain_data++;
	rohc_remain_len--;

	/* check the minimal length to decode the inner & outer IP header flags
	 * and the SN */
	if(rohc_remain_len < (ip + ip2 + S))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* remember position of inner IP header flags if present */
	if(ip)
	{
		rohc_decomp_debug(context, "inner IP header flags field is present in "
		                  "EXT-3 = 0x%02x\n", GET_BIT_0_7(rohc_remain_data));
		if(g_context->multiple_ip)
		{
			ip2_flags_pos = rohc_remain_data;
		}
		else
		{
			ip_flags_pos = rohc_remain_data;
		}
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* remember position of outer IP header flags if present */
	if(ip2)
	{
		rohc_decomp_debug(context, "outer IP header flags field is present in "
		                  "EXT-3 = 0x%02x\n", GET_BIT_0_7(rohc_remain_data));
		ip_flags_pos = rohc_remain_data;
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* extract the SN if present */
	if(S)
	{
		APPEND_SN_BITS(PACKET_EXT_3, bits, GET_BIT_0_7(rohc_remain_data), 8);
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* extract and decode TS if present */
	if(rts)
	{
		size_t ts_sdvl_size;
		uint32_t ts_ext; /* TS bits extracted from extension header */
		size_t ts_ext_nr;

		/* decode SDVL-encoded TS value */
		ts_sdvl_size = sdvl_decode(rohc_remain_data, rohc_remain_len,
		                           &ts_ext, &ts_ext_nr);
		if(ts_sdvl_size <= 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to decode SDVL-encoded TS field\n");
			goto error;
		}
		APPEND_TS_BITS(PACKET_EXT_3, bits, ts_ext, ts_ext_nr);

		rohc_remain_data += ts_sdvl_size;
		rohc_remain_len -= ts_sdvl_size;
	}

	/* decode the inner IP header fields (pointed by packet) according to the
	 * inner IP header flags (pointed by ip(2)_flags_pos) if present */
	if(ip)
	{
		if(g_context->multiple_ip)
		{
			size = parse_inner_header_flags(decomp, context, ip2_flags_pos,
			                                rohc_remain_data, rohc_remain_len,
			                                &bits->inner_ip);

			/* inner RND changed? */
			if(bits->inner_ip.rnd_nr > 0)
			{
				are_all_ipv4_rnd &= bits->inner_ip.rnd;
				if(bits->inner_ip.rnd != g_context->inner_ip_changes->rnd)
				{
					rohc_decomp_debug(context, "RND changed for inner IP header "
					                  "(%u -> %u)\n", g_context->inner_ip_changes->rnd,
					                  bits->inner_ip.rnd);
					rnd_changed = true;
				}
			}
			else if(bits->inner_ip.version == IPV4)
			{
				are_all_ipv4_rnd &= g_context->inner_ip_changes->rnd;
			}
		}
		else
		{
			size = parse_inner_header_flags(decomp, context, ip_flags_pos,
			                                rohc_remain_data, rohc_remain_len,
			                                &bits->outer_ip);

			/* outer RND changed? */
			if(bits->outer_ip.rnd_nr > 0)
			{
				are_all_ipv4_rnd &= bits->outer_ip.rnd;
				if(bits->outer_ip.rnd != g_context->outer_ip_changes->rnd)
				{
					rohc_decomp_debug(context, "RND changed for outer IP header "
					                  "(%u -> %u)\n", g_context->outer_ip_changes->rnd,
					                  bits->outer_ip.rnd);
					rnd_changed = true;
				}
			}
			else if(bits->outer_ip.version == IPV4)
			{
				are_all_ipv4_rnd &= g_context->outer_ip_changes->rnd;
			}
		}
		if(size < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode the inner IP header flags & fields\n");
			goto error;
		}

		rohc_remain_data += size;
		rohc_remain_len -= size;
	}
	else
	{
		/* no inner IP header flags, so get context(RND) */
		if(g_context->multiple_ip)
		{
			if(bits->inner_ip.version == IPV4)
			{
				are_all_ipv4_rnd &= g_context->inner_ip_changes->rnd;
			}
		}
		else
		{
			if(bits->outer_ip.version == IPV4)
			{
				are_all_ipv4_rnd &= g_context->outer_ip_changes->rnd;
			}
		}
	}

	/* skip the IP-ID if present, it will be parsed later once all RND bits
	 * have been parsed (ie. outer IP header flags), otherwise a problem
	 * may occur: if you have context(outer RND) = 1 and context(inner RND) = 0
	 * and value(outer RND) = 0 and value(inner RND) = 1, then here in the
	 * code, we have no IP header with non-random IP-ID */
	if(I)
	{
		/* check the minimal length to decode the IP-ID field */
		if(rohc_remain_len < 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* both inner and outer IP-ID fields are 2-byte long */
		I_bits = rohc_ntoh16(GET_NEXT_16_BITS(rohc_remain_data));
		rohc_remain_data += 2;
		rohc_remain_len -= 2;
	}
	else
	{
		I_bits = 0;
	}

	/* decode the outer IP header fields according to the outer IP header
	 * flags if present */
	if(ip2)
	{
		size = parse_outer_header_flags(decomp, context, ip_flags_pos,
		                                rohc_remain_data, rohc_remain_len,
		                                &bits->outer_ip);
		if(size == -1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode the outer IP header flags & fields\n");
			goto error;
		}

		/* outer RND changed? */
		if(bits->outer_ip.rnd_nr > 0)
		{
			are_all_ipv4_rnd &= bits->outer_ip.rnd;
			if(bits->outer_ip.rnd != g_context->outer_ip_changes->rnd)
			{
				rohc_decomp_debug(context, "RND changed for outer IP header "
				                  "(%u -> %u)\n", g_context->outer_ip_changes->rnd,
				                  bits->outer_ip.rnd);
				rnd_changed = true;
			}
		}
		else if(bits->outer_ip.version == IPV4)
		{
			are_all_ipv4_rnd &= g_context->outer_ip_changes->rnd;
		}

		rohc_remain_data += size;
		rohc_remain_len -= size;
	}
	else if(g_context->multiple_ip && bits->outer_ip.version == IPV4)
	{
		/* no outer IP header flags, so get context(RND) */
		are_all_ipv4_rnd &= g_context->outer_ip_changes->rnd;
	}

	/* if RND changed while parsing UO-1-ID, UOR-2-RTP, UOR-2-ID, or UOR-2-TS,
	 * we might have to restart parsing */
	if(packet_type == PACKET_UO_1_ID && rnd_changed)
	{
		/* RFC 3095, section 5.7.5.1 says:
		 *   The values of the RND and RND2 flags are changed by sending UOR-2
		 *   headers with Extension 3, or IR-DYN headers, where the flag(s) have
		 *   their new values.
		 *   [...]
		 *   When no IPv4 header is present in the static context, or the RND
		 *   flags for all IPv4 headers in the context have been established to
		 *   be 1, the packet types R-1-ID, R-1-TS, UO-1-ID, and UO-1-TS MUST
		 *   NOT be used.
		 *   [...]
		 *   While in the transient state in which an RND flag is being
		 *   established, the packet types R-1-ID, R-1-TS, UO-1-ID, and UO-1-TS
		 *   MUST NOT be used. */
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "at least one RND changed while parsing UO-1-ID, "
		             "compressor does not conform to RFC, discard packet\n");
		goto error;
	}
	else if(is_uor2_reparse_required(packet_type, are_all_ipv4_rnd))
	{
		/* RFC 3095, section 5.7.5.1 says:
		 *   While in the transient state in which an RND flag is being
		 *   established, the packet types R-1-ID, R-1-TS, UO-1-ID, and UO-1-TS
		 *   MUST NOT be used.  This implies that the RND flag(s) of Extension 3
		 *   may have to be inspected before the exact format of a base header
		 *   carrying an Extension 3 can be determined, i.e., whether a T-bit is
		 *   present or not. */
		rohc_decomp_debug(context, "at least one RND changed and it makes our "
		                  "choice of packet type wrong, we must reparse the "
		                  "UOR-2* packet with a different packet type\n");
		goto reparse;
	}

	if(I)
	{
		/* determine which IP header is the innermost IPv4 header with
		 * non-random IP-ID */
		if(g_context->multiple_ip && is_ipv4_non_rnd_pkt(bits->inner_ip))
		{
			/* inner IP header is IPv4 with non-random IP-ID */
			if(bits->inner_ip.id_nr > 0 && bits->inner_ip.id != 0)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "IP-ID field present (I = 1) but inner IP-ID "
				             "already updated\n");
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
				goto error;
#endif
			}
			bits->inner_ip.id = I_bits;
			bits->inner_ip.id_nr = 16;
			rohc_decomp_debug(context, "%zd bits of inner IP-ID in EXT3 = 0x%x\n",
			                  bits->inner_ip.id_nr, bits->inner_ip.id);
		}
		else if(is_ipv4_non_rnd_pkt(bits->outer_ip))
		{
			/* inner IP header is not 'IPv4 with non-random IP-ID', but outer
			 * IP header is */
			if(bits->outer_ip.id_nr > 0 && bits->outer_ip.id != 0)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "IP-ID field present (I = 1) but outer IP-ID "
				             "already updated\n");
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
				goto error;
#endif
			}
			bits->outer_ip.id = I_bits;
			bits->outer_ip.id_nr = 16;
			rohc_decomp_debug(context, "%zd bits of outer IP-ID in EXT3 = 0x%x\n",
			                  bits->outer_ip.id_nr, bits->outer_ip.id);
		}
		else
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "extension 3 cannot contain IP-ID bits because "
			             "no IP header is IPv4 with non-random IP-ID\n");
			goto error;
		}
	}

	/* decode RTP header flags & fields if present */
	if(rtp)
	{
		int rpt, csrc, tss, tis;
		uint8_t rtp_m_ext; /* the RTP Marker (M) flag in extension header */

		/* check the minimal length to decode RTP header flags */
		if(rohc_remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* decode RTP header flags */
		bits->mode = GET_BIT_6_7(rohc_remain_data);
		bits->mode_nr = 2;
		rpt = GET_REAL(GET_BIT_5(rohc_remain_data));
		rtp_m_ext = GET_REAL(GET_BIT_4(rohc_remain_data));
		/* check that the RTP Marker (M) value found in the extension is the
		 * same as the one we previously found in UO* base header. RFC 4815 at
		 * §8.4 says:
		 *   The RTP header part of Extension 3, as defined by RFC 3095
		 *   Section 5.7.5, includes a one-bit field for the RTP Marker bit.
		 *   This field is also present in all compressed base header formats
		 *   except for UO-1-ID; meaning, there may be two occurrences of the
		 *   field within one single compressed header. In such cases, the
		 *   two M fields must have the same value.
		 */
		if(bits->rtp_m_nr > 0 && bits->rtp_m != rtp_m_ext)
		{
			assert(bits->rtp_m_nr == 1);
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "RTP Marker flag mismatch (base header = %u, "
			             "extension 3 = %u)\n", bits->rtp_m, rtp_m_ext);
			goto error;
		}
		else
		{
			/* set RTP M flag */
			bits->rtp_m = rtp_m_ext;
			bits->rtp_m_nr = 1;
		}
		rohc_decomp_debug(context, "%zd-bit RTP Marker (M) = %u\n",
		                  bits->rtp_m_nr, bits->rtp_m);
		bits->rtp_x = GET_REAL(GET_BIT_3(rohc_remain_data));
		bits->rtp_x_nr = 1;
		rohc_decomp_debug(context, "%zd-bit RTP eXtension (R-X) = %u\n",
		                  bits->rtp_x_nr, bits->rtp_x);
		csrc = GET_REAL(GET_BIT_2(rohc_remain_data));
		tss = GET_REAL(GET_BIT_1(rohc_remain_data));
		tis = GET_REAL(GET_BIT_0(rohc_remain_data));
		rohc_remain_data++;
		rohc_remain_len--;

		/* check the minimal length to decode RTP header fields */
		if(rohc_remain_len < (rpt + csrc + tss + tis))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			            "ROHC packet too small (len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* decode RTP header fields */
		if(rpt)
		{
			bits->rtp_p = GET_REAL(GET_BIT_7(rohc_remain_data));
			bits->rtp_p_nr = 1;
			rohc_decomp_debug(context, "%zd-bit RTP Padding (R-P) = 0x%x\n",
			                  bits->rtp_p_nr, bits->rtp_p);
			bits->rtp_pt = GET_BIT_0_6(rohc_remain_data);
			bits->rtp_pt_nr = 7;
			rohc_decomp_debug(context, "%zd-bit RTP Payload Type (R-PT) = 0x%x\n",
			                  bits->rtp_pt_nr, bits->rtp_pt);
			rohc_remain_data++;
			rohc_remain_len--;
		}

		if(csrc)
		{
			/* TODO: Compressed CSRC list */
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "Compressed CSRC list not supported yet\n");
			goto error;
		}

		if(tss)
		{
			struct d_rtp_context *rtp_context;
			uint32_t ts_stride;
			size_t ts_stride_bits_nr;
			size_t ts_stride_size;

			rtp_context = (struct d_rtp_context *) g_context->specific;

			/* decode SDVL-encoded TS value */
			ts_stride_size = sdvl_decode(rohc_remain_data, rohc_remain_len,
			                             &ts_stride, &ts_stride_bits_nr);
			if(ts_stride_size <= 0)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "failed to decode SDVL-encoded TS_STRIDE field\n");
				goto error;
			}
			rohc_decomp_debug(context, "decoded TS_STRIDE = %u / 0x%x\n",
			                  ts_stride, ts_stride);

			rohc_remain_data += ts_stride_size;
			rohc_remain_len -= ts_stride_size;

			/* temporarily store the decoded TS_STRIDE in context */
			d_record_ts_stride(rtp_context->ts_scaled_ctxt, ts_stride);
		}

		if(tis)
		{
			/* TODO: TIME_STRIDE */
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "TIME_STRIDE not supported yet\n");
			goto error;
		}
	}

	return (rohc_data_len - rohc_remain_len);

error:
	return -1;
reparse:
	return -2;
}


/**
 * @brief Does the UOR-2* packet need to be parsed again?
 *
 * When parsing a UOR-2* packet, if RND changes, the packet might need to be
 * parsed again with another UOR-2* packet type in mind:
 *  - UOR-2-RTP needs to be parsed again as UOR-2-ID or UOR-2-TS
 *    if one of the RND flags becomes 0.
 *  - UOR-2-ID needs to be parsed again as UOR-2-RTP
 *    if none of the RND flags is 0 anymore.
 *  - UOR-2-TS needs to be parsed again as UOR-2-RTP
 *    if none of the RND flags is 0 anymore.
 *
 * @param packet_type       The packet type
 * @param are_all_ipv4_rnd  Whether all RND values for outer and inner IP
 *                          headers are set to 1
 * @return                  Whether packet shall be parsed again or not
 */
static inline bool is_uor2_reparse_required(const rohc_packet_t packet_type,
                                            const int are_all_ipv4_rnd)
{
	return ((packet_type == PACKET_UOR_2_RTP && !are_all_ipv4_rnd) ||
	        (packet_type == PACKET_UOR_2_ID && are_all_ipv4_rnd) ||
	        (packet_type == PACKET_UOR_2_TS && are_all_ipv4_rnd));
}


/**
 * @brief Parse the UDP/RTP tail of the UO* ROHC packets.
 *
 * @param context      The decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int rtp_parse_uo_remainder(const struct d_context *const context,
                                  const unsigned char *packet,
                                  unsigned int length,
                                  struct rohc_extr_bits *const bits)
{
	struct d_generic_context *g_context;
	struct d_rtp_context *rtp_context;
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	rtp_context = g_context->specific;
	assert(packet != NULL);
	assert(bits != NULL);

	/* UDP checksum if necessary:
	 *  udp_checksum_present < 0 <=> not initialized
	 *  udp_checksum_present = 0 <=> UDP checksum field not present
	 *  udp_checksum_present > 0 <=> UDP checksum field present */
	if(rtp_context->udp_checksum_present < 0)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "udp_checksum_present not initialized and packet is not "
		             "one IR packet\n");
		goto error;
	}
	else if(rtp_context->udp_checksum_present == 0)
	{
		bits->udp_check_nr = 0;
		rohc_decomp_debug(context, "UDP checksum not present\n");
	}
	else
	{
		/* check the minimal length to decode the UDP checksum */
		if(length < 2)
		{
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP,
			             context->profile->id,
			             "ROHC packet too small (len = %d)\n", length);
			goto error;
		}

		/* retrieve the UDP checksum from the ROHC packet */
		bits->udp_check = GET_NEXT_16_BITS(packet);
		bits->udp_check_nr = 16;
		rohc_decomp_debug(context, "UDP checksum = 0x%04x\n",
		                  rohc_ntoh16(bits->udp_check));
		packet += 2;
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
 *  - RTP TimeStamp (TS)
 *  - RTP Marker (M) flag
 *  - RTP eXtension (R-X) flag
 *  - RTP Padding (R-P) flag
 *  - RTP Payload Type (R-PT)
 *
 * @param context  The decompression context
 * @param bits     The extracted bits
 * @param decoded  OUT: The corresponding decoded values
 * @return         true if decoding is successful, false otherwise
 */
static bool rtp_decode_values_from_bits(const struct d_context *context,
                                        const struct rohc_extr_bits bits,
                                        struct rohc_decoded_values *const decoded)
{
	struct d_generic_context *g_context;
	struct d_rtp_context *rtp_context;
	struct udphdr *udp;
	struct rtphdr *rtp;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	rtp_context = g_context->specific;
	assert(decoded != NULL);

	udp = (struct udphdr *) g_context->outer_ip_changes->next_header;
	rtp = (struct rtphdr *) (udp + 1);

	/* decode UDP source port */
	if(bits.udp_src_nr > 0)
	{
		/* take packet value */
		assert(bits.udp_src_nr == 16);
		decoded->udp_src = bits.udp_src;
	}
	else
	{
		/* keep context value */
		decoded->udp_src = udp->source;
	}
	rohc_decomp_debug(context, "decoded UDP source port = 0x%04x\n",
	                  rohc_ntoh16(decoded->udp_src));

	/* decode UDP destination port */
	if(bits.udp_dst_nr > 0)
	{
		/* take packet value */
		assert(bits.udp_dst_nr == 16);
		decoded->udp_dst = bits.udp_dst;
	}
	else
	{
		/* keep context value */
		decoded->udp_dst = udp->dest;
	}
	rohc_decomp_debug(context, "decoded UDP destination port = 0x%04x\n",
	                  rohc_ntoh16(decoded->udp_dst));

	/* UDP checksum:
	 *  - error if udp_checksum_present not initialized,
	 *    ie. udp_checksum_present < 0
	 *  - copy from packet if checksum is present,
	 *    ie. udp_checksum_present > 0
	 *  - set checksum to zero if checksum is not present,
	 *    ie. udp_checksum_present = 0  */
	if(rtp_context->udp_checksum_present < 0)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "udp_checksum_present not initialized\n");
		goto error;
	}
	else if(rtp_context->udp_checksum_present > 0)
	{
		assert(bits.udp_check_nr == 16);
		decoded->udp_check = bits.udp_check;
	}
	else
	{
		assert(bits.udp_check_nr == 16 || bits.udp_check_nr == 0);
		assert(bits.udp_check == 0);
		decoded->udp_check = 0;
	}
	rohc_decomp_debug(context, "decoded UDP checksum = 0x%04x (checksum "
	                  "present = %d)\n", rohc_ntoh16(decoded->udp_check),
	                  rtp_context->udp_checksum_present);

	/* decode version field */
	if(bits.rtp_version_nr > 0)
	{
		/* take packet value */
		assert(bits.rtp_version_nr == 2);
		decoded->rtp_version = bits.rtp_version;
	}
	else
	{
		/* keep context value */
		decoded->rtp_version = rtp->version;
	}
	rohc_decomp_debug(context, "decoded RTP version = %u\n", decoded->rtp_version);

	/* decode RTP Padding (R-P) flag */
	if(bits.rtp_p_nr > 0)
	{
		/* take packet value */
		assert(bits.rtp_p_nr == 1);
		decoded->rtp_p = bits.rtp_p;
	}
	else
	{
		/* keep context value */
		decoded->rtp_p = rtp->padding;
	}
	rohc_decomp_debug(context, "decoded R-P flag = %u\n", decoded->rtp_p);

	/* decode RTP eXtension (R-X) flag */
	if(bits.rtp_x_nr > 0)
	{
		/* take packet value */
		assert(bits.rtp_x_nr == 1);
		decoded->rtp_x = bits.rtp_x;
	}
	else
	{
		/* keep context value */
		decoded->rtp_x = rtp->extension;
	}
	rohc_decomp_debug(context, "decoded R-X flag = %u\n", decoded->rtp_x);

	/* decode RTP CC */
	if(bits.rtp_cc_nr > 0)
	{
		/* take packet value */
		assert(bits.rtp_cc_nr == 4);
		decoded->rtp_cc = bits.rtp_cc;
	}
	else
	{
		/* keep context value */
		decoded->rtp_cc = rtp->cc;
	}
	rohc_decomp_debug(context, "decoded CC = %u\n", decoded->rtp_cc);

	/* decode RTP Marker (M) flag */
	if(bits.rtp_m_nr > 0)
	{
		assert(bits.rtp_m_nr == 1);
		decoded->rtp_m = bits.rtp_m;
	}
	else
	{
		/* RFC 3095 §5.7 says:
		 *   Context(M) is initially zero and is never updated. value(M) = 1
		 *   only when field(M) = 1.
		 */
		decoded->rtp_m = 0;
	}
	rohc_decomp_debug(context, "decoded RTP M flag = %u\n", decoded->rtp_m);

	/* decode RTP Payload Type (R-PT) */
	if(bits.rtp_pt_nr > 0)
	{
		/* take value from base header */
		assert(bits.rtp_pt_nr == 7);
		decoded->rtp_pt = bits.rtp_pt;
	}
	else
	{
		/* keep context value */
		decoded->rtp_pt = rtp->pt;
	}
	rohc_decomp_debug(context, "decoded R-PT = %u\n", decoded->rtp_pt);

	/* decode RTP TimeStamp (TS) */
	rohc_decomp_debug(context, "%zd-bit TS delta = 0x%x\n", bits.ts_nr, bits.ts);
	if(!bits.is_ts_scaled)
	{
		/* some LSB bits of the unscaled TS were transmitted */

		bool ts_decode_ok;

		if(bits.ts_nr == 32)
		{
			rohc_decomp_debug(context, "TS absolute value is transmitted\n");
		}
		else if(bits.ts_nr > 0)
		{
			rohc_decomp_debug(context, "TS is not scaled\n");
		}
		else
		{
			/* RFC 4815, §4.2 says:
			 *   If a packet with no TS bits is received with Tsc = 0, the
			 *   decompressor MUST discard the packet. */
			rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
			             "TS not scaled (Tsc = %d) and no TS bit received, "
			             "discard the packet\n", bits.is_ts_scaled);
			goto error;
		}

		ts_decode_ok = ts_decode_unscaled_bits(rtp_context->ts_scaled_ctxt,
		                                       bits.ts, bits.ts_nr,
		                                       &decoded->ts);
		if(!ts_decode_ok)
		{
			rohc_decomp_debug(context, "failed to decode %zd-bit unscaled TS "
			                  "0x%x\n", bits.ts_nr, bits.ts);
			goto error;
		}
	}
	else if(bits.ts_nr == 0)
	{
		/* TS is scaled but no TS_SCALED bits were transmitted */
		rohc_decomp_debug(context, "TS is deducted from SN\n");
		assert(decoded->sn <= 0xffff);
		decoded->ts = ts_deduce_from_sn(rtp_context->ts_scaled_ctxt, decoded->sn);
	}
	else
	{
		/* TS is scaled and some TS_SCALED bits were transmitted */

		bool ts_decode_ok;

		rohc_decomp_debug(context, "TS is scaled\n");
		ts_decode_ok = ts_decode_scaled_bits(rtp_context->ts_scaled_ctxt,
		                                     bits.ts, bits.ts_nr,
		                                     &decoded->ts);
		if(!ts_decode_ok)
		{
			rohc_decomp_debug(context, "failed to decode %zd-bit TS_SCALED "
			                  "0x%x\n", bits.ts_nr, bits.ts);
			goto error;
		}
	}
	rohc_decomp_debug(context, "decoded timestamp = %u / 0x%x (nr bits = %zd, "
	                  "bits = %u / 0x%x)\n", decoded->ts, decoded->ts,
	                  bits.ts_nr, bits.ts, bits.ts);

	/* decode RTP SSRC */
	if(bits.rtp_ssrc_nr > 0)
	{
		/* take packet value */
		assert(bits.rtp_ssrc_nr == 32);
		decoded->rtp_ssrc = bits.rtp_ssrc;
	}
	else
	{
		/* keep context value */
		decoded->rtp_ssrc = rtp->ssrc;
	}
	rohc_decomp_debug(context, "decoded SSRC = %u\n", decoded->rtp_ssrc);

	return true;

error:
	return false;
}


/**
 * @brief Build an uncompressed UDP/RTP header.
 *
 * @param context      The decompression context
 * @param decoded      The values decoded from the ROHC header
 * @param dest         The buffer to store the UDP/RTP header (MUST be at least
 *                     of sizeof(struct udphdr) + sizeof(struct rtphdr) length)
 * @param payload_len  The length of the UDP/RTP payload
 * @return             The length of the next header (ie. the UDP/RTP header),
 *                     -1 in case of error
 */
static int rtp_build_uncomp_rtp(const struct d_context *const context,
                                const struct rohc_decoded_values decoded,
                                unsigned char *dest,
                                const unsigned int payload_len)
{
	struct udphdr *udp;
	struct rtphdr *rtp;

	assert(context != NULL);
	assert(dest != NULL);
	udp = (struct udphdr *) dest;
	rtp = (struct rtphdr *) (udp + 1);

	/* UDP static fields */
	udp->source = decoded.udp_src;
	udp->dest = decoded.udp_dst;

	/* UDP changing fields */
	udp->check = decoded.udp_check;

	/* UDP interfered fields */
	udp->len = rohc_hton16(payload_len + sizeof(struct udphdr) +
	                       sizeof(struct rtphdr));
	rohc_decomp_debug(context, "UDP + RTP length = 0x%04x\n",
	                  rohc_ntoh16(udp->len));

	/* RTP fields: version, R-P flag, R-X flag, M flag, R-PT, TS and SN */
	rtp->version = decoded.rtp_version;
	rtp->padding = decoded.rtp_p;
	rtp->extension = decoded.rtp_x;
	rtp->cc = decoded.rtp_cc;
	rtp->m = decoded.rtp_m;
	rtp->pt = decoded.rtp_pt & 0x7f;
	assert(decoded.sn <= 0xffff);
	rtp->sn = rohc_hton16((uint16_t) decoded.sn);
	rtp->timestamp = rohc_hton32(decoded.ts);
	rtp->ssrc = decoded.rtp_ssrc;

	return sizeof(struct udphdr) + sizeof(struct rtphdr);
}


/**
 * @brief Update context with decoded UDP/RTP values
 *
 * The following decoded values are updated in context:
 *  - UDP source port
 *  - UDP destination port
 *  - RTP TimeStamp (TS)
 *  - all other static/dynamic RTP fields
 *
 * @param context  The decompression context
 * @param decoded  The decoded values to update in the context
 */
static void rtp_update_context(const struct d_context *context,
                               const struct rohc_decoded_values decoded)
{
	struct d_generic_context *g_context;
	struct d_rtp_context *rtp_context;
	struct udphdr *udp;
	struct rtphdr *rtp;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	rtp_context = g_context->specific;

	/* update context for UDP fields */
	udp = (struct udphdr *) g_context->outer_ip_changes->next_header;
	udp->source = decoded.udp_src;
	udp->dest = decoded.udp_dst;

	/* update context for RTP fields */
	rtp = (struct rtphdr *) (udp + 1);
	assert(decoded.sn <= 0xffff);
	ts_update_context(rtp_context->ts_scaled_ctxt, decoded.ts, decoded.sn);
	rtp->version = decoded.rtp_version;
	rtp->padding = decoded.rtp_p;
	rtp->extension = decoded.rtp_x;
	rtp->cc = decoded.rtp_cc;
	rtp->m = decoded.rtp_m;
	rtp->pt = decoded.rtp_pt;
	rtp->ssrc = decoded.rtp_ssrc;
}


/*
 * Private helper functions
 */

/**
 * @brief Is the outer IP header IPv4 wrt context?
 *
 * @param ctxt  The generic decompression context
 * @return      true if IPv4, false otherwise
 */
static inline bool is_outer_ipv4_ctxt(const struct d_generic_context *const ctxt)
{
	return (ip_get_version(&ctxt->outer_ip_changes->ip) == IPV4);
}


/**
 * @brief Is the outer IP header IPv4 and its IP-ID random wrt context?
 *
 * @param ctxt  The generic decompression context
 * @return      true if IPv4, false otherwise
 */
static inline bool is_outer_ipv4_rnd_ctxt(const struct d_generic_context *const ctxt)
{
	return (is_outer_ipv4_ctxt(ctxt) && ctxt->outer_ip_changes->rnd == 1);
}


/**
 * @brief Is the inner IP header IPv4 wrt context?
 *
 * @param ctxt  The generic decompression context
 * @return      true if IPv4, false otherwise
 */
static inline bool is_inner_ipv4_ctxt(const struct d_generic_context *const ctxt)
{
	return (ctxt->multiple_ip &&
	        ip_get_version(&ctxt->inner_ip_changes->ip) == IPV4);
}


/**
 * @brief Is the inner IP header IPv4 and its IP-ID random wrt context?
 *
 * @param ctxt  The generic decompression context
 * @return      true if IPv4, false otherwise
 */
static inline bool is_inner_ipv4_rnd_ctxt(const struct d_generic_context *const ctxt)
{
	return (is_inner_ipv4_ctxt(ctxt) && ctxt->inner_ip_changes->rnd == 1);
}


/**
 * @brief Define the decompression part of the RTP profile as described
 *        in the RFC 3095.
 */
struct d_profile d_rtp_profile =
{
	ROHC_PROFILE_RTP,       /* profile ID (see 8 in RFC 3095) */
	"RTP / Decompressor",   /* profile description */
	.detect_packet_type = rtp_detect_packet_type,
	d_generic_decode,
	d_rtp_create,
	d_rtp_destroy,
	d_generic_get_sn,
};

