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
 * @file d_udp.c
 * @brief ROHC decompression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#include "d_udp.h"
#include "rohc_bit_ops.h"
#include "rohc_traces.h"
#include "rohc_debug.h"
#include "crc.h"

#include <netinet/ip.h>
#include <netinet/udp.h>


/*
 * Private function prototypes.
 */

static void d_udp_destroy(void *const context)
	__attribute__((nonnull(1)));

static int udp_parse_dynamic_udp(struct d_generic_context *context,
                                 const unsigned char *packet,
                                 unsigned int length,
                                 struct rohc_extr_bits *const bits);

static int udp_parse_uo_remainder(struct d_generic_context *context,
                                  const unsigned char *packet,
                                  unsigned int length,
                                  struct rohc_extr_bits *const bits);

static bool udp_decode_values_from_bits(const struct d_context *context,
                                        const struct rohc_extr_bits bits,
                                        struct rohc_decoded_values *const decoded);

static int udp_build_uncomp_udp(const struct d_generic_context *const context,
                                const struct rohc_decoded_values decoded,
                                unsigned char *dest,
                                const unsigned int payload_len);


/**
 * @brief Create the UDP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return The newly-created UDP decompression context
 */
void * d_udp_create(void)
{
	struct d_generic_context *context;
	struct d_udp_context *udp_context;

	/* create the generic context */
	context = d_generic_create();
	if(context == NULL)
	{
		goto quit;
	}

	/* create the UDP-specific part of the context */
	udp_context = malloc(sizeof(struct d_udp_context));
	if(udp_context == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the UDP-specific context\n");
		goto destroy_context;
	}
	memset(udp_context, 0, sizeof(struct d_udp_context));
	context->specific = udp_context;

	/* create the LSB decoding context for SN */
	context->sn_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_SN);
	if(context->sn_lsb_ctxt == NULL)
	{
		rohc_debugf(0, "failed to create the LSB decoding context for SN\n");
		goto free_udp_context;
	}

	/* the UDP checksum field present flag will be initialized
	 * with the IR packets */
	udp_context->udp_checksum_present = -1;

	/* some UDP-specific values and functions */
	context->next_header_len = sizeof(struct udphdr);
	context->detect_packet_type = ip_detect_packet_type;
	context->parse_static_next_hdr = udp_parse_static_udp;
	context->parse_dyn_next_hdr = udp_parse_dynamic_udp;
	context->parse_uo_remainder = udp_parse_uo_remainder;
	context->decode_values_from_bits = udp_decode_values_from_bits;
	context->build_next_header = udp_build_uncomp_udp;
	context->compute_crc_static = udp_compute_crc_static;
	context->compute_crc_dynamic = udp_compute_crc_dynamic;
	context->update_context = udp_update_context;

	/* create the UDP-specific part of the header changes */
	context->outer_ip_changes->next_header_len = sizeof(struct udphdr);
	context->outer_ip_changes->next_header = malloc(sizeof(struct udphdr));
	if(context->outer_ip_changes->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the UDP-specific "
		            "part of the outer IP header changes\n");
		goto free_lsb_sn;
	}
	memset(context->outer_ip_changes->next_header, 0, sizeof(struct udphdr));

	context->inner_ip_changes->next_header_len = sizeof(struct udphdr);
	context->inner_ip_changes->next_header = malloc(sizeof(struct udphdr));
	if(context->inner_ip_changes->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the UDP-specific "
		            "part of the inner IP header changes\n");
		goto free_outer_ip_changes_next_header;
	}
	memset(context->inner_ip_changes->next_header, 0, sizeof(struct udphdr));

	/* set next header to UDP */
	context->next_header_proto = IPPROTO_UDP;

	return context;

free_outer_ip_changes_next_header:
	zfree(context->outer_ip_changes->next_header);
free_lsb_sn:
	rohc_lsb_free(context->sn_lsb_ctxt);
free_udp_context:
	zfree(udp_context);
destroy_context:
	d_generic_destroy(context);
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
static void d_udp_destroy(void *const context)
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
 * @brief Parse the UDP static part of the ROHC packet.
 *
 * @param context The generic decompression context
 * @param packet  The ROHC packet to parse
 * @param length  The length of the ROHC packet
 * @param bits    OUT: The bits extracted from the ROHC header
 * @return        The number of bytes read in the ROHC packet,
 *                -1 in case of failure
 */
int udp_parse_static_udp(struct d_generic_context *context,
                         const unsigned char *packet,
                         unsigned int length,
                         struct rohc_extr_bits *const bits)
{
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the UDP static part */
	if(length < 4)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	bits->udp_src = GET_NEXT_16_BITS(packet);
	bits->udp_src_nr = 16;
	rohc_debugf(3, "UDP source port = 0x%04x\n", ntohs(bits->udp_src));
	packet += 2;
	read += 2;

	bits->udp_dst = GET_NEXT_16_BITS(packet);
	bits->udp_dst_nr = 16;
	rohc_debugf(3, "UDP destination port = 0x%04x\n", ntohs(bits->udp_dst));
	packet += 2;
	read += 2;

	return read;

error:
	return -1;
}


/**
 * @brief Parse the UDP dynamic part of the ROHC packet.
 *
 * @param context      The generic decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int udp_parse_dynamic_udp(struct d_generic_context *context,
                                 const unsigned char *packet,
                                 unsigned int length,
                                 struct rohc_extr_bits *const bits)
{
	struct d_udp_context *udp_context;
	int read = 0; /* number of bytes read from the packet */
	int ret;

	assert(context != NULL);
	assert(context->specific != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	udp_context = context->specific;

	/* UDP checksum */
	if(length < 2)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}
	bits->udp_check = GET_NEXT_16_BITS(packet);
	bits->udp_check_nr = 16;
	rohc_debugf(3, "UDP checksum = 0x%04x\n", ntohs(bits->udp_check));
	packet += 2;
	read += 2;

	/* determine whether the UDP checksum will be present in UO packets */
	udp_context->udp_checksum_present = (bits->udp_check > 0);

	/* SN field */
	ret = ip_parse_dynamic_ip(context, packet, length - read, bits);
	if(ret == -1)
	{
		goto error;
	}
	packet += ret;
	read += ret;

	return read;

error:
	return -1;
}


/**
 * @brief Parse the UDP tail of the UO* ROHC packets.
 *
 * @param context      The generic decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param dest         The decoded UDP header
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int udp_parse_uo_remainder(struct d_generic_context *context,
                                  const unsigned char *packet,
                                  unsigned int length,
                                  struct rohc_extr_bits *const bits)
{
	struct d_udp_context *udp_context;
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(context->specific != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	udp_context = context->specific;

	/* UDP checksum if necessary:
	 *  udp_checksum_present < 0 <=> not initialized
	 *  udp_checksum_present = 0 <=> UDP checksum field not present
	 *  udp_checksum_present > 0 <=> UDP checksum field present */
	if(udp_context->udp_checksum_present > 0)
	{
		/* check the minimal length to decode the UDP checksum */
		if(length < 2)
		{
			rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
			goto error;
		}

		/* retrieve the UDP checksum from the ROHC packet */
		bits->udp_check = GET_NEXT_16_BITS(packet);
		bits->udp_check_nr = 16;
		rohc_debugf(3, "UDP checksum = 0x%04x\n", ntohs(bits->udp_check));
		packet += 2;
		read += 2;
	}
	else if(udp_context->udp_checksum_present < 0)
	{
		rohc_debugf(0, "udp_checksum_present not initialized and "
		            "packet is not one IR packet\n");
		goto error;
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
static bool udp_decode_values_from_bits(const struct d_context *context,
                                        const struct rohc_extr_bits bits,
                                        struct rohc_decoded_values *const decoded)
{
	struct d_generic_context *g_context;
	struct d_udp_context *udp_context;
	struct udphdr *udp;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(g_context->specific != NULL);
	udp_context = g_context->specific;
	assert(decoded != NULL);

	udp = (struct udphdr *) g_context->outer_ip_changes->next_header;

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
	rohc_debugf(3, "decoded UDP source port = 0x%04x\n",
	            ntohs(decoded->udp_src));

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
	rohc_debugf(3, "decoded UDP destination port = 0x%04x\n",
	            ntohs(decoded->udp_dst));

	/* UDP checksum:
	 *  - error if udp_checksum_present not initialized,
	 *    ie. udp_checksum_present < 0
	 *  - copy from packet if checksum is present,
	 *    ie. udp_checksum_present > 0
	 *  - set checksum to zero if checksum is not present,
	 *    ie. udp_checksum_present = 0  */
	if(udp_context->udp_checksum_present < 0)
	{
		rohc_debugf(0, "udp_checksum_present not initialized\n");
		goto error;
	}
	else if(udp_context->udp_checksum_present > 0)
	{
		assert(bits.udp_check_nr == 16);
		decoded->udp_check = bits.udp_check;
	}
	else if(g_context->packet_type == PACKET_IR ||
	        g_context->packet_type == PACKET_IR_DYN)
	{
		assert(bits.udp_check_nr == 16);
		assert(bits.udp_check == 0);
		decoded->udp_check = 0;
	}
	else
	{
		assert(bits.udp_check_nr == 0);
		decoded->udp_check = 0;
	}
	rohc_debugf(3, "decoded UDP checksum = 0x%04x (checksum present = %d)\n",
	            ntohs(decoded->udp_check), udp_context->udp_checksum_present);

	return true;

error:
	return false;
}


/**
 * @brief Build an uncompressed UDP header.
 *
 * @param context      The generic decompression context
 * @param decoded      The values decoded from the ROHC header
 * @param dest         The buffer to store the UDP header (MUST be at least
 *                     of sizeof(struct udphdr) length)
 * @param payload_len  The length of the UDP payload
 * @return             The length of the next header (ie. the UDP header),
 *                     -1 in case of error
 */
static int udp_build_uncomp_udp(const struct d_generic_context *const context,
                                const struct rohc_decoded_values decoded,
                                unsigned char *dest,
                                const unsigned int payload_len)
{
	struct udphdr *udp = (struct udphdr *) dest;

	/* static fields */
	udp->source = decoded.udp_src;
	udp->dest = decoded.udp_dst;

	/* changing fields */
	udp->check = decoded.udp_check;

	/* interfered fields */
	udp->len = htons(payload_len + sizeof(struct udphdr));
	rohc_debugf(3, "UDP length = 0x%04x\n", ntohs(udp->len));

	return sizeof(struct udphdr);
}


/**
 * @brief Update context with decoded UDP values
 *
 * The following decoded values are updated in context:
 *  - UDP source port
 *  - UDP destination port
 *
 * @param context  The decompression context
 * @param decoded  The decoded values to update in the context
 */
void udp_update_context(const struct d_context *context,
                        const struct rohc_decoded_values decoded)
{
	struct d_generic_context *g_context;
	struct udphdr *udp;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;

	udp = (struct udphdr *) g_context->outer_ip_changes->next_header;
	udp->source = decoded.udp_src;
	udp->dest = decoded.udp_dst;
}


/**
 * @brief Define the decompression part of the UDP profile as described
 *        in the RFC 3095.
 */
struct d_profile d_udp_profile =
{
	ROHC_PROFILE_UDP,       /* profile ID (see 8 in RFC 3095) */
	"UDP / Decompressor",   /* profile description */
	d_generic_decode,       /* profile handlers */
	d_udp_create,
	d_udp_destroy,
	d_generic_get_sn,
};

