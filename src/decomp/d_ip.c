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
 * @file d_ip.c
 * @brief ROHC decompression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "d_ip.h"
#include "rohc_traces.h"
#include "rohc_bit_ops.h"
#include "rohc_packets.h"
#include "rohc_debug.h" /* for zfree() */
#include "decode.h"

#include "config.h" /* for HAVE_*_H definitions */

#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif


/*
 * Private function prototypes.
 */

static void d_ip_destroy(void *const context)
	__attribute__((nonnull(1)));


/**
 * @brief Create the IP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return A fake IP decompression context
 */
void * d_ip_create(void)
{
	struct d_generic_context *context;

	/* create the generic context */
	context = d_generic_create();
	if(context == NULL)
	{
		goto quit;
	}

	/* create the LSB decoding context for SN */
	context->sn_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_SN);
	if(context->sn_lsb_ctxt == NULL)
	{
		rohc_debugf(0, "failed to create the LSB decoding context for SN\n");
		goto free_context;
	}

	/* some IP-specific values and functions */
	context->detect_packet_type = ip_detect_packet_type;
	context->parse_dyn_next_hdr = ip_parse_dynamic_ip;

	return context;

free_context:
	zfree(context);
quit:
	return NULL;
}


/**
 * @brief Destroy the given IP-only context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
void d_ip_destroy(void *const context)
{
	struct d_generic_context *g_context;

	assert(context != NULL);
	g_context = (struct d_generic_context *) context;

	rohc_lsb_free(g_context->sn_lsb_ctxt);
	d_generic_destroy(context);
}


/**
 * @brief Detect the type of ROHC packet for IP-based non-RTP profiles
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param packet         The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
rohc_packet_t ip_detect_packet_type(struct rohc_decomp *decomp,
                                    struct d_context *context,
                                    const unsigned char *packet,
                                    const size_t rohc_length,
                                    const size_t large_cid_len)
{
	rohc_packet_t type;

	if(rohc_length < 1)
	{
		rohc_debugf(0, "ROHC packet too small to read the first byte that "
		            "contains the packet type (len = %zd)\n", rohc_length);
		goto error;
	}

	if(d_is_uo0(packet, rohc_length))
	{
		/* UO-0 packet */
		type = PACKET_UO_0;
	}
	else if(d_is_uo1(packet, rohc_length))
	{
		/* UO-1 packet */
		type = PACKET_UO_1;
	}
	else if(d_is_uor2(packet, rohc_length))
	{
		/* UOR-2 packet */
		type = PACKET_UOR_2;
	}
	else if(d_is_irdyn(packet, rohc_length))
	{
		/* IR-DYN packet */
		type = PACKET_IR_DYN;
	}
	else if(d_is_ir(packet, rohc_length))
	{
		/* IR packet */
		type = PACKET_IR;
	}
	else
	{
		/* unknown packet */
		rohc_debugf(0, "failed to recognize the packet type in byte 0x%02x\n",
		            *packet);
		type = PACKET_UNKNOWN;
	}

	return type;

error:
	return PACKET_UNKNOWN;
}


/**
 * @brief Parse the IP dynamic part of the ROHC packet.
 *
 * @param context      The generic decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
int ip_parse_dynamic_ip(struct d_generic_context *context,
                        const unsigned char *packet,
                        unsigned int length,
                        struct rohc_extr_bits *const bits)
{
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	if(context->packet_type == PACKET_IR ||
	   context->packet_type == PACKET_IR_DYN)
	{
		/* check the minimal length to decode the SN field */
		if(length < 2)
		{
			rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
			goto error;
		}

		/* parse 16-bit SN */
		bits->sn = ntohs(GET_NEXT_16_BITS(packet));
		bits->sn_nr = 16;
		rohc_debugf(2, "SN = %u (0x%04x)\n", bits->sn, bits->sn);
		packet += 2;
		read += 2;
	}

	return read;

error:
	return -1;
}


/**
 * @brief Define the decompression part of the IP-only profile as described
 *        in the RFC 3843.
 */
struct d_profile d_ip_profile =
{
	ROHC_PROFILE_IP,              /* profile ID (see 5 in RFC 3843) */
	"IP / Decompressor",          /* profile description */
	d_generic_decode,             /* profile handlers */
	d_ip_create,
	d_ip_destroy,
	d_generic_get_sn,
};

