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
#include "rohc_bit_ops.h"
#include "rohc_traces.h"
#include "rohc_packets.h"
#include "rohc_debug.h" /* for zfree() */


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

		/* parse SN */
		bits->sn = ntohs(GET_NEXT_16_BITS(packet));
		bits->sn_nr = 16;
		rohc_debugf(2, "SN = %d (0x%04x)\n", bits->sn, bits->sn);
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

