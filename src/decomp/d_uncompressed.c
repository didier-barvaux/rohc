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
 * @file d_uncompressed.c
 * @brief ROHC decompression context for the uncompressed profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "d_uncompressed.h"
#include "rohc_traces.h"


/**
 * @brief Allocate profile-specific data, nothing to allocate for the
 *        uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return The newly-created generic decompression context
 */
void * uncompressed_allocate_decode_data(void)
{
	return (void *) 1;
}


/**
 * @brief Destroy profile-specific data, nothing to destroy for the
 *        uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
void uncompressed_free_decode_data(void *context)
{
}


/**
 * @brief Decode one IR packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param rohc_packet     The ROHC packet to decode
 * @param rohc_length     The length of the ROHC packet to decode
 * @param large_cid_len   The length of the large CID field
 * @param is_addcid_used  Whether the add-CID field is present or not
 * @param dest            The decoded IP packet
 * @return                The length of the uncompressed IP packet
 *                        or ROHC_OK_NO_DATA if no data is returned
 *                        or ROHC_ERROR if an error occurs
 */
int uncompressed_decode_ir(struct rohc_decomp *decomp,
                           struct d_context *context,
                           const unsigned char *const rohc_packet,
                           const unsigned int rohc_length,
                           int large_cid_len,
                           int is_addcid_used,
                           unsigned char *dest)
{
	/* remaining ROHC data not parsed yet */
	const unsigned char *rohc_remain_data = rohc_packet;
	unsigned int rohc_remain_len = rohc_length;

	/* ROHC and uncompressed payloads (they are the same) */
	const unsigned char *payload_data;
	unsigned int payload_len;

	/* change state to Full Context */
	context->state = FULL_CONTEXT;

	/* skip the first bytes:
	 * 	IR type + Profile ID + CRC (+ eventually CID bytes) */
	rohc_remain_data += 3 + large_cid_len;
	rohc_remain_len -= 3 + large_cid_len;

	/* ROHC header is now fully decoded */
	payload_data = rohc_remain_data;
	payload_len = rohc_remain_len;

	/* check IR packet size */
	if(payload_len == 0)
		return ROHC_OK_NO_DATA;

	/* copy IR packet to uncompressed packet */
	memcpy(dest, payload_data, payload_len);

	return payload_len;
}


/**
 * @brief Find the length of data in an IR packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context         The decompression context
 * @param packet          The IR packet after the Add-CID byte if present
 * @param plen            The length of the IR-DYN packet minus the Add-CID byte
 * @param large_cid_len   The size of the large CID field
 * @return                The length of data in the IR packet,
 *                        0 if an error occurs
 */
unsigned int uncompressed_detect_ir_size(struct d_context *context,
                                         unsigned char *packet,
                                         unsigned int plen,
                                         unsigned int large_cid_len)
{
	/* check if ROHC packet is large enough to contain
	   the first byte + Profile ID + CRC in addition to the large CID */
	if(plen < (1 + large_cid_len + 1 + 1))
		return 0;

	/* first byte + Profile ID + CRC */
	return 3;
}


/**
 * @brief Find the length of data in an IR-DYN packet.
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context         The decompression context
 * @param packet          The IR-DYN packet after the Add-CID byte if present
 * @param plen            The length of the IR-DYN packet minus the Add-CID byte
 * @param large_cid_len   The size of the large CID field
 * @return                The length of data in the IR-DYN packet,
 *                        0 if an error occurs
 */
unsigned int uncompressed_detect_ir_dyn_size(struct d_context *context,
                                              unsigned char *packet,
                                              unsigned int plen,
                                              unsigned int large_cid_len)
{
	rohc_debugf(0, "IR-DYN packet is not defined in uncompressed profile\n");
	return 0;
}


/**
 * @brief Decode one IR-DYN, UO-0, UO-1 or UOR-2 packet, but not IR packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp      The ROHC decompressor
 * @param context     The decompression context
 * @param rohc_packet The ROHC packet to decode
 * @param rohc_length The length of the ROHC packet
 * @param second_byte The offset for the second byte of the ROHC packet
 *                    (depends on the CID encoding and the packet type)
 * @param dest        The decoded IP packet
 * @return            The length of the uncompressed IP packet
 *                    or ROHC_ERROR if an error occurs
 */
int uncompressed_decode(struct rohc_decomp *decomp,
                        struct d_context *context,
                        const unsigned char *const rohc_packet,
                        const unsigned int rohc_length,
                        int second_byte,
                        unsigned char *dest)
{
	/* remaining ROHC data not parsed yet */
	const unsigned char *rohc_remain_data = rohc_packet;
	unsigned int rohc_remain_len = rohc_length;

	/* state must not be No Context */
	if(context->state == NO_CONTEXT)
	{
		rohc_debugf(0, "cannot receive Normal packets in No Context state\n");
		goto error;
	}

	/* check if the ROHC packet is large enough to read the second byte */
	if(second_byte >= rohc_length)
	{
		rohc_debugf(0, "ROHC packet too small (len = %u)\n", rohc_length);
		goto error;
	}

	/* copy the first byte of the ROHC packet to the decompressed packet */
	*dest = GET_BIT_0_7(rohc_packet);
	dest += 1;
	rohc_remain_data += second_byte;
	rohc_remain_len -= second_byte;

	/* copy the second byte and the following bytes of the ROHC packet
	 * to the decompressed packet */
	memcpy(dest, rohc_remain_data, rohc_remain_len);

	return (1 + rohc_remain_len);

error:
	return ROHC_ERROR;
}


/**
 * @brief Get the reference SN value of the context. Always return 0 for the
 *        uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference SN value
 */
int uncompressed_get_sn(struct d_context *context)
{
	return 0;
}


/**
 * @brief Define the decompression part of the Uncompressed profile as
 *        described in the RFC 3095.
 */
struct d_profile d_uncomp_profile =
{
	ROHC_PROFILE_UNCOMPRESSED,     /* profile ID (see 8 in RFC 3095) */
	"Uncompressed / Decompressor", /* profile description */
	uncompressed_decode,           /* profile handlers */
	uncompressed_decode_ir,
	uncompressed_allocate_decode_data,
	uncompressed_free_decode_data,
	uncompressed_detect_ir_size,
	uncompressed_detect_ir_dyn_size,
	NULL,
	uncompressed_get_sn,
};

