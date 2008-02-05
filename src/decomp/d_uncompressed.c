/**
 * @file d_uncompressed.c
 * @brief ROHC decompression context for the uncompressed profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "d_uncompressed.h"


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
 * @param packet          The ROHC packet to decode
 * @param payload_size    The length of the ROHC packet to decode
 * @param large_cid_len   The length of the large CID field
 * @param is_addcid_used  Whether the add-CID field is present or not
 * @param dest            The decoded IP packet
 * @return                The length of the uncompressed IP packet
 *                        or ROHC_OK_NO_DATA if no data is returned
 *                        or ROHC_ERROR if an error occurs
 */
int uncompressed_decode_ir(struct rohc_decomp *decomp,
                           struct d_context *context,
                           unsigned char *packet,
                           int payload_size,
                           int large_cid_len,
                           int is_addcid_used,
                           unsigned char *dest)
{
	/* change state to Full Context */
	context->state = FULL_CONTEXT;

	/* skip the first bytes:
	 * 	IR type + Profile ID + CRC (+ eventually CID bytes) */
	packet += 3 + large_cid_len;
	payload_size -= 3 + large_cid_len;

	/* check IR packet size */
	if(payload_size == 0)
		return ROHC_OK_NO_DATA;

	/* copy IR packet to uncompressed packet */
	memcpy(dest, packet, payload_size);

	return payload_size;
}


/**
 * @brief Find the length of data in an IR packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context         The decompression context
 * @param packet          The pointer on the IR packet
 * @param plen            The length of the IR packet
 * @param second_byte     The offset for the second byte of the IR packet
 * @param profile_id      The ID of the decompression profile
 * @return                The length of data in the IR packet,
 *                        0 if an error occurs
 */
unsigned int uncompressed_detect_ir_size(struct d_context *context,
					 unsigned char *packet,
                                         unsigned int plen,
                                         int second_byte,
                                         int profile_id)
{
	/* check if ROHC  packet is large enough */
	if(second_byte + 2 >= plen)
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
 * @param first_byte The first byte of the IR-DYN packet
 * @param plen       The length of the IR-DYN packet
 * @param largecid   Whether large CIDs are used or not
 * @param context    The decompression context
 * @param packet     The ROHC packet
 * @return           The length of data in the IR-DYN packet,
 *                   0 if an error occurs
 */
unsigned int uncompressed_detect_ir_dyn_size(unsigned char *first_byte,
                                             unsigned int plen,
                                             int largecid,
                                             struct d_context *context,
					     unsigned char *packet)
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
 * @param packet      The ROHC packet to decode
 * @param size        The length of the ROHC packet
 * @param second_byte The offset for the second byte of the ROHC packet (depends
 *                    on the CID encoding)
 * @param dest        The decoded IP packet
 * @return            The length of the uncompressed IP packet
 *                    or ROHC_ERROR if an error occurs
 */
int uncompressed_decode(struct rohc_decomp *decomp,
                        struct d_context *context,
                        unsigned char *packet,
                        int size,
                        int second_byte,
                        unsigned char *dest)
{
	/* state must not be No Context */
	if(context->state == NO_CONTEXT)
	{
		rohc_debugf(0, "cannot receive Normal packets in No Context state\n");
		goto error;
	}

	/* check if the ROHC packet is large enough to read the second byte */
	if(second_byte >= size)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", size);
		goto error;
	}

	/* copy the first byte of the ROHC packet to the decompressed packet */
	*dest = GET_BIT_0_7(packet);
	dest += 1;
	packet += second_byte;

	/* copy the second byte and the following bytes of the ROHC packet
	 * to the decompressed packet */
	memcpy(dest, packet, size - second_byte);

	return size - second_byte + 1;

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
	"1.0",                         /* profile version */
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

