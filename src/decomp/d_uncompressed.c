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
 * @param dynamic_present Whether the IR packet contains a dynamic part or not
 * @param dest            The decoded IP packet
 * @return                The length of the uncompressed IP packet
 *                        or ROHC_OK_NO_DATA if no data is returned
 *                        or ROHC_ERROR if an error occurs
 */
int uncompressed_decode_ir(struct rohc_decomp *decomp, struct d_context *context,
                           unsigned char *packet, int payload_size,
                           int dynamic_present, unsigned char *dest)
{
	/* change state to Full Context */
	context->state = FULL_CONTEXT;

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
 * @param packet          The pointer on the IR packet
 * @param second_byte     The offset for the second byte of the IR packet
 * @return                The length of data in the IR packet,
 *                        0 if an error occurs
 */
int uncompressed_detect_ir_size(unsigned char *packet, int second_byte)
{
	int ret = 10;
	int d = GET_BIT_0(packet);

	if(d)
		ret += 5 + 2;

	if(packet[second_byte + 2] != 0x40)
		return 0;

	return ret;
}


/**
 * @brief Find the length of data in an IR-DYN packet.
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param first_byte The first byte of the IR-DYN packet
 * @param context    The decompression context
 * @return           The length of data in the IR-DYN packet,
 *                   0 if an error occurs
 */
int uncompressed_detect_ir_dyn_size(unsigned char *first_byte,
                                    struct d_context *context)
{
	return 7;
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
		return ROHC_ERROR;

	/* copy the first byte of the ROHC packet to the decompressed packet */
	*dest = GET_BIT_0_7(packet);
	dest += 1;
	packet += second_byte;

	/* copy the second byte and the following bytes of the ROHC packet
	 * to the decompressed packet */
	memcpy(dest, packet, size - second_byte);

	return size - second_byte + 1;
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
	uncompressed_get_sn,
};

