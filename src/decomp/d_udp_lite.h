/**
 * @file d_udp_lite.h
 * @brief ROHC decompression context for the UDP-Lite profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef D_UDP_LITE_H
#define D_UDP_LITE_H

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "d_generic.h"
#include "d_udp.h"
#include "udp_lite.h"


/**
 * @brief Define the UDP-Lite part of the decompression profile context.
 *
 * This object must be used with the generic part of the decompression
 * context d_generic_context.
 *
 * @see d_generic_context
 */
struct d_udp_lite_context
{
	/**
	 * @brief Whether the UDP-Lite checksum coverage field is present or not
	 *
	 * Possible values are:
	 *   -1 if not initialized
	 *    0 if not present
	 *    1 if present
	 */
	int cfp;

	/**
	 * @brief Whether the UDP-Lite checksum coverage field can be inferred
	 *        or not
	 *
	 * Possible values are:
	 *   -1 if not initialized
	 *    0 if not present
	 *    1 if present
	 */
	int cfi;

	/**
	 * @brief Checksum Coverage Extension
	 *
	 * Possible values are:
	 *  - 0 if not present
	 *  - PACKET_CCE if present and ON
	 *  - PACKET_CCE_OFF if present and OFF
	 */
	int cce_packet;
};


/*
 * Public function prototypes.
 */

int udp_lite_decode_dynamic_udp(struct d_generic_context *context,
                                const unsigned char *packet,
                                unsigned int length,
                                unsigned char *dest);

int udp_lite_build_uncompressed_udp(struct d_generic_context *context,
                                    struct d_generic_changes *active,
                                    unsigned char *dest,
                                    int payload_size);


#endif

