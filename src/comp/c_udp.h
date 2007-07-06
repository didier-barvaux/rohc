/**
 * @file c_udp.h
 * @brief ROHC compression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_UDP_H
#define C_UDP_H

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "c_generic.h"


/**
 * @brief Define the UDP-specific temporary variables in the profile compression
 *        context.
 *
 * This object must be used by the UDP-specific decompression context sc_udp_context.
 *
 * @see sc_udp_context
 */
struct udp_tmp_variables
{
	/// The number of UDP fields that changed in the UDP header
	int send_udp_dynamic;
};


/**
 * @brief Define the UDP part of the profile decompression context.
 *
 * This object must be used with the generic part of the decompression
 * context c_generic_context.
 *
 * @see c_generic_context
 */
struct sc_udp_context
{
	/// The number of times the checksum field was added to the compressed header
	int udp_checksum_change_count;

	/// The previous UDP header
	struct udphdr old_udp;

	/// @brief UDP-specific temporary variables that are used during one single
	///        compression of packet
	struct udp_tmp_variables tmp_variables;
};


/*
 * Function prototypes.
 */

int c_udp_create(struct c_context *context, const struct ip_packet ip);

int c_udp_check_context(struct c_context *context, const struct ip_packet ip);

int c_udp_encode(struct c_context *context,
                 const struct ip_packet ip,
                 int packet_size,
                 unsigned char *dest,
                 int dest_size,
                 int *payload_offset);

void udp_decide_state(struct c_context *context);

int udp_code_UO_packet_tail(struct c_context *context,
                            const unsigned char *next_header,
                            unsigned char *dest,
                            int counter);

int udp_code_static_udp_part(struct c_context *context,
                             const unsigned char *next_header,
                             unsigned char *dest,
                             int counter);


#endif

