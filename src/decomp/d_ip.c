/**
 * @file d_ip.c
 * @brief ROHC decompression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "d_ip.h"


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
		goto quit;

	/* some IP-specific values and functions */
	context->decode_dynamic_next_header = ip_decode_dynamic_ip;

	return context;

quit:
	return NULL;
}

/**
 * @brief Get the size of the static part of an IR packet (without IP)
 * @return the size
 */
int ip_get_static_part(void)
{
	return 0;
}

/**
 * @brief Decode the IP dynamic part of the ROHC packet.
 *
 * @param context      The generic decompression context
 * @param packet       The ROHC packet to decode
 * @param length       The length of the ROHC packet
 * @param dest         Not used
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
int ip_decode_dynamic_ip(struct d_generic_context *context,
                         const unsigned char *packet,
                         unsigned int length,
                         unsigned char *dest)
{
	int read = 0; /* number of bytes read from the packet */
	int sn;

	if(context->packet_type == PACKET_IR ||
	   context->packet_type == PACKET_IR_DYN)
	{
		/* check the minimal length to decode the SN field */
		if(length < 2)
		{
			rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
			goto error;
		}

		/* init the SN */
		sn = ntohs(* ((uint16_t *) packet));
		d_lsb_init(&context->sn, sn, 3);
		packet += 2;
		read += 2;

		/* init the outer IP-ID (IPv4 only) */
		if(ip_get_version(context->active1->ip) == IPV4)
			d_ip_id_init(&context->ip_id1, ntohs(ipv4_get_id(context->active1->ip)), sn);

		/* init the inner IP-ID (IPv4 only) */
		if(context->multiple_ip && ip_get_version(context->active2->ip) == IPV4)
			d_ip_id_init(&context->ip_id2, ntohs(ipv4_get_id(context->active2->ip)), sn);
	}

	return read;

error:
	return -1;
}


/**
 * @brief Find the length of the IR header.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * \verbatim

 Basic structure of the IR packet (5.7.7.1):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  |         Add-CID octet         |  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   1   0 | D |
    +---+---+---+---+---+---+---+---+
    |                               |
 3  /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
 4  |            Profile            |  1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              |  1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  |         Static chain          |  variable length
    |                               |
    +---+---+---+---+---+---+---+---+
    |                               |
 7  |         Dynamic chain         |  present if D = 1, variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 8  |             SN                |  2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    |                               |
 9  |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * The function computes the length of the fields 2 + 4-8, ie. the first byte,
 * the Profile and CRC fields, the static and dynamic chains (outer and inner
 * IP headers + UDP header) and the SN.
 *
 * @param context         The decompression context
 * @param packet          The pointer on the IR packet
 * @param plen            The length of the IR packet
 * @param second_byte     The offset for the second byte of the IR packet
 *                        (ie. the field 4 in the figure)
 * @param profile_id      The ID of the decompression profile
 * @return                The length of the IR header,
 *                        0 if an error occurs
 */
unsigned int ip_detect_ir_size(struct d_context *context,
			       unsigned char *packet,
                               unsigned int plen,
                               int second_byte,
                               int profile_id)
{
	unsigned int length;

	/* Profile and CRC fields + IP static & dynamic chains */
	length = d_generic_detect_ir_size(context, packet, plen, second_byte, profile_id);
	if(length == 0)
		goto quit;

	/* Sequence Number (SN) */
	length += 2;

quit:
	return length;
}


/**
 * @brief Find the length of the IR-DYN header.
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * \verbatim

 Basic structure of the IR-DYN packet (5.7.7.2):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         : if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   0   0   0 | IR-DYN packet type
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /     0-2 octets of CID info    / 1-2 octets if for large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
 4  |            Profile            | 1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              | 1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /         Dynamic chain         / variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 7  |             SN                | 2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    :                               :
 8  /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * The function computes the length of the fields 2 + 4-7, ie. the first byte,
 * the Profile and CRC fields, the dynamic chains (outer and inner IP headers +
 * UDP header) and the SN.
 *
 * @param first_byte The first byte of the IR-DYN packet
 * @param plen       The length of the IR-DYN packet
 * @param largecid   Whether large CIDs are used or not
 * @param context    The decompression context
 * @param packet     The ROHC packet
 * @return           The length of the IR-DYN header,
 *                   0 if an error occurs
 */
unsigned int ip_detect_ir_dyn_size(unsigned char *first_byte,
                                   unsigned int plen,
                                   int largecid,
                                   struct d_context *context,
				   unsigned char *packet)
{
	unsigned int length;

	/* Profile and CRC fields + IP dynamic chains */
	length = d_generic_detect_ir_dyn_size(first_byte, plen, largecid, context, packet);
	if(length == 0)
		goto quit;

	/* Sequence Number (SN) */
	length += 2;

quit:
	return length;
}


/**
 * @brief Define the decompression part of the IP-only profile as described
 *        in the RFC 3843.
 */
struct d_profile d_ip_profile =
{
	ROHC_PROFILE_IP,              /* profile ID (see 5 in RFC 3843) */
	"1.0",                        /* profile version */
	"IP / Decompressor",          /* profile description */
	d_generic_decode,             /* profile handlers */
	d_generic_decode_ir,
	d_ip_create,
	d_generic_destroy,
	ip_detect_ir_size,
	ip_detect_ir_dyn_size,
	ip_get_static_part,
	d_generic_get_sn,
};

