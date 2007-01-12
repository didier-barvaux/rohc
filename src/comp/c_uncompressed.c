/**
 * @file c_uncompressed.c
 * @brief ROHC compression context for the uncompressed profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "c_uncompressed.h"


/**
 * @brief Create a new Uncompressed context and initialize it thanks
 *        to the given IP packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP packet given to initialize the new context
 * @return        1 if successful, 0 otherwise
 */
int c_uncompressed_create(struct c_context *context, const struct iphdr *ip)
{
	struct sc_uncompressed_context *uncomp_context;
	int success = 0;

	uncomp_context = malloc(sizeof(struct sc_uncompressed_context));
	if(uncomp_context == NULL)
	{
	  rohc_debugf(0, "no memory for the uncompressed context\n");
	  goto quit;
	}
	context->specific = uncomp_context;

	uncomp_context->ir_count = 0;
	uncomp_context->normal_count = 0;
	uncomp_context->go_back_ir_count = 0;

	success = 1;

quit:
	return success;
}


/**
 * @brief Destroy the Uncompressed context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
void c_uncompressed_destroy(struct c_context *context)
{
	if(context->specific != NULL)
		zfree(context->specific);
}


/**
 * @brief Check if an IP packet belongs to the Uncompressed context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP packet to check
 * @return        Always return 1 to tell that the IP packet belongs
 *                to the context
 */
int c_uncompressed_check_context(struct c_context *context,
                                 const struct iphdr *ip)
{
	return 1;
}

/**
 * @brief Encode an IP packet according to a pattern decided by several
 *        different factors.
 *
 * 1. Decide state\n
 * 2. Code packet\n
 * \n
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context        The compression context
 * @param ip             The IP packet to encode
 * @param packet_size    The length of the IP packet to encode
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 */
int c_uncompressed_encode(struct c_context *context,
                          const struct iphdr *ip,
                          int packet_size,
                          unsigned char *dest,
                          int dest_size,
                          int *payload_offset)
{
	int size;

	/* STEP 1: decide state */
	uncompressed_decide_state(context);

	/* STEP 2: Code packet */
	size = uncompressed_code_packet(context, ip, dest,
	                                payload_offset, dest_size);

	return size;
}


/**
 * @brief Update the profile when feedback arrives.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param feedback The feedback information including the whole feedback packet
 */
void c_uncompressed_feedback(struct c_context *context,
                             struct c_feedback *feedback)
{
	unsigned char *p = feedback->data + feedback->specific_offset;

	if(feedback->type == 1) /* ACK */
	{
	}
	else if(feedback->type == 2) /* FEEDBACK-2 */
	{
		unsigned int crc = 0, crc_used=0;
		int sn_not_valid = 0;
		unsigned char mode = (p[0] >> 4) & 3;
		unsigned int sn = ((p[0] & 15) << 8) + p[1];
		int remaining = feedback->specific_size - 2;
		p += 2;

		/* parse options */
		while(remaining > 0)
		{
			int opt = p[0] >> 4;
			int optlen = p[0] & 0x0f;

			switch(opt)
			{
				case 1: /* CRC */
					crc = p[1];
					crc_used = 1;
					p[1] = 0; /* set to zero for crc computation */
					break;
//				case 2: /* Reject */
//					break;
				case 3: /* SN-Not-Valid */
					sn_not_valid = 1;
					break;
				case 4: /* SN */
					// TODO: how are several SN options combined?
					sn = (sn << 8) + p[1];
					break;
//				case 7: /* Loss */
//					break;
				default:
					rohc_debugf(0, "unknown feedback type: %d\n", opt);
					break;
			}

			remaining -= 1 + optlen;
			p += 1 + optlen;
		}

		/* check CRC if used */
		if(crc_used)
		{
			if(crc_calculate(CRC_TYPE_8, feedback->data, feedback->size ) != crc)
			{
				rohc_debugf(0, "CRC check failed (size = %d)\n", feedback->size);
				return;
			}
		}

		if(mode != 0)
		{
			if(crc_used)
				uncompressed_change_mode(context, mode);
			else
				rohc_debugf(0, "mode change requested but no CRC was given\n");
		}

		switch(feedback->acktype)
		{
			case ACK:
				break;
			case NACK:
				break;
			case STATIC_NACK:
				uncompressed_change_state(context, IR);
				break;
			case RESERVED:
				rohc_debugf(0, "reserved field used\n");
				break;
		}

	}
	else
	{
		rohc_debugf(0, "feedback type not implemented (%d)\n", feedback->type);
	}
}


/**
 * @brief Decide the state that should be used for the next packet.
 *
 * @param context The compression context
 */
void uncompressed_decide_state(struct c_context *context)
{
	struct sc_uncompressed_context *uncomp_context =
		(struct sc_uncompressed_context *) context->specific;

	if(context->state == IR && uncomp_context->ir_count >= MAX_IR_COUNT)
		uncompressed_change_state(context, FO);
	
	if(context->mode == U_MODE)
		uncompressed_periodic_down_transition(context);
}


/**
 * @brief Periodically change the context state after a certain number
 *        of packets.
 *
 * @param context The compression context
 */
void uncompressed_periodic_down_transition(struct c_context *context)
{
	struct sc_uncompressed_context *uncomp_context =
		(struct sc_uncompressed_context *) context->specific;

	if(uncomp_context->go_back_ir_count == CHANGE_TO_IR_COUNT)
	{
		uncomp_context->go_back_ir_count = 0;
		uncompressed_change_state(context, IR);
	}

	if(context->state == FO)
		uncomp_context->go_back_ir_count++;
}


/**
 * @brief Change the mode of the context.
 *
 * @param context  The compression context
 * @param new_mode The new mode the context must enter in
 */
void uncompressed_change_mode(struct c_context *context, rohc_mode new_mode)
{
	if(context->mode != new_mode)
	{
		context->mode = new_mode;
		uncompressed_change_state(context, IR);
	}
}


/**
 * @brief Change the state of the context.
 *
 * @param context   The compression context
 * @param new_state The new state the context must enter in
 */
void uncompressed_change_state(struct c_context *context,
                               rohc_c_state new_state)
{
	struct sc_uncompressed_context *uncomp_context =
		(struct sc_uncompressed_context *) context->specific;

	/* reset counters only if different state */
	if(context->state != new_state)
	{
		/* reset counters */
		uncomp_context->ir_count = 0;
		uncomp_context->normal_count = 0;
	
		/* change state */
		context->state = new_state;
	}
}


/**
 * @brief Build the ROHC packet to send.
 *
 * @param context        The compression context
 * @param ip             The IP header
 * @param dest           The rohc-packet-under-build buffer
 * @param payload_offset OUT: the offset of the payload in the buffer
 * @param dest_size      The maximal size of the ROHC packet
 * @return               The position in the rohc-packet-under-build buffer
 *                       if successful, -1 otherwise
 */
int uncompressed_code_packet(struct c_context *context,
                             const struct iphdr *ip,
                             unsigned char *dest,
                             int *payload_offset,
                             int dest_size)
{
	int (*code_packet)(struct c_context *context, const struct iphdr *ip,
	                   unsigned char *dest, int *payload_offset, int dest_size);
	struct sc_uncompressed_context *uncomp_context =
		(struct sc_uncompressed_context *) context->specific;
	int size = -1;

	switch(context->state)
	{
		case IR:
			rohc_debugf(1, "build IR packet\n");
			uncomp_context->ir_count++;
			code_packet = uncompressed_code_IR_packet;
			break;

		case FO:
			rohc_debugf(1, "build normal packet\n");
			uncomp_context->normal_count++;
			code_packet = uncompressed_code_normal_packet;
			break;

		default:
			rohc_debugf(0, "unknown state, cannot build packet\n");
			code_packet = NULL;
	}

	if(code_packet != NULL)
		size = code_packet(context, ip, dest, payload_offset, dest_size);

	return size;
}


/**
 * @brief Build the IR packet.
 *
 * \verbatim

 IR packet (5.10.1)

     0   1   2   3   4   5   6   7
    --- --- --- --- --- --- --- ---
 1 :         Add-CID octet         : if for small CIDs and (CID != 0)
   +---+---+---+---+---+---+---+---+
 2 | 1   1   1   1   1   1   0 |res|
   +---+---+---+---+---+---+---+---+
   :                               :
 3 /    0-2 octets of CID info     / 1-2 octets if for large CIDs
   :                               :
   +---+---+---+---+---+---+---+---+
 4 |          Profile = 0          | 1 octet
   +---+---+---+---+---+---+---+---+
 5 |              CRC              | 1 octet
   +---+---+---+---+---+---+---+---+
   :                               : (optional)
 6 /           IP packet           / variable length
   :                               :
    --- --- --- --- --- --- --- ---

\endverbatim
 *
 * Part 6 is not managed by this function.
 *
 * @param context        The compression context
 * @param ip             The IP header
 * @param dest           The rohc-packet-under-build buffer
 * @param payload_offset OUT: the offset of the payload in the buffer
 * @param dest_size      The maximal size of the ROHC packet
 * @return               The position in the rohc-packet-under-build buffer
 *                       if successful, -1 otherwise
 */
int uncompressed_code_IR_packet(struct c_context *context,
                                const struct iphdr *ip,
                                unsigned char *dest,
                                int *payload_offset,
                                int dest_size)
{
	int counter = 0;
	int first_position;

	rohc_debugf(2, "code IR packet (CID = %d)\n", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context, dest, dest_size, &first_position);

	/* part 2 */
	dest[first_position] = 0xfc;

	/* part 4 */
	dest[counter] = ROHC_PROFILE_UNCOMPRESSED;
	counter++;

	/* part 5 */
	dest[counter]= crc_calculate(CRC_TYPE_8, dest, counter);
	counter++;

	*payload_offset = 0;

	return counter;
}


/**
 * @brief Build the Normal packet.
 *
 * \verbatim

 Normal packet (5.10.2)

     0   1   2   3   4   5   6   7
    --- --- --- --- --- --- --- ---
 1 :         Add-CID octet         : if for small CIDs and (CID != 0)
   +---+---+---+---+---+---+---+---+
 2 |   first octet of IP packet    |
   +---+---+---+---+---+---+---+---+
   :                               :
 3 /    0-2 octets of CID info     / 1-2 octets if for large CIDs
   :                               :
   +---+---+---+---+---+---+---+---+
   |                               |
 4 /      rest of IP packet        / variable length
   |                               |
   +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Part 4 is not managed by this function.
 *
 * @param context        The compression context
 * @param ip             The IP header
 * @param dest           The rohc-packet-under-build buffer
 * @param payload_offset OUT: the offset of the payload in the buffer
 * @param dest_size      The maximal size of the ROHC packet
 * @return               The position in the rohc-packet-under-build buffer
 *                       if successful, -1 otherwise
 */
int uncompressed_code_normal_packet(struct c_context *context,
                                    const struct iphdr *ip,
                                    unsigned char *dest,
                                    int *payload_offset,
                                    int dest_size)
{
	int counter = 0;
	int first_position;

	rohc_debugf(2, "code normal packet (CID = %d)\n", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context, dest, dest_size, &first_position);

	/* part 2 */
	dest[first_position] = ((unsigned char *) ip)[0];

	*payload_offset = 1;
	return counter;
}


/**
 * @brief Define the compression part of the Uncompressed profile as described
 *        in the RFC 3095.
 */
struct c_profile c_uncompressed_profile =
{
	0,                            /* IP protocol */
	ROHC_PROFILE_UNCOMPRESSED,    /* profile ID (see 8 in RFC 3095) */
	"1.0b",                       /* profile version */
	"Uncompressed / Compressor",  /* profile description */
	c_uncompressed_create,        /* profile handlers */
	c_uncompressed_destroy,
	c_uncompressed_check_context,
	c_uncompressed_encode,
	c_uncompressed_feedback,
};

