/**
 * @file d_udp.c
 * @brief ROHC decompression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "d_udp.h"


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
		goto quit;

	/* create the UDP-specific part of the context */
	udp_context = malloc(sizeof(struct d_udp_context));
	if(udp_context == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the UDP-specific context\n");
		goto destroy_context;
	}
	bzero(udp_context, sizeof(struct d_udp_context));
	context->specific = udp_context;

	/* the UDP checksum field present flag will be initialized
	 * with the IR packets */
	udp_context->udp_checksum_present = -1;

	/* some UDP-specific values and functions */
	context->next_header_len = sizeof(struct udphdr);
	context->build_next_header = udp_build_uncompressed_udp;
	context->decode_static_next_header = udp_decode_static_udp;
	context->decode_dynamic_next_header = udp_decode_dynamic_udp;

	/* create the UDP-specific part of the header changes */
	context->last1->next_header_len = sizeof(struct udphdr);
	context->last1->next_header = malloc(sizeof(struct udphdr));
	if(context->last1->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the UDP-specific "
		               "part of the header changes last1\n");
		goto free_udp_context;
	}
	bzero(context->last1->next_header, sizeof(struct udphdr));

	context->last2->next_header_len = sizeof(struct udphdr);
	context->last2->next_header = malloc(sizeof(struct udphdr));
	if(context->last2->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the UDP-specific "
		               "part of the header changes last2\n");
		goto free_last1_next_header;
	}
	bzero(context->last2->next_header, sizeof(struct udphdr));

	context->active1->next_header_len = sizeof(struct udphdr);
	context->active1->next_header = malloc(sizeof(struct udphdr));
	if(context->active1->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the UDP-specific "
		               "part of the header changes active1\n");
		goto free_last2_next_header;
	}
	bzero(context->active1->next_header, sizeof(struct udphdr));

	context->active2->next_header_len = sizeof(struct udphdr);
	context->active2->next_header = malloc(sizeof(struct udphdr));
	if(context->active2->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the UDP-specific "
		               "part of the header changes active2\n");
		goto free_active1_next_header;
	}
	bzero(context->active2->next_header, sizeof(struct udphdr));

	return context;

free_active1_next_header:
	zfree(context->active1->next_header);
free_last2_next_header:
	zfree(context->last2->next_header);
free_last1_next_header:
	zfree(context->last1->next_header);
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
void d_udp_destroy(void *context)
{
	struct d_generic_context *c = context;

	if(c != NULL)
	{
		/* clean UDP-specific memory */
		if(c->last1 != NULL && c->last1->next_header != NULL)
			zfree(c->last1->next_header);
		if(c->last2 != NULL && c->last2->next_header != NULL)
			zfree(c->last2->next_header);
		if(c->active1 != NULL && c->active1->next_header != NULL)
			zfree(c->active1->next_header);
		if(c->active2 != NULL && c->active2->next_header != NULL)
			zfree(c->active2->next_header);

		/* destory the generic decompression context (c->specific is
		 * destroyed by d_generic_destroy) */
		d_generic_destroy(c);
	}
}


/**
 * @brief Decode one IR packet for the UDP profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param packet          The ROHC packet to decode
 * @param copy_size       The length of the ROHC packet to decode
 * @param dynamic_present Whether the IR packet contains a dynamic part or not
 * @param dest            The decoded IP packet
 * @return                The length of the uncompressed IP packet
 *                        or ROHC_OK_NO_DATA if no data is returned
 *                        or ROHC_ERROR if an error occurs
 */
int d_udp_decode_ir(struct rohc_decomp *decomp,
                    struct d_context *context,
                    unsigned char *packet,
                    int copy_size,
                    int dynamic_present,
                    unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_udp_context *udp_context = g_context->specific;

	udp_context->udp_checksum_present = -1;

	return d_generic_decode_ir(decomp, context, packet, copy_size,
	                           dynamic_present, dest);
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
int udp_detect_ir_size(unsigned char *packet, int second_byte)
{
	int length, d;

	length = d_generic_detect_ir_size(packet, second_byte);

	if(length != 0)
	{
		length += 4;

		d = GET_BIT_0(packet);
		if(d)
			length += 2;
	}

	return length;
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
int udp_detect_ir_dyn_size(unsigned char *first_byte,
                           struct d_context *context)
{
	return d_generic_detect_ir_dyn_size(first_byte, context) + 2;
}


/**
 * @brief Decode the UDP static part of the ROHC packet.
 *
 * @param context The generic decompression context
 * @param packet  The ROHC packet to decode
 * @param dest    The decoded UDP header
 * @return        The number of bytes read from the ROHC packet
 */
int udp_decode_static_udp(struct d_generic_context *context,
                          const unsigned char *packet,
                          unsigned char *dest)
{
	struct udphdr *udp = (struct udphdr *) dest;

	udp->source = *((uint16_t *) packet);
	packet += 2;

	udp->dest = *((uint16_t *) packet);

	return 4;
}


/**
 * @brief Decode the UDP dynamic part of the ROHC packet.
 *
 * @param context      The generic decompression context
 * @param packet       The ROHC packet to decode
 * @param payload_size The length of the remaining data in the ROHC packet
 * @param dest         The decoded UDP header
 * @return             The number of bytes read from the ROHC packet
 */
int udp_decode_dynamic_udp(struct d_generic_context *context,
                           const unsigned char *packet,
                           int payload_size,
                           unsigned char *dest)
{
	struct d_udp_context *udp_context;
	struct udphdr *udp;
	int length = 0;
	
	udp_context = context->specific;
	udp = (struct udphdr *) dest;

	/* UDP checksum if necessary:
	 *  udp_checksum_present < 0 <=> not initialized
	 *  udp_checksum_present = 0 <=> UDP checksum field not present
	 *  udp_checksum_present > 0 <=> UDP checksum field present */
	if(udp_context->udp_checksum_present != 0)
	{
		/* retrieve the UDP checksum from the ROHC packet */
		udp->check = *((uint16_t *) packet);
		length += 2;

		/* init the UDP context if necessary */
		if(udp_context->udp_checksum_present < 0)
			udp_context->udp_checksum_present = udp->check;
	}

	return length;
}


/**
 * @brief Build an uncompressed UDP header.
 *
 * @param context      The generic decompression context
 * @param active       The UDP header changes
 * @param dest         The buffer to store the UDP header (MUST be at least
 *                     of sizeof(struct udphdr) length)
 * @param payload_size The length of the UDP payload
 */
void udp_build_uncompressed_udp(struct d_generic_context *context,
                                struct d_generic_changes *active,
                                unsigned char *dest,
                                int payload_size)
{
	struct d_udp_context *udp_context = context->specific;
	struct udphdr *udp_active = (struct udphdr *) active->next_header;
	struct udphdr *udp = (struct udphdr *) dest;

	/* static + checksum */
	memcpy(dest, udp_active, sizeof(struct udphdr));

	/* UDP checksum (0 if checksum field not present
	 * or udp_checksum_present not initialized, swap
	 * bit order if NBO is not set */
	if(udp_context->udp_checksum_present)
	{
		if(!active->nbo)
			udp->check = swab16(udp->check);
	}
	else
		udp->check = 0;

	/* interfered fields */
	udp->len = htons(payload_size + sizeof(struct udphdr));
}


/**
 * @brief Define the decompression part of the UDP profile as described
 *        in the RFC 3095.
 */
struct d_profile d_udp_profile =
{
	ROHC_PROFILE_UDP,       /* profile ID (see 8 in RFC 3095) */
	"1.0",                  /* profile version */
	"UDP / Decompressor",   /* profile description */
	d_generic_decode,       /* profile handlers */
	d_udp_decode_ir,
	d_udp_create,
	d_udp_destroy,
	udp_detect_ir_size,
	udp_detect_ir_dyn_size,
	d_generic_get_sn,
};

