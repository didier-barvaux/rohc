/**
 * @file d_generic.c
 * @brief ROHC generic decompression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "d_generic.h"


/*
 * Private function prototypes.
 */

int decode_irdyn(struct rohc_decomp *decomp,
                 struct d_context *context,
                 unsigned char *head,
                 unsigned char *packet,
                 unsigned char *dest,
                 int payload_size);

int decode_uo1(struct rohc_decomp *decomp,
               struct d_context *context,
               unsigned char *head,
               unsigned char *packet,
               unsigned char *dest,
               int payload_size);

int decode_uo0(struct rohc_decomp *decomp,
               struct d_context *context,
               unsigned char *head,
               unsigned char *packet,
               unsigned char *dest,
               int payload_size);

int do_decode_uo0_and_uo1(struct d_context *context,
                          const unsigned char *packet,
                          unsigned char *dest,
                          int *payload_size,
                          int sn_bits, int nb_of_sn_bits,
                          int *id, int nb_of_id_bits,
                          int *id2, int *sn, int *calc_crc);

int decode_uor2(struct rohc_decomp *decomp,
                struct d_context *context,
                unsigned char *head,
                unsigned char *packet,
                unsigned char *dest,
                int payload_size);

int do_decode_uor2(struct rohc_decomp *decomp,
                   struct d_context *context,
                   unsigned char *packet,
                   unsigned char *dest,
                   int *payload_size,
                   int *id, int *id2,
                   int *sn, int *sn_size, int sn_bits,
                   int ext, int *calc_crc);

int decode_extension0(unsigned char *packet, int *sn, int *ip_id);

int decode_extension1(unsigned char *packet, int *sn, int *ip_id);

int decode_extension2(unsigned char *packet, int *sn, int *ip_id, int *ip_id2);

int decode_extension3(struct rohc_decomp *decomp,
                      struct d_context *context,
                      unsigned char *packet,
                      int *sn,
                      int *sn_size,
                      int *ip_id_changed,
                      int *update_id2);

int extension_type(const unsigned char *packet);

int d_decode_static_ip4(const unsigned char *packet, struct iphdr *dest);

int d_decode_dynamic_ip4(const unsigned char *packet, struct iphdr *dest,
                         int *rnd, int *nbo);

int decode_outer_header_flags(unsigned char *flags,
                              unsigned char *fields,
                              struct iphdr *ip,
                              int *rnd, int *nbo,
                              int *updated_id);

int decode_inner_header_flags(unsigned char *flags,
                              unsigned char * fields,
                              struct iphdr *ip,
                              int *rnd, int *nbo);

void build_uncompressed_ip4(struct d_generic_changes *active,
                            int ip_id,
                            unsigned char *dest,
                            int payload_size);

void copy_generic_changes(struct d_generic_changes *dst,
                          struct d_generic_changes *src);

int cmp_generic_changes(struct d_generic_changes *first,
                        struct d_generic_changes *second);

void sync_on_failure(struct d_generic_context *context);

void synchronize(struct d_generic_context *context);

void update_inter_packet(struct d_generic_context *context);

int act_on_crc_failure(struct rohc_decomp *decomp,
                       struct d_context *context,
                       unsigned char *packet, unsigned char *dest,
                       int sn_size, int *sn, int sn_bits,
                       int *payload_size,
                       int *id, int id_size, int *id2,
                       int *calc_crc, int real_crc,
                       int ext);


/**
 * @brief Create the generic decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return The newly-created generic decompression context
 */
void * d_generic_create(void)
{
	struct d_generic_context *context;

	/* allocate memory for the generic context */
	context = malloc(sizeof(struct d_generic_context));
	if(context == NULL)
	{
		rohc_debugf(0, "no memory for the generic decompression context\n");
		goto quit;
	}
	bzero(context, sizeof(struct d_generic_context));

	/* allocate memory for the header changes */
	context->last1 = malloc(sizeof(struct d_generic_changes));
	if(context->last1 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the header changes last1\n");
		goto free_context;
	}
	bzero(context->last1, sizeof(struct d_generic_changes));

	context->last2 = malloc(sizeof(struct d_generic_changes));
	if(context->last2 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the header changes last2\n");
		goto free_last1;
	}
	bzero(context->last2, sizeof(struct d_generic_changes));

	context->active1 = malloc(sizeof(struct d_generic_changes));
	if(context->active1 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the header changes active1\n");
		goto free_last2;
	}
	bzero(context->active1, sizeof(struct d_generic_changes));

	context->active2 = malloc(sizeof(struct d_generic_changes));
	if(context->active2 == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the header changes active2\n");
		goto free_active1;
	}
	bzero(context->active2, sizeof(struct d_generic_changes));

	return context;

free_active1:
	zfree(context->active1);
free_last2:
	zfree(context->last2);
free_last1:
	zfree(context->last1);
free_context:
	zfree(context);
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
void d_generic_destroy(void *context)
{
	struct d_generic_context *c = context;

	if(c != NULL)
	{
		if(c->last1 != NULL)
			zfree(c->last1);
		if(c->last2 != NULL)
			zfree(c->last2);
		if(c->active1 != NULL)
			zfree(c->active1);
		if(c->active2 != NULL)
			zfree(c->active2);

		if(c->specific != NULL)
			zfree(c->specific);

		zfree(c);
	}
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
int d_generic_decode_ir(struct rohc_decomp *decomp,
                        struct d_context *context,
                        unsigned char *packet,
                        int payload_size,
                        int dynamic_present,
                        unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;

	unsigned char *org_packet = packet;
	unsigned char *org_dest = dest;

	int size, sn;

	rohc_debugf(2, "decode an IR packet\n");

	g_context->current_packet_time = get_microseconds();

	/* decode the static part of the outer IPv4 header */
	size = d_decode_static_ip4(packet, &active1->ip);
	if(size == -1)
	{
		rohc_debugf(0, "cannot decode the outer IP static part\n");
		return ROHC_ERROR;
	}
	
	packet += size;
	payload_size -= size;

	if(active1->ip.protocol == IPPROTO_IPIP)
	{
		g_context->multiple_ip = 1;
		rohc_debugf(1, "multiple IP headers\n");
	}
	else
		g_context->multiple_ip = 0;

	/* decode the static part of the inner IPv4 header
	 * if multiple IP headers */
	if(g_context->multiple_ip)
	{
		size = d_decode_static_ip4(packet, &active2->ip);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the inner IP static part\n");
			return ROHC_ERROR;
		}
		
		packet += size;
		payload_size -= size;
	}

	/* decode the static part of the UDP header if necessary */
	if(g_context->decode_static_next_header != NULL)
	{
		size = g_context->decode_static_next_header(g_context, packet,
		                                            active1->next_header);
		packet += size;
		payload_size -= size;
	}

	/* decode the dynamic part of the ROHC packet */
	if(dynamic_present)
	{
		/* decode the dynamic part of the outer IP header */
		size = d_decode_dynamic_ip4(packet, &active1->ip, &active1->rnd, &active1->nbo);
		packet += size;
		payload_size -= size;

		/* decode the dynamic part of theinner IP header */
		if(g_context->multiple_ip)
		{
			size = d_decode_dynamic_ip4(packet, &active2->ip, &active2->rnd, &active2->nbo);
			packet += size;
			payload_size -= size;
		}

		/* decode the dynamic part of the UDP header if necessary */
		if(g_context->decode_dynamic_next_header != NULL)
		{
			size = g_context->decode_dynamic_next_header(g_context, packet,
			                                             /* -2 for the SN field */
			                                             payload_size - 2,
			                                             active1->next_header);
			packet += size;
			payload_size -= size;
		}

		/* reset the correction counter */
		g_context->counter = 0;

		/* init the SN and the outer IP-ID */
		sn = ntohs(* ((uint16_t *) packet));
		d_lsb_init(&g_context->sn, sn, -1);
		d_ip_id_init(&g_context->ip_id1, ntohs(active1->ip.id), sn);
		packet += 2;
		payload_size -= 2;

		/* init the inner IP-ID */
		if(g_context->multiple_ip)
			d_ip_id_init(&g_context->ip_id2, ntohs(active2->ip.id), sn);

		/* set the state to Full Context */
		context->state = FULL_CONTEXT;
	}
	else if(context->state != FULL_CONTEXT)
	{
		/* in 'Static Context' or 'No Context' state and the packet does not
		 * contain a dynamic part */
		rohc_debugf(0, "receive IR packet without a dynamic part, but not "
		               "in Full Context state\n");
		return ROHC_ERROR;
	}

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		build_uncompressed_ip4(active1, ntohs(active1->ip.id), dest, payload_size + sizeof(struct iphdr) + active1->next_header_len);
		dest += sizeof(struct iphdr);
		build_uncompressed_ip4(active2, ntohs(active2->ip.id), dest, payload_size + active2->next_header_len);
	}
	else
		build_uncompressed_ip4(active1, ntohs(active1->ip.id), dest, payload_size + active1->next_header_len);
	dest += sizeof(struct iphdr);

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
		g_context->build_next_header(g_context, active1, dest, payload_size);
	dest += active1->next_header_len;

	/* synchronize the IP header changes */
	synchronize(g_context);

	/* update the inter-packet variable */
	update_inter_packet(g_context);

	/* payload */
	rohc_debugf(3, "ROHC payload is %d-byte length\n", payload_size);
	if(payload_size == 0)
		return ROHC_OK_NO_DATA;
	memcpy(dest, packet, payload_size);

	/* statistics */
	context->header_compressed_size += packet - org_packet;
	c_add_wlsb(context->header_16_compressed, 0, 0, packet - org_packet);
	context->header_uncompressed_size += dest - org_dest;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, dest - org_dest);

	return payload_size + (dest - org_dest);
}


/**
 * @brief Decode the IPv4 static part of a ROHC packet.
 *
 * @param packet The ROHC packet to decode
 * @param dest   The decoded IPv4 packet
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_static_ip4(const unsigned char *packet, struct iphdr *dest)
{
	dest->version = GET_BIT_4_7(packet);
	if(dest->version != 4)
	{
		rohc_debugf(0, "wrong IP version (%d)\n", dest->version);
		return -1;
	}
	packet++;

	dest->protocol = GET_BIT_0_7(packet);
	packet++;

	dest->saddr = *((uint32_t *) packet);
	packet += 4;

	dest->daddr = *((uint32_t *) packet);

	return 10;
}


/**
 * @brief Decode the IPv4 dynamic part of a ROHC packet.
 *
 * @param packet The ROHC packet to decode
 * @param dest   The decoded IPv4 packet
 * @param rnd    Boolean to store whether the IP-ID is random or not
 * @param nbo    Boolean to store whether the IP-ID is in NBO or not
 * @return       The number of bytes read in the ROHC packet
 */
int d_decode_dynamic_ip4(const unsigned char *packet, struct iphdr *dest,
                         int *rnd, int *nbo)
{
  	dest->tos = GET_BIT_0_7(packet);
	packet++;

	dest->ttl = GET_BIT_0_7(packet);
	packet++;

	dest->id = *((uint16_t *) packet);
	packet += 2;

	if(GET_BIT_7(packet))
		dest->frag_off = htons(0x4000);
	else
		dest->frag_off = htons(0x0000);

	*nbo = GET_REAL(GET_BIT_5(packet));
	*rnd = GET_REAL(GET_BIT_6(packet));
	
	return 5;
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
int d_generic_detect_ir_size(unsigned char *packet, int second_byte)
{
	int length, d;

	length = 10;
	d = GET_BIT_0(packet);

	if(d)
		length += 5 + 2;

	if(packet[second_byte + 2] != 0x40)
		return 0;

	if(packet[second_byte + 3] == IPPROTO_IPIP)
	{
		length += 10;
		
		if(d)
			length += 5;

		if(packet[second_byte + 12] != 0x40)
			return 0;
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
int d_generic_detect_ir_dyn_size(unsigned char *first_byte,
                                 struct d_context *context)
{
	struct d_generic_context *g_context = context->specific;
	int length;
	
	length = 7; /* minimum value */

	/* multiple IP headers? */
	if(g_context->active1->ip.protocol == IPPROTO_IPIP)
		length += 5;

	return length;
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
int d_generic_decode(struct rohc_decomp *decomp,
                     struct d_context *context,
                     unsigned char *packet,
                     int size,
                     int second_byte,
                     unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	int (*decode_packet)(struct rohc_decomp *decomp, struct d_context *context,
	                     unsigned char *head, unsigned char *packet,
	                     unsigned char *dest, int payload_size);
	int length = ROHC_ERROR;

	/* ---- DEBUG ---- */
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	struct d_generic_changes *last1 = g_context->last1;
	struct d_generic_changes *last2 = g_context->last2;

	g_context->current_packet_time = get_microseconds();

	rohc_debugf(2, "nbo = %d rnd = %d\n", last1->nbo, last1->rnd);
	if(g_context->multiple_ip)
		rohc_debugf(2, "multiple IP header: nbo2 = %d rnd2 = %d\n",
		            last2->nbo, last2->rnd);

	if(!cmp_generic_changes(active1, last1))
		rohc_debugf(0, "last1 and active1 structs are not synchronized\n");
	if(!cmp_generic_changes(active2, last2))
		rohc_debugf(0, "last2 and active2 structs are not synchronized\n");
	/* ---- DEBUG ---- */

	/* only the IR packet can be received in the No Context state,
	 * the IR-DYN, UO-0, UO-1 or UOR-2 can not. */
	if(context->state == NO_CONTEXT)
		goto error;

	/* parse the packet according to its type */
	switch(packet_type(packet))
	{
		case PACKET_UO_0:
			g_context->packet_type = PACKET_UO_0;
			if(context->state == STATIC_CONTEXT)
				goto error;
			decode_packet = decode_uo0;
			break;

		case PACKET_UO_1:
			g_context->packet_type = PACKET_UO_1;
			if(context->state  == STATIC_CONTEXT)
				goto error;
			decode_packet = decode_uo1;
			break;

		case PACKET_UOR_2:
			g_context->packet_type = PACKET_UOR_2;
			decode_packet = decode_uor2;
			break;

		case PACKET_IR_DYN:
			g_context->packet_type = PACKET_IR_DYN;
			decode_packet = decode_irdyn;
			break;

		default:
			rohc_debugf(0, "unknown packet type\n");
			goto error;
	}

	rohc_debugf(2, "decode the packet (type %d)\n", g_context->packet_type);
	length = decode_packet(decomp, context, packet, packet + second_byte, dest, size - second_byte);

error:
	return length;
}


/**
 * @brief Get the reference SN value of the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference SN value
 */
int d_generic_get_sn(struct d_context *context)
{
	struct d_generic_context *g_context = context->specific;
	return d_get_lsb_ref(&g_context->sn);
}


/**
 * @brief Decode one UO-0 packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param head         The first byte the the ROHC packet
 * @param packet       The end of the ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param payload_size The length of the ROHC payload
 * @return             The length of the uncompressed IP packet
 */
int decode_uo0(struct rohc_decomp *decomp,
               struct d_context *context,
               unsigned char *head,
               unsigned char *packet,
               unsigned char *dest,
               int payload_size)
{
	struct d_generic_context *g_context = context->specific;
	int org_payload_size;
	int id, id2 = -1;
	int sn, sn_bits, sn_size;
	int calc_crc, real_crc;
	int extra_fields;

	/* first byte */
	real_crc = GET_BIT_0_2(head);
	sn_bits = GET_BIT_3_6(head);
	sn_size = 4;

	/* keep payload size value in case of CRC failure */
	org_payload_size = payload_size;

	/* decode the packet */
	extra_fields = do_decode_uo0_and_uo1(context, packet, dest, &payload_size,
	                                     sn_bits, sn_size , &id, 0 , &id2, &sn,
	                                     &calc_crc);

	/* try to guess the correct SN value in case of failure */
	if(calc_crc != real_crc)
	{
		rohc_debugf(0, "CRC failure (calc = 0x%x, real = 0x%x)\n",
		            calc_crc, real_crc);

		payload_size = org_payload_size;
		act_on_crc_failure(0, context, packet, dest, sn_size, &sn, sn_bits,
		                   &payload_size, &id, 0, &id2, &calc_crc, real_crc, 0);

		return ROHC_ERROR_CRC;
	}

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(g_context->counter)
	{
		if(g_context->counter == 1)
		{
			rohc_debugf(2, "throw away packet, just 2 packages right so far\n");

			g_context->counter++;

			/* pdate the inter-packet variable */
			update_inter_packet(g_context);
			synchronize(g_context);

			/* update SN and IP-IDs */	
			d_lsb_sync_ref(&g_context->sn);
			d_lsb_update(&g_context->sn, sn);
			d_ip_id_update(&g_context->ip_id1, id, sn);
			if (g_context->multiple_ip)
				d_ip_id_update(&g_context->ip_id2, id2, sn);

			return ROHC_ERROR_CRC;
		}
		else if(g_context->counter == 2)
		{
			g_context->counter = 0;
			rohc_debugf(2, "the repair is deemed successful\n");
		}
		else
		{
			rohc_debugf(0, "CRC-valid counter not valid (%d)\n",
			            g_context->counter);
			g_context->counter = 0;
			return ROHC_ERROR_CRC;
		}
	}

	packet += extra_fields;
	dest += (g_context->multiple_ip + 1) * sizeof(struct iphdr) +
	        g_context->next_header_len;

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN and IP-IDs */
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn);
	d_ip_id_update(&g_context->ip_id1, id, sn);
	if(g_context->multiple_ip)
		d_ip_id_update(&g_context->ip_id2, id2, sn);

	/* payload */
	memcpy(dest, packet, payload_size);

	/* statistics */
	context->header_compressed_size += extra_fields;
	c_add_wlsb(context->header_16_compressed, 0, 0, extra_fields);
	context->header_uncompressed_size += (g_context->multiple_ip + 1) * sizeof(struct iphdr) + g_context->next_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, (g_context->multiple_ip + 1) * sizeof(struct iphdr) + g_context->next_header_len);

	return payload_size + (g_context->multiple_ip + 1) * sizeof(struct iphdr) + g_context->next_header_len;
}


/**
 * @brief Decode one UO-1 packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param head         The first byte the the ROHC packet
 * @param packet       The end of the ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param payload_size The length of the ROHC payload
 * @return             The length of the uncompressed IP packet
 */
int decode_uo1(struct rohc_decomp *decomp,
               struct d_context *context,
               unsigned char *head,
               unsigned char *packet,
               unsigned char *dest,
               int payload_size)
{
	struct d_generic_context *g_context = context->specific;
	int org_payload_size;
	int id, id2 = -1;
	int sn, sn_bits, sn_size;
	int extra_fields;
	int calc_crc, real_crc;

	/* first byte */
	id = GET_BIT_0_5(head);

	/* second byte */
	real_crc = GET_BIT_0_2(packet);
	sn_bits = GET_BIT_3_7(packet);
	sn_size = 5;
	packet++;
	payload_size--;

	/* keep payload size value in case of CRC failure */
	org_payload_size = payload_size;

	/* decode the packet */
	extra_fields = do_decode_uo0_and_uo1(context, packet, dest, &payload_size,
	                                     sn_bits, sn_size , &id, 6 , &id2, &sn,
	                                     &calc_crc);

	/* try to guess the correct SN value in case of failure */
	if(calc_crc != real_crc)
	{
		rohc_debugf(0, "CRC failure (calc = 0x%x, real = 0x%x)\n",
		            calc_crc, real_crc);

		payload_size = org_payload_size;
		act_on_crc_failure(0, context, packet, dest, sn_size, &sn, sn_bits,
		                   &payload_size, &id, 6, &id2, &calc_crc, real_crc, 0);

		return ROHC_ERROR_CRC;
	}

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(g_context->counter)
	{
		if(g_context->counter == 1)
		{
			rohc_debugf(2, "throw away packet, just 2 packages right so far\n");

			g_context->counter++;

			/* update the inter-packet variable */
			update_inter_packet(g_context);
			synchronize(g_context);

			/* update SN and IP-IDs */
			d_lsb_sync_ref(&g_context->sn);
			d_lsb_update(&g_context->sn, sn);
			d_ip_id_update(&g_context->ip_id1, id, sn);
			if(g_context->multiple_ip)
				d_ip_id_update(&g_context->ip_id2, id2, sn);

			return ROHC_ERROR_CRC;
		}
		else if(g_context->counter == 2)
		{
			g_context->counter = 0;
			rohc_debugf(2, "the repair is deemed successful\n");
		}
		else
		{
			rohc_debugf(0, "CRC-valid counter not valid (%d)\n",
			            g_context->counter);
			g_context->counter = 0;
			return ROHC_ERROR_CRC;
		}
	}

	packet += extra_fields;
	dest += (g_context->multiple_ip + 1) * sizeof(struct iphdr) +
	        g_context->next_header_len;

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN and IP-IDs */
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn);
	d_ip_id_update(&g_context->ip_id1, id, sn);
	if(g_context->multiple_ip)
		d_ip_id_update(&g_context->ip_id2, id2, sn);

	/* payload */
	memcpy(dest, packet, payload_size);

	/* statistics */
	context->header_compressed_size += extra_fields;
	c_add_wlsb(context->header_16_compressed, 0, 0, extra_fields);
	context->header_uncompressed_size += (g_context->multiple_ip + 1) * sizeof(struct iphdr) + g_context->next_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, (g_context->multiple_ip + 1) * sizeof(struct iphdr) + g_context->next_header_len);

	return payload_size + (g_context->multiple_ip + 1)  * sizeof(struct iphdr) + g_context->next_header_len;
}


/**
 * @brief Decode one UOR-2 packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param head         The first byte the the ROHC packet
 * @param packet       The end of the ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param payload_size The length of the ROHC payload
 * @return             The length of the uncompressed IP packet
 */
int decode_uor2(struct rohc_decomp *decomp,
                struct d_context *context,
                unsigned char *head,
                unsigned char *packet,
                unsigned char *dest,
                int payload_size)
{
	struct d_generic_context *g_context = context->specific;
	unsigned char *org_packet;
	unsigned char *org_dest;
	int org_payload_size;
	int extra_fields = 0;
	int sn_size = 0;
	int id = 0, id2 = 0;
	int sn_bits, sn = 0;
	int calc_crc = 0, real_crc;
	int ext;

	/* first byte */
	sn_bits = GET_BIT_0_4(head);
	rohc_debugf(3, "SN bits = 0x%x\n", sn_bits);

	/* second byte */
	real_crc = GET_BIT_0_6(packet);
	rohc_debugf(3, "CRC = 0x%02x\n", real_crc);
	ext = GET_BIT_7(packet);
	rohc_debugf(3, "Extension type = 0x%x\n", ext);
	packet++;
	payload_size--;

	/* keep some values in case of CRC failure */
	org_packet = packet;
	org_dest = dest;
	org_payload_size = payload_size;

	/* decode the packet (and the extension if necessary) */
	extra_fields = do_decode_uor2(decomp, context, packet, dest,
	                              &payload_size, &id, &id2, &sn,
	                              &sn_size, sn_bits, ext, &calc_crc);

	/* try to guess the correct SN value in case of failure */
	if(calc_crc != real_crc)
	{
		rohc_debugf(0, "CRC failure (calc = 0x%02x, real = 0x%02x)\n",
		            calc_crc, real_crc);

		packet = org_packet;
		dest = org_dest;
		payload_size = org_payload_size;
		id = 0;
		id2 = 0;
		calc_crc = 0;

		act_on_crc_failure(decomp, context, packet, dest, sn_size, &sn, sn_bits,
		                   &payload_size, &id, 0, &id2, &calc_crc, real_crc, ext);

		return ROHC_ERROR_CRC;
	}

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(g_context->counter)
	{
		if(g_context->counter == 1)
		{
			rohc_debugf(2, "throw away packet, just 2 packets right so far\n");

			g_context->counter++;

			/* update the inter-packet variable */
			update_inter_packet(g_context);
			synchronize(g_context);

			/* update SN and IP-IDs */
			d_lsb_sync_ref(&g_context->sn);
			d_lsb_update(&g_context->sn, sn);
			d_ip_id_update(&g_context->ip_id1, id, sn);
			if(g_context->multiple_ip)
				d_ip_id_update(&g_context->ip_id2, id2, sn);

			return ROHC_ERROR_CRC;
		}
		else if(g_context->counter == 2)
		{
			g_context->counter = 0;
			rohc_debugf(2, "the repair is deemed successful\n");
		}
		else
		{
			rohc_debugf(0, "CRC-valid counter not valid (%d)\n",
			            g_context->counter);
			g_context->counter = 0;
			return ROHC_ERROR_CRC;
		}
	}

	context->state = FULL_CONTEXT;

	packet += extra_fields;
	dest += (g_context->multiple_ip + 1) * sizeof(struct iphdr) +
	        g_context->next_header_len;

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN and IP-IDs */
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn);
	d_ip_id_update(&g_context->ip_id1, id, sn);
	if(g_context->multiple_ip)
		d_ip_id_update(&g_context->ip_id2, id2, sn);

	/* payload */
	memcpy(dest, packet, payload_size);

	/* statistics */
	context->header_compressed_size += packet - org_packet;
	c_add_wlsb(context->header_16_compressed, 0, 0, packet - org_packet);
	context->header_uncompressed_size += (g_context->multiple_ip + 1) * sizeof(struct iphdr) + g_context->next_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, (g_context->multiple_ip + 1) * sizeof(struct iphdr) + g_context->next_header_len);

	return payload_size + (g_context->multiple_ip + 1) * sizeof(struct iphdr) + g_context->next_header_len;
}


/**
 * @brief Decode one IR-DYN packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param head         The first byte the the ROHC packet
 * @param packet       The end of the ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param payload_size The length of the ROHC payload
 * @return             The length of the uncompressed IP packet
 */
int decode_irdyn(struct rohc_decomp *decomp,
                 struct d_context *context,
                 unsigned char *head,
                 unsigned char *packet,
                 unsigned char *dest,
                 int payload_size)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	unsigned char *org_packet = packet;
	unsigned char *org_dest = dest;
	int sn = 0;
	int size;

	/* decode the dynamic part of the outer IP header */
	size = d_decode_dynamic_ip4(packet, &active1->ip, &active1->rnd, &active1->nbo);
	packet += size;
	payload_size -= size;

	/* decode the dynamic part of the inner IP header */
	if(g_context->multiple_ip)
	{
		size = d_decode_dynamic_ip4(packet, &active2->ip, &active2->rnd, &active2->nbo);
		packet += size;
		payload_size -= size;
	}

	/* decode the dynamic part of the next header if necessary */
	if(g_context->decode_dynamic_next_header != NULL)
	{
		size = g_context->decode_dynamic_next_header(g_context, packet,
			                                          /* -2 for the SN field */
		                                             payload_size - 2,
		                                             active1->next_header);
		packet += size;
		payload_size -= size;
	}

	/* init the SN and the outer IP-ID */
	sn = ntohs(*((uint16_t *) packet));
	d_lsb_init(&g_context->sn, sn, -1);
	d_ip_id_init(&g_context->ip_id1, ntohs(active1->ip.id), sn);
	packet += 2;
	payload_size -= 2;
	
	synchronize(g_context);

	/* init the inner IP-ID */
	if(g_context->multiple_ip)
		d_ip_id_init(&g_context->ip_id2, ntohs(active2->ip.id), sn);

	/* reset the correction counter */
	g_context->counter = 0;

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		d_ip_id_init(&g_context->ip_id2, ntohs(active2->ip.id), sn);
		build_uncompressed_ip4(active1, ntohs(active1->ip.id), dest, payload_size + sizeof(struct iphdr) + active1->next_header_len);
		dest += sizeof(struct iphdr);
		build_uncompressed_ip4(active2, ntohs(active2->ip.id), dest, payload_size + active2->next_header_len);
	}
	else
	{
		build_uncompressed_ip4(active1, ntohs(active1->ip.id), dest, payload_size + active1->next_header_len);
	}
	dest += sizeof(struct iphdr);

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
		g_context->build_next_header(g_context, active1, dest, payload_size);
	dest += active1->next_header_len;

	context->state = FULL_CONTEXT;

	/* update the inter-packet variable */
	update_inter_packet(g_context);

	/* copy the payload */
	memcpy(dest, packet, payload_size);

	/* statistics */
	context->header_compressed_size += packet - org_packet;
	c_add_wlsb(context->header_16_compressed, 0, 0, packet - org_packet);
	context->header_uncompressed_size += dest - org_dest;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, dest - org_dest);

	return payload_size + dest - org_dest;
}


/**
 * @brief Decode one UO-0 or UO-1 packet.
 *
 * @param context       The decompression context
 * @param packet        The ROHC packet to decode
 * @param dest          The decoded IP packet
 * @param payload_size  The length of the ROHC payload
 * @param sn_bits       The SN bits as they are transmitted in the ROHC packet
 * @param nb_of_sn_bits The number of bits that code the SN field
 * @param id            The outer IP-ID
 * @param nb_of_id_bits The number of bits that code the outer IP-ID field
 * @param id2           The inner IP-ID
 * @param sn            The SN value
 * @param calc_crc      The computed CRC 
 * @return              The data length read from the ROHC packet
 */
int do_decode_uo0_and_uo1(struct d_context *context,
                          const unsigned char *packet,
                          unsigned char *dest,
                          int *payload_size,
                          int sn_bits, int nb_of_sn_bits,
                          int *id, int nb_of_id_bits,
                          int *id2,
                          int *sn,
                          int *calc_crc)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	unsigned char *org_dest = dest;
	int field_counter = 0;
	int size;

	*sn = d_lsb_decode(&g_context->sn, sn_bits, nb_of_sn_bits);

	/* random IP-ID ? */
	if(active1->rnd)
	{
		*id = ntohs(*((uint16_t *) packet));
		packet += 2;
		field_counter += 2;
		*payload_size -= 2;
	}
	else
	{
		if(nb_of_id_bits)
			*id = d_ip_id_decode(&g_context->ip_id1, *id, nb_of_id_bits, *sn);
		else
			*id = d_ip_id_decode(&g_context->ip_id1, 0, 0, *sn);
	}

	/* multiple IP headers */
	if(g_context->multiple_ip)
	{
		if(active2->rnd)
		{
			*id2 = ntohs(*((uint16_t *) packet));
			packet += 2;
			field_counter += 2;
			*payload_size -= 2;
		}
		else
		{
			*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
		}
	}

	/* decode the dynamic part of the UDP header */
	if(g_context->decode_dynamic_next_header != NULL)
	{
		size = g_context->decode_dynamic_next_header(g_context, packet,
		                                             *payload_size,
		                                             active1->next_header);
		packet += size;
		field_counter += size;
		*payload_size -= size;
	}

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		build_uncompressed_ip4(active1, *id, dest, *payload_size +
		                       sizeof(struct iphdr) + active1->next_header_len);
		dest += sizeof(struct iphdr);
		build_uncompressed_ip4(active2, *id2, dest, *payload_size +
		                       active2->next_header_len);
	}
	else
	{
		build_uncompressed_ip4(active1, *id, dest, *payload_size +
		                       active1->next_header_len);
	}
	dest += sizeof(struct iphdr);

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
		g_context->build_next_header(g_context, active1, dest, *payload_size);
	dest += active1->next_header_len;

	/* check CRC */
	*calc_crc = crc_calculate(CRC_TYPE_3, org_dest, dest - org_dest);

	return field_counter;
}


/**
 * @brief Decode one UOR-2 packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param packet       The ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param payload_size The length of the ROHC payload
 * @param id           The outer IP-ID
 * @param id2          The inner IP-ID
 * @param sn           The SN value
 * @param sn_size      The SN size
 * @param sn_bits      The SN bits as they are transmitted in the ROHC packet
 * @param ext          Whether the UOR-2 packet owns an extension or not
 * @param calc_crc     The computed CRC 
 * @return             The data length read from the ROHC packet
 */
int do_decode_uor2(struct rohc_decomp *decomp,
                   struct d_context *context,
                   unsigned char *packet,
                   unsigned char *dest,
                   int *payload_size,
                   int *id, int *id2,
                   int *sn, int *sn_size, int sn_bits,
                   int ext, int *calc_crc)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	unsigned char *org_dest = dest;
	int id2_updated = 0;
	int no_ip_id_update = 0;
	int size = 0;
	int field_counter = 0;

	*sn = sn_bits;

	/* does the packet owns one extension? */
	if(ext)
	{
		/* decode extension */
		switch(extension_type(packet))
		{
			case PACKET_EXT_0:
				size = decode_extension0(packet, sn, id);
				/* ip_id_bits = 3 */
				*sn_size = 8;
				*sn = d_lsb_decode(&g_context->sn, *sn, *sn_size);
				*id = d_ip_id_decode(&g_context->ip_id1, *id, 3, *sn);
				*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
				break;

			case PACKET_EXT_1:
				size = decode_extension1(packet, sn, id);
				/* ip_id bits = 11 */
				*sn_size = 8;
				*sn = d_lsb_decode(&g_context->sn, *sn, *sn_size);
				*id = d_ip_id_decode(&g_context->ip_id1, *id, 11, *sn);
				*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
				break;

			case PACKET_EXT_2:
				size = decode_extension2(packet, sn, id, id2);
				/* ip_id bits = 8 */
				*sn_size = 8;
				*sn = d_lsb_decode(&g_context->sn, *sn, *sn_size);
				*id2 = d_ip_id_decode(&g_context->ip_id1, *id, 8, *sn); /* inner header */
				*id = d_ip_id_decode(&g_context->ip_id2, *id2, 11, *sn); /* outer header */
				break;

			case PACKET_EXT_3:
				*sn_size = 5;
				size = decode_extension3(decomp, context, packet, sn, sn_size,
				                         &no_ip_id_update, &id2_updated);

				*sn = d_lsb_decode(&g_context->sn, *sn, *sn_size);

				if(no_ip_id_update)
					*id = ntohs(active1->ip.id);
				else
					*id = d_ip_id_decode(&g_context->ip_id1, 0, 0, *sn);

				if(g_context->multiple_ip)
				{
					if(id2_updated)
						*id2 = ntohs(active2->ip.id);
					else
						*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
				}
				break;
		}

		packet += size;
		field_counter += size;
		*payload_size -= size;
	}
	else
	{
		/* no extension */
		*sn_size = 5;
		*sn = d_lsb_decode(&g_context->sn, *sn , *sn_size);
		*id = d_ip_id_decode(&g_context->ip_id1, 0, 0, *sn);
		if(g_context->multiple_ip)
			*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
		*payload_size -= 1;
	}

	/* random IP-ID ? */
	if(active1->rnd)
	{
		*id = ntohs(*((uint16_t *) packet));
		packet += 2;
		field_counter += 2;
		*payload_size -= 2;
	}

	/* multiple IP headers */
	if(g_context->multiple_ip && active2->rnd)
	{
		*id2 = ntohs(*((uint16_t *) packet));
		packet += 2;
		field_counter += 2;
		*payload_size -= 2;
	}

	rohc_debugf(3, "SN = 0x%x\n", *sn);
	rohc_debugf(3, "outer IP-ID = 0x%04x\n", *id);
	if(g_context->multiple_ip)
		rohc_debugf(3, "inner IP-ID = 0x%04x\n", *id2);

	/* decode the dynamic part of the next header */
	if(g_context->decode_dynamic_next_header != NULL)
	{
		size = g_context->decode_dynamic_next_header(g_context, packet,
		                                             *payload_size,
		                                             active1->next_header);
		packet += size;
		field_counter += size;
		*payload_size -= size;
	}

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		build_uncompressed_ip4(active1, *id, dest, *payload_size +
		                       sizeof(struct iphdr) + active1->next_header_len);
		dest += sizeof(struct iphdr);
		build_uncompressed_ip4(active2, *id2, dest, *payload_size +
		                       active2->next_header_len);
	}
	else
		build_uncompressed_ip4(active1, *id, dest, *payload_size + active1->next_header_len);
	dest += sizeof(struct iphdr);

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
		g_context->build_next_header(g_context, active1, dest, *payload_size);
	dest += active1->next_header_len;

	/* CRC check */
	*calc_crc = crc_calculate(CRC_TYPE_7, org_dest, dest - org_dest);
	rohc_debugf(3, "size = %d => CRC = 0x%x\n",
	            dest - org_dest, *calc_crc);

	return field_counter;
}



/**
 * @brief Decode the extension 0 of the UOR-2 packet
 *
 * Actions taken:
 *  - SN value is expanded with 3 lower bits,
 *  - IP-ID is replaced with 3 bits.
 *
 * @param packet The ROHC packet to decode
 * @param sn     The updated SN value
 * @param ip_id  The IP-ID value
 * @return       The data length read from the ROHC packet = 1
 */
int decode_extension0(unsigned char *packet, int *sn, int *ip_id)
{
	rohc_debugf(3, "decode UOR-2 extension 0\n");

	*sn = (*sn << 3) | GET_BIT_3_5(packet);
	*ip_id = GET_BIT_0_2(packet);

	return 1;
}


/**
 * @brief Decode the extension 1 of the UOR-2 packet
 *
 * Actions taken:
 *  - SN value is expanded with 3 lower bits,
 *  - IP-ID is replaced with 11 bits.
 *
 * @param packet The ROHC packet to decode
 * @param sn     The updated SN value
 * @param ip_id  The IP-ID
 * @return       The data length read from the ROHC packet = 2
 */
int decode_extension1(unsigned char *packet, int *sn, int *ip_id)
{
	rohc_debugf(3, "decode UOR-2 extension 1\n");

	*sn = (*sn << 3) | GET_BIT_3_5(packet);
	*ip_id = GET_BIT_0_2(packet);
	packet++;

	*ip_id = (*ip_id << 8) | *packet;

	return 2;
}


/**
 * @brief Decode the extension 2 of the UOR-2 packet
 *
 * Actions taken:
 *  - SN value is expanded with 3 lower bits,
 *  - IP-ID is replaced with 8 bits.
 *
 * @param packet The ROHC packet to decode
 * @param sn     The updated SN value
 * @param ip_id  The inner IP-ID
 * @param ip_id2 The outer IP-ID
 * @return       The data length read from the ROHC packet = 3
 */
int decode_extension2(unsigned char *packet, int *sn, int *ip_id, int *ip_id2)
{
	rohc_debugf(3, "decode UOR-2 extension 2\n");

	*sn = (*sn << 3) | GET_BIT_3_5(packet);
	*ip_id2 = GET_BIT_0_2(packet);
	packet++;

	*ip_id2 = (*ip_id2 << 8) | *packet;
	packet++;

	*ip_id = *packet;

	return 3;
}


/**
 * @brief Decode the extension 3 of the UOR-2 packet
 *
 * Actions taken:
 *  - update random fields in the header changes,
 *  - the SN is eventually expanded with 8 lower bits.
 *
 * @param decomp        The ROHC decompressor
 * @param context       The decompression context
 * @param packet        The ROHC packet to decode
 * @param sn            The updated SN value
 * @param sn_size       The new SN size
 * @param ip_id_changed The boolean indicate whether the outer IP-ID changed
 * @param update_id2    The boolean indicate whether the inner IP-ID changed
 * @return              The data length read from the ROHC packet
 */
int decode_extension3(struct rohc_decomp *decomp,
                      struct d_context *context,
                      unsigned char *packet,
                      int *sn,
                      int *sn_size,
                      int *ip_id_changed,
                      int *update_id2)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	unsigned char *org = packet;
	unsigned char *fields  = packet + 1;
	int S, mode, I, ip, ip2;
	int size;

	rohc_debugf(3, "decode UOR-2 extension 3\n");

	/* extract flags */
	S = GET_BIT_5(packet);
	mode = GET_BIT_3_4(packet);
	I = GET_BIT_2(packet);
	ip = GET_BIT_1(packet);
	ip2 = GET_BIT_0(packet);
	rohc_debugf(3, "S = %d, mode = 0x%x, I = %d, ip = %d, ip2 = %d\n",
	            S, mode, I, ip, ip2);
	packet++;

	if(ip)
		fields++;
	if(ip2)
		fields++;

	/* extract the SN if present */
	if(S)
	{
		*sn = (*sn << 8) + *fields;
		*sn_size += 8;
		fields++;
	}

	/* decode the inner IP header fields (pointed by fields) according to the
	 * inner IP header flags (pointed by packet) if present */
	if(ip)
	{
		if(g_context->multiple_ip)
			size = decode_inner_header_flags(packet, fields, &active2->ip,
			                                 &active2->rnd, &active2->nbo);
		else
			size = decode_inner_header_flags(packet, fields, &active1->ip,
			                                 &active1->rnd, &active1->nbo);
		fields += size;
	}

	/* decode the IP-ID if present */
	if(I)
	{
		if(g_context->multiple_ip)
		{
			active2->ip.id = *((uint16_t *) fields);
			rohc_debugf(3, "inner IP-ID changed (0x%04x)\n", active1->ip.id);
			fields += 2;
			*update_id2 = 1;
		}
		else
		{
			active1->ip.id = *((uint16_t *) fields);
			rohc_debugf(3, "outer IP-ID changed (0x%04x)\n", active1->ip.id);
			fields += 2;
			*ip_id_changed = 1;
		}
	}

	/* decode the outer IP header fields (pointed by fields) according to the
	 * outer IP header flags (pointed by packet) if present */
	if(ip2)
	{
		size = decode_outer_header_flags(packet, fields, &active1->ip, &active1->rnd,
		                                 &active1->nbo, ip_id_changed);
		fields += size;
	}

	if(mode != context->mode)
	{
		rohc_debugf(2, "mode is not equal on decomp and comp.\n");
		d_change_mode_feedback(decomp, context);
	}

	return (fields - org);
}


/**
 * @brief Find out of which type is the ROHC packet.
 *
 * @param packet The ROHC packet
 * @return       The packet type among PACKET_UO_0, PACKET_UO_1,
 *               PACKET_UOR_2, PACKET_IR_DYN, PACKET_IR or PACKET_UNKNOWN
 */
int packet_type(const unsigned char *packet)
{
	int type = PACKET_UNKNOWN;

	if(!GET_BIT_7(packet))
		type = PACKET_UO_0;
	else if(!GET_BIT_6(packet))
		type = PACKET_UO_1;
	else if(GET_BIT_5_7(packet) == 6)
		type = PACKET_UOR_2;
	else if(*packet == 0xf8)
		type = PACKET_IR_DYN;
	else if((*packet & 0xfe) == 0xfc)
		type = PACKET_IR;

	return type;
}


/**
 * @brief Find out which extension is carried by the UOR-2 packet.
 *
 * @param packet The ROHC UOR-2 packet
 * @return       The UOR-2 extension type among PACKET_EXT_0, PACKET_EXT_1,
 *               PACKET_EXT_2 or PACKET_EXT_3
 */
int extension_type(const unsigned char *packet)
{
	return GET_BIT_6_7(packet);
}


/**
 * @brief Decode the inner IP header flags and fields.
 *
 * Store the values in an IP header struct.
 *
 * @param flags  The ROHC flags that indicate which IP fields are present
 *               in the packet
 * @param fields The ROHC packet part that contain some IP header fields
 * @param ip     The IP header to store the decoded values in
 * @param rnd    The boolean to store whether the IP-ID is random or not
 * @param nbo    The boolean to store whether the IP-ID is in NBO or not
 * @return       The data length read from the ROHC packet
 */
int decode_inner_header_flags(unsigned char *flags,
                              unsigned char * fields,
                              struct iphdr *ip,
                              int *rnd, int *nbo)
{
	int size = 0;

	if(GET_BIT_7(flags))
	{
		ip->tos = *fields;
		rohc_debugf(3, "TOS = 0x%02x\n", ip->tos);
		fields++;
		size++;
	}

	if(GET_BIT_6(flags))
	{
		ip->ttl = *fields;
		rohc_debugf(3, "TTL = 0x%02x\n", ip->ttl);
		fields++;
		size++;
	}

	if(GET_BIT_5(flags))
		ip->frag_off = htons(IP_DF);
	else
		ip->frag_off = 0;
	rohc_debugf(3, "Fragment Offset = 0x%02x\n", ip->frag_off);

	if(GET_BIT_4(flags))
	{
		ip->protocol = *fields;
		rohc_debugf(3, "Protocol = 0x%02x\n", ip->protocol);
		fields++;
		size++;
	}

	if(GET_BIT_3(flags))
	{
		/* TODO: list compression */
		rohc_debugf(0, "list compression is not supported\n");
	}

	*nbo = GET_BIT_2(flags);
	*rnd = GET_BIT_1(flags);

	return size;
}


/**
 * @brief Decode the outer IP header flags and fields.
 *
 * Store the values in an IP header struct.
 *
 * @param flags      The ROHC flags that indicate which IP fields are present
 *                   in the packet
 * @param fields     The ROHC packet part that contain some IP header fields
 * @param ip         The IP header to store the decoded values in
 * @param rnd        The boolean to store whether the IP-ID is random or not
 * @param nbo        The boolean to store whether the IP-ID is in NBO or not
 * @param updated_id The boolean to store whether the IP-ID is updated or not
 * @return           The data length read from the ROHC packet
 */
int decode_outer_header_flags(unsigned char *flags,
                              unsigned char *fields,
                              struct iphdr *ip,
                              int *rnd, int *nbo,
                              int *updated_id)
{
	int size;

	size = decode_inner_header_flags(flags, fields, ip, rnd, nbo);

	if(GET_BIT_0(flags))
	{
		ip->id = *((uint16_t *) fields);
		rohc_debugf(3, "IP ID = 0x%04x\n", ip->id);
		fields += 2;
		size += 2;
		*updated_id = 1;
	}

	return size;
}


/**
 * @brief Build an uncompressed IPv4 header.
 *
 * @param active       The IPv4 header changes
 * @param ip_id        The IPv4 IP-ID value
 * @param dest         The buffer to store the IPv4 header (MUST be at least
 *                     of sizeof(struct iphdr) length)
 * @param payload_size The length of the IPv4 payload
 */
void build_uncompressed_ip4(struct d_generic_changes *active,
                            int ip_id,
                            unsigned char *dest,
                            int payload_size)
{
	struct iphdr *ip = (struct iphdr *) dest;

	/* static & some changing */
	memcpy(dest, &active->ip, sizeof(struct iphdr));

	/* IP-ID */
	ip->id = htons(ip_id);
	if(!active->nbo)
		ip->id = swab16(ip->id);
	rohc_debugf(3, "IP-ID = 0x%04x\n", ip->id);

	/* static-known fields */
	ip->ihl = 5;
	rohc_debugf(3, "IHL = 0x%x\n", ip->ihl);

	/* interfered fields */
	ip->tot_len = htons(payload_size + ip->ihl * 4);
	rohc_debugf(3, "Total Length = 0x%04x (IHL * 4 + %d)\n",
	            ip->tot_len, payload_size);
	ip->check = 0;
	ip->check = ip_fast_csum(dest, ip->ihl);
	rohc_debugf(3, "IP checksum = 0x%04x\n", ip->check);
}


/**
 * @brief Try to repair the SN in one of two different ways.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param packet       The ROHC packet with a wrong CRC
 * @param dest         The decoded IP packet
 * @param sn_size      The number of bits used to code the SN
 * @param sn           OUT: The Sequence Number (SN) value
 * @param sn_bits      The LSB part of the SN
 * @param payload_size OUT: The length of the ROHC payload
 * @param id           OUT: The outer IP-ID
 * @param id_size      The number of bits used to code the IP-ID
 * @param id2          OUT: The inner IP-ID
 * @param calc_crc     OUT: The computed CRC
 * @param real_crc     The CRC transmitted in the ROHC packet
 * @param ext          Whether the UOR-2 packet owns an extension or not
 * @return             Always return ROHC_ERROR_CRC
 */
int act_on_crc_failure(struct rohc_decomp *decomp,
                       struct d_context *context,
                       unsigned char *packet, unsigned char *dest,
                       int sn_size, int *sn, int sn_bits,
                       int *payload_size,
                       int *id, int id_size, int *id2,
                       int *calc_crc, int real_crc,
                       int ext)
{
	struct d_generic_context *g_context = context->specific;
	int sn_ref = 0, interval = 0;
	int sn_curr2 = 0, sn_curr1 = 0;
	int sn_update = 0;

	sync_on_failure(g_context);

	/* do we try SN recovery on CRC failure? */
	if(!CRC_ACTION)
		goto skip;

	rohc_debugf(0, "try to repair the CRC\n");

	/* if last packet time = 0, then IR was just sent and we can not
	 * compute the receive interval (interval is set to 0) */
	if(g_context->last_packet_time)
		interval = g_context->current_packet_time - g_context->last_packet_time;

	/* if the receive interval is too big, a SN LSB wraparound probably
	 * occured. The limited size of the Sequence Number (SN) field is not
	 * sufficient to code the SN completely (only the Least Significant Bits
	 * (LSB) are coded in the SN field), so when the SN grows too much the
	 * Most Significant Bits (MSB) change but the information does not appear
	 * in the SN field.
	 */
	if(interval > ((1 << sn_size) * g_context->inter_arrival_time))
	{
		/* SN LSB wraparound, compute a new SN reference and try to decode SN */
		rohc_debugf(0, "repair with the assumption: SN LSB wraparound\n");
		rohc_debugf(2, "inter_arrival_time = %d and current interval is = %d\n",
		            g_context->inter_arrival_time, interval);
		rohc_debugf(2, "add %d to SN\n", 1 << sn_size);

		/* compute a new SN reference */
		sn_ref = d_get_lsb_ref(&g_context->sn);
		sn_ref += 1 << sn_size;

		/* sync SN with the new reference */
		d_lsb_sync_ref(&g_context->sn);
		d_lsb_update(&g_context->sn, sn_ref);

		/* decode SN with the new reference */
		*sn = d_lsb_decode(&g_context->sn, sn_bits, sn_size );
	}
	else
	{
		/* no SN LSB wraparound, try to sync SN with the old sn_ref value */
		rohc_debugf(0, "repair with the assumption: incorrect SN-updates\n");
		rohc_debugf(2, "inter_arrival_time = %d and current interval is = %d\n",
		            g_context->inter_arrival_time, interval);

		/* save current SN reference */
		sn_curr1 = d_get_lsb_ref(&g_context->sn);

		/* try to decode SN with the old SN reference */
		d_lsb_update(&g_context->sn, d_get_lsb_old_ref(&g_context->sn));
		sn_curr2 = d_lsb_decode(&g_context->sn, sn_bits, sn_size);
		if(sn_curr2 == *sn)
		{
			/* decoding with the old SN reference failed */
			rohc_debugf(2, "with old ref value we get the same sn\n");
			goto failure;
		}

		*sn = sn_curr2;
		d_lsb_update(&g_context->sn, sn_curr2);
		sn_update = 1;
	}

	g_context->counter = 0;

	/* try a new decompression with another SN */
	rohc_debugf(2, "try a new decompression with another SN\n");
	switch(g_context->packet_type)
	{
		case PACKET_UO_0:
		case PACKET_UO_1:
			do_decode_uo0_and_uo1(context, packet, dest, payload_size, sn_bits, sn_size , id, id_size, id2, sn, calc_crc);
			break;

		case PACKET_UOR_2:
			*sn = sn_bits; /* TODO: why? */
			do_decode_uor2(decomp, context, packet, dest, payload_size, id, id2, sn, &sn_size, sn_bits, ext, calc_crc);
			break;

		default:
			rohc_debugf(0, "unknown packet type (%d)\n", g_context->packet_type);
			if(sn_update)
				d_lsb_update(&g_context->sn, sn_curr1);
			goto failure;
	}

	/* is the packet correctly decoded with the corrected SN? */
	if(*calc_crc != real_crc)
	{
		rohc_debugf(0, "CRC failure also on the second attempt (calc = %x, real = %x)\n",
		            *calc_crc, real_crc);
		g_context->counter = 0;
		if(sn_update)
			d_lsb_update(&g_context->sn, sn_curr1); /* reference curr1 should be used */
		sync_on_failure(g_context);
		goto failure;
	}

	/* the ROHC packet is successfully decoded */
	rohc_debugf(2, "update and sync with the new SN then throw away the packet\n");
	g_context->counter++;
	update_inter_packet(g_context);

	synchronize(g_context);

	/* update SN, outer IP-ID and inner IP-ID windows */
	if(!sn_update)
	{
		d_lsb_sync_ref(&g_context->sn);
		d_lsb_update(&g_context->sn, *sn);
	}
	else
		d_lsb_update(&g_context->sn, sn_curr2);

	d_ip_id_update(&g_context->ip_id1, *id, *sn);
	if(g_context->multiple_ip)
		d_ip_id_update(&g_context->ip_id2, *id2, *sn);

failure:
skip:
	return ROHC_ERROR_CRC;
}


/**
 * @brief Replace last header changes with the active ones.
 *
 * @param context The generic decompression context
 */
void synchronize(struct d_generic_context *context)
{
	copy_generic_changes(context->last1, context->active1);
	copy_generic_changes(context->last2, context->active2);
}


/**
 * @brief Replace the active header changes with the last ones.
 *
 * @param context The generic decompression context
 */
void sync_on_failure(struct d_generic_context *context)
{
	copy_generic_changes(context->active1, context->last1);
	copy_generic_changes(context->active2, context->last2);
}


/**
 * @brief Copy the header changes object into another one.
 *
 * @param dst The destination header changes
 * @param src The source header changes
 */
void copy_generic_changes(struct d_generic_changes *dst,
                          struct d_generic_changes *src)
{
	if(dst->next_header_len != src->next_header_len)
	{
		rohc_debugf(0, "src and dest next headers have not the same length "
		            "(%u != %u)\n", src->next_header_len, dst->next_header_len);
		return;
	}

	dst->rnd = src->rnd;
	dst->nbo = src->nbo;
	dst->ip = src->ip;

	memcpy(dst->next_header, src->next_header, dst->next_header_len);
}


/**
 * @brief Compare two header changes objects.
 *
 * @param first  One header changes object
 * @param second Another header changes object
 * @return       1 if the two objects match, 0 otherwise
 */
int cmp_generic_changes(struct d_generic_changes *first,
                        struct d_generic_changes *second)
{
	return (first->rnd == second->rnd &&
	        first->nbo == second->nbo &&
	        memcmp(&first->ip, &second->ip, sizeof(struct iphdr)) == 0 &&
			  memcmp(first->next_header, second->next_header, first->next_header_len) == 0);
}


/**
 * @brief Update the inter-packet time, a sort of average over the last
 *        inter-packet times.
 *
 * @param context The generic decompression context
 */
void update_inter_packet(struct d_generic_context *context)
{
	int last_time = context->last_packet_time;
	int delta = 0;

	rohc_debugf(2, "current time = %d and last time = %d\n",
	            context->current_packet_time, last_time);

	if(last_time)
		delta = context->current_packet_time - last_time;

	context->last_packet_time = context->current_packet_time;

	if(context->inter_arrival_time)
		context->inter_arrival_time = (context->inter_arrival_time >> WEIGHT_OLD)
		                              + (delta >> WEIGHT_NEW);
	else
		context->inter_arrival_time = delta;

	rohc_debugf(2, "inter_arrival_time = %d and current arrival delta is = %d\n",
	            context->inter_arrival_time, delta);
}

