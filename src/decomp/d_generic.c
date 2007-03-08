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
                 int plen);

int decode_uo1(struct rohc_decomp *decomp,
               struct d_context *context,
               unsigned char *head,
               unsigned char *packet,
               unsigned char *dest,
               int plen);

int decode_uo0(struct rohc_decomp *decomp,
               struct d_context *context,
               unsigned char *head,
               unsigned char *packet,
               unsigned char *dest,
               int plen);

int do_decode_uo0_and_uo1(struct d_context *context,
                          const unsigned char *packet,
                          unsigned char *dest,
                          int *plen,
                          int sn_bits, int nb_of_sn_bits,
                          int *id, int nb_of_id_bits,
                          int *id2, int *sn, int *calc_crc);

int decode_uor2(struct rohc_decomp *decomp,
                struct d_context *context,
                unsigned char *head,
                unsigned char *packet,
                unsigned char *dest,
                int plen);

int do_decode_uor2(struct rohc_decomp *decomp,
                   struct d_context *context,
                   unsigned char *packet,
                   unsigned char *dest,
                   int *plen,
                   int *id, int *id2,
                   int *sn, int *sn_size, int sn_bits,
                   int ext, int *calc_crc);

int decode_extension0(unsigned char *packet,
                      unsigned int length,
                      int *sn, int *ip_id);

int decode_extension1(unsigned char *packet,
                      unsigned int length,
                      int *sn, int *ip_id);

int decode_extension2(unsigned char *packet,
                      unsigned int length,
                      int *sn, int *ip_id, int *ip_id2);

int decode_extension3(struct rohc_decomp *decomp,
                      struct d_context *context,
                      unsigned char *packet,
                      unsigned int length,
                      int *sn, int *sn_size,
                      int *is_id_updated,
                      int *is_id2_updated);

int extension_type(const unsigned char *packet);

int d_decode_static_ip(const unsigned char *packet,
                       const unsigned int length,
                       struct d_generic_changes *info);
int d_decode_static_ip4(const unsigned char *packet,
                        const unsigned int length,
                        struct ip_packet *ip);
int d_decode_static_ip6(const unsigned char *packet,
                        const unsigned int length,
                        struct ip_packet *ip);

int d_decode_dynamic_ip(const unsigned char *packet,
                        unsigned int length,
                        struct d_generic_changes *info);
int d_decode_dynamic_ip4(const unsigned char *packet,
                         unsigned int length,
                         struct ip_packet *ip,
                         int *rnd, int *nbo);
int d_decode_dynamic_ip6(const unsigned char *packet,
                         unsigned int length,
                         struct ip_packet *ip);

int decode_outer_header_flags(unsigned char *flags,
                              unsigned char *fields,
                              unsigned int length,
                              struct d_generic_changes *info,
                              int *updated_id);

int decode_inner_header_flags(unsigned char *flags,
                              unsigned char * fields,
                              unsigned int length,
                              struct d_generic_changes *info);

unsigned int build_uncompressed_ip(struct d_generic_changes *active,
                                   unsigned char *dest,
                                   unsigned int payload_size);
unsigned int build_uncompressed_ip4(struct d_generic_changes *active,
                                    unsigned char *dest,
                                    unsigned int payload_size);
unsigned int build_uncompressed_ip6(struct d_generic_changes *active,
                                    unsigned char *dest,
                                    unsigned int payload_size);

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

	/* no packet was successfully processed for the moment */
	context->first_packet_processed = 0;
	
	/* no default next header */
	context->next_header_proto = 0;

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
 * @param plen            The length of the ROHC packet to decode
 * @param large_cid_len   The length of the large CID field
 * @param is_addcid_used  Whether the add-CID field is present or not
 * @param dest            The decoded IP packet
 * @return                The length of the uncompressed IP packet
 *                        or ROHC_OK_NO_DATA if no data is returned
 *                        or ROHC_ERROR if an error occurs
 */
int d_generic_decode_ir(struct rohc_decomp *decomp,
                        struct d_context *context,
                        unsigned char *packet,
                        int plen,
                        int large_cid_len,
                        int is_addcid_used,
                        unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *last1 = g_context->last1;
	struct d_generic_changes *last2 = g_context->last2;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;

	unsigned char *org_packet = packet;
	unsigned char *org_dest = dest;

	int dynamic_present;
	int size, sn;
	unsigned int protocol;
	int multiple_ip;

	rohc_debugf(2, "decode an IR packet\n");

	/* set the packet type */
	g_context->packet_type = PACKET_IR;

	g_context->current_packet_time = get_microseconds();

	/* is the dynamic flag set ? */
	dynamic_present = GET_BIT_0(packet);

	/* skip the first bytes:
	 * 	IR type + Profile ID + CRC (+ eventually CID bytes) */
	packet += 3 + large_cid_len;
	plen -= 3 + large_cid_len;

	/* decode the static part of the outer header */
	size = d_decode_static_ip(packet, plen, active1);
	if(size == -1)
	{
		rohc_debugf(0, "cannot decode the outer IP static part\n");
		goto error;
	}
	packet += size;
	plen -= size;

	/* check the version of the outer IP header against the context if the IR
	 * packet is not the first ROHC packet processed by the context */
	if(g_context->first_packet_processed &&
	   ip_get_version(active1->ip) != ip_get_version(last1->ip))
	{
		rohc_debugf(0, "IP version mismatch (packet = %d, context = %d)\n",
		            ip_get_version(active1->ip), ip_get_version(last1->ip));
		goto error;
	}

	/* check for the presence of a second IP header */
	protocol = ip_get_protocol(active1->ip);
	if(protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6)
	{
		multiple_ip = 1;
		rohc_debugf(1, "second IP header detected\n");
	}
	else
		multiple_ip = 0;

	/* check the number of IP headers against the context if the IR packet is
	 * not the first ROHC packet processed by the context, otherwise initialize
	 * the context */
	if(g_context->first_packet_processed &&
	   multiple_ip != g_context->multiple_ip)
	{
		rohc_debugf(0, "number of IP headers mismatch (packet = %d, "
		            "context = %d)\n", multiple_ip, g_context->multiple_ip);
		goto error;
	}
	else
		g_context->multiple_ip = multiple_ip;
	
	/* decode the static part of the inner IP header
	 * if multiple IP headers */
	if(g_context->multiple_ip)
	{
		size = d_decode_static_ip(packet, plen, active2);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the inner IP static part\n");
			goto error;
		}
		packet += size;
		plen -= size;

		/* check the version of the inner IP header against the context if the IR
		 * packet is not the first ROHC packet processed by the context */
		if(g_context->first_packet_processed &&
		   ip_get_version(active2->ip) != ip_get_version(last2->ip))
		{
			rohc_debugf(0, "IP version mismatch (packet = %d, context = %d)\n",
			            ip_get_version(active2->ip), ip_get_version(last2->ip));
			goto error;
		}
	
		/* update the next header protocol */
		protocol = ip_get_protocol(active2->ip);
	}

	/* decode the static part of the next header header if necessary */
	if(g_context->decode_static_next_header != NULL)
	{
		/* check the next header protocol against the context if the IR packet is
		 * not the first ROHC packet processed by the context, otherwise
		 * initialize the context */
		if(g_context->first_packet_processed &&
		   protocol != g_context->next_header_proto)
		{
			rohc_debugf(0, "next header protocol mismatch (packet = %d, "
			            "context = %d)\n", protocol,
			            g_context->next_header_proto);
			goto error;
		}

		size = g_context->decode_static_next_header(g_context, packet,
		                                            plen,
		                                            active1->next_header);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the next header static part\n");
			goto error;
		}
		packet += size;
		plen -= size;
	}

	/* decode the dynamic part of the ROHC packet */
	if(dynamic_present)
	{
		/* decode the dynamic part of the outer IP header */
		size = d_decode_dynamic_ip(packet, plen, active1);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the inner IP dynamic part\n");
			goto error;
		}
		packet += size;
		plen -= size;

		/* decode the dynamic part of the inner IP header */
		if(g_context->multiple_ip)
		{
			size = d_decode_dynamic_ip(packet, plen, active2);
			if(size == -1)
			{
				rohc_debugf(0, "cannot decode the outer IP dynamic part\n");
				goto error;
			}
			packet += size;
			plen -= size;
		}

		/* decode the dynamic part of the next header header if necessary */
		if(g_context->decode_dynamic_next_header != NULL)
		{
			size = g_context->decode_dynamic_next_header(g_context, packet,
			                                             plen,
			                                             active1->next_header);
			if(size == -1)
			{
				rohc_debugf(0, "cannot decode the next header dynamic part\n");
				goto error;
			}
			packet += size;
			plen -= size;
		}

		/* reset the correction counter */
		g_context->counter = 0;

		/* init the SN and the outer IP-ID (IPv4 only) */
		sn = ntohs(* ((uint16_t *) packet));
		d_lsb_init(&g_context->sn, sn, -1);
		if(ip_get_version(active1->ip) == IPV4)
			d_ip_id_init(&g_context->ip_id1, ntohs(ipv4_get_id(active1->ip)), sn);
		packet += 2;
		plen -= 2;

		/* init the inner IP-ID (IPv4 only) */
		if(g_context->multiple_ip && ip_get_version(active2->ip) == IPV4)
			d_ip_id_init(&g_context->ip_id2, ntohs(ipv4_get_id(active2->ip)), sn);

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
		dest += build_uncompressed_ip(active1, dest, plen +
		                              ip_get_hdrlen(active2->ip) +
		                              active1->next_header_len);
		dest += build_uncompressed_ip(active2, dest, plen +
		                              active2->next_header_len);
	}
	else
		dest += build_uncompressed_ip(active1, dest, plen +
		                              active1->next_header_len);

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
		dest += g_context->build_next_header(g_context, active1, dest, plen);

	/* synchronize the IP header changes */
	synchronize(g_context);

	/* the first packet is now processed */
	if(!g_context->first_packet_processed)
		g_context->first_packet_processed = 1;

	/* update the inter-packet variable */
	update_inter_packet(g_context);

	/* payload */
	rohc_debugf(3, "ROHC payload (length = %d bytes) starts at offset %d\n",
	            plen, packet - org_packet);
	if(plen == 0)
		goto no_data;
	memcpy(dest, packet, plen);

	/* statistics */
	context->header_compressed_size += is_addcid_used + (packet - org_packet);
	c_add_wlsb(context->header_16_compressed, 0, 0, is_addcid_used + (packet - org_packet));
	context->header_uncompressed_size += dest - org_dest;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, dest - org_dest);

	return plen + (dest - org_dest);

no_data:
	return ROHC_OK_NO_DATA;
error:
	return ROHC_ERROR;
}


/**
 * @brief Decode the IP static part of a ROHC packet.
 *
 * See 5.7.7.3 and 5.7.7.4 in RFC 3095 for details.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param info   The decoded IP header information
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_static_ip(const unsigned char *packet,
                       const unsigned int length,
                       struct d_generic_changes *info)
{
	unsigned int ip_version;
	int read; /* number of bytes read from the packet */

	/* check the minimal length to decode the IP version */
	if(length < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* retrieve the IP version */
	ip_version = GET_BIT_4_7(packet);

	/* reject non IPv4/IPv6 packets */
	if(ip_version != IPV4 && ip_version != IPV6)
	{
		rohc_debugf(0, "wrong IP version (%d)\n", ip_version);
		goto error;
	}

	/* create a new empty IP packet with no payload */
	ip_new(&info->ip, ip_version);

	/* decode the dynamic part of the IP header depending on the IP version */
	if(ip_version == IPV4)
		read = d_decode_static_ip4(packet, length, &info->ip);
	else /* IPV6 */
		read = d_decode_static_ip6(packet, length, &info->ip);

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IPv4 static part of a ROHC packet.
 *
 * See 5.7.7.4 in RFC 3095 for details.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param ip     The decoded IP packet
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_static_ip4(const unsigned char *packet,
                        const unsigned int length,
                        struct ip_packet *ip)
{
	int read = 0; /* number of bytes read from the packet */
	unsigned int version;

	/* check the minimal length to decode the IPv4 static part */
	if(length < 10)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* read the IP version */
	version = GET_BIT_4_7(packet);
	if(version != IPV4 || ip->version != IPV4)
	{
		rohc_debugf(0, "wrong IP version (%d)\n", version);
		goto error;
	}
	rohc_debugf(3, "IP Version = %d\n", version);
	packet++;
	read++;

	/* read the protocol number */
	ip_set_protocol(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "Protocol = 0x%02x\n", ip_get_protocol(*ip));
	packet++;
	read++;

	/* read the source IP address */
	ip_set_saddr(ip, packet);
	rohc_debugf(3, "Source Address = 0x%08x\n", ipv4_get_saddr(*ip));
	packet += 4;
	read += 4;

	/* read the destination IP address */
	ip_set_daddr(ip, packet);
	rohc_debugf(3, "Destination Address = 0x%08x\n", ipv4_get_daddr(*ip));
	packet += 4;
	read += 4;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IPv6 static part of a ROHC packet.
 *
 * See 5.7.7.3 in RFC 3095 for details.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param ip     The decoded IP packet
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_static_ip6(const unsigned char *packet,
                        const unsigned int length,
                        struct ip_packet *ip)
{
	int read = 0; /* number of bytes read from the packet */
	unsigned int version;

	/* check the minimal length to decode the IPv6 static part */
	if(length < 36)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* read the IP version */
	version = GET_BIT_4_7(packet);
	if(version != IPV6 || ip->version != IPV6)
	{
		rohc_debugf(0, "wrong IP version (%d)\n", version);
		goto error;
	}
	rohc_debugf(3, "IP Version = %d\n", version);

	/* read the flow label */
	ipv6_set_flow_label(ip, (GET_BIT_0_3(packet) << 16) |
	                        (GET_BIT_0_7(packet + 1) << 8) |
	                        GET_BIT_0_7(packet + 2));
	rohc_debugf(3, "Flow Label = 0x%05x\n", ipv6_get_flow_label(*ip));
	packet += 3;
	read += 3;

	/* read the next header value */	
	ip_set_protocol(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "Next Header = 0x%02x\n", ip_get_protocol(*ip));
	packet++;
	read++;

	/* read the source IP address */
	ip_set_saddr(ip, packet);
	rohc_debugf(3, "Source Address = " IPV6_ADDR_FORMAT "\n",
	            IPV6_ADDR(ipv6_get_saddr(ip)));
	packet += 16;
	read += 16;

	/* read the destination IP address */
	ip_set_daddr(ip, packet);
	rohc_debugf(3, "Destination Address = " IPV6_ADDR_FORMAT "\n",
	            IPV6_ADDR(ipv6_get_daddr(ip)));
	packet += 16;
	read += 16;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IP dynamic part of a ROHC packet.
 *
 * See 5.7.7.3 and 5.7.7.4 in RFC 3095 for details.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param info   The decoded IP header information
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_dynamic_ip(const unsigned char *packet,
                        unsigned int length,
                        struct d_generic_changes *info)
{
	int read; /* number of bytes read from the packet */

	/* decode the dynamic part of the IP header depending on the IP version */
	if(ip_get_version(info->ip) == IPV4)
		read = d_decode_dynamic_ip4(packet, length, &info->ip,
		                            &info->rnd, &info->nbo);
	else /* IPV6 */
		read = d_decode_dynamic_ip6(packet, length, &info->ip);
	
	return read;
}


/**
 * @brief Decode the IPv4 dynamic part of a ROHC packet.
 *
 * See 5.7.7.4 in RFC 3095 for details. Generic extension header list is not
 * managed yet.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param ip     The decoded IP packet
 * @param rnd    Boolean to store whether the IP-ID is random or not
 * @param nbo    Boolean to store whether the IP-ID is in NBO or not
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_dynamic_ip4(const unsigned char *packet,
                         unsigned int length,
                         struct ip_packet *ip,
                         int *rnd, int *nbo)
{
	int read = 0; /* number of bytes read from the packet */

	/* check the minimal length to decode the IPv4 dynamic part */
	if(length < 5)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* read the TOS field */
  	ip_set_tos(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "TOS = 0x%02x\n", ip_get_tos(*ip));
	packet++;
	read++;

	/* read the TTL field */
	ip_set_ttl(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "TTL = 0x%02x\n", ip_get_ttl(*ip));
	packet++;
	read++;

	/* read the IP-ID field */
	ipv4_set_id(ip, *((uint16_t *) packet));
	rohc_debugf(3, "IP-ID = 0x%04x\n", ntohs(ipv4_get_id(*ip)));
	packet += 2;
	read += 2;

	/* read the DF flag */
	ipv4_set_df(ip, GET_REAL(GET_BIT_7(packet)));

	/* read the RND flag */
	*rnd = GET_REAL(GET_BIT_6(packet));

	/* read the NBO flag */
	*nbo = GET_REAL(GET_BIT_5(packet));
	rohc_debugf(3, "DF = %d, RND = %d, NBO = %d\n",
	            ipv4_get_df(*ip), *rnd, *nbo);
	packet++;
	read++;

	/* generic extension header list is not managed yet */

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IPv6 dynamic part of a ROHC packet.
 *
 * See 5.7.7.3 in RFC 3095 for details. Generic extension header list is not
 * managed yet.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param ip     The decoded IP packet
 * @return       The number of bytes read in the ROHC packet,
 *               -1 in case of failure
 */
int d_decode_dynamic_ip6(const unsigned char *packet,
                         unsigned int length,
                         struct ip_packet *ip)
{
	int read = 0; /* number of bytes read from the packet */

	/* check the minimal length to decode the IPv6 dynamic part */
	if(length < 2)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* read the TC field */
  	ip_set_tos(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "TC = 0x%02x\n", ip_get_tos(*ip));
	packet++;
	read++;

	/* read the HL field */
	ip_set_ttl(ip, GET_BIT_0_7(packet));
	rohc_debugf(3, "HL = 0x%02x\n", ip_get_ttl(*ip));
	packet++;
	read++;
	
	/* generic extension header list is not managed yet */

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
 8  |             SN                | 2 octets
    +---+---+---+---+---+---+---+---+
    |                               |
 9  |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * The function computes the length of the fields 2 + 4-8, ie. the first byte,
 * the Profile and CRC fields and the static and dynamic chains (outer and inner
 * IP headers).
 *
 * @param packet          The pointer on the IR packet
 * @param plen            The length of the IR packet
 * @param second_byte     The offset for the second byte of the IR packet
 *                        (ie. the field 4 in the figure)
 * @param profile_id      The ID of the decompression profile
 * @return                The length of the IR header,
 *                        0 if an error occurs
 */
unsigned int d_generic_detect_ir_size(unsigned char *packet,
                                      unsigned int plen,
                                      int second_byte,
                                      int profile_id)
{
	unsigned int length = 0;
	int ip_offset;
	int d;
	unsigned int ip_version, ip2_version = 0;
	unsigned int proto;

	/* skip:
	 *  - the first byte of the ROHC packet (field 2)
	 *  - the Profile byte (field 4) if the profile ID != 0
	 *  - the CRC byte (field 5) */
	length += 1 + (profile_id == 0 ? 0 : 1) + 1;
	ip_offset = second_byte + 2;

	/* check if IR packet is large enough to contain an IP version field */
	if(ip_offset >= plen)
	{
		rohc_debugf(0, "ROHC packet too small for outer IP version field "
		               "(len = %d)\n", plen);
		goto error;
	}

	/* check IP version */
	ip_version = (packet[ip_offset] >> 4) & 0x0f;
	if(ip_version != IPV4 && ip_version != IPV6)
	{
		rohc_debugf(0, "bad outer IP version (%d)\n", ip_version);
		goto error;
	}

	/* IP static part (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */ 
	if(ip_version == IPV4)
		length += 10;
	else /* IPv6 */
		length += 36;

	/* check if IR packet is large enough to contain an IP protocol field */
	if(ip_offset + (ip_version == IPV4 ? 1 : 3) >= plen)
	{
		rohc_debugf(0, "ROHC packet too small for protocol field (len = %d)\n",
		            plen);
		goto error;
	}

	/* analyze the second header if present */
	proto = packet[ip_offset + (ip_version == IPV4 ? 1 : 3)];
	if(proto == IPPROTO_IPIP || proto == IPPROTO_IPV6)
	{
		/* change offset to point on the second IP header
		 * (substract 1 because of the first byte) */
		ip_offset = second_byte + (length - 1);

		/* check if IR packet is large enough to contain an IP version field */
		if(ip_offset >= plen)
		{
			rohc_debugf(0, "ROHC packet too small for inner IP version field "
			               "(len = %d)\n", plen);
			goto error;
		}

		/* check IP version */
		ip2_version = (packet[ip_offset] >> 4) & 0x0f;
		if(ip2_version != IPV4 && ip2_version != IPV6)
		{
			rohc_debugf(0, "bad inner IP version (%d)\n", ip2_version);
			goto error;
		}

		/* IP static part (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */ 
		if(ip2_version == IPV4)
			length += 10;
		else /* IPv6 */
			length += 36;
	}

	/* IP dynamic part if included (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */
	d = GET_REAL(GET_BIT_0(packet));
	if(d)
	{
		/* IP dynamic part of the outer header */
		if(ip_version == IPV4)
			length += 5;
		else /* IPv6 */
			length += 2;

		/* IP dynamic part of the inner header if present */
		if(proto == IPPROTO_IPIP || proto == IPPROTO_IPV6)
		{
			if(ip2_version == IPV4)
				length += 5;
			else /* IPv6 */
				length += 2;
		}
	}

	/* Sequence Number (SN) at the end of the header */
	length += 2;

	return length;

error:
	return 0;
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
 7  |             SN                | 2 octets
    +---+---+---+---+---+---+---+---+
    :                               :
 8  /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * The function computes the length of the fields 2 + 4-7, ie. the first byte,
 * the Profile and CRC fields and the dynamic chains (outer and inner IP
 * headers).
 *
 * @param first_byte The first byte of the IR-DYN packet
 * @param plen       The length of the IR-DYN packet
 * @param context    The decompression context
 * @return           The length of the IR-DYN header,
 *                   0 if an error occurs
 */
unsigned int d_generic_detect_ir_dyn_size(unsigned char *first_byte,
                                          unsigned int plen,
                                          struct d_context *context)
{
	struct d_generic_context *g_context = context->specific;
	unsigned int length = 0;
	unsigned int protocol;
	ip_version version, version2;

	/* skip:
	 *  - the first byte of the ROHC packet (field 2)
	 *  - the Profile byte (field 4)
	 *  - the CRC byte (field 5) */
	length += 3;

	/* get the IP version of the outer header */
	version = ip_get_version(g_context->active1->ip);
	
	/* IP dynamic part of the outer header
	 * (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */
	if(version == IPV4)
		length += 5;
	else /* IPV6 */
		length += 2;

	/* analyze the second header if present */
	protocol = ip_get_protocol(g_context->active1->ip);
	if(protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6)
	{
		/* get the IP version of the inner header */
		version2 = ip_get_version(g_context->active2->ip);

		/* IP dynamic part of the inner header
		 * (see 5.7.7.3 & 5.7.7.4 in RFC 3095) */
		if(version2 == IPV4)
			length += 5;
		else /* IPv6 */
			length += 2;
	}

	/* Sequence Number (SN) at the end of the header */
	length += 2;

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
	                     unsigned char *dest, int plen);
	int length = ROHC_ERROR;

	g_context->current_packet_time = get_microseconds();

	/* check if the ROHC packet is large enough to read the second byte */
	if(second_byte >= size)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", size);
		goto error;
	}

	/* ---- DEBUG ---- */
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	struct d_generic_changes *last1 = g_context->last1;
	struct d_generic_changes *last2 = g_context->last2;

	if(ip_get_version(last1->ip) == IPV4)
		rohc_debugf(2, "nbo = %d rnd = %d\n", last1->nbo, last1->rnd);
	if(g_context->multiple_ip && ip_get_version(last2->ip) == IPV4)
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
	if(length != ROHC_ERROR)
		rohc_debugf(2, "uncompressed packet length = %d bytes\n", length);

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
 * @param plen         The length of the ROHC packet
 * @return             The length of the uncompressed IP packet,
 *                     or ROHC_ERROR in case of error
 */
int decode_uo0(struct rohc_decomp *decomp,
               struct d_context *context,
               unsigned char *head,
               unsigned char *packet,
               unsigned char *dest,
               int plen)
{
	struct d_generic_context *g_context = context->specific;
	int id, id2 = -1;
	int sn, sn_bits, sn_size;
	int calc_crc, real_crc;
	int hlen; /* uncompressed header length */
	int org_plen;
	int i;

	/* first byte */
	real_crc = GET_BIT_0_2(head);
	sn_bits = GET_BIT_3_6(head);
	sn_size = 4;
	rohc_debugf(3, "first byte = 0x%02x (real CRC = 0x%x, SN = 0x%x)\n",
	            *head, real_crc, sn_bits);

	/* keep the packet size value in case of CRC failure */
	org_plen = plen;

	/* decode the packet */
	hlen = do_decode_uo0_and_uo1(context, packet, dest, &plen, sn_bits,
	                             sn_size, &id, 0, &id2, &sn, &calc_crc);
	if(hlen == -1)
	{
		rohc_debugf(0, "cannot decode the UO-0 packet\n");
		goto error;
	}

	/* try to guess the correct SN value in case of failure */
	if(calc_crc != real_crc)
	{
		rohc_debugf(0, "CRC failure (calc = 0x%x, real = 0x%x)\n",
		            calc_crc, real_crc);
		rohc_debugf(3, "uncompressed headers (length = %d): ", hlen);
		for(i = 0; i < hlen; i++)
			rohc_debugf_(3, "0x%02x ", dest[i]);
		rohc_debugf_(3, "\n");

		plen = org_plen;
		act_on_crc_failure(0, context, packet, dest, sn_size, &sn, sn_bits,
		                   &plen, &id, 0, &id2, &calc_crc, real_crc, 0);

		goto error_crc;
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

			/* update SN (and IP-IDs if IPv4) */	
			d_lsb_sync_ref(&g_context->sn);
			d_lsb_update(&g_context->sn, sn);
			if(ip_get_version(g_context->active1->ip) == IPV4)
				d_ip_id_update(&g_context->ip_id1, id, sn);
			if(g_context->multiple_ip &&
			   ip_get_version(g_context->active2->ip) == IPV4)
				d_ip_id_update(&g_context->ip_id2, id2, sn);

			goto error_crc;
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
			goto error_crc;
		}
	}

	packet += org_plen - plen;
	dest += hlen;

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN (and IP-IDs if IPv4) */	
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn);
	if(ip_get_version(g_context->active1->ip) == IPV4)
		d_ip_id_update(&g_context->ip_id1, id, sn);
	if(g_context->multiple_ip && ip_get_version(g_context->active2->ip) == IPV4)
		d_ip_id_update(&g_context->ip_id2, id2, sn);

	/* payload */
	rohc_debugf(3, "ROHC payload (length = %d bytes) starts at offset %d\n",
	            plen, packet - head);
	if(plen == 0)
		goto no_data;
	memcpy(dest, packet, plen);

	/* statistics */
	context->header_compressed_size += packet - head;
	c_add_wlsb(context->header_16_compressed, 0, 0, packet - head);
	context->header_uncompressed_size += hlen;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, hlen);

	return hlen + plen;

no_data:
	return ROHC_OK_NO_DATA;
error:
	return ROHC_ERROR;
error_crc:
	return ROHC_ERROR_CRC;
}


/**
 * @brief Decode one UO-1 packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param head         The first byte the the ROHC packet
 * @param packet       The end of the ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param plen         The length of the ROHC packet
 * @return             The length of the uncompressed IP packet
 *                     or ROHC_ERROR in case of error
 */
int decode_uo1(struct rohc_decomp *decomp,
               struct d_context *context,
               unsigned char *head,
               unsigned char *packet,
               unsigned char *dest,
               int plen)
{
	struct d_generic_context *g_context = context->specific;
	int org_plen;
	int id, id2 = -1;
	int sn, sn_bits, sn_size;
	int hlen; /* uncompressed header length */
	int calc_crc, real_crc;
	int i;

	/* check if the ROHC packet is large enough to read the second byte */
	if(plen < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", plen);
		goto error;
	}

	/* first byte */
	id = GET_BIT_0_5(head);

	/* second byte */
	real_crc = GET_BIT_0_2(packet);
	sn_bits = GET_BIT_3_7(packet);
	sn_size = 5;
	packet++;
	plen--;

	/* keep the packet size value in case of CRC failure */
	org_plen = plen;

	/* decode the packet */
	hlen = do_decode_uo0_and_uo1(context, packet, dest, &plen, sn_bits,
	                             sn_size, &id, 6, &id2, &sn, &calc_crc);
	if(hlen == -1)
	{
		rohc_debugf(0, "cannot decode the UO-1 packet\n");
		goto error;
	}

	/* try to guess the correct SN value in case of failure */
	if(calc_crc != real_crc)
	{
		rohc_debugf(0, "CRC failure (calc = 0x%x, real = 0x%x)\n",
		            calc_crc, real_crc);
		rohc_debugf(3, "uncompressed headers (length = %d): ", hlen);
		for(i = 0; i < hlen; i++)
			rohc_debugf_(3, "0x%02x ", dest[i]);
		rohc_debugf_(3, "\n");

		plen = org_plen;
		act_on_crc_failure(0, context, packet, dest, sn_size, &sn, sn_bits,
		                   &plen, &id, 6, &id2, &calc_crc, real_crc, 0);

		goto error_crc;
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

			/* update SN (and IP-IDs if IPv4) */
			d_lsb_sync_ref(&g_context->sn);
			d_lsb_update(&g_context->sn, sn);
			if(ip_get_version(g_context->active1->ip) == IPV4)
				d_ip_id_update(&g_context->ip_id1, id, sn);
			if(g_context->multiple_ip &&
			   ip_get_version(g_context->active2->ip) == IPV4)
				d_ip_id_update(&g_context->ip_id2, id2, sn);

			goto error_crc;
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
			goto error_crc;
		}
	}

	packet += org_plen - plen;
	dest += hlen;

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN and IP-IDs */
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn);
	if(ip_get_version(g_context->active1->ip) == IPV4)
		d_ip_id_update(&g_context->ip_id1, id, sn);
	if(g_context->multiple_ip && ip_get_version(g_context->active2->ip) == IPV4)
		d_ip_id_update(&g_context->ip_id2, id2, sn);

	/* payload */
	rohc_debugf(3, "ROHC payload (length = %d bytes) starts at offset %d\n",
	            plen, packet - head);
	if(plen == 0)
		goto no_data;
	memcpy(dest, packet, plen);

	/* statistics */
	context->header_compressed_size += packet - head;
	c_add_wlsb(context->header_16_compressed, 0, 0, packet - head);
	context->header_uncompressed_size += hlen;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, hlen);

	return hlen + plen;

no_data:
	return ROHC_OK_NO_DATA;
error:
	return ROHC_ERROR;
error_crc:
	return ROHC_ERROR_CRC;
}


/**
 * @brief Decode one UOR-2 packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param head         The first byte the the ROHC packet
 * @param packet       The end of the ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param plen         The length of the ROHC packet
 * @return             The length of the uncompressed IP packet
 *                     or ROHC_ERROR in case of error
 */
int decode_uor2(struct rohc_decomp *decomp,
                struct d_context *context,
                unsigned char *head,
                unsigned char *packet,
                unsigned char *dest,
                int plen)
{
	struct d_generic_context *g_context = context->specific;
	unsigned char *org_packet;
	unsigned char *org_dest;
	int org_plen;
	int hlen; /* uncompressed header length */
	int sn_size = 0;
	int id = 0, id2 = 0;
	int sn_bits, sn = 0;
	int calc_crc = 0, real_crc;
	int ext;
	int i;

	/* check if the ROHC packet is large enough to read the second byte */
	if(plen < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", plen);
		goto error_size;
	}

	/* first byte */
	sn_bits = GET_BIT_0_4(head);
	rohc_debugf(3, "SN bits = 0x%x\n", sn_bits);

	/* second byte */
	real_crc = GET_BIT_0_6(packet);
	rohc_debugf(3, "CRC = 0x%02x\n", real_crc);
	ext = GET_REAL(GET_BIT_7(packet));
	rohc_debugf(3, "Extension is present = %d\n", ext);
	packet++;
	plen--;

	/* keep some values in case of CRC failure */
	org_packet = packet;
	org_dest = dest;
	org_plen = plen;

	/* decode the packet (and the extension if necessary) */
	hlen = do_decode_uor2(decomp, context, packet, dest, &plen, &id, &id2,
	                      &sn,  &sn_size, sn_bits, ext, &calc_crc);
	if(hlen == -1)
	{
		rohc_debugf(0, "cannot decode the UOR-2 packet\n");
		goto error_size;
	}

	/* try to guess the correct SN value in case of failure */
	if(calc_crc != real_crc)
	{
		rohc_debugf(0, "CRC failure (calc = 0x%02x, real = 0x%02x)\n",
		            calc_crc, real_crc);
		rohc_debugf(3, "uncompressed headers (length = %d): ", hlen);
		for(i = 0; i < hlen; i++)
			rohc_debugf_(3, "0x%02x ", dest[i]);
		rohc_debugf_(3, "\n");

		packet = org_packet;
		dest = org_dest;
		plen = org_plen;
		id = 0;
		id2 = 0;
		calc_crc = 0;

		act_on_crc_failure(decomp, context, packet, dest, sn_size, &sn, sn_bits,
		                   &plen, &id, 0, &id2, &calc_crc, real_crc, ext);

		goto error_crc;
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
			if(ip_get_version(g_context->active1->ip) == IPV4)
				d_ip_id_update(&g_context->ip_id1, id, sn);
			if(g_context->multiple_ip &&
			   ip_get_version(g_context->active2->ip) == IPV4)
				d_ip_id_update(&g_context->ip_id2, id, sn);

			goto error_crc;
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
			goto error_crc;
		}
	}

	context->state = FULL_CONTEXT;

	packet += org_plen - plen;
	dest += hlen;

	/* update the inter-packet variable */
	update_inter_packet(g_context);
	synchronize(g_context);

	/* update SN and IP-IDs */
	d_lsb_sync_ref(&g_context->sn);
	d_lsb_update(&g_context->sn, sn);
	if(ip_get_version(g_context->active1->ip) == IPV4)
		d_ip_id_update(&g_context->ip_id1, id, sn);
	if(g_context->multiple_ip && ip_get_version(g_context->active2->ip) == IPV4)
		d_ip_id_update(&g_context->ip_id2, id2, sn);

	/* payload */
	rohc_debugf(3, "ROHC payload (length = %d bytes) starts at offset %d\n",
	            plen, packet - head);
	if(plen == 0)
		goto no_data;
	memcpy(dest, packet, plen);

	/* statistics */
	context->header_compressed_size += packet - head;
	c_add_wlsb(context->header_16_compressed, 0, 0, packet - head);
	context->header_uncompressed_size += hlen;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, hlen);

	return hlen + plen;

no_data:
	return ROHC_OK_NO_DATA;
error_size:
	return ROHC_ERROR;
error_crc:
	return ROHC_ERROR_CRC;
}


/**
 * @brief Decode one IR-DYN packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param head         The first byte the the ROHC packet
 * @param packet       The end of the ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param plen         The length of the ROHC packet
 * @return             The length of the uncompressed IP packet
 *                     or ROHC_ERROR in case of error
 */
int decode_irdyn(struct rohc_decomp *decomp,
                 struct d_context *context,
                 unsigned char *head,
                 unsigned char *packet,
                 unsigned char *dest,
                 int plen)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	unsigned char *org_dest = dest;
	int sn = 0;
	int size;

	/* decode the dynamic part of the outer IP header */
	size = d_decode_dynamic_ip(packet, plen, active1);
	if(size == -1)
	{
		rohc_debugf(0, "cannot decode the outer IP dynamic part\n");
		goto error;
	}
	packet += size;
	plen -= size;

	/* decode the dynamic part of the inner IP header */
	if(g_context->multiple_ip)
	{
		size = d_decode_dynamic_ip(packet, plen, active2);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the outer IP dynamic part\n");
			goto error;
		}
		packet += size;
		plen -= size;
	}

	/* decode the dynamic part of the next header if necessary */
	if(g_context->decode_dynamic_next_header != NULL)
	{
		size = g_context->decode_dynamic_next_header(g_context, packet, plen,
		                                             active1->next_header);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the next header dynamic part\n");
			goto error;
		}
		packet += size;
		plen -= size;
	}

	/* init the SN (and the outer IP-ID if IPv4) */
	sn = ntohs(*((uint16_t *) packet));
	d_lsb_init(&g_context->sn, sn, -1);
	packet += 2;
	plen -= 2;

	/* init the outer IP-ID if IPv4 */
	if(ip_get_version(active1->ip) == IPV4)
		d_ip_id_init(&g_context->ip_id1, ntohs(ipv4_get_id(active1->ip)), sn);

	/* init the inner IP-ID if multiple headers and IPv4 */
	if(g_context->multiple_ip && ip_get_version(active2->ip) == IPV4)
		d_ip_id_init(&g_context->ip_id2, ntohs(ipv4_get_id(active2->ip)), sn);

	/* synchronize the old headers with the new ones in the context */
	synchronize(g_context);

	/* reset the correction counter */
	g_context->counter = 0;

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		dest += build_uncompressed_ip(active1, dest, plen +
		                              ip_get_hdrlen(active2->ip) +
		                              active1->next_header_len);
		dest += build_uncompressed_ip(active2, dest, plen +
		                              active2->next_header_len);
	}
	else
		dest += build_uncompressed_ip(active1, dest, plen +
		                              active1->next_header_len);

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
		dest += g_context->build_next_header(g_context, active1, dest, plen);

	context->state = FULL_CONTEXT;

	/* update the inter-packet variable */
	update_inter_packet(g_context);

	/* copy the payload */
	rohc_debugf(3, "ROHC payload (length = %d bytes) starts at offset %d\n",
	            plen, packet - head);
	if(plen == 0)
		goto no_data;
	memcpy(dest, packet, plen);

	/* statistics */
	context->header_compressed_size += packet - head;
	c_add_wlsb(context->header_16_compressed, 0, 0, packet - head);
	context->header_uncompressed_size += dest - org_dest;
	c_add_wlsb(context->header_16_uncompressed, 0, 0, dest - org_dest);

	return (dest - org_dest) + plen;

no_data:
	return ROHC_OK_NO_DATA;
error:
	return ROHC_ERROR;
}


/**
 * @brief Decode one UO-0 or UO-1 packet.
 *
 * @param context       The decompression context
 * @param packet        The ROHC packet to decode
 * @param dest          The decoded IP packet
 * @param plen          IN/OUT: The length of the ROHC packet
 * @param sn_bits       The SN bits as they are transmitted in the ROHC packet
 * @param nb_of_sn_bits The number of bits that code the SN field
 * @param id            The outer IP-ID
 * @param nb_of_id_bits The number of bits that code the outer IP-ID field
 * @param id2           The inner IP-ID
 * @param sn            The SN value
 * @param calc_crc      The computed CRC 
 * @return              The length of the uncompressed IP packet,
 *                      -1 in case of error
 */
int do_decode_uo0_and_uo1(struct d_context *context,
                          const unsigned char *packet,
                          unsigned char *dest,
                          int *plen,
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
	int size;

	*sn = d_lsb_decode(&g_context->sn, sn_bits, nb_of_sn_bits);
	rohc_debugf(3, "SN = %d\n", *sn);

	/* random IP-ID in the outer IPv4 header ? */
	if(ip_get_version(active1->ip) == IPV4)
	{
		if(active1->rnd)
		{
			/* check if the ROHC packet is large enough to read
			 * the outer IPv4 header */
			if(*plen < 2)
			{
				rohc_debugf(0, "ROHC packet too small for outer IP-ID "
				               "(len = %d)\n", *plen);
				goto error;
			}

			*id = ntohs(*((uint16_t *) packet));
			packet += 2;
			*plen -= 2;
		}
		else
		{
			if(nb_of_id_bits)
				*id = d_ip_id_decode(&g_context->ip_id1, *id, nb_of_id_bits, *sn);
			else
				*id = d_ip_id_decode(&g_context->ip_id1, 0, 0, *sn);
		}

		ipv4_set_id(&active1->ip, htons(*id));
		rohc_debugf(3, "outer IP-ID = 0x%04x (rnd = %d, ID bits = %d)\n",
		            ntohs(ipv4_get_id(active1->ip)), active1->rnd, nb_of_id_bits);
	}

	/* random IP-ID in the inner IPv4 header ? */
	if(g_context->multiple_ip && ip_get_version(active2->ip) == IPV4)
	{
		if(active2->rnd)
		{
			/* check if the ROHC packet is large enough to read
			 * the inner IPv4 header */
			if(*plen < 2)
			{
				rohc_debugf(0, "ROHC packet too small for inner IP-ID "
				               "(len = %d)\n", *plen);
				goto error;
			}

			*id2 = ntohs(*((uint16_t *) packet));
			packet += 2;
			*plen -= 2;
		}
		else
			*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
		
		ipv4_set_id(&active2->ip, htons(*id2));
		rohc_debugf(3, "inner IP-ID = 0x%04x (rnd = %d)\n",
		            ntohs(ipv4_get_id(active2->ip)), active2->rnd);
	}

	/* decode the dynamic part of the UDP header */
	if(g_context->decode_dynamic_next_header != NULL)
	{
		size = g_context->decode_dynamic_next_header(g_context, packet,
		                                             *plen,
		                                             active1->next_header);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the next header dynamic part\n");
			goto error;
		}
		packet += size;
		*plen -= size;
	}

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		dest += build_uncompressed_ip(active1, dest, *plen +
		                              ip_get_hdrlen(active2->ip) +
		                              active1->next_header_len);
		dest += build_uncompressed_ip(active2, dest, *plen +
		                              active2->next_header_len);
	}
	else
		dest += build_uncompressed_ip(active1, dest, *plen +
		                              active1->next_header_len);

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
		dest += g_context->build_next_header(g_context, active1, dest, *plen);

	/* check CRC */
	*calc_crc = crc_calculate(CRC_TYPE_3, org_dest, dest - org_dest);
	rohc_debugf(3, "size = %d => CRC = 0x%x\n", dest - org_dest, *calc_crc);

	return dest - org_dest;

error:
	return -1;
}


/**
 * @brief Decode one UOR-2 packet.
 *
 * @param decomp       The ROHC decompressor
 * @param context      The decompression context
 * @param packet       The ROHC packet to decode
 * @param dest         The decoded IP packet
 * @param plen         IN/OUT: The length of the ROHC packet
 * @param id           The outer IP-ID
 * @param id2          The inner IP-ID
 * @param sn           The SN value
 * @param sn_size      The SN size
 * @param sn_bits      The SN bits as they are transmitted in the ROHC packet
 * @param ext          Whether the UOR-2 packet owns an extension or not
 * @param calc_crc     The computed CRC 
 * @return             The length of the uncompressed IP packet,
 *                     -1 in case of error
 */
int do_decode_uor2(struct rohc_decomp *decomp,
                   struct d_context *context,
                   unsigned char *packet,
                   unsigned char *dest,
                   int *plen,
                   int *id, int *id2,
                   int *sn, int *sn_size, int sn_bits,
                   int ext, int *calc_crc)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	unsigned char *org_dest = dest;
	int is_id2_updated = 0;
	int is_id_updated = 0;
	int size;

	*sn = sn_bits;

	/* does the packet own one extension? */
	if(ext)
	{
		/* check if the ROHC packet is large enough to read extension type */
		if(*plen < 1)
		{
			rohc_debugf(0, "ROHC packet too small for extension (len = %d)\n", *plen);
			goto error;
		}

		/* decode extension */
		switch(extension_type(packet))
		{
			case PACKET_EXT_0:
				/* check extension usage */
				if(ip_get_version(active1->ip) != IPV4)
				{
					rohc_debugf(0, "cannot use the extension 0 of the UOR-2 "
					               "packet with outer IPv6 header\n");
					goto error;
				}

				/* decode the extension */
				size = decode_extension0(packet, *plen, sn, id);
				if(size == -1)
				{
					rohc_debugf(0, "cannot decode the extension 0 of "
					               "the UOR-2 packet\n");
					goto error;
				}

				/* update SN and IP-ID according to the extension data */
				/* ip_id_bits = 3 */
				*sn_size = 8;
				*sn = d_lsb_decode(&g_context->sn, *sn, *sn_size);
				*id = d_ip_id_decode(&g_context->ip_id1, *id, 3, *sn);
				if(g_context->multiple_ip && ip_get_version(active2->ip) == IPV4)
					*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
				break;

			case PACKET_EXT_1:
				/* check extension usage */
				if(ip_get_version(active1->ip) != IPV4)
				{
					rohc_debugf(0, "cannot use the extension 1 of the UOR-2 "
					               "packet with outer IPv6 header\n");
					goto error;
				}

				/* decode the extension */
				size = decode_extension1(packet, *plen, sn, id);
				if(size == -1)
				{
					rohc_debugf(0, "cannot decode the extension 1 of "
					               "the UOR-2 packet\n");
					goto error;
				}

				/* update SN and IP-ID according to the extension data */
				/* ip_id bits = 11 */
				*sn_size = 8;
				*sn = d_lsb_decode(&g_context->sn, *sn, *sn_size);
				*id = d_ip_id_decode(&g_context->ip_id1, *id, 11, *sn);
				if(g_context->multiple_ip && ip_get_version(active2->ip) == IPV4)
					*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
				break;

			case PACKET_EXT_2:
				/* check extension usage */
				if(ip_get_version(active1->ip) != IPV4 ||
				   (g_context->multiple_ip && ip_get_version(active2->ip) != IPV4))
				{
					rohc_debugf(0, "cannot use the extension 2 of the UOR-2 "
					               "packet with outer or inner IPv6 header\n");
					goto error;
				}

				/* decode the extension */
				size = decode_extension2(packet, *plen, sn, id, id2);
				if(size == -1)
				{
					rohc_debugf(0, "cannot decode the extension 2 of "
					               "the UOR-2 packet\n");
					goto error;
				}

				/* update SN and IP-ID according to the extension data */
				/* ip_id bits = 8 */
				*sn_size = 8;
				*sn = d_lsb_decode(&g_context->sn, *sn, *sn_size);
				*id2 = d_ip_id_decode(&g_context->ip_id1, *id, 8, *sn); /* inner header */
				*id = d_ip_id_decode(&g_context->ip_id2, *id2, 11, *sn); /* outer header */
				break;

			case PACKET_EXT_3:
				/* check extension usage: nothing to do */
				
				/* decode the extension */
				*sn_size = 5;
				size = decode_extension3(decomp, context, packet, *plen, sn,
				                         sn_size, &is_id_updated, &is_id2_updated);
				if(size == -1)
				{
					rohc_debugf(0, "cannot decode the extension 3 of "
					               "the UOR-2 packet\n");
					goto error;
				}
				else if(is_id_updated && ip_get_version(active1->ip) != IPV4)
				{
					rohc_debugf(0, "extension 3 must not update the outer IP-ID "
					               "because the outer header is IPv6\n");
					goto error;
				}
				else if(is_id2_updated && (!g_context->multiple_ip ||
				        ip_get_version(active2->ip) != IPV4))
				{
					rohc_debugf(0, "extension 3 must not update the inner IP-ID "
					               "because the inner header is IPv6\n");
					goto error;
				}

				/* update SN (and IP-ID if IPv4) according to the extension data */
				*sn = d_lsb_decode(&g_context->sn, *sn, *sn_size);

				if(ip_get_version(active1->ip) == IPV4)
				{
					if(is_id_updated)
						*id = ntohs(ipv4_get_id(active1->ip));
					else
						*id = d_ip_id_decode(&g_context->ip_id1, 0, 0, *sn);
				}

				if(g_context->multiple_ip && ip_get_version(active2->ip) == IPV4)
				{
					if(is_id2_updated)
						*id2 = ntohs(ipv4_get_id(active2->ip));
					else
						*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
				}
				break;
			default:
				rohc_debugf(0, "unknown extension (%d)\n", extension_type(packet));
				goto error;
		}

		packet += size;
		*plen -= size;
	}
	else
	{
		rohc_debugf(3, "no extension to decode in UOR-2 packet\n");

		/* no extension */
		*sn_size = 5;
		
		/* update SN (and IP-ID if IPv4) */
		*sn = d_lsb_decode(&g_context->sn, *sn , *sn_size);
		if(ip_get_version(active1->ip) == IPV4)
			*id = d_ip_id_decode(&g_context->ip_id1, 0, 0, *sn);
		if(g_context->multiple_ip && ip_get_version(active2->ip) == IPV4)
			*id2 = d_ip_id_decode(&g_context->ip_id2, 0, 0, *sn);
	}

	rohc_debugf(3, "SN = %d\n", *sn);
	
	if(ip_get_version(active1->ip) == IPV4)
	{
		/* random outer IP-ID ? */
		if(active1->rnd)
		{
			*id = ntohs(*((uint16_t *) packet));
			rohc_debugf(3, "outer IP-ID = 0x%04x (RND)\n", *id);
			packet += 2;
			*plen -= 2;
		}
		else
			rohc_debugf(3, "outer IP-ID = 0x%04x\n", *id);
		
		/* set the IP-ID */
		ipv4_set_id(&active1->ip, htons(*id));
	}

	if(g_context->multiple_ip && ip_get_version(active2->ip) == IPV4)
	{
		/* random inner IP-ID ? */
		if(active2->rnd)
		{
			*id2 = ntohs(*((uint16_t *) packet));
			rohc_debugf(3, "inner IP-ID = 0x%04x (RND)\n", *id2);
			packet += 2;
			*plen -= 2;
		}
		else
			rohc_debugf(3, "inner IP-ID = 0x%04x\n", *id2);
		
		/* set the IP-ID */
		ipv4_set_id(&active2->ip, htons(*id2));
	}

	/* decode the dynamic part of the next header */
	if(g_context->decode_dynamic_next_header != NULL)
	{
		size = g_context->decode_dynamic_next_header(g_context, packet,
		                                             *plen,
		                                             active1->next_header);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the next header dynamic part\n");
			goto error;
		}
		packet += size;
		*plen -= size;
	}

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		dest += build_uncompressed_ip(active1, dest, *plen +
		                              ip_get_hdrlen(active2->ip) +
		                              active1->next_header_len);
		dest += build_uncompressed_ip(active2, dest, *plen +
		                              active2->next_header_len);
	}
	else
		dest += build_uncompressed_ip(active1, dest, *plen +
		                              active1->next_header_len);

	/* build the next header if necessary */
	if(g_context->build_next_header != NULL)
		dest += g_context->build_next_header(g_context, active1, dest, *plen);

	/* CRC check */
	*calc_crc = crc_calculate(CRC_TYPE_7, org_dest, dest - org_dest);
	rohc_debugf(3, "size = %d => CRC = 0x%x\n", dest - org_dest, *calc_crc);

	return dest - org_dest;

error:
	return -1;
}



/**
 * @brief Decode the extension 0 of the UOR-2 packet
 *
 * Actions taken:
 *  - SN value is expanded with 3 lower bits,
 *  - IP-ID is replaced with 3 bits.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param sn     The updated SN value
 * @param ip_id  The IP-ID value
 * @return       The data length read from the ROHC packet,
 *               -1 in case of error
 */
int decode_extension0(unsigned char *packet,
                      unsigned int length,
                      int *sn, int *ip_id)
{
	int read = 0;

	rohc_debugf(3, "decode UOR-2 extension 0\n");

	/* check the minimal length to decode the extension 0 */
	if(length < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	*sn = (*sn << 3) | GET_BIT_3_5(packet);
	*ip_id = GET_BIT_0_2(packet);
	packet++;
	read++;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the extension 1 of the UOR-2 packet
 *
 * Actions taken:
 *  - SN value is expanded with 3 lower bits,
 *  - IP-ID is replaced with 11 bits.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param sn     The updated SN value
 * @param ip_id  The IP-ID
 * @return       The data length read from the ROHC packet,
 *               -1 in case of error
 */
int decode_extension1(unsigned char *packet, unsigned int length,
                      int *sn, int *ip_id)
{
	int read = 0;

	rohc_debugf(3, "decode UOR-2 extension 1\n");

	/* check the minimal length to decode the extension 1 */
	if(length < 2)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	*sn = (*sn << 3) | GET_BIT_3_5(packet);
	*ip_id = GET_BIT_0_2(packet);
	packet++;
	read++;

	*ip_id = (*ip_id << 8) | *packet;
	packet++;
	read++;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the extension 2 of the UOR-2 packet
 *
 * Actions taken:
 *  - SN value is expanded with 3 lower bits,
 *  - IP-ID is replaced with 8 bits.
 *
 * @param packet The ROHC packet to decode
 * @param length The length of the ROHC packet
 * @param sn     The updated SN value
 * @param ip_id  The inner IP-ID
 * @param ip_id2 The outer IP-ID
 * @return       The data length read from the ROHC packet,
 *               -1 in case of error
 */
int decode_extension2(unsigned char *packet, unsigned int length,
                      int *sn, int *ip_id, int *ip_id2)
{
	int read = 0;

	rohc_debugf(3, "decode UOR-2 extension 2\n");

	/* check the minimal length to decode the extension 2 */
	if(length < 3)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* get the SN and 8 bits of the outer IP-ID */
	*sn = (*sn << 3) | GET_BIT_3_5(packet);
	*ip_id2 = GET_BIT_0_2(packet);
	packet++;
	read++;

	/* get the last bits of the outer IP-ID */
	*ip_id2 = (*ip_id2 << 8) | *packet;
	packet++;
	read++;

	/* get the inner IP-ID */
	*ip_id = *packet;
	packet++;
	read++;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the extension 3 of the UOR-2 packet
 *
 * Actions taken:
 *  - update random fields in the header changes,
 *  - the SN is eventually expanded with 8 lower bits.
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param packet          The ROHC packet to decode
 * @param length          The length of the ROHC packet
 * @param sn              IN/OUT: The updated SN value
 * @param sn_size         IN/OUT: The new SN size
 * @param is_id_updated   OUT: Whether the outer IP-ID is updated by the
 *                             extension or not
 * @param is_id2_updated  OUT: Whether the inner IP-ID is updated by the
 *                             extension ornnot
 * @return                The data length read from the ROHC packet,
 *                        -1 in case of error
 */
int decode_extension3(struct rohc_decomp *decomp,
                      struct d_context *context,
                      unsigned char *packet,
                      unsigned int length,
                      int *sn,
                      int *sn_size,
                      int *is_id_updated,
                      int *is_id2_updated)
{
	struct d_generic_context *g_context = context->specific;
	struct d_generic_changes *active1 = g_context->active1;
	struct d_generic_changes *active2 = g_context->active2;
	unsigned char *org = packet;
	unsigned char *fields  = packet + 1;
	int S, mode, I, ip, ip2;
	int size;

	rohc_debugf(3, "decode UOR-2 extension 3\n");

	/* check the minimal length to decode the flags */
	if(length < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* extract flags */
	S = GET_REAL(GET_BIT_5(packet));
	mode = GET_BIT_3_4(packet);
	I = GET_REAL(GET_BIT_2(packet));
	ip = GET_REAL(GET_BIT_1(packet));
	ip2 = GET_REAL(GET_BIT_0(packet));
	rohc_debugf(3, "S = %d, mode = 0x%x, I = %d, ip = %d, ip2 = %d\n",
	            S, mode, I, ip, ip2);
	packet++;
	length--;

	/* check the minimal length to decode the first bytes */
	if(length < ip + ip2 + S)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

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
		length--;
	}

	/* decode the inner IP header fields (pointed by fields) according to the
	 * inner IP header flags (pointed by packet) if present */
	if(ip)
	{
		if(g_context->multiple_ip)
			size = decode_inner_header_flags(packet, fields, length, active2);
		else
			size = decode_inner_header_flags(packet, fields, length, active1);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the inner IP header flags & fields\n");
			goto error;
		}
		fields += size;
		length -= size;
	}

	/* check the minimal length to decode the IP-ID field */
	if(length < fields - org + I * 2)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* decode the IP-ID if present */
	if(I)
	{
		if(g_context->multiple_ip)
		{
			ipv4_set_id(&active2->ip, *((uint16_t *) fields));
			rohc_debugf(3, "inner IP-ID changed (0x%04x)\n",
			            ntohs(ipv4_get_id(active2->ip)));
			fields += 2;
			length -= 2;
			*is_id_updated = 0;
			*is_id2_updated = 1;
		}
		else
		{
			ipv4_set_id(&active1->ip, *((uint16_t *) fields));
			rohc_debugf(3, "outer IP-ID changed (0x%04x)\n",
			            ntohs(ipv4_get_id(active1->ip)));
			fields += 2;
			length -= 2;
			*is_id_updated = 1;
			*is_id2_updated = 0;
		}
	}
	else
	{
		*is_id_updated = 0;
		*is_id2_updated = 0;
	}

	/* decode the outer IP header fields (pointed by fields) according to the
	 * outer IP header flags (pointed by packet) if present */
	if(ip2)
	{
		size = decode_outer_header_flags(packet, fields, length,
		                                 active1, is_id_updated);
		if(size == -1)
		{
			rohc_debugf(0, "cannot decode the outer IP header flags & fields\n");
			goto error;
		}
		fields += size;
		length -= size;
	}

	if(mode != context->mode)
	{
		rohc_debugf(2, "mode is not equal on decomp and comp.\n");
		d_change_mode_feedback(decomp, context);
	}

	return (fields - org);

error:
	return -1;
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
 * Store the values in an IP header info structure.
 *
 * \verbatim

  Inner IP header flags (5.7.5):

       0     1     2     3     4     5     6     7
     ..... ..... ..... ..... ..... ..... ..... .....
    | TOS | TTL | DF  | PR  | IPX | NBO | RND | ip2 |  if ip = 1
     ..... ..... ..... ..... ..... ..... ..... .....

  Inner IP header fields (5.7.5):

    ..... ..... ..... ..... ..... ..... ..... .....
   |         Type of Service/Traffic Class         |  if TOS = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   |         Time to Live/Hop Limit                |  if TTL = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   |         Protocol/Next Header                  |  if PR = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   /         IP extension headers                  /  variable,
    ..... ..... ..... ..... ..... ..... ..... .....   if IPX = 1

\endverbatim
 *
 * @param flags  The ROHC flags that indicate which IP fields are present
 *               in the packet
 * @param fields The ROHC packet part that contains some IP header fields
 * @param length The length of the ROHC packet part that contains some IP
 *               header fields
 * @param info   The IP header info to store the decoded values in
 * @return       The data length read from the ROHC packet,
 *               -1 in case of error
 */
int decode_inner_header_flags(unsigned char *flags,
                              unsigned char *fields,
                              unsigned int length,
                              struct d_generic_changes *info)
{
	int is_tos, is_ttl, is_pr, is_ipx;
	int df, nbo, rnd;
	int read = 0;

	/* get the inner IP header flags */
	is_tos = GET_REAL(GET_BIT_7(flags));
	is_ttl = GET_REAL(GET_BIT_6(flags));
	df = GET_REAL(GET_BIT_5(flags));
	is_pr = GET_REAL(GET_BIT_4(flags));
	is_ipx = GET_REAL(GET_BIT_3(flags));
	nbo = GET_REAL(GET_BIT_2(flags));
	rnd = GET_REAL(GET_BIT_1(flags));
	rohc_debugf(3, "header flags: TOS = %d, TTL = %d, PR = %d, IPX = %d\n",
	            is_tos, is_ttl, is_pr, is_ipx);

	/* check the minimal length to decode the header fields */
	if(length < is_tos + is_ttl + is_pr /* TODO: list compression */)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* get the TOS/TC field if present */
	if(is_tos)
	{
		ip_set_tos(&info->ip, *fields);
		rohc_debugf(3, "TOS/TC = 0x%02x\n", *fields);
		fields++;
		read++;
	}

	/* get the TTL/HL field if present */
	if(is_ttl)
	{
		ip_set_ttl(&info->ip, *fields);
		rohc_debugf(3, "TTL/HL = 0x%02x\n", *fields);
		fields++;
		read++;
	}

	/* get the DF flag if IPv4 */
	if(ip_get_version(info->ip) == IPV4)
	{
		ipv4_set_df(&info->ip, df);
		rohc_debugf(3, "DF = %d\n", ipv4_get_df(info->ip));
	}
	else if(df) /* IPv6 and DF flag set */
	{
		rohc_debugf(0, "DF flag set and IP header is IPv6\n");
		goto error;
	}

	/* get the Protocol field if present */
	if(is_pr)
	{
		ip_set_protocol(&info->ip, *fields);
		rohc_debugf(3, "Protocol/Next Header = 0x%02x\n", *fields);
		fields++;
		read++;
	}

	/* get the IP extension headers */
	if(is_ipx)
	{
		/* TODO: list compression */
		rohc_debugf(0, "list compression is not supported\n");
	}

	/* get the NBO and RND flags if IPv4 */
	if(ip_get_version(info->ip) == IPV4)
	{
		info->nbo = nbo;
		info->rnd = rnd;
	}
	else
	{
		/* IPv6 and NBO flag set */
		if(nbo)
		{
			rohc_debugf(0, "NBO flag set and IP header is IPv6\n");
			goto error;
		}

		/* IPv6 and RND flag set */
		if(rnd)
		{
			rohc_debugf(0, "RND flag set and IP header is IPv6\n");
			goto error;
		}
	}

	return read;

error:
	return -1;
}


/**
 * @brief Decode the outer IP header flags and fields.
 *
 * Store the values in an IP header info structure.
 *
 * \verbatim

  Outer IP header flags (5.7.5):

       0     1     2     3     4     5     6     7
     ..... ..... ..... ..... ..... ..... ..... .....
    | TOS2| TTL2| DF2 | PR2 |IPX2 |NBO2 |RND2 |  I2 |  if ip2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....

  Outer IP header fields

     ..... ..... ..... ..... ..... ..... ..... .....
    |      Type of Service/Traffic Class            |  if TOS2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    |         Time to Live/Hop Limit                |  if TTL2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    |         Protocol/Next Header                  |  if PR2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    /         IP extension header(s)                /  variable,
     ..... ..... ..... ..... ..... ..... ..... .....    if IPX2 = 1
    |                  IP-ID                        |  2 octets,
     ..... ..... ..... ..... ..... ..... ..... .....    if I2 = 1

\endverbatim
 *
 * @param flags      The ROHC flags that indicate which IP fields are present
 *                   in the packet
 * @param fields     The ROHC packet part that contain some IP header fields
 * @param length     The length of the ROHC packet part that contains some IP
 *                   header fields
 * @param info       The IP header info to store the decoded values in
 * @param updated_id The boolean to store whether the IP-ID is updated or not
 * @return           The data length read from the ROHC packet,
 *                   -1 in case of error
 */
int decode_outer_header_flags(unsigned char *flags,
                              unsigned char *fields,
                              unsigned int length,
                              struct d_generic_changes *info,
                              int *updated_id)
{
	int is_I2;
	int read;

	/* decode the some outer IP header flags and fields that are identical
	 * to inner IP header flags and fields */
	read = decode_inner_header_flags(flags, fields, length, info);
	if(read == -1)
		goto error;
	length -= read;

	/* get the other outer IP header flags */
	is_I2 = GET_REAL(GET_BIT_0(flags));
	rohc_debugf(3, "header flags: I2 = %d\n", is_I2);

	/* check the minimal length to decode the outer header fields */
	if(length < is_I2 * 2)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* get the outer IP-ID if IPv4 */
	if(is_I2)
	{
		if(ip_get_version(info->ip) != IPV4)
		{
			rohc_debugf(0, "IP-ID field present (I2 = 1) and "
			               "IP header is IPv6\n");
			goto error;
		}

		if(*updated_id)
		{
			rohc_debugf(0, "IP-ID field present (I2 = 1) but IP-ID already "
			               "updated\n");
			goto error;
		}

		ipv4_set_id(&info->ip, *((uint16_t *) fields));
		rohc_debugf(3, "IP-ID = 0x%04x\n", ntohs(ipv4_get_id(info->ip)));
		fields += 2;
		read += 2;
		*updated_id = 1;
	}
	else
		*updated_id = 0;

	return read;

error:
	return -1;
}


/**
 * @brief Build an uncompressed IP header.
 *
 * @param active       The IP header changes
 * @param dest         The buffer to store the IP header (MUST be at least
 *                     of sizeof(struct iphdr) or sizeof(struct ip6_hdr) bytes
 *                     depending on the IP version)
 * @param payload_size The length of the IP payload
 * @return             The length of the IP header
 */
unsigned int build_uncompressed_ip(struct d_generic_changes *active,
                                   unsigned char *dest,
                                   unsigned int payload_size)
{
	unsigned int length;

	if(ip_get_version(active->ip) == IPV4)
		length = build_uncompressed_ip4(active, dest, payload_size);
	else
		length = build_uncompressed_ip6(active, dest, payload_size);

	return length;
}


/**
 * @brief Build an uncompressed IPv4 header.
 *
 * @param active       The IPv4 header changes
 * @param dest         The buffer to store the IPv4 header (MUST be at least
 *                     of sizeof(struct iphdr) bytes)
 * @param payload_size The length of the IPv4 payload
 * @return             The length of the IPv4 header
 */
unsigned int build_uncompressed_ip4(struct d_generic_changes *active,
                                    unsigned char *dest,
                                    unsigned int payload_size)
{
	struct iphdr *ip = (struct iphdr *) dest;

	/* static & changing */
	memcpy(dest, &active->ip.header.v4, sizeof(struct iphdr));

	/* IP-ID: reverse the byte order if necessary */
	if(!active->nbo)
		ip->id = swab16(ip->id);
	rohc_debugf(3, "IP-ID = 0x%04x\n", ntohs(ip->id));

	/* static-known fields */
	ip->ihl = 5;
	rohc_debugf(3, "IHL = 0x%x\n", ip->ihl);

	/* interfered fields */
	ip->tot_len = htons(payload_size + ip->ihl * 4);
	rohc_debugf(3, "Total Length = 0x%04x (IHL * 4 + %d)\n",
	            ntohs(ip->tot_len), payload_size);
	ip->check = 0;
	ip->check = ip_fast_csum(dest, ip->ihl);
	rohc_debugf(3, "IP checksum = 0x%04x\n", ntohs(ip->check));

	return sizeof(struct iphdr);
}


/**
 * @brief Build an uncompressed IPv6 header.
 *
 * @param active       The IPv6 header changes
 * @param dest         The buffer to store the IPv6 header (MUST be at least
 *                     of sizeof(struct ip6_hdr) bytes)
 * @param payload_size The length of the IPv6 payload
 * @return             The length of the IPv6 header
 */
unsigned int build_uncompressed_ip6(struct d_generic_changes *active,
                                    unsigned char *dest,
                                    unsigned int payload_size)
{
	struct ip6_hdr *ip = (struct ip6_hdr *) dest;

	/* static & changing */
	memcpy(dest, &active->ip.header.v6, sizeof(struct ip6_hdr));

	/* interfered fields */
	ip->ip6_plen = htons(payload_size);
	rohc_debugf(3, "Payload Length = 0x%04x\n", ntohs(payload_size));

	return sizeof(struct ip6_hdr);
}


/**
 * @brief Try to repair the SN in one of two different ways.
 *
 * TODO: check this function
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
	unsigned int interval = 0;
	int sn_ref = 0;
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
		rohc_debugf(2, "inter_arrival_time = %u and current interval is = %u\n",
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
		rohc_debugf(2, "inter_arrival_time = %u and current interval is = %u\n",
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
	        memcmp(&first->ip, &second->ip, sizeof(struct ip_packet)) == 0 &&
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
	unsigned int last_time = context->last_packet_time;
	int delta = 0;

	rohc_debugf(2, "current time = %u and last time = %u\n",
	            context->current_packet_time, last_time);

	if(last_time)
		delta = context->current_packet_time - last_time;

	context->last_packet_time = context->current_packet_time;

	if(context->inter_arrival_time)
		context->inter_arrival_time = (context->inter_arrival_time >> WEIGHT_OLD)
		                              + (delta >> WEIGHT_NEW);
	else
		context->inter_arrival_time = delta;

	rohc_debugf(2, "inter_arrival_time = %u and current arrival delta is = %d\n",
	            context->inter_arrival_time, delta);
}

