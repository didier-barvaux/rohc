/**
 * @file crc.c
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "crc.h"
#include "rtp.h"
#include <netinet/udp.h>
#include <assert.h>


unsigned char crc_table_8[256];
unsigned char crc_table_7[256];
unsigned char crc_table_6[256];
unsigned char crc_table_3[256];
unsigned char crc_table_2[256];


static unsigned char *ipv6_get_first_extension(const unsigned char *ip,
                                               uint8_t *type);


/**
 * @brief Get the polynom for the CRC type.
 *
 * @param type The CRC type
 * @return     The polynom for the requested CRC type
 */
int crc_get_polynom(int type)
{
	int polynom;

	switch(type)
	{
		case CRC_TYPE_2:
			polynom = 0x3;
			break;
		case CRC_TYPE_3:
			polynom = 0x6;
			break;
		case CRC_TYPE_6:
			polynom = 0x30;
			break;
		case CRC_TYPE_7:
			polynom = 0x79;
			break;
		case CRC_TYPE_8:
			polynom = 0xe0;
			break;
		default:
			polynom = 0;
			break;
	}

	return polynom;
}


/**
 * @brief Initialize a table given a 256 bytes table and the polynom to use
 *
 * @param table The 256 bytes table
 * @param poly  The polynom
 */
void crc_init_table(unsigned char *table, unsigned char poly)
{
	unsigned char crc;
	int i, j;

	for(i = 0; i < 256; i++)
	{
		crc = i;

		for(j = 0; j < 8; j++)
		{
			if(crc & 1)
				crc = (crc >> 1) ^ poly;
			else
				crc = crc >> 1;
		}

		table[i] = crc;
	}
}


/**
 * @brief Optimized CRC-8 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_8(unsigned char *buf,
                                int size,
                                unsigned int init_val)
{
	int i;
	unsigned char crc = init_val;

	for(i = 0; i < size; i++)
		crc = crc_table_8[buf[i] ^ crc];

	return crc;
}


/**
 * @brief Optimized CRC-7 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_7(unsigned char *buf,
                                int size,
                                unsigned int init_val)
{
	int i;
	unsigned char crc = init_val;

	for(i = 0; i < size; i++)
		crc = crc_table_7[buf[i] ^ (crc & 127)];

	return crc;
}

/**
 * @brief Optimized CRC-6 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_6(unsigned char *buf,
                                int size,
                                unsigned int init_val)
{
	int i;
	unsigned char crc = init_val;

	for(i = 0; i < size; i++)
		crc = crc_table_6[buf[i] ^ (crc & 63)];

	return crc;
}

/**
 * @brief Optimized CRC-3 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_3(unsigned char *buf,
                                int size,
                                unsigned int init_val)
{
	int i;
	unsigned char crc = init_val;

	for(i = 0; i < size; i++)
		crc = crc_table_3[buf[i] ^ (crc & 7)];

	return crc;
}

/**
 * @brief Optimized CRC-2 calculation using a table
 *
 * @param buf  The data to compute the CRC for
 * @param size The size of the data
 * @return     The CRC byte
 */
inline unsigned char crc_calc_2(unsigned char *buf,
                                int size,
                                unsigned int init_val)
{
	int i;
	unsigned char crc = init_val;

	for(i = 0; i < size; i++)
		crc = crc_table_2[buf[i] ^ (crc & 3)];

	return crc;
}

/**
 * @brief Calculate the checksum for the given data.
 *
 * @param type     The CRC type (CRC_TYPE_2, CRC_TYPE_3, CRC_TYPE_6, CRC_TYPE_7 or CRC_TYPE_8)
 * @param data     The data to calculate the checksum on
 * @param length   The length of the data
 * @param init_val The initial CRC value
 * @return         The checksum
 */
unsigned int crc_calculate(int type,
                           unsigned char *data, 
                           int length,
                           unsigned int init_val)
{
	unsigned int crc;

	switch(type)
	{
		case CRC_TYPE_8:
			crc = crc_calc_8(data, length, init_val);
			break;
		case CRC_TYPE_7:
			crc = crc_calc_7(data, length, init_val);
			break;
		case CRC_TYPE_6:
			crc = crc_calc_6(data, length, init_val);
			break;
		case CRC_TYPE_3:
			crc = crc_calc_3(data, length, init_val);
			break;
		case CRC_TYPE_2:
			crc = crc_calc_2(data, length, init_val);
			break;
		default:
			crc = 0;
			break;
	}

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of an IP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-2, 7-10, 13-20 in original IPv4 header
 *    - bytes 1-4, 7-40 in original IPv6 header
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @return            The checksum
 */
unsigned int compute_crc_static(const unsigned char *ip,
                                const unsigned char *ip2,
                                const unsigned char *next_header,
                                unsigned int crc_type,
                                unsigned int init_val)
{
	unsigned int crc;
	ip_version version;
	int ret;

	assert(ip != NULL);

	ret = get_ip_version(ip, 2,  &version);
	assert(ret);

	crc = init_val;

	/* first IPv4 header */
	if(version == IPV4)
	{
		struct iphdr *ip_hdr = (struct iphdr *) ip;
		/* bytes 1-2 (Version, Header length, TOS) */
		crc = crc_calculate(crc_type,
		                    (unsigned char *)(ip_hdr), 2, crc);
		/* bytes 7-10 (Flags, Fragment Offset, TTL, Protocol) */
		crc = crc_calculate(crc_type,
		                    (unsigned char *)(&ip_hdr->frag_off), 4, crc);
		/* bytes 13-20 (Source Address, Destination Address) */
		crc = crc_calculate(crc_type,
		                    (unsigned char *)(&ip_hdr->saddr), 8, crc);
	}
	else /* first IPv6 header */
	{
		struct ip6_hdr *ip_hdr = (struct ip6_hdr *) ip;
		/* bytes 1-4 (Version, TC, Flow Label) */
		crc = crc_calculate(crc_type,
		                    (unsigned char *)(&ip_hdr->ip6_flow),
		                    4, crc);
		/* bytes 7-40 (Next Header, Hop Limit, Source Address, Destination Address) */
		crc = crc_calculate(crc_type,
		                    (unsigned char *)(&ip_hdr->ip6_nxt),
		                    34, crc);
		/* IPv6 extensions */
		crc = ipv6_ext_compute_crc_static(ip, crc_type, crc);
	}

	/* second header */
	if(ip2 != NULL)
	{
		ret = get_ip_version(ip2, 2, &version);
		assert(ret);

		/* IPv4 */
		if(version == IPV4)
		{
			struct iphdr *ip2_hdr = (struct iphdr *) ip;
			/* bytes 1-2 (Version, Header length, TOS) */
			crc = crc_calculate(crc_type,
			                    (unsigned char *)(ip2_hdr), 2, crc);
			/* bytes 7-10 (Flags, Fragment Offset, TTL, Protocol) */
			crc = crc_calculate(crc_type,
			                    (unsigned char *)(&ip2_hdr->frag_off), 4, crc);
			/* bytes 13-20 (Source Address, Destination Address) */
			crc = crc_calculate(crc_type,
			                    (unsigned char *)(&ip2_hdr->saddr), 8, crc);
		}
		else /* IPv6 */
		{
			struct ip6_hdr *ip2_hdr = (struct ip6_hdr *) ip2;
			/* bytes 1-4 (Version, TC, Flow Label) */
			crc = crc_calculate(crc_type,
			                    (unsigned char *)(&ip2_hdr->ip6_flow),
			                    4, crc);
			/* bytes 7-40 (Next Header, Hop Limit, Source Address, Destination Address) */
			crc = crc_calculate(crc_type,
			                    (unsigned char *)(&ip2_hdr->ip6_nxt),
			                    34, crc);
			/* IPv6 extensions */
			crc = ipv6_ext_compute_crc_static(ip2, crc_type, crc);
		}
	}

	return crc;
}



/**
 * @brief Compute the CRC-DYNAMIC part of an IP header
 *
 * Concerned fields are:
 *   - bytes 3-4, 5-6, 11-12 in original IPv4 header
 *   - bytes 5-6 in original IPv6 header
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @return            The checksum
 */
unsigned int compute_crc_dynamic(const unsigned char *ip,
                                 const unsigned char *ip2,
                                 const unsigned char *next_header,
                                 unsigned int crc_type,
                                 unsigned int init_val)
{
	unsigned int crc;
	ip_version version;
	int ret;

	assert(ip != NULL);

	ret = get_ip_version(ip, 2, &version);
	assert(ret);

	crc = init_val;

	/* first IPv4 header */
	if(version == IPV4)
	{
		struct iphdr *ip_hdr = (struct iphdr *) ip;
		/* bytes 3-6 (Total Length, Identification) */
		crc = crc_calculate(crc_type,
		                    (unsigned char *)(&ip_hdr->id), 4, crc);
		/* bytes 11-12 (Header Checksum) */
		crc = crc_calculate(crc_type,
		                    (unsigned char *)(&ip_hdr->check), 2, crc);
	}
	else /* first IPv6 header */
	{
		struct ip6_hdr *ip_hdr = (struct ip6_hdr *) ip;
		/* bytes 5-6 (Payload Length) */
		crc = crc_calculate(crc_type,
		                    (unsigned char *)(&ip_hdr->ip6_plen),
		                    2, crc);
		/* IPv6 extensions (only AH is CRC-DYNAMIC) */
		crc = ipv6_ext_compute_crc_dynamic(ip, crc_type, crc);
	}

	/* second_header */
	if(ip2 != NULL)
	{
		ret = get_ip_version(ip2, 2, &version);
		assert(ret);

		/* IPv4 */
		if(version == IPV4)
		{
			struct iphdr *ip2_hdr = (struct iphdr *) ip2;
			/* bytes 3-6 (Total Length, Identification) */
			crc = crc_calculate(crc_type,
			                    (unsigned char *)(&ip2_hdr->id), 4, crc);
			/* bytes 11-12 (Header Checksum) */
			crc = crc_calculate(crc_type,
			                    (unsigned char *)(&ip2_hdr->check), 2, crc);
		}
		else /* IPv6 */
		{
			struct ip6_hdr *ip2_hdr = (struct ip6_hdr *) ip2;
			/* bytes 5-6 (Payload Length) */
			crc = crc_calculate(crc_type,
			                    (unsigned char *)(&ip2_hdr->ip6_plen),
			                    2, crc);
			/* IPv6 extensions (only AH is CRC-DYNAMIC) */
			crc = ipv6_ext_compute_crc_dynamic(ip2, crc_type, crc);
		}
	}

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of an UDP or UDO-Lite header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-4 in original UDP header
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @return            The checksum
 */
unsigned int udp_compute_crc_static(const unsigned char *ip,
                                    const unsigned char *ip2,
                                    const unsigned char *next_header,
                                    unsigned int crc_type,
                                    unsigned int init_val)
{
	unsigned int crc;
	struct udphdr *udp;

	assert(ip != NULL);
	assert(next_header != NULL);

	crc = init_val;

	/* compute the CRC-STATIC value for IP and IP2 headers */
	crc = compute_crc_static(ip, ip2, next_header, crc_type, crc);

	/* get the start of UDP header */
	udp = (struct udphdr *) next_header;

	/* bytes 1-4 (Source Port, Destination Port) */
	crc = crc_calculate(crc_type, (unsigned char *)(&udp->source), 4, crc);

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an UDP or UDP-Lite header
 *
 * Concerned fields are:
 *   - bytes 5-6, 7-8 in original UDP header
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @return            The checksum
 */
unsigned int udp_compute_crc_dynamic(const unsigned char *ip,
                                     const unsigned char *ip2,
                                     const unsigned char *next_header,
                                     unsigned int crc_type,
                                     unsigned int init_val)
{
	unsigned int crc;
	struct udphdr *udp;

	assert(ip != NULL);
	assert(next_header != NULL);

	crc = init_val;

	/* compute the CRC-DYNAMIC value for IP and IP2 headers */
	crc = compute_crc_dynamic(ip, ip2, next_header, crc_type, crc);

	/* get the start of UDP header */
	udp = (struct udphdr *) next_header;

	/* bytes 5-8 (Length, Checksum) */
	crc = crc_calculate(crc_type, (unsigned char *)(&udp->len), 4, crc);

	return crc;
}

/**
 * @brief Compute the CRC-STATIC part of a RTP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1, 9-12 (and CSRC list) in original RTP header
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @return            The checksum
 */
unsigned int rtp_compute_crc_static(const unsigned char *ip,
                                    const unsigned char *ip2,
                                    const unsigned char *next_header,
                                    unsigned int crc_type,
                                    unsigned int init_val)
{
	unsigned int crc;
	struct rtphdr *rtp;

	assert(ip != NULL);
	assert(next_header != NULL);

	crc = init_val;

	/* compute the CRC-STATIC value for IP, IP2 and UDP headers */
	crc = udp_compute_crc_static(ip, ip2, next_header, crc_type, crc);

	/* get the start of RTP header */
	rtp = (struct rtphdr *) (next_header + sizeof(struct udphdr));

	/* byte 1 (Version, P, X, CC) */
	crc = crc_calculate(crc_type, (unsigned char *)rtp, 1, crc);

	/* bytes 9-12 (SSRC identifier) */
	crc = crc_calculate(crc_type, (unsigned char *)(&rtp->ssrc), 4, crc);

	/* TODO CSRC identifiers */

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of a RTP header
 *
 * Concerned fields are:
 *   - bytes 2, 3-4, 5-8 in original RTP header
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @return            The checksum
 */
unsigned int rtp_compute_crc_dynamic(const unsigned char *ip,
                                     const unsigned char *ip2,
                                     const unsigned char *next_header,
                                     unsigned int crc_type,
                                     unsigned int init_val)
{
	unsigned int crc;
	struct rtphdr *rtp;

	assert(ip != NULL);
	assert(next_header != NULL);

	crc = init_val;

	/* compute the CRC-DYNAMIC value for IP, IP2 and UDP headers */
	crc = udp_compute_crc_dynamic(ip, ip2, next_header, crc_type, crc);

	/* get the start of RTP header */
	rtp = (struct rtphdr *) (next_header + sizeof(struct udphdr));

	/* bytes 2-8 (Payload Type, Sequence Number, Timestamp) */
	crc = crc_calculate(crc_type, (unsigned char *)(rtp) + 1, 7, crc);

	return crc;
}

/**
 * @brief Compute the CRC-STATIC part of IPv6 extensions
 *
 * All extensions are concerned except entire AH header.
 *
 * @param ip          The IPv6 packet
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @return            The checksum
 */
unsigned int ipv6_ext_compute_crc_static(const unsigned char *ip,
                                         unsigned int crc_type,
                                         unsigned int init_val)
{
	unsigned int crc;
	unsigned char *ext;
	uint8_t ext_type;

	crc = init_val;

	ext = ipv6_get_first_extension(ip, &ext_type);
	while(ext != NULL)
	{
		if(ext_type != AUTH)
		{
			crc = crc_calculate(crc_type, ext, ip_get_extension_size(ext), crc);
		}
		ext = ip_get_next_ext_header_from_ext(ext, &ext_type);
	}

	return crc;
}

/**
 * @brief Compute the CRC-DYNAMIC part of IPv6 extensions
 *
 * Only entire AH header is concerned.
 *
 * @param ip          The IPv6 packet
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @return            The checksum
 */
unsigned int ipv6_ext_compute_crc_dynamic(const unsigned char *ip,
                                          unsigned int crc_type,
                                          unsigned int init_val)
{
	unsigned int crc;
	unsigned char *ext;
	uint8_t ext_type;

	crc = init_val;

	ext = ipv6_get_first_extension(ip, &ext_type);
	while(ext != NULL)
	{
		if(ext_type == AUTH)
		{
			crc = crc_calculate(crc_type, ext, ip_get_extension_size(ext), crc);
		}
		ext = ip_get_next_ext_header_from_ext(ext, &ext_type);
	}

	return crc;
}

/**
 * @brief Get the first extension in an IPv6 packet
 *
 * @param ip   The IPv6 packet
 * @param type The type of the extension
 * @return     The extension, NULL if there is no extension
 */
static unsigned char *ipv6_get_first_extension(const unsigned char *ip,
                                               uint8_t *type)
{
	struct ip6_hdr *ip_hdr;

	ip_hdr = (struct ip6_hdr *)ip;
	*type = ip_hdr->ip6_nxt;
	switch (*type)
	{
		case HOP_BY_HOP:
		case DESTINATION:
		case ROUTING:
		case AUTH: //extension header
			break;
		default:
			goto end;
	}

	return (unsigned char *)(ip + sizeof(struct ip6_hdr));
end:
	return NULL;
}

