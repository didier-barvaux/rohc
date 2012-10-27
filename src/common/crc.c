/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file crc.c
 * @brief ROHC CRC routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 * @author Didier Barvaux <didier@barvaux.org>
 * @author FWX <rohc_team@dialine.fr>
 */

#include "crc.h"
#include "protocols/udp.h"
#include "protocols/rtp.h"
#include "protocols/esp.h"
#include "protocols/tcp.h"
#include "rohc_traces.h" // FWX2

#include <stdlib.h>
#include <assert.h>


/* TODO API: remove these variables once compatibility is not needed anymore */
unsigned char crc_table_8[256];
unsigned char crc_table_7[256];
unsigned char crc_table_6[256];
unsigned char crc_table_3[256];
unsigned char crc_table_2[256];


/**
 * Prototypes of private functions
 */

static unsigned int ipv6_ext_calc_crc_static(const unsigned char *const ip,
                                             const rohc_crc_type_t crc_type,
                                             const unsigned int init_val,
                                             const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static unsigned int ipv6_ext_calc_crc_dyn(const unsigned char *const ip,
                                          const rohc_crc_type_t crc_type,
                                          const unsigned int init_val,
                                          const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static unsigned char * ipv6_get_first_extension(const unsigned char *const ip,
                                                uint8_t *const type)
	__attribute__((nonnull(1, 2)));


static bool rohc_crc_get_polynom(const rohc_crc_type_t crc_type,
                                 unsigned char *const polynom)
	__attribute__((nonnull(2), warn_unused_result));


static inline unsigned char crc_calc_8(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static inline unsigned char crc_calc_7(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char const *crc_table)
	__attribute__((nonnull(1, 4)));
static inline unsigned char crc_calc_6(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static inline unsigned char crc_calc_3(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static inline unsigned char crc_calc_2(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));



/**
 * Public functions
 */


/**
 * @brief Get the polynom for the given CRC type.
 *
 * @deprecated please do not use crc_get_polynom anymore,
 *             simply remove it from your code
 *
 * @param type The CRC type
 * @return     The polynom for the requested CRC type
 *
 * @ingroup rohc_common
 */
int crc_get_polynom(int type)
{
	/* nothing to do here: CRC tables are initialized in compressors and
	 * decompressors */
	return 0;
}


/**
 * @brief Initialize a CRC table given a 256-byte table and the polynom to use
 *
 * @deprecated please do not use crc_init_table anymore,
 *             simply remove it from your code
 *
 * @param table The 256-byte table
 * @param poly  The polynom
 *
 * @ingroup rohc_common
 */
void crc_init_table(unsigned char *table, unsigned char poly)
{
	/* nothing to do here: CRC tables are initialized in compressors and
	 * decompressors */
}


/**
 * @brief Initialize a CRC table given a 256-byte table and the CRC type to use
 *
 * @param table     IN/OUT: The 256-byte table to initialize
 * @param crc_type  The type of CRC to initialize the table for
 * @return          true in case of success, false in case of failure
 */
bool rohc_crc_init_table(unsigned char *const table,
                         const rohc_crc_type_t crc_type)
{
	unsigned char crc;
	unsigned char polynom;
	bool is_fine;
	int i, j;

	/* sanity check */
	assert(table != NULL);

	/* determine the polynom to use */
	is_fine = rohc_crc_get_polynom(crc_type, &polynom);
	if(is_fine != true)
	{
		goto error;
	}

	/* fill the CRC table */
	for(i = 0; i < 256; i++)
	{
		crc = i;

		for(j = 0; j < 8; j++)
		{
			if(crc & 1)
			{
				crc = (crc >> 1) ^ polynom;
			}
			else
			{
				crc = crc >> 1;
			}
		}

		table[i] = crc;
	}

	/* everything went fine */
	return true;

error:
	return false;
}


/**
 * @brief Calculate the checksum for the given data.
 *
 * @param crc_type   The CRC type
 * @param data       The data to calculate the checksum on
 * @param length     The length of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The checksum
 */
unsigned int crc_calculate(const rohc_crc_type_t crc_type,
                           const unsigned char *const data,
                           const int length,
                           const unsigned int init_val,
                           const unsigned char *const crc_table)
{
	unsigned int crc;

	/* sanity checks */
	assert(data != NULL);
	assert(crc_table != NULL);

	/* call the function that corresponds to the CRC type */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_8:
			crc = crc_calc_8(data, length, init_val, crc_table);
			break;
		case ROHC_CRC_TYPE_7:
			crc = crc_calc_7(data, length, init_val, crc_table);
			break;
		case ROHC_CRC_TYPE_6:
			crc = crc_calc_6(data, length, init_val, crc_table);
			break;
		case ROHC_CRC_TYPE_3:
			crc = crc_calc_3(data, length, init_val, crc_table);
			break;
		case ROHC_CRC_TYPE_2:
			crc = crc_calc_2(data, length, init_val, crc_table);
			break;
		default:
			/* undefined CRC type, should not happen */
			assert(0);
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
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int compute_crc_static(const unsigned char *const ip,
                                const unsigned char *const ip2,
                                const unsigned char *const next_header,
                                const rohc_crc_type_t crc_type,
                                const unsigned int init_val,
                                const unsigned char *const crc_table)
{
	unsigned int crc;
	ip_version version;
	int ret;

	assert(ip != NULL);
	assert(crc_table != NULL);

	ret = get_ip_version(ip, 2,  &version);
	assert(ret);

	crc = init_val;

	/* first IPv4 header */
	if(version == IPV4)
	{
		struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) ip;

		/* bytes 1-2 (Version, Header length, TOS) */
		crc = crc_calculate(crc_type, (unsigned char *)(ip_hdr), 2,
		                    crc, crc_table);
		/* bytes 7-10 (Flags, Fragment Offset, TTL, Protocol) */
		crc = crc_calculate(crc_type, (unsigned char *)(&ip_hdr->frag_off), 4,
		                    crc, crc_table);
		/* bytes 13-20 (Source Address, Destination Address) */
		crc = crc_calculate(crc_type, (unsigned char *)(&ip_hdr->saddr), 8,
		                    crc, crc_table);
	}
	else /* first IPv6 header */
	{
		struct ipv6_hdr *ip_hdr = (struct ipv6_hdr *) ip;

		/* bytes 1-4 (Version, TC, Flow Label) */
		crc = crc_calculate(crc_type, (unsigned char *)(&ip_hdr->ip6_flow), 4,
		                    crc, crc_table);
		/* bytes 7-40 (Next Header, Hop Limit, Source Address, Destination Address) */
		crc = crc_calculate(crc_type, (unsigned char *)(&ip_hdr->ip6_nxt), 34,
		                    crc, crc_table);
		/* IPv6 extensions */
		crc = ipv6_ext_calc_crc_static(ip, crc_type, crc, crc_table);
	}

	/* second header */
	if(ip2 != NULL)
	{
		ret = get_ip_version(ip2, 2, &version);
		assert(ret);

		/* IPv4 */
		if(version == IPV4)
		{
			struct ipv4_hdr *ip2_hdr = (struct ipv4_hdr *) ip2;

			/* bytes 1-2 (Version, Header length, TOS) */
			crc = crc_calculate(crc_type, (unsigned char *)(ip2_hdr), 2,
			                    crc, crc_table);
			/* bytes 7-10 (Flags, Fragment Offset, TTL, Protocol) */
			crc = crc_calculate(crc_type, (unsigned char *)(&ip2_hdr->frag_off), 4,
			                    crc, crc_table);
			/* bytes 13-20 (Source Address, Destination Address) */
			crc = crc_calculate(crc_type, (unsigned char *)(&ip2_hdr->saddr), 8,
			                    crc, crc_table);
		}
		else /* IPv6 */
		{
			struct ipv6_hdr *ip2_hdr = (struct ipv6_hdr *) ip2;

			/* bytes 1-4 (Version, TC, Flow Label) */
			crc = crc_calculate(crc_type, (unsigned char *)(&ip2_hdr->ip6_flow), 4,
			                    crc, crc_table);
			/* bytes 7-40 (Next Header, Hop Limit, Source Address, Destination Address) */
			crc = crc_calculate(crc_type, (unsigned char *)(&ip2_hdr->ip6_nxt), 34,
			                    crc, crc_table);
			/* IPv6 extensions */
			crc = ipv6_ext_calc_crc_static(ip2, crc_type, crc, crc_table);
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
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int compute_crc_dynamic(const unsigned char *const ip,
                                 const unsigned char *const ip2,
                                 const unsigned char *const next_header,
                                 const rohc_crc_type_t crc_type,
                                 const unsigned int init_val,
                                 const unsigned char *const crc_table)
{
	unsigned int crc;
	ip_version version;
	int ret;

	assert(ip != NULL);
	assert(crc_table != NULL);

	ret = get_ip_version(ip, 2, &version);
	assert(ret);

	crc = init_val;

	/* first IPv4 header */
	if(version == IPV4)
	{
		struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *) ip;
		/* bytes 3-6 (Total Length, Identification) */
		crc = crc_calculate(crc_type, (unsigned char *)(&ip_hdr->tot_len), 4,
		                    crc, crc_table);
		/* bytes 11-12 (Header Checksum) */
		crc = crc_calculate(crc_type, (unsigned char *)(&ip_hdr->check), 2,
		                    crc, crc_table);
	}
	else /* first IPv6 header */
	{
		struct ipv6_hdr *ip_hdr = (struct ipv6_hdr *) ip;
		/* bytes 5-6 (Payload Length) */
		crc = crc_calculate(crc_type, (unsigned char *)(&ip_hdr->ip6_plen), 2,
		                    crc, crc_table);
		/* IPv6 extensions (only AH is CRC-DYNAMIC) */
		crc = ipv6_ext_calc_crc_dyn(ip, crc_type, crc, crc_table);
	}

	/* second_header */
	if(ip2 != NULL)
	{
		ret = get_ip_version(ip2, 2, &version);
		assert(ret);

		/* IPv4 */
		if(version == IPV4)
		{
			struct ipv4_hdr *ip2_hdr = (struct ipv4_hdr *) ip2;
			/* bytes 3-6 (Total Length, Identification) */
			crc = crc_calculate(crc_type, (unsigned char *)(&ip2_hdr->tot_len), 4,
			                    crc, crc_table);
			/* bytes 11-12 (Header Checksum) */
			crc = crc_calculate(crc_type, (unsigned char *)(&ip2_hdr->check), 2,
			                    crc, crc_table);
		}
		else /* IPv6 */
		{
			struct ipv6_hdr *ip2_hdr = (struct ipv6_hdr *) ip2;
			/* bytes 5-6 (Payload Length) */
			crc = crc_calculate(crc_type, (unsigned char *)(&ip2_hdr->ip6_plen), 2,
			                    crc, crc_table);
			/* IPv6 extensions (only AH is CRC-DYNAMIC) */
			crc = ipv6_ext_calc_crc_dyn(ip2, crc_type, crc, crc_table);
		}
	}

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of an UDP or UDP-Lite header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-4 in original UDP header
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int udp_compute_crc_static(const unsigned char *const ip,
                                    const unsigned char *const ip2,
                                    const unsigned char *const next_header,
                                    const rohc_crc_type_t crc_type,
                                    const unsigned int init_val,
                                    const unsigned char *const crc_table)
{
	unsigned int crc;
	struct udphdr *udp;

	assert(ip != NULL);
	assert(next_header != NULL);
	assert(crc_table != NULL);

	crc = init_val;

	/* compute the CRC-STATIC value for IP and IP2 headers */
	crc = compute_crc_static(ip, ip2, next_header, crc_type, crc, crc_table);

	/* get the start of UDP header */
	udp = (struct udphdr *) next_header;

	/* bytes 1-4 (Source Port, Destination Port) */
	crc = crc_calculate(crc_type, (unsigned char *)(&udp->source), 4,
	                    crc, crc_table);

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an UDP or UDP-Lite header
 *
 * Concerned fields are:
 *   - bytes 5-6, 7-8 in original UDP header
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int udp_compute_crc_dynamic(const unsigned char *const ip,
                                     const unsigned char *const ip2,
                                     const unsigned char *const next_header,
                                     const rohc_crc_type_t crc_type,
                                     const unsigned int init_val,
                                     const unsigned char *const crc_table)
{
	unsigned int crc;
	struct udphdr *udp;

	assert(ip != NULL);
	assert(next_header != NULL);
	assert(crc_table != NULL);

	crc = init_val;

	/* compute the CRC-DYNAMIC value for IP and IP2 headers */
	crc = compute_crc_dynamic(ip, ip2, next_header, crc_type, crc, crc_table);

	/* get the start of UDP header */
	udp = (struct udphdr *) next_header;

	/* bytes 5-8 (Length, Checksum) */
	crc = crc_calculate(crc_type, (unsigned char *)(&udp->len), 4,
	                    crc, crc_table);

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of an ESP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-4 in original ESP header
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int esp_compute_crc_static(const unsigned char *const ip,
                                    const unsigned char *const ip2,
                                    const unsigned char *const next_header,
                                    const rohc_crc_type_t crc_type,
                                    const unsigned int init_val,
                                    const unsigned char *const crc_table)
{
	unsigned int crc;
	struct esphdr *esp;

	assert(ip != NULL);
	assert(next_header != NULL);
	assert(crc_table != NULL);

	crc = init_val;

	/* compute the CRC-STATIC value for IP and IP2 headers */
	crc = compute_crc_static(ip, ip2, next_header, crc_type, crc, crc_table);

	/* get the start of ESP header */
	esp = (struct esphdr *) next_header;

	/* bytes 1-4 (Security parameters index) */
	crc = crc_calculate(crc_type, (unsigned char *)(&esp->spi), 4,
	                    crc, crc_table);

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an ESP header
 *
 * Concerned fields are:
 *   - bytes 5-8 in original ESP header
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int esp_compute_crc_dynamic(const unsigned char *const ip,
                                     const unsigned char *const ip2,
                                     const unsigned char *const next_header,
                                     const rohc_crc_type_t crc_type,
                                     const unsigned int init_val,
                                     const unsigned char *const crc_table)
{
	unsigned int crc;
	struct esphdr *esp;

	assert(ip != NULL);
	assert(next_header != NULL);
	assert(crc_table != NULL);

	crc = init_val;

	/* compute the CRC-DYNAMIC value for IP and IP2 headers */
	crc = compute_crc_dynamic(ip, ip2, next_header, crc_type, crc, crc_table);

	/* get the start of ESP header */
	esp = (struct esphdr *) next_header;

	/* bytes 5-8 (Sequence number) */
	crc = crc_calculate(crc_type, (unsigned char *)(&esp->sn), 4,
	                    crc, crc_table);

	return crc;
}


/**
 * @brief Compute the CRC-STATIC part of a RTP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1, 9-12 (and CSRC list) in original RTP header
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int rtp_compute_crc_static(const unsigned char *const ip,
                                    const unsigned char *const ip2,
                                    const unsigned char *const next_header,
                                    const rohc_crc_type_t crc_type,
                                    const unsigned int init_val,
                                    const unsigned char *const crc_table)
{
	unsigned int crc;
	struct rtphdr *rtp;

	assert(ip != NULL);
	assert(next_header != NULL);
	assert(crc_table != NULL);

	crc = init_val;

	/* compute the CRC-STATIC value for IP, IP2 and UDP headers */
	crc = udp_compute_crc_static(ip, ip2, next_header, crc_type, crc, crc_table);

	/* get the start of RTP header */
	rtp = (struct rtphdr *) (next_header + sizeof(struct udphdr));

	/* byte 1 (Version, P, X, CC) */
	crc = crc_calculate(crc_type, (unsigned char *)rtp, 1, crc, crc_table);

	/* bytes 9-12 (SSRC identifier) */
	crc = crc_calculate(crc_type, (unsigned char *)(&rtp->ssrc), 4,
	                    crc, crc_table);

	/* TODO: CSRC identifiers */

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of a RTP header
 *
 * Concerned fields are:
 *   - bytes 2, 3-4, 5-8 in original RTP header
 *
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int rtp_compute_crc_dynamic(const unsigned char *const ip,
                                     const unsigned char *const ip2,
                                     const unsigned char *const next_header,
                                     const rohc_crc_type_t crc_type,
                                     const unsigned int init_val,
                                     const unsigned char *const crc_table)
{
	unsigned int crc;
	struct rtphdr *rtp;

	assert(ip != NULL);
	assert(next_header != NULL);
	assert(crc_table != NULL);

	crc = init_val;

	/* compute the CRC-DYNAMIC value for IP, IP2 and UDP headers */
	crc = udp_compute_crc_dynamic(ip, ip2, next_header, crc_type, crc, crc_table);

	/* get the start of RTP header */
	rtp = (struct rtphdr *) (next_header + sizeof(struct udphdr));

	/* bytes 2-8 (Payload Type, Sequence Number, Timestamp) */
	crc = crc_calculate(crc_type, ((unsigned char *) rtp) + 1, 7,
	                    crc, crc_table);

	return crc;
}


// Begin FWX2

/**
 * @brief Compute the CRC-STATIC part of an TCP header
 *
 * Concerned fields are:
 *  all fields expect those for CRC-DYNAMIC
 *    - bytes 1-4 in original TCP header
 * 
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int tcp_compute_crc_static(const unsigned char *const ip,
                                    const unsigned char *const ip2,
                                    const unsigned char *const next_header,
                                    const rohc_crc_type_t crc_type,
                                    const unsigned int init_val,
                                    const unsigned char *const crc_table)
{
	unsigned int crc;
	struct tcphdr *tcp;

	assert(ip != NULL);
	assert(next_header != NULL);
	assert(crc_table != NULL);

	crc = init_val;

	/* compute the CRC-STATIC value for IP and IP2 headers */
	crc = compute_crc_static(ip, ip2, next_header, crc_type, crc, crc_table);

	/* get the start of TCP header */
	tcp = (struct tcphdr *) next_header;

	/* bytes 1-4 (Source and destination ports) */
	crc = crc_calculate(crc_type, (unsigned char *)(&tcp->src_port), 4,
	                    crc, crc_table);

        rohc_debugf(3, "length 4 crc %Xh\n",crc);

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an TCP header
 *
 * Concerned fields are:
 *   - bytes 5-8 in original ESP header
 * 
 * @param ip          The outer IP packet
 * @param ip2         The inner IP packet if there is 2 IP headers, NULL otherwise
 * @param next_header The next header located after the IP header(s)
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
unsigned int tcp_compute_crc_dynamic(const unsigned char *const ip,
                                     const unsigned char *const ip2,
                                     const unsigned char *const next_header,
                                     const rohc_crc_type_t crc_type,
                                     const unsigned int init_val,
                                     const unsigned char *const crc_table)
{
	unsigned int crc;
	struct tcphdr *tcp;

	assert(ip != NULL);
	assert(next_header != NULL);
	assert(crc_table != NULL);

	crc = init_val;

	/* compute the CRC-DYNAMIC value for IP and IP2 headers */
	crc = compute_crc_dynamic(ip, ip2, next_header, crc_type, crc, crc_table);

	/* get the start of TCP header */
	tcp = (struct tcphdr *) next_header;

	/* bytes 5-20 + TCP options */
	crc = crc_calculate(crc_type, (unsigned char *)(&tcp->seq_number), sizeof(struct tcphdr) - 4 + ( tcp->data_offset << 2 ) - sizeof(struct tcphdr),
	                    crc, crc_table);

        rohc_debugf(3, "length %d crc %Xh\n",(int)(sizeof(struct tcphdr) - 4 + ( tcp->data_offset << 2 ) - sizeof(struct tcphdr)),crc);

	return crc;
}

// End FWX2


/**
 * Private functions
 */

/**
 * @brief Compute the CRC-STATIC part of IPv6 extensions
 *
 * All extensions are concerned except entire AH header.
 *
 * @param ip          The IPv6 packet
 * @param crc_type    The type of CRC
 * @param init_val    The initial CRC value
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
static unsigned int ipv6_ext_calc_crc_static(const unsigned char *const ip,
                                             const rohc_crc_type_t crc_type,
                                             const unsigned int init_val,
                                             const unsigned char *const crc_table)
{
	unsigned int crc;
	unsigned char *ext;
	uint8_t ext_type;

	assert(ip != NULL);

	crc = init_val;

	ext = ipv6_get_first_extension(ip, &ext_type);
	while(ext != NULL)
	{
		if(ext_type != IPV6_EXT_AUTH)
		{
			crc = crc_calculate(crc_type, ext, ip_get_extension_size(ext),
			                    crc, crc_table);
		}
		ext = ip_get_next_ext_from_ext(ext, &ext_type);
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
 * @param crc_table   The pre-computed table for fast CRC computation
 * @return            The checksum
 */
static unsigned int ipv6_ext_calc_crc_dyn(const unsigned char *const ip,
                                          const rohc_crc_type_t crc_type,
                                          const unsigned int init_val,
                                          const unsigned char *const crc_table)
{
	unsigned int crc;
	unsigned char *ext;
	uint8_t ext_type;

	assert(ip != NULL);

	crc = init_val;

	ext = ipv6_get_first_extension(ip, &ext_type);
	while(ext != NULL)
	{
		if(ext_type == IPV6_EXT_AUTH)
		{
			crc = crc_calculate(crc_type, ext, ip_get_extension_size(ext),
			                    crc, crc_table);
		}
		ext = ip_get_next_ext_from_ext(ext, &ext_type);
	}

	return crc;
}


/**
 * @brief Get the polynom for the given CRC type
 *
 * @param type     The CRC type
 * @param polynom  IN/OUT: the polynom for the requested CRC type
 * @return         true in case of success, false otherwise
 */
static bool rohc_crc_get_polynom(const rohc_crc_type_t crc_type,
                                 unsigned char *const polynom)
{
	/* sanity check */
	assert(polynom != NULL);

	/* determine the polynom for CRC */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_2:
			*polynom = 0x3;
			break;
		case ROHC_CRC_TYPE_3:
			*polynom = 0x6;
			break;
		case ROHC_CRC_TYPE_6:
			*polynom = 0x30;
			break;
		case ROHC_CRC_TYPE_7:
			*polynom = 0x79;
			break;
		case ROHC_CRC_TYPE_8:
			*polynom = 0xe0;
			break;
		default:
			/* unknown CRC type, should not happen */
			assert(0);
			goto error;
	}

	/* everything went fine */
	return true;

error:
	return false;
}


/**
 * @brief Get the first extension in an IPv6 packet
 *
 * @param ip   The IPv6 packet
 * @param type The type of the extension
 * @return     The extension, NULL if there is no extension
 */
static unsigned char * ipv6_get_first_extension(const unsigned char *const ip,
                                                uint8_t *const type)
{
	struct ipv6_hdr *ip_hdr;

	assert(ip != NULL);
	assert(type != NULL);

	ip_hdr = (struct ipv6_hdr *)ip;
	*type = ip_hdr->ip6_nxt;
	switch(*type)
	{
		case IPV6_EXT_HOP_BY_HOP:
		case IPV6_EXT_DESTINATION:
		case IPV6_EXT_ROUTING:
		case IPV6_EXT_AUTH:
			/* known extension header */
			break;
		default:
			goto end;
	}

	return (((unsigned char *) ip) + sizeof(struct ipv6_hdr));

end:
	return NULL;
}


/**
 * @brief Optimized CRC-8 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The CRC byte
 */
static inline unsigned char crc_calc_8(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
{
	int i;
	unsigned char crc = init_val;

	assert(buf != NULL);
	assert(crc_table != NULL);

	for(i = 0; i < size; i++)
	{
		crc = crc_table[buf[i] ^ crc];
	}

	return crc;
}


/**
 * @brief Optimized CRC-7 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The CRC byte
 */
static inline unsigned char crc_calc_7(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
{
	int i;
	unsigned char crc = init_val;

	assert(buf != NULL);
	assert(crc_table != NULL);

	for(i = 0; i < size; i++)
	{
		crc = crc_table[buf[i] ^ (crc & 127)];
	}

	return crc;
}


/**
 * @brief Optimized CRC-6 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The CRC byte
 */
static inline unsigned char crc_calc_6(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
{
	int i;
	unsigned char crc = init_val;

	assert(buf != NULL);
	assert(crc_table != NULL);

	for(i = 0; i < size; i++)
	{
		crc = crc_table[buf[i] ^ (crc & 63)];
	}

	return crc;
}


/**
 * @brief Optimized CRC-3 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The CRC byte
 */
static inline unsigned char crc_calc_3(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
{
	int i;
	unsigned char crc = init_val;

	assert(buf != NULL);
	assert(crc_table != NULL);

	for(i = 0; i < size; i++)
	{
		crc = crc_table[buf[i] ^ (crc & 7)];
	}

	return crc;
}


/**
 * @brief Optimized CRC-2 calculation using a table
 *
 * @param buf        The data to compute the CRC for
 * @param size       The size of the data
 * @param init_val   The initial CRC value
 * @param crc_table  The pre-computed table for fast CRC computation
 * @return           The CRC byte
 */
static inline unsigned char crc_calc_2(const unsigned char *const buf,
                                       const int size,
                                       const unsigned int init_val,
                                       const unsigned char *const crc_table)
{
	int i;
	unsigned char crc = init_val;

	assert(buf != NULL);
	assert(crc_table != NULL);

	for(i = 0; i < size; i++)
	{
		crc = crc_table[buf[i] ^ (crc & 3)];
	}

	return crc;
}

