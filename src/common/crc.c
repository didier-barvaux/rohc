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

#include <stdlib.h>
#include <assert.h>


/* TODO API: remove these variables once compatibility is not needed anymore */
unsigned char crc_table_8[256];
unsigned char crc_table_7[256];
unsigned char crc_table_6[256];
unsigned char crc_table_3[256];
unsigned char crc_table_2[256];

/**
 * @brief The pre-computed table for 32-bit Frame Check Sequence (FCS)
 *
 *   x**0 + x**1 + x**2 + x**4 + x**5 +
 *   x**7 + x**8 + x**10 + x**11 + x**12 + x**16 +
 *   x**22 + x**23 + x**26 + x**32
 *
 * Copied from RFC 1662, appendix C.3
 */
static uint32_t crc_table_fcs32[256] =
{
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};


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
                                       const size_t size,
                                       const unsigned char init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static inline unsigned char crc_calc_7(const unsigned char *const buf,
                                       const size_t size,
                                       const unsigned char init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static inline unsigned char crc_calc_6(const unsigned char *const buf,
                                       const size_t size,
                                       const unsigned char init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static inline unsigned char crc_calc_3(const unsigned char *const buf,
                                       const size_t size,
                                       const unsigned char init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));
static inline unsigned char crc_calc_2(const unsigned char *const buf,
                                       const size_t size,
                                       const unsigned char init_val,
                                       const unsigned char *const crc_table)
	__attribute__((nonnull(1, 4)));



/**
 * Public functions
 */


#if !defined(ENABLE_DEPRECATED_API) || ENABLE_DEPRECATED_API == 1

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

#endif /* !defined(ENABLE_DEPRECATED_API) || ENABLE_DEPRECATED_API == 1 */


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
                           const size_t length,
                           const unsigned char init_val,
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
 * @brief Optimized CRC FCS-32 calculation using a table
 *
 * @param data      The data to compute the CRC for
 * @param length    The size of the data
 * @param init_val  The initial value of the CRC
 * @return          The 32-bit CRC
 */
uint32_t crc_calc_fcs32(const unsigned char *const data,
                        const size_t length,
                        const uint32_t init_val)
{
	uint32_t crc = init_val;
	size_t i;

	assert(data != NULL);

	for(i = 0; i < length; i++)
	{
		crc = (crc >> 8) ^ crc_table_fcs32[(crc ^ data[i]) & 0xff];
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

	return crc;
}


/**
 * @brief Compute the CRC-DYNAMIC part of an TCP header
 *
 * Concerned fields are:
 *   - bytes 5-20 in original TCP header
 *   - TCP options
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
	crc = crc_calculate(crc_type, (unsigned char *)(&tcp->seq_number),
	                    sizeof(struct tcphdr) - 4 + (tcp->data_offset << 2) -
	                    sizeof(struct tcphdr), crc, crc_table);

	return crc;
}



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
                                       const size_t size,
                                       const unsigned char init_val,
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
                                       const size_t size,
                                       const unsigned char init_val,
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
                                       const size_t size,
                                       const unsigned char init_val,
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
                                       const size_t size,
                                       const unsigned char init_val,
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
                                       const size_t size,
                                       const unsigned char init_val,
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

