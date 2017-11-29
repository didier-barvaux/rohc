/*
 * Copyright 2015 Didier Barvaux
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file   ipv6.h
 * @brief  The IPv6 header
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_PROTOCOLS_IPV6_H
#define ROHC_PROTOCOLS_IPV6_H

#include "rohc_utils.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif


/** The format to print an IPv6 address */
#define IPV6_ADDR_FORMAT \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"


/** The data to print an IPv6 address in (struct ipv6_addr *) format */
#define IPV6_ADDR_IN6(x) \
	IPV6_ADDR_RAW((x)->u8)


/** The data to print an IPv6 address in raw format */
#define IPV6_ADDR_RAW(x) \
	(x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5], (x)[6], (x)[7], \
	(x)[8], (x)[9], (x)[10], (x)[11], (x)[12], (x)[13], (x)[14], (x)[15]


/** Compare two IPv6 addresses in (struct ipv6_addr *) format */
#define IPV6_ADDR_CMP(x, y) \
	((x)->u32[0] == (y)->u32[0] && (x)->u32[1] == (y)->u32[1] && \
	 (x)->u32[2] == (y)->u32[2] && (x)->u32[3] == (y)->u32[3])


/**
 * @brief The IPv6 address
 */
struct ipv6_addr
{
	union /* IPv6 address may be accessed by 8, 16 or 32-bit blocks */
	{
		uint8_t u8[16];   /**< The 16  8-bit blocks of the IPv6 address */
		uint16_t u16[8];  /**< The  8 16-bit blocks of the IPv6 address */
		uint32_t u32[4];  /**< The  4 32-bit blocks of the IPv6 address */
	} __attribute__((packed));
} __attribute__((packed));


/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert(sizeof(struct ipv6_addr) == 16,
               "IPv6 address should exactly 16-byte long");
#endif


/**
 * @brief The IPv6 header
 */
struct ipv6_hdr
{
	union
	{
		uint32_t version_tc_flow;  /**< The combined version, TC, Flow Label fields */
#define IPV6_VERSION_MASK 0xf0000000U  /**< The mask for the Traffic Class (TC) field */
#define IPV6_TC_MASK      0x0ff00000U  /**< The mask for the Traffic Class (TC) field */
#define IPV6_FLOW_MASK    0x000fffffU  /**< The mask for the Flow Label field */
		struct
		{
#if WORDS_BIGENDIAN == 1
			uint8_t version:4;  /**< The IP version */
			uint8_t tc1:4;      /**< The Traffic Class (TC) (part 1) */
			uint8_t tc2:4;      /**< The Traffic Class (TC) (part 2) */
			uint8_t flowl1:4;   /**< The Flow Label (part 1) */
#else
			uint8_t tc1:4;
			uint8_t version:4;
			uint8_t flow1:4;
			uint8_t tc2:4;
#endif
			uint16_t flow2;     /**< The Flow Label (part 2) */
		} __attribute__((packed));
		struct
		{
#if WORDS_BIGENDIAN == 1
			uint8_t version_:4; /**< The IP version */
			uint8_t dscp1:4;    /**< The Differentiated Services Code Point (DSCP) (part 1) */
			uint8_t dscp2:2;    /**< The Differentiated Services Code Point (DSCP) (part 2) */
			uint8_t ecn:2;      /**< The Explicit Congestion Notification (ECN) */
			uint8_t flowl1_:4;  /**< The Flow Label (part 1) */
#else
			uint8_t dscp1:4;
			uint8_t version_:4;
			uint8_t flowl1_:4;
			uint8_t ecn:2;
			uint8_t dscp2:2;
#endif
			uint16_t flow2_;    /**< The Flow Label (part 2) */
		} __attribute__((packed));

	} __attribute__((packed));

	uint16_t plen;                /**< The Payload Length */
	uint8_t nh;                   /**< The protocol of the Next Header (NH) */
	uint8_t hl;                   /**< The Hop Limit (HL) */
	struct ipv6_addr saddr;     /**< The source IP address */
	struct ipv6_addr daddr;     /**< The destination IP address */

} __attribute__((packed));


/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert(sizeof(struct ipv6_hdr) == 40,
               "IPv6 header should exactly 40-byte long");
#endif


/** The maximum value of the length field of one IPv6 extension header */
#define IPV6_OPT_HDR_LEN_FIELD_MAX_VAL  4U
/** The maximum length of one IPv6 extension header */
#define IPV6_OPT_HDR_LEN_MAX            ((IPV6_OPT_HDR_LEN_FIELD_MAX_VAL + 1) * 8)
/** The maximum length for the IPv6 extension header context */
#define IPV6_OPT_CTXT_LEN_MAX           (IPV6_OPT_HDR_LEN_MAX - 2)


/** The IPv6 option header */
struct ipv6_opt
{
	uint8_t next_header;   /**< The protocol of the next header */
	uint8_t length;        /**< The length of the header in 8-byte units minus 1 */
	uint8_t value[1];      /**< The start of the IPv6 option header */ /* TODO */
} __attribute__((packed));


/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert(sizeof(struct ipv6_opt) == 3,
               "IPv6 option header should exactly 3-byte long");
#endif


static inline uint8_t ipv6_get_tc(const struct ipv6_hdr *const ipv6)
	__attribute__((warn_unused_result, nonnull(1), pure));
static inline void ipv6_set_tc(struct ipv6_hdr *const ipv6, const uint8_t tc)
	__attribute__((nonnull(1)));

static inline void ipv6_set_dscp_ecn(struct ipv6_hdr *const ipv6,
                                     const uint8_t dscp,
                                     const uint8_t ecn)
	__attribute__((nonnull(1)));

static inline uint8_t ipv6_get_dscp(const struct ipv6_hdr *const ipv6)
	__attribute__((warn_unused_result, nonnull(1), pure));
static inline void ipv6_set_dscp(struct ipv6_hdr *const ipv6, const uint8_t dscp)
	__attribute__((nonnull(1)));

static inline uint32_t ipv6_get_flow_label(const struct ipv6_hdr *const ipv6)
	__attribute__((warn_unused_result, nonnull(1), pure));
static inline void ipv6_set_flow_label(struct ipv6_hdr *const ipv6,
                                       const uint32_t flow_label)
	__attribute__((nonnull(1)));

static inline size_t ipv6_opt_get_length(const struct ipv6_opt *const opt)
	__attribute__((warn_unused_result, nonnull(1), pure));


/**
 * @brief Get the Traffic Class (TC) of the given IPv6 packet
 *
 * @param ipv6  The header of the IPv6 packet
 * @return      The 8-bit Traffic Class (TC)
 */
static inline uint8_t ipv6_get_tc(const struct ipv6_hdr *const ipv6)
{
	return ((ipv6->tc1 << 4) | ipv6->tc2);
}


/**
 * @brief Set the Traffic Class (TC) of the given IPv6 packet
 *
 * @param[in,out] ipv6  The header of the IPv6 packet
 * @param tc            The 8-bit Traffic Class (TC)
 */
static inline void ipv6_set_tc(struct ipv6_hdr *const ipv6, const uint8_t tc)
{
	ipv6->tc1 = (tc >> 4) & 0x0f;
	ipv6->tc2 = tc & 0x0f;
}


/**
 * @brief Set the DSCP and ECN of the given IPv6 packet
 *
 * @param[in,out] ipv6  The header of the IPv6 packet
 * @param dscp          The 6-bit DSCP
 * @param ecn           The 2-bit ECN
 */
static inline void ipv6_set_dscp_ecn(struct ipv6_hdr *const ipv6,
                                     const uint8_t dscp,
                                     const uint8_t ecn)
{
	ipv6_set_tc(ipv6, ((dscp << 2) & 0xfc) | (ecn & 0x03));
}


/**
 * @brief Get the Differentiated Services Code Point (DSCP) of the given IPv6 packet
 *
 * @param ipv6  The header of the IPv6 packet
 * @return      The 6-bit DSCP
 */
static inline uint8_t ipv6_get_dscp(const struct ipv6_hdr *const ipv6)
{
	return ((ipv6->dscp1 << 2) | ipv6->dscp2);
}


/**
 * @brief Set the Differentiated Services Code Point (DSCP) of the given IPv6 packet
 *
 * @param[in,out] ipv6  The header of the IPv6 packet
 * @param dscp          The 6-bit DSCP
 */
static inline void ipv6_set_dscp(struct ipv6_hdr *const ipv6, const uint8_t dscp)
{
	ipv6->dscp1 = (dscp >> 2) & 0x0f;
	ipv6->dscp2 = dscp & 0x03;
}


/**
 * @brief Get the Flow Label of the given IPv6 packet
 *
 * @param ipv6  The header of the IPv6 packet
 * @return      The 20-bit Flow Label
 */
static inline uint32_t ipv6_get_flow_label(const struct ipv6_hdr *const ipv6)
{
	return (rohc_ntoh32(ipv6->version_tc_flow) & IPV6_FLOW_MASK);
}


/**
 * @brief Set the Flow Label of the given IPv6 packet
 *
 * @param[in,out] ipv6  The header of the IPv6 packet
 * @param flow_label    The 20-bit Flow Label
 */
static inline void ipv6_set_flow_label(struct ipv6_hdr *const ipv6,
                                       const uint32_t flow_label)
{
	ipv6->flow1 = (flow_label >> 16);
	ipv6->flow2 = rohc_hton16(flow_label & 0xffff);
}


/**
 * @brief get the length (in bytes) of the IPv6 option header
 *
 * @param opt  The IPv6 option header
 * @return     The length (in bytes) of the IPv6 option header
 */
static inline size_t ipv6_opt_get_length(const struct ipv6_opt *const opt)
{
	return ((opt->length + 1) * 8);
}


#endif

