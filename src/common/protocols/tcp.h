/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013 Viveris Technologies
 * Copyright 2012 WBX
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
 * @file   tcp.h
 * @brief  TCP header description.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_PROTOCOLS_TCP_H
#define ROHC_PROTOCOLS_TCP_H

#include <stdint.h>

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif


/************************************************************************
 * Uncompressed TCP base header                                         *
 ************************************************************************/

/**
 * @brief The TCP base header without options
 *
 * See RFC4996 page 72/73
 */
struct tcphdr
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
#if WORDS_BIGENDIAN == 1
	uint8_t data_offset:4;
	uint8_t res_flags:4;
	uint8_t ecn_flags:2;
	uint8_t urg_flag:1;
	uint8_t ack_flag:1;
	uint8_t psh_flag:1;
	uint8_t rsf_flags:3;
#else
	uint8_t res_flags:4;
	uint8_t data_offset:4;
	uint8_t rsf_flags:3;
	uint8_t psh_flag:1;
	uint8_t ack_flag:1;
	uint8_t urg_flag:1;
	uint8_t ecn_flags:2;
#endif
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
	uint8_t options[0];          /**< The beginning of the TCP options */
} __attribute__((packed));


/* The RSF flags */
#define RSF_RST_ONLY  0x04
#define RSF_SYN_ONLY  0x02
#define RSF_FIN_ONLY  0x01
#define RSF_NONE      0x00



/************************************************************************
 * Uncompressed TCP options                                             *
 ************************************************************************/

/**
 * @brief The maximum length of TCP options supported by the TCP protocol
 *
 * The TCP data offset is coded on 32-bit words on 4 bits, so the whole TCP
 * header may be up to 15*4=60 bytes. The base TCP header is 20-byte long.
 */
#define ROHC_TCP_OPTS_LEN_MAX_PROTO  (15U * 4U - (uint8_t) sizeof(struct tcphdr))


/**
 * @brief The maximum of TCP options supported by the TCP protocol
 *
 * One TCP header may contain up to 40 bytes of options, so it may contain
 * up 40 1-byte options.
 *
 * @see ROHC_TCP_OPTS_MAX
 */
#define ROHC_TCP_OPTS_MAX_PROTO  ROHC_TCP_OPTS_LEN_MAX_PROTO


/**
 * @brief The maximum of TCP options supported by the TCP profile
 *
 * One TCP header may contain up to 40 bytes of options, so it may contain
 * up 40 1-byte options, so the ROHC (de)compressors should expect such TCP
 * packets. However the m field in the compressed list of TCP options (see
 * RFC 6846, section 6.3.3 for more details) cannot be larger than 15, so
 * restrict the number of TCP options that value. One TCP packet with more
 * than 15 TCP options will be compressed with the IP-only profile.
 *
 * @see ROHC_TCP_OPTS_MAX_PROTO
 */
#define ROHC_TCP_OPTS_MAX  15U


/** The length of the header of one TCP option */
#define ROHC_TCP_OPT_HDR_LEN  2U


/** The maximum length of TCP options supported by the TCP protocol */
#define ROHC_TCP_OPT_MAX_LEN_PROTO  0xffU


/** The different TCP options */
typedef enum
{
	TCP_OPT_EOL       = 0U,  /**< The End of Option List (EOL) TCP option */
	TCP_OPT_NOP       = 1U,  /**< The No OPeration (NOP) TCP option */
	TCP_OPT_MSS       = 2U,  /**< The Maximum Segment Size (MSS) TCP option */
#define TCP_OLEN_MSS         4U
	TCP_OPT_WS        = 3U,  /**< The Window Scale (WS) TCP option */
#define TCP_OLEN_WS          3U
	TCP_OPT_SACK_PERM = 4U,  /**< The SACK Permitted TCP option */
#define TCP_OLEN_SACK_PERM   2U
	TCP_OPT_SACK      = 5U,  /**< The Selective ACKnowledgement (SACK) TCP option */
	TCP_OPT_TS        = 8U,  /**< The TimeStamp (TS) TCP option */
#define TCP_OLEN_TS         10U
	TCP_OPT_MAX       = 255U /**< The maximum TCP option */

} rohc_tcp_option_type_t;


/**
 * @brief The Selective Acknowlegment TCP option
 *
 * See RFC2018 for TCP Selective Acknowledgement Options
 * See RFC4996 page 66
 */
typedef struct
{
	uint32_t block_start;
	uint32_t block_end;
} __attribute__((packed)) sack_block_t;


/** The maximum number of SACK blocks in the TCP SACK option */
#define TCP_SACK_BLOCKS_MAX_NR  4U


/** The Timestamp option of the TCP header */
struct tcp_option_timestamp
{
	uint32_t ts;        /**< The timestamp value */
	uint32_t ts_reply;  /**< The timestamp echo reply value */
} __attribute__((packed));



/************************************************************************
 * Helper functions                                                     *
 ************************************************************************/

static inline char * tcp_opt_get_descr(const uint8_t opt_type)
	__attribute__((warn_unused_result, const));


/**
 * @brief Get a string that describes the given option type
 *
 * @param opt_type  The type of the option to get a description for
 * @return          The description of the option
 */
static inline char * tcp_opt_get_descr(const uint8_t opt_type)
{
	switch(opt_type)
	{
		case TCP_OPT_EOL:
			return "EOL";
		case TCP_OPT_NOP:
			return "NOP";
		case TCP_OPT_MSS:
			return "MSS";
		case TCP_OPT_WS:
			return "Window Scale";
		case TCP_OPT_SACK_PERM:
			return "SACK permitted";
		case TCP_OPT_SACK:
			return "SACK";
		case TCP_OPT_TS:
			return "Timestamp";
		default:
			return "generic";
	}
}

#endif /* ROHC_PROTOCOLS_TCP_H */

