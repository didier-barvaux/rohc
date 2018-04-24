/*
 * Copyright 2015,2016 Didier Barvaux
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
 * @file   feedback.h
 * @brief  ROHC feedback definitions and formats
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_FEEDBACK_H
#define ROHC_FEEDBACK_H

#include "rohc.h"

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>


/** The type of ROHC feedback */
enum rohc_feedback_type
{
	ROHC_FEEDBACK_1 = 1,  /**< ROHC FEEDBACK-1 */
	ROHC_FEEDBACK_2 = 2,  /**< ROHC FEEDBACK-2 */
};


/** The type of acknowledgement */
enum rohc_feedback_ack_type
{
	ROHC_FEEDBACK_ACK         = 0, /**< The classical ACKnowledgement */
	ROHC_FEEDBACK_NACK        = 1, /**< The Negative ACKnowledgement */
	ROHC_FEEDBACK_STATIC_NACK = 2, /**< The Negative STATIC ACKnowledgement */
	ROHC_FEEDBACK_RESERVED    = 3, /**< reserved (MUST NOT be used for parsability) */
};


/**
 * @brief Whether the feedback is protected by a CRC or not
 */
typedef enum
{
	ROHC_FEEDBACK_WITH_NO_CRC   = 0,  /**< No CRC protects the feedback */
	ROHC_FEEDBACK_WITH_CRC_OPT  = 1,  /**< A CRC option protects the feedback */
	ROHC_FEEDBACK_WITH_CRC_BASE = 2,  /**< A base header CRC protects the feedback */
	ROHC_FEEDBACK_WITH_CRC_BASE_TCP = 3,  /**< A base header CRC protects the feedback */

} rohc_feedback_crc_t;


/** The ROHC feedback options */
enum rohc_feedback_opt
{
	ROHC_FEEDBACK_OPT_CRC            =  1, /**< The Feedback CRC option */
	ROHC_FEEDBACK_OPT_REJECT         =  2, /**< The Feedback REJECT option */
	ROHC_FEEDBACK_OPT_SN_NOT_VALID   =  3, /**< The Feedback SN-NOT-VALID option */
/** The Feedback MSN-NOT-VALID option (TCP profile) */
#define ROHC_FEEDBACK_OPT_MSN_NOT_VALID ROHC_FEEDBACK_OPT_SN_NOT_VALID
/** The Feedback ACKNUMBER-NOT-VALID option (ROHCv2 profiles) */
#define ROHC_FEEDBACK_OPT_ACKNUMBER_NOT_VALID ROHC_FEEDBACK_OPT_SN_NOT_VALID
	ROHC_FEEDBACK_OPT_SN             =  4, /**< The Feedback SN option */
/** The Feedback MSN option (TCP profile) */
#define ROHC_FEEDBACK_OPT_MSN ROHC_FEEDBACK_OPT_SN
	ROHC_FEEDBACK_OPT_CLOCK          =  5, /**< The Feedback CLOCK option */
	ROHC_FEEDBACK_OPT_JITTER         =  6, /**< The Feedback JITTER option */
	ROHC_FEEDBACK_OPT_LOSS           =  7, /**< The Feedback LOSS option */
	ROHC_FEEDBACK_OPT_CV_REQUEST     =  8, /**< The Feedback CV-REQUEST option */
	ROHC_FEEDBACK_OPT_CONTEXT_MEMORY =  9, /**< The Feedback CONTEXT_MEMORY option */
	ROHC_FEEDBACK_OPT_CLOCK_RESOLUTION = 10, /**< The Feedback CLOCK_RESOLUTION option */
	ROHC_FEEDBACK_OPT_UNKNOWN_11     = 11, /**< Unknown option with value 11 */
	ROHC_FEEDBACK_OPT_UNKNOWN_12     = 12, /**< Unknown option with value 12 */
	ROHC_FEEDBACK_OPT_UNKNOWN_13     = 13, /**< Unknown option with value 13 */
	ROHC_FEEDBACK_OPT_UNKNOWN_14     = 14, /**< Unknown option with value 14 */
	ROHC_FEEDBACK_OPT_UNKNOWN_15     = 15, /**< Unknown option with value 15 */
	ROHC_FEEDBACK_OPT_MAX                  /**< The max number of feedback options */
};


/** The ROHC FEEDBACK-2 format as defined in RFC3095 */
struct rohc_feedback_2_rfc3095
{
#if WORDS_BIGENDIAN == 1
	uint8_t ack_type:2; /**< The type of acknowledgement \see rohc_feedback_ack_type */
	uint8_t mode:2;     /**< The decompression context mode */
	uint8_t sn1:4;      /**< The 4 first LSB bits of the SN being acked */
#else
	uint8_t sn1:4;
	uint8_t mode:2;
	uint8_t ack_type:2;
#endif
	uint8_t sn2;        /**< The 8 next  LSB bits of the SN being acked */
} __attribute__((packed));


/** The ROHC FEEDBACK-2 format as defined in RFC6846 */
struct rohc_feedback_2_rfc6846
{
#if WORDS_BIGENDIAN == 1
	uint8_t ack_type:2; /**< The type of acknowledgement \see rohc_feedback_ack_type */
	uint8_t sn1:6;      /**< The 6 first LSB bits of the SN being acked */
#else
	uint8_t sn1:6;
	uint8_t ack_type:2;
#endif
	uint8_t sn2;        /**< The 8 next  LSB bits of the SN being acked */
	uint8_t crc;        /**< The feedback CRC */
} __attribute__((packed));


/** The characteristics of one ROHC feedback option */
struct rohc_feedback_opt_charac
{
	const char *const name;
	bool unknown;
	bool supported;
	size_t expected_len;
	enum {
		ROHC_FEEDBACK_OPT_CRC_REQUIRED,
		ROHC_FEEDBACK_OPT_CRC_SUGGESTED,
		ROHC_FEEDBACK_OPT_CRC_NOT_REQUIRED,
	} crc_req;
	size_t max_occurs[ROHC_PROFILE_MAX];
};


/**
 * @brief Max occurrences of a feedback option in one feedback packet
 *
 * Even if the standard says that some options may be present multiple times,
 * don't allow more than a raisonable occurrences. It allows the library to
 * protect itself against abuses.
 */
#define ROHC_FEEDBACK_OPT_MAX_OCCURS  100U


/** Feedback options capacities */
static const struct rohc_feedback_opt_charac
	rohc_feedback_opt_charac[ROHC_FEEDBACK_OPT_MAX] =
{
	[0]                        = {
		.name = "unknown option with value 0",
		.unknown = true,
	},
	[ROHC_FEEDBACK_OPT_CRC]    = {
		.name = "CRC",
		.unknown = false,
		.supported = true,
		.expected_len = 2U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_NOT_REQUIRED,
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC3095 §5.7.6.3 */
			[ROHC_PROFILE_UDP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_ESP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHC_PROFILE_IP]           = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHC_PROFILE_RTP_LLA]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 0, /* RFC6846 §8.3.2 */
			[ROHC_PROFILE_UDPLITE_RTP]  = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_UDPLITE]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHCv2_PROFILE_IP_UDP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP_ESP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP]         = 0, /* RFC5225 §6.9.2 */
		}
	},
	[ROHC_FEEDBACK_OPT_REJECT] = {
		.name = "REJECT",
		.unknown = false,
		.supported = true,
		.expected_len = 1U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_REQUIRED, /* RFC3095, §5.7.6.4 */
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC3095 §5.7.6.4 */
			[ROHC_PROFILE_UDP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_ESP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHC_PROFILE_IP]           = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHC_PROFILE_RTP_LLA]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 1, /* RFC6846 §8.3.2.1 */
			[ROHC_PROFILE_UDPLITE_RTP]  = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_UDPLITE]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHCv2_PROFILE_IP_UDP]     = 1, /* RFC5225 §6.9.2.1 */
			[ROHCv2_PROFILE_IP_ESP]     = 1, /* RFC5225 §6.9.2.1 */
			[ROHCv2_PROFILE_IP]         = 1, /* RFC5225 §6.9.2.1 */
		}
	},
	[ROHC_FEEDBACK_OPT_SN_NOT_VALID] = {
		.name = "(M)SN-NOT-VALID/ACKNUMBER-NOT-VALID",
		.unknown = false,
		.supported = true,
		.expected_len = 1U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_NOT_REQUIRED,
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC3095 §5.7.6.5 */
			[ROHC_PROFILE_UDP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_ESP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHC_PROFILE_IP]           = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHC_PROFILE_RTP_LLA]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 1, /* RFC6846 §8.3.2.2 */
			[ROHC_PROFILE_UDPLITE_RTP]  = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_UDPLITE]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHCv2_PROFILE_IP_UDP]     = 1, /* RFC5225 §6.9.2.2 */
			[ROHCv2_PROFILE_IP_ESP]     = 1, /* RFC5225 §6.9.2.2 */
			[ROHCv2_PROFILE_IP]         = 1, /* RFC5225 §6.9.2.2 */
		}
	},
	[ROHC_FEEDBACK_OPT_SN] = {
		.name = "(M)SN",
		.unknown = false,
		.supported = true,
		.expected_len = 2U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_NOT_REQUIRED,
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = 1, /* RFC4815 §8.5: 1 option needed for 16-bit SN */
			[ROHC_PROFILE_UDP]          = 1, /* same as RTP */
			[ROHC_PROFILE_ESP]          = 3, /* RFC4815 §8.5: 3 options needed for 32-bit SN */
			[ROHC_PROFILE_IP]           = 1, /* same as UDP */
			[ROHC_PROFILE_RTP_LLA]      = 1, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 1, /* RFC6846 §8.3.2.3 */
			[ROHC_PROFILE_UDPLITE_RTP]  = 1, /* same as RTP */
			[ROHC_PROFILE_UDPLITE]      = 1, /* same as UDP */
			[ROHCv2_PROFILE_IP_UDP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP_ESP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP]         = 0, /* RFC5225 §6.9.2 */
		}
	},
	[ROHC_FEEDBACK_OPT_CLOCK] = {
		.name = "CLOCK",
		.unknown = false,
		.supported = false,
		.expected_len = 2U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_SUGGESTED, /* RFC3095, §5.7.6.7 */
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC3095 §5.7.6.7 */
			[ROHC_PROFILE_UDP]          = 0, /* RFC3095 §5.11.6 */
			[ROHC_PROFILE_ESP]          = 0, /* same as UDP */
			[ROHC_PROFILE_IP]           = 0, /* same as UDP */
			[ROHC_PROFILE_RTP_LLA]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 0, /* RFC6846 §8.3.2 */
			[ROHC_PROFILE_UDPLITE_RTP]  = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_UDPLITE]      = 0, /* same as UDP */
			[ROHCv2_PROFILE_IP_UDP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP_ESP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP]         = 0, /* RFC5225 §6.9.2 */
		}
	},
	[ROHC_FEEDBACK_OPT_JITTER] = {
		.name = "JITTER",
		.unknown = false,
		.supported = false,
		.expected_len = 2U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_SUGGESTED, /* RFC3095, §5.7.6.8 */
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC3095 §5.7.6.8 */
			[ROHC_PROFILE_UDP]          = 0, /* RFC3095 §5.11.6 */
			[ROHC_PROFILE_ESP]          = 0, /* same as UDP */
			[ROHC_PROFILE_IP]           = 0, /* same as UDP */
			[ROHC_PROFILE_RTP_LLA]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 0, /* RFC6846 §8.3.2 */
			[ROHC_PROFILE_UDPLITE_RTP]  = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_UDPLITE]      = 0, /* same as UDP */
			[ROHCv2_PROFILE_IP_UDP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP_ESP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP]         = 0, /* RFC5225 §6.9.2 */
		}
	},
	[ROHC_FEEDBACK_OPT_LOSS] = {
		.name = "LOSS",
		.unknown = false,
		.supported = false,
		.expected_len = 2U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_SUGGESTED, /* RFC3095, §5.7.6.9 */
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC3095 §5.7.6.9 */
			[ROHC_PROFILE_UDP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_ESP]          = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHC_PROFILE_IP]           = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHC_PROFILE_RTP_LLA]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 0, /* RFC6846 §8.3.2 */
			[ROHC_PROFILE_UDPLITE_RTP]  = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as RTP */
			[ROHC_PROFILE_UDPLITE]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* same as UDP */
			[ROHCv2_PROFILE_IP_UDP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP_ESP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP]         = 0, /* RFC5225 §6.9.2 */
		}
	},
	[ROHC_FEEDBACK_OPT_CV_REQUEST] = {
		.name = "CV-REQUEST",
		.unknown = false,
		.supported = false,
		.expected_len = 1U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_NOT_REQUIRED,
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = 0, /* RFC3095 §5.7.6.2 */
			[ROHC_PROFILE_UDP]          = 0, /* same as RTP */
			[ROHC_PROFILE_ESP]          = 0, /* same as UDP */
			[ROHC_PROFILE_IP]           = 0, /* same as UDP */
			[ROHC_PROFILE_RTP_LLA]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC4362 §4.5 */
			[ROHC_PROFILE_TCP]          = 0, /* RFC6846 §8.3.2 */
			[ROHC_PROFILE_UDPLITE_RTP]  = 0, /* same as RTP */
			[ROHC_PROFILE_UDPLITE]      = 0, /* same as UDP */
			[ROHCv2_PROFILE_IP_UDP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP_ESP]     = 0, /* RFC5225 §6.9.2 */
			[ROHCv2_PROFILE_IP]         = 0, /* RFC5225 §6.9.2 */
		}
	},
	[ROHC_FEEDBACK_OPT_CONTEXT_MEMORY] = {
		.name = "CONTEXT_MEMORY",
		.unknown = false,
		.supported = false,
		.expected_len = 1U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_NOT_REQUIRED,
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = 0, /* RFC3095 §5.7.6.2 */
			[ROHC_PROFILE_UDP]          = 0, /* same as RTP */
			[ROHC_PROFILE_ESP]          = 0, /* same as UDP */
			[ROHC_PROFILE_IP]           = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC3843 §3.7 */
			[ROHC_PROFILE_RTP_LLA]      = 0, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 1, /* RFC6846 §8.3.2.4 */
			[ROHC_PROFILE_UDPLITE_RTP]  = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC4019 §5.7 */
			[ROHC_PROFILE_UDPLITE]      = ROHC_FEEDBACK_OPT_MAX_OCCURS, /* RFC4019 §5.7 */
			[ROHCv2_PROFILE_IP_UDP]     = 1, /* RFC5225 §6.9.2.3 */
			[ROHCv2_PROFILE_IP_ESP]     = 1, /* RFC5225 §6.9.2.3 */
			[ROHCv2_PROFILE_IP]         = 1, /* RFC5225 §6.9.2.3 */
		}
	},
	[ROHC_FEEDBACK_OPT_CLOCK_RESOLUTION] = {
		.name = "CLOCK_RESOLUTION",
		.unknown = false,
		.supported = false,
		.expected_len = 2U,
		.crc_req = ROHC_FEEDBACK_OPT_CRC_NOT_REQUIRED,
		.max_occurs = {
			[ROHC_PROFILE_UNCOMPRESSED] = 0, /* RFC3095 §5.10.4 */
			[ROHC_PROFILE_RTP]          = 0, /* RFC3095 §5.7.6.2 */
			[ROHC_PROFILE_UDP]          = 0, /* same as RTP */
			[ROHC_PROFILE_ESP]          = 0, /* same as UDP */
			[ROHC_PROFILE_IP]           = 0, /* RFC3843 §3.7 */
			[ROHC_PROFILE_RTP_LLA]      = 0, /* same as RTP */
			[ROHC_PROFILE_TCP]          = 0, /* RFC6846 §8.3.2 */
			[ROHC_PROFILE_UDPLITE_RTP]  = 0, /* RFC4019 §5.7 */
			[ROHC_PROFILE_UDPLITE]      = 0, /* RFC4019 §5.7 */
			[ROHCv2_PROFILE_IP_UDP]     = 1, /* RFC5225 §6.9.2.4 */
			[ROHCv2_PROFILE_IP_ESP]     = 1, /* RFC5225 §6.9.2.4 */
			[ROHCv2_PROFILE_IP]         = 1, /* RFC5225 §6.9.2.4 */
		}
	},
	[ROHC_FEEDBACK_OPT_UNKNOWN_11] = {
		.name = "unknown option with value 11",
		.unknown = true,
	},
	[ROHC_FEEDBACK_OPT_UNKNOWN_12] = {
		.name = "unknown option with value 12",
		.unknown = true,
	},
	[ROHC_FEEDBACK_OPT_UNKNOWN_13] = {
		.name = "unknown option with value 13",
		.unknown = true,
	},
	[ROHC_FEEDBACK_OPT_UNKNOWN_14] = {
		.name = "unknown option with value 14",
		.unknown = true,
	},
	[ROHC_FEEDBACK_OPT_UNKNOWN_15] = {
		.name = "unknown option with value 15",
		.unknown = true,
	},
};


#endif

