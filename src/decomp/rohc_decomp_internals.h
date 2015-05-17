/*
 * Copyright 2012,2013,2014 Didier Barvaux
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
 * @file    rohc_decomp_internals.h
 * @brief   Internal structures for ROHC decompression
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  Didier Barvaux <didier@barvaux.org>
 * @author  David Moreau from TAS
 */

#ifndef ROHC_DECOMP_INTERNALS_H
#define ROHC_DECOMP_INTERNALS_H

#include "rohc_internal.h"
#include "rohc_decomp.h"
#include "rohc_traces_internal.h"
#include "crc.h"


/*
 * Constants and macros
 */


/** The number of ROHC profiles ready to be used */
#define D_NUM_PROFILES 7U


/** Print a warning trace for the given decompression context */
#define rohc_decomp_warn(context, format, ...) \
	rohc_warning((context)->decompressor, ROHC_TRACE_DECOMP, \
	             (context)->profile->id, \
	             format, ##__VA_ARGS__)

/** Print a debug trace for the given decompression context */
#define rohc_decomp_debug(context, format, ...) \
	rohc_debug((context)->decompressor, ROHC_TRACE_DECOMP, \
	           (context)->profile->id, \
	           format, ##__VA_ARGS__)


/*
 * Definitions of ROHC compression structures
 */


/**
 * @brief Some compressor statistics
 */
struct d_statistics
{
	/* The number of received packets */
	unsigned long received;
	/* The number of bad decompressions due to wrong CRC */
	unsigned long failed_crc;
	/* The number of bad decompressions due to being in the No Context state */
	unsigned long failed_no_context;
	/* The number of bad decompressions */
	unsigned long failed_decomp;

	/** The cumulative size of the compressed packets */
	unsigned long total_compressed_size;
	/** The cumulative size of the uncompressed packets */
	unsigned long total_uncompressed_size;
};


/**
 * @brief The ROHC decompressor
 */
struct rohc_decomp
{
	/** The medium associated with the decompressor */
	struct rohc_medium medium;

	/** Enabled/disabled features for the decompressor */
	rohc_decomp_features_t features;

	/** Which profiles are enabled and with one are not? */
	bool enabled_profiles[D_NUM_PROFILES];

	/** The array of decompression contexts that use the decompressor */
	struct rohc_decomp_ctxt **contexts;
	/** The number of decompression contexts in use */
	size_t num_contexts_used;
	/** The last decompression context used by the decompressor */
	struct rohc_decomp_ctxt *last_context;

	/**
	 * @brief The feedback interval limits
	 *
	 * maxval can be updated by the user thanks to the user_interactions
	 * function.
	 *
	 * @see user_interactions
	 */
	unsigned int maxval;
	/** Variable related to the feedback interval */
	unsigned int errval;
	/** Variable related to the feedback interval */
	unsigned int okval;
	/** Variable related to the feedback interval */
	int curval;


	/* segment-related variables */

/** The maximal value for MRRU */
#define ROHC_MAX_MRRU 65535
	/** The Reconstructed Reception Unit */
	unsigned char rru[ROHC_MAX_MRRU];
	/** The length (in bytes) of the Reconstructed Reception Unit */
	size_t rru_len;
	/** The Maximum Reconstructed Reception Unit (MRRU) */
	size_t mrru;


	/* CRC-related variables: */

	/** The table to enable fast CRC-3 computation */
	unsigned char crc_table_3[256];
	/** The table to enable fast CRC-7 computation */
	unsigned char crc_table_7[256];
	/** The table to enable fast CRC-8 computation */
	unsigned char crc_table_8[256];


	/** Some statistics about the decompression processes */
	struct d_statistics stats;

	/** The callback function used to manage traces */
	rohc_trace_callback2_t trace_callback;
	/** The private context of the callback function used to manage traces */
	void *trace_callback_priv;
};


/**
 * @brief The different correction algorithms available in case of CRC failure
 */
typedef enum
{
	ROHC_DECOMP_CRC_CORR_SN_NONE    = 0, /**< No correction */
	ROHC_DECOMP_CRC_CORR_SN_WRAP    = 1, /**< Correction of SN wraparound */
	ROHC_DECOMP_CRC_CORR_SN_UPDATES = 2, /**< Correction of incorrect SN updates */

} rohc_decomp_crc_corr_t;


/** The context for correction upon CRC failure */
struct rohc_decomp_crc_corr_ctxt
{
	/** The algorithm being used for correction CRC failure */
	rohc_decomp_crc_corr_t algo;
	/** Correction counter (see e and f in 5.3.2.2.4 of the RFC 3095) */
	size_t counter;
/** The number of last packets to record arrival times for */
#define ROHC_MAX_ARRIVAL_TIMES  10U
	/** The arrival times for the last packets */
	struct rohc_ts arrival_times[ROHC_MAX_ARRIVAL_TIMES];
	/** The number of arrival times in arrival_times */
	size_t arrival_times_nr;
	/** The index for the arrival time of the next packet */
	size_t arrival_times_index;
};


/** The information related to the CRC of a ROHC packet */
struct rohc_decomp_crc
{
	rohc_crc_type_t type;  /**< The type of CRC that protects the ROHC header */
	uint8_t bits;          /**< The CRC bits found in ROHC header */
	size_t bits_nr;        /**< The number of CRC bits found in ROHC header */
};


/**
 * @brief The volatile part of the ROHC decompression context
 *
 * The volatile part of the ROHC decompression context lasts only one single
 * packet. Between two ROHC packets, the volatile part of the context is
 * erased.
 */
struct rohc_decomp_volat_ctxt
{
	/** The CRC information extracted from the ROHC packet being parsed */
	struct rohc_decomp_crc crc;

	/** The profile-specific data for bits extracted from the ROHC packet,
	 * defined by the profiles */
	void *extr_bits;

	/** The profile-specific data for values decoded from persistent context
	 * and bits extracted from the ROHC packet, defined by the profiles */
	void *decoded_values;
};


/**
 * @brief The ROHC decompression context
 */
struct rohc_decomp_ctxt
{
	/** The Context IDentifier (CID) */
	rohc_cid_t cid;

	/** The associated decompressor */
	struct rohc_decomp *decompressor;

	/** The associated profile */
	const struct rohc_decomp_profile *profile;
	/** The persistent profile-specific data, defined by the profiles */
	void *persist_ctxt;
	/** The volatile data, erased between two ROHC packets */
	struct rohc_decomp_volat_ctxt volat_ctxt;

	/** The operation mode in which the context operates */
	rohc_mode_t mode;
	/** The operation state in which the context operates */
	rohc_decomp_state_t state;

	/** Whether the operation modes at compressor and decompressor mismatch */
	bool do_change_mode;  /** TODO: find another way to ACK(mode) */

	/** Usage timestamp */
	unsigned int latest_used;
	/** Usage timestamp */
	unsigned int first_used;

	/** Variable related to feedback interval */
	int curval;

	/** The context for corrections upon CRC failure */
	struct rohc_decomp_crc_corr_ctxt crc_corr;

	/* below are some statistics */

	/** The type of the last decompressed ROHC packet */
	rohc_packet_t packet_type;

	/** The average size of the uncompressed packets */
	int total_uncompressed_size;
	/** The average size of the compressed packets */
	int total_compressed_size;
	/** The average size of the uncompressed headers */
	int header_uncompressed_size;
	/** The average size of the compressed headers */
	int header_compressed_size;

	/* The number of received packets */
	int num_recv_packets;
	/** The number of successful corrections upon CRC failure */
	unsigned long corrected_crc_failures;
	/** The number of successful corrections of SN wraparound upon CRC failure */
	unsigned long corrected_sn_wraparounds;
	/** The number of successful corrections of incorrect SN updates upon CRC
	 *  failure */
	unsigned long corrected_wrong_sn_updates;

	/** The number of (possible) lost packet(s) before last packet */
	unsigned long nr_lost_packets;
	/** The number of packet(s) before the last packet if late */
	unsigned long nr_misordered_packets;
	/** Is last packet a (possible) duplicated packet? */
	bool is_duplicated;
};


/**
 * @brief The informations required for sending feedback to compressor
 *
 * To be able to send some feedback to the compressor, the decompressor shall
 * (aside the decompression status itself) collect some informations about
 * the packet being decompressed:
 *  \li the Context ID (CID) of the packet (even if context was not found)
 *  \li the CID type of the channel
 *  \li the ID of the decompression profile
 *  \li was the decompression context found?
 *  \li if context was found, the context mode
 *  \li if context was found, the context state
 *  \li if context was found, the SN (LSB bits) of the latest successfully
 *      decompressed packet
 */
struct rohc_decomp_feedback_infos
{
	rohc_cid_type_t cid_type;  /**< The CID type of the channel */
	rohc_cid_t cid;            /**< The CID of the packet */
	rohc_profile_t profile_id; /**< The decompression profile (ROHC_PROFILE_GENERAL
	                                if not identified) */
	bool context_found;        /**< Whether the context was found or not */
	rohc_mode_t mode;          /**< The context mode (if context found) */
	rohc_decomp_state_t state; /**< The context state (if context found) */
	uint32_t sn_bits;          /**< The SN LSB bits (if context found) */
	size_t sn_bits_nr;         /**< The number of SN LSB bits (if context found) */
};


typedef bool (*rohc_decomp_new_context_t)(const struct rohc_decomp_ctxt *const context,
                                          void **const persist_ctxt,
                                          struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

typedef void (*rohc_decomp_free_context_t)(void *const persist_ctxt,
                                           const struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((nonnull(2)));

typedef rohc_packet_t (*rohc_decomp_detect_pkt_type_t) (const struct rohc_decomp_ctxt *const context,
                                                        const uint8_t *const rohc_packet,
                                                        const size_t rohc_length,
                                                        const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

typedef bool (*rohc_decomp_parse_pkt_t)(const struct rohc_decomp_ctxt *const context,
                                        const struct rohc_buf rohc_packet,
                                        const size_t large_cid_len,
                                        rohc_packet_t *const packet_type,
                                        struct rohc_decomp_crc *const extr_crc,
                                        void *const extr_bits,
                                        size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 4, 5, 6, 7)));

typedef bool (*rohc_decomp_decode_bits_t)(const struct rohc_decomp_ctxt *const context,
                                          const void *const extr_bits,
                                          const size_t payload_len,
                                          void *const decoded_values)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

typedef rohc_status_t (*rohc_decomp_build_hdrs_t)(const struct rohc_decomp *const decomp,
                                                  const struct rohc_decomp_ctxt *const context,
                                                  const rohc_packet_t packet_type,
                                                  const struct rohc_decomp_crc *const extr_crc,
                                                  const void *const decoded_values,
                                                  const size_t payload_len,
                                                  struct rohc_buf *const uncomp_hdrs,
                                                  size_t *const uncomp_hdrs_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5, 7, 8)));

typedef void (*rohc_decomp_update_ctxt_t)(struct rohc_decomp_ctxt *const context,
                                          const void *const decoded_values,
                                          const size_t payload_len)
	__attribute__((nonnull(1, 2)));

typedef bool (*rohc_decomp_attempt_repair_t)(const struct rohc_decomp *const decomp,
                                             const struct rohc_decomp_ctxt *const context,
                                             const struct rohc_ts pkt_arrival_time,
                                             struct rohc_decomp_crc_corr_ctxt *const crc_corr,
                                             void *const extr_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

typedef uint32_t (*rohc_decomp_get_sn_t)(const struct rohc_decomp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));


/**
 * @brief The ROHC decompression profile.
 *
 * The object defines a ROHC profile. Each field must be filled in
 * for each new profile.
 */
struct rohc_decomp_profile
{
	/** The profile ID as reserved by IANA */
	const rohc_profile_t id;

	/** The maximum number of bits of the Master Sequence Number (MSN) */
	const size_t msn_max_bits;

	/** @brief The handler used to create the profile-specific part of the
	 *         decompression context */
	rohc_decomp_new_context_t new_context;

	/** @brief The handler used to destroy the profile-specific part of the
	 *         decompression context */
	rohc_decomp_free_context_t free_context;

	/** The handler used to detect the type of the ROHC packet */
	rohc_decomp_detect_pkt_type_t detect_pkt_type;

	/* The handler used to parse a ROHC packet */
	rohc_decomp_parse_pkt_t parse_pkt;

	/* The handler used to decode the bits extracted from a ROHC packet */
	rohc_decomp_decode_bits_t decode_bits;

	/* The handler used to build the uncompressed packet after decoding */
	rohc_decomp_build_hdrs_t build_hdrs;

	/* The handler used to update the context after successful decompression */
	rohc_decomp_update_ctxt_t update_ctxt;

	/* The handler used to attempt packet/context correction upon CRC failure */
	rohc_decomp_attempt_repair_t attempt_repair;

	/* The handler used to retrieve the Sequence Number (SN) */
	rohc_decomp_get_sn_t get_sn;
};

#endif

