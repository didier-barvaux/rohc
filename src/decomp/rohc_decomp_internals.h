/*
 * Copyright 2012,2013,2014 Didier Barvaux
 *
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
#include "rohc_stats.h"



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
	/* The number of feedback packets sent to the associated compressor */
	unsigned long feedbacks;

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
	/** The compressor associated with the decompressor */
	struct rohc_comp *compressor;

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

	/** The callback function used to get log messages */
	rohc_trace_callback_t trace_callback;
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
	/** Profile-specific data, defined by the profiles */
	void *specific;

	/** The operation mode in which the context operates */
	rohc_mode_t mode;
	/** The operation state in which the context operates */
	rohc_decomp_state_t state;

	/** Usage timestamp */
	unsigned int latest_used;
	/** Usage timestamp */
	unsigned int first_used;

	/** Variable related to feedback interval */
	int curval;

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
	/* The number of received IR packets */
	int num_recv_ir;
	/* The number of received IR-DYN packets */
	int num_recv_ir_dyn;
	/* The number of sent feedbacks */
	int num_sent_feedbacks;

	/* The number of decompression failures */
	int num_decomp_failures;
	/** The number of successful corrections upon CRC failure */
	unsigned long corrected_crc_failures;
	/** The number of successful corrections of SN wraparound upon CRC failure */
	unsigned long corrected_sn_wraparounds;
	/** The number of successful corrections of incorrect SN updates upon CRC
	 *  failure */
	unsigned long corrected_wrong_sn_updates;

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	/* The size of the last 16 uncompressed packets */
	struct rohc_stats total_16_uncompressed;
	/* The size of the last 16 compressed packets */
	struct rohc_stats total_16_compressed;
	/* The size of the last 16 uncompressed headers */
	struct rohc_stats header_16_uncompressed;
	/* The size of the last 16 compressed headers */
	struct rohc_stats header_16_compressed;
#endif

	/** The number of (possible) lost packet(s) before last packet */
	unsigned long nr_lost_packets;
	/** The number of packet(s) before the last packet if late */
	unsigned long nr_misordered_packets;
	/** Is last packet a (possible) duplicated packet? */
	bool is_duplicated;
};


/**
 * @brief The ROHC decompression profile.
 *
 * The object defines a ROHC profile. Each field must be filled in
 * for each new profile.
 */
struct rohc_decomp_profile
{
	/* The profile ID as reserved by IANA */
	const rohc_profile_t id;

	/* @brief The handler used to create the profile-specific part of the
	 *        decompression context */
	void * (*new_context)(const struct rohc_decomp_ctxt *const context);

	/* @brief The handler used to destroy the profile-specific part of the
	 *        decompression context */
	void (*free_context)(void *const context);

	/* The handler used to decode a ROHC packet */
	int (*decode)(struct rohc_decomp *const decomp,
	              struct rohc_decomp_ctxt *const context,
	              const struct rohc_ts arrival_time,
	              const unsigned char *const rohc_packet,
	              const size_t rohc_length,
	              const size_t add_cid_len,
	              const size_t large_cid_len,
	              unsigned char *const dest,
	              const size_t uncomp_packet_max_len,
	              rohc_packet_t *const packet_type);

	/** The handler used to detect the type of the ROHC packet */
	rohc_packet_t (*detect_pkt_type)(const struct rohc_decomp_ctxt *const context,
	                                 const uint8_t *const rohc_packet,
	                                 const size_t rohc_length,
	                                 const size_t large_cid_len)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/* The handler used to retrieve the Sequence Number (SN) */
	uint32_t (*get_sn)(const struct rohc_decomp_ctxt *const context);
};



/*
 * Prototypes of library-private functions
 */

void d_change_mode_feedback(const struct rohc_decomp *const decomp,
                            const struct rohc_decomp_ctxt *const context);


#endif

