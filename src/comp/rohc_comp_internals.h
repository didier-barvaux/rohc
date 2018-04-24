/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2012,2013,2014 Viveris Technologies
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
 * @file    rohc_comp_internals.h
 * @brief   Internal structures for ROHC compression
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_INTERNALS_H
#define ROHC_COMP_INTERNALS_H

#include "rohc_internal.h"
#include "rohc_traces_internal.h"
#include "rohc_packets.h"
#include "rohc_comp.h"
#include "schemes/comp_wlsb.h"
#include "net_pkt.h"
#include "feedback.h"

#include <stdbool.h>


/*
 * Constants and macros
 */

/** The number of ROHC profiles ready to be used */
#define C_NUM_PROFILES 10U

/** The default maximal number of packets sent in > IR states (= FO and SO
 *  states) before changing back the state to IR (periodic refreshes) */
#define CHANGE_TO_IR_COUNT  1700

/** The default maximal delay (in ms) spent in > IR states (= FO and SO states)
 *  before changing back the state to IR (periodic refreshes) */
#define CHANGE_TO_IR_TIME  1000U

/** The default maximal number of packets sent in > FO states (= SO state)
 *  before changing back the state to FO (periodic refreshes) */
#define CHANGE_TO_FO_COUNT  700

/** The default maximal delay (in ms) spent in > FO states (= SO state)
 *  before changing back the state to FO (periodic refreshes) */
#define CHANGE_TO_FO_TIME  500U

/** The minimal number of packets that must be sent while in IR state before
 *  being able to switch to the FO state */
#define MAX_IR_COUNT  3U

/** The minimal number of packets that must be sent while in CR state before
 *  being able to switch to the FO state */
#define MAX_CR_COUNT  MAX_IR_COUNT

/** The minimal number of packets that must be sent while in FO state before
 *  being able to switch to the SO state */
#define MAX_FO_COUNT  3U

/** The minimal number of packets that must be sent while in INIT_STRIDE
 *  state before being able to switch to the SEND_SCALED state */
#define ROHC_INIT_TS_STRIDE_MIN  3U

/**
 * @brief Default number of transmission for lists to become a reference list
 *
 * The minimal number of times of compressed list shall be sent to become
 * a reference list. L is the name specified in the RFC.
 */
#define ROHC_LIST_DEFAULT_L  5U


/** Print a warning trace for the given compression context */
#define rohc_comp_warn(context, format, ...) \
	rohc_warning((context)->compressor, ROHC_TRACE_COMP, \
	             (context)->profile->id, \
	             format, ##__VA_ARGS__)

/** Print a debug trace for the given compression context */
#define rohc_comp_debug(context, format, ...) \
	rohc_debug((context)->compressor, ROHC_TRACE_COMP, \
	           (context)->profile->id, \
	           format, ##__VA_ARGS__)

/** Dump a buffer for the given compression context */
#define rohc_comp_dump_buf(context, descr, buf, buf_len) \
	do { \
		if(((context)->compressor->features & ROHC_COMP_FEATURE_DUMP_PACKETS) != 0) { \
			rohc_dump_buf((context)->compressor->trace_callback, \
			              (context)->compressor->trace_callback_priv, \
			              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG, \
			              descr, buf, buf_len); \
		} \
	} while(0)


/*
 * Declare ROHC compression structures that are defined at the end of this
 * file but used by other structures at the beginning of the file.
 */

struct rohc_comp_ctxt;


/*
 * Definitions of ROHC compression structures
 */


/**
 * @brief The ROHC compressor
 */
struct rohc_comp
{
	/** The medium associated with the decompressor */
	struct rohc_medium medium;

	/** Enabled/disabled features for the compressor */
	rohc_comp_features_t features;

	/** The array of compression contexts that use the compressor */
	struct rohc_comp_ctxt *contexts;
	/** The number of compression contexts in use in the array */
	size_t num_contexts_used;

	/** Which profiles are enabled and with one are not? */
	bool enabled_profiles[C_NUM_PROFILES];


	/* CRC-related variables: */

	/** The table to enable fast CRC-3 computation */
	uint8_t crc_table_3[256];
	/** The table to enable fast CRC-7 computation */
	uint8_t crc_table_7[256];
	/** The table to enable fast CRC-8 computation */
	uint8_t crc_table_8[256];


	/* segment-related variables */

/** The maximal value for MRRU */
#define ROHC_MAX_MRRU 65535
	/** The remaining bytes of the Reconstructed Reception Unit (RRU) waiting
	 *  to be split into segments */
	uint8_t rru[ROHC_MAX_MRRU];
	/** The offset of the remaining bytes in the RRU buffer */
	size_t rru_off;
	/** The number of the remaining bytes in the RRU buffer */
	size_t rru_len;


	/* variables related to RTP detection */

	/** The callback function used to detect RTP packet */
	rohc_rtp_detection_callback_t rtp_callback;
	/** Pointer to an external memory area provided/used by the callback user */
	void *rtp_private;


	/* some statistics about the compression process: */

	/** The number of sent packets */
	int num_packets;
	/** The size of all the received uncompressed IP packets */
	int total_uncompressed_size;
	/** The size of all the sent compressed ROHC packets */
	int total_compressed_size;

	/** The last context used by the compressor */
	struct rohc_comp_ctxt *last_context;


	/* random callback */

	/** The user-defined callback for random numbers */
	rohc_comp_random_cb_t random_cb;
	/** Private data that will be given to the callback for random numbers */
	void *random_cb_ctxt;


	/* user interaction variables: */

	/** The width of the W-LSB sliding window */
	size_t wlsb_window_width;
	/** The reorder offset specifies how much reordering is handled by the
	 *  W-LSB encoding of the MSN in ROHCv2 profiles */
	rohc_reordering_offset_t reorder_ratio;
	/** The maximal number of packets sent in > IR states (= FO and SO
	 *  states) before changing back the state to IR (periodic refreshes) */
	size_t periodic_refreshes_ir_timeout_pkts;
	/** The maximal delay spent in > IR states (= FO and SO states) before
	 *  changing back the state to IR (periodic refreshes) */
	uint64_t periodic_refreshes_ir_timeout_time;
	/** The maximal number of packets sent in > FO states (= SO state)
	 *  before changing back the state to FO (periodic refreshes) */
	size_t periodic_refreshes_fo_timeout_pkts;
	/** The maximal delay spent in > FO states (= SO state) before changing back
	 *  the state to FO (periodic refreshes) */
	uint64_t periodic_refreshes_fo_timeout_time;
	/** Maximum Reconstructed Reception Unit */
	size_t mrru;
	/** The connection type (currently not used) */
	int connection_type;
	/** The number of uncompressed transmissions for list compression (L) */
	size_t list_trans_nr;

	/** The callback function used to manage traces */
	rohc_trace_callback2_t trace_callback;
	/** The private context of the callback function used to manage traces */
	void *trace_callback_priv;
};


/**
 * @brief The ROHC compression profile
 *
 * The object defines a ROHC profile. Each field must be filled in
 * for each new profile.
 */
struct rohc_comp_profile
{
	/** The profile ID as reserved by IANA */
	const rohc_profile_t id;

	/**
	 * @brief The IP protocol ID used to find out which profile is able to
	 *        compress an IP packet
	 */
	const unsigned short protocol;

	/**
	 * @brief The handler used to create the profile-specific part of the
	 *        compression context from a given packet
	 */
	bool (*create)(struct rohc_comp_ctxt *const context,
	               const struct net_pkt *const packet)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/**
	 * @brief The handler used to create the profile-specific part of the
	 *        compression context from a given context
	 */
	bool (*clone)(struct rohc_comp_ctxt *const ctxt,
                 const struct rohc_comp_ctxt *const base_ctxt)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/**
	 * @brief The handler used to destroy the profile-specific part of the
	 *        compression context
	 */
	void (*destroy)(struct rohc_comp_ctxt *const context)
		__attribute__((nonnull(1)));

	/**
	 * @brief The handler used to check whether an uncompressed IP packet
	 *        fits the current profile or not
	 */
	bool (*check_profile)(const struct rohc_comp *const comp,
	                      const struct net_pkt *const packet)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/**
	 * @brief The handler used to check whether an uncompressed IP packet
	 *        belongs to a context or not
	 */
	bool (*check_context)(const struct rohc_comp_ctxt *const context,
	                      const struct net_pkt *const packet,
	                      size_t *const cr_score)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	/**
	 * @brief The handler used to encode uncompressed IP packets
	 *
	 * @param context            The compression context
	 * @param ip                 The IP packet to encode
	 * @param packet_size        The length of the IP packet to encode
	 * @param rohc_pkt           OUT: The ROHC packet
	 * @param rohc_pkt_max_len   The maximum length of the ROHC packet
	 * @param packet_type        OUT: The type of ROHC packet that is created
	 * @param payload_offset     OUT: The offset for the payload in the IP packet
	 * @return                   The length of the ROHC packet if successful,
	 *                           -1 otherwise
	 */
	int (*encode)(struct rohc_comp_ctxt *const context,
	              const struct net_pkt *const uncomp_pkt,
	              uint8_t *const rohc_pkt,
	              const size_t rohc_pkt_max_len,
	              rohc_packet_t *const packet_type,
	              size_t *const payload_offset)
		__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

	/**
	 * @brief The handler used to warn the profile-specific part of the
	 *        context about the arrival of feedback data
	 */
	bool (*feedback)(struct rohc_comp_ctxt *const context,
	                 const enum rohc_feedback_type feedback_type,
	                 const uint8_t *const packet,
	                 const size_t packet_len,
	                 const uint8_t *const feedback_data,
	                 const size_t feedback_data_len)
		__attribute__((warn_unused_result, nonnull(1, 3, 5)));
};


/**
 * @brief The ROHC compression context
 */
struct rohc_comp_ctxt
{
	/** Whether the context is in use or not */
	int used;
	/** The time when the context was created (in seconds) */
	uint64_t latest_used;
	/** The time when the context was last used (in seconds) */
	uint64_t first_used;

	/** The context unique ID (CID) */
	rohc_cid_t cid;

	/** The associated compressor */
	struct rohc_comp *compressor;

	/** The associated profile */
	const struct rohc_comp_profile *profile;
	/** Profile-specific data, defined by the profiles */
	void *specific;

	/** Whether Context Replication (CR) may be used */
	bool do_ctxt_replication;
	/** The base context for Context Replication (CR) */
	rohc_cid_t cr_base_cid;

	/** The operation mode in which the context operates among:
	 *  ROHC_U_MODE, ROHC_O_MODE, ROHC_R_MODE */
	rohc_mode_t mode;
	/** The operation state in which the context operates: IR, FO, SO */
	rohc_comp_state_t state;

	/* below are some statistics */

	/* The type of ROHC packet created for the last compressed packet */
	rohc_packet_t packet_type;

	/** The number of packets sent while in Initialization & Refresh (IR) state */
	size_t ir_count;
	/** The number of packets sent while in First Order (FO) state */
	size_t fo_count;
	/** The number of packets sent while in Second Order (SO) state */
	size_t so_count;
	/** The number of packets sent while in Context Replication (CR) state */
	size_t cr_count;

	/**
	 * @brief The number of packet sent while in SO state, used for the periodic
	 *        refreshes of the context
	 * @see rohc_comp_periodic_down_transition
	 */
	size_t go_back_fo_count;
	/**
	 * @brief The last time that the context was in FO state, used for the
	 *        periodic refreshes of the context
	 * @see rohc_comp_periodic_down_transition
	 */
	struct rohc_ts go_back_fo_time;
	/**
	 * @brief The number of packet sent while in FO or SO state, used for the
	 *        periodic refreshes of the context
	 * @see rohc_comp_periodic_down_transition
	 */
	size_t go_back_ir_count;
	/**
	 * @brief The last time that the context was in IR state, used for the
	 *        periodic refreshes of the context
	 * @see rohc_comp_periodic_down_transition
	 */
	struct rohc_ts go_back_ir_time;

	/** The cumulated size of the uncompressed packets */
	int total_uncompressed_size;
	/** The cumulated size of the compressed packets */
	int total_compressed_size;
	/** The cumulated size of the uncompressed headers */
	int header_uncompressed_size;
	/** The cumulated size of the compressed headers */
	int header_compressed_size;

	/** The total size of the last uncompressed packet */
	int total_last_uncompressed_size;
	/** The total size of the last compressed packet */
	int total_last_compressed_size;
	/** The header size of the last uncompressed packet */
	int header_last_uncompressed_size;
	/** The header size of the last compressed packet */
	int header_last_compressed_size;

	/** The number of sent packets */
	int num_sent_packets;
};


void rohc_comp_change_mode(struct rohc_comp_ctxt *const context,
                           const rohc_mode_t new_mode)
	__attribute__((nonnull(1)));

void rohc_comp_change_state(struct rohc_comp_ctxt *const context,
                            const rohc_comp_state_t new_state)
	__attribute__((nonnull(1)));

void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context,
                                        const struct rohc_ts pkt_time)
	__attribute__((nonnull(1)));

bool rohc_comp_reinit_context(struct rohc_comp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));

bool rohc_comp_feedback_parse_opts(const struct rohc_comp_ctxt *const context,
                                   const uint8_t *const packet,
                                   const size_t packet_len,
                                   const uint8_t *const feedback_data,
                                   const size_t feedback_data_len,
                                   size_t opts_present[ROHC_FEEDBACK_OPT_MAX],
                                   uint32_t *const sn_bits,
                                   size_t *const sn_bits_nr,
                                   const rohc_feedback_crc_t crc_type,
                                   uint8_t crc_in_packet,
                                   size_t crc_pos_from_end)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 6, 7, 8)));

#endif

