/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013,2014,2018 Viveris Technologies
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
 * @file rohc_decomp.c
 * @brief ROHC decompression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

/**
 * @defgroup rohc_decomp  The ROHC decompression API
 *
 * The decompression API of the ROHC library allows a program to decompress
 * some ROHC packets into uncompressed packets.
 *
 * The program shall first create a decompressor context and configure it. It
 * then may decompress as many packets as needed. When done, the ROHC
 * decompressor context shall be destroyed.
 */

#include "rohc_decomp.h"
#include "rohc_decomp_internals.h"
#include "rohc_traces_internal.h"
#include "rohc_time_internal.h"
#include "rohc_utils.h"
#include "rohc_bit_ops.h"
#include "rohc_debug.h"
#include "feedback_create.h"
#include "feedback_parse.h"
#include "sdvl.h"
#include "rohc_add_cid.h"
#include "rohc_decomp_detect_packet.h"
#include "crc.h"

#include <string.h>
#include <stdarg.h>
#include <assert.h>


/* ROHCv1 profiles */
extern const struct rohc_decomp_profile d_uncomp_profile;
extern const struct rohc_decomp_profile d_udp_profile;
extern const struct rohc_decomp_profile d_ip_profile;
extern const struct rohc_decomp_profile d_udplite_profile;
extern const struct rohc_decomp_profile d_esp_profile;
extern const struct rohc_decomp_profile d_rtp_profile;
extern const struct rohc_decomp_profile d_tcp_profile;

/* ROHCv2 profiles */
extern const struct rohc_decomp_profile rohc_decomp_rfc5225_ip_profile;
extern const struct rohc_decomp_profile rohc_decomp_rfc5225_ip_udp_profile;
extern const struct rohc_decomp_profile rohc_decomp_rfc5225_ip_esp_profile;


/**
 * @brief The decompression parts of the ROHC profiles.
 */
static const struct rohc_decomp_profile *const rohc_decomp_profiles[D_NUM_PROFILES] =
{
	&d_uncomp_profile,
	&d_rtp_profile,
	&d_udp_profile,
	&d_esp_profile,
	&d_ip_profile,
	&d_tcp_profile,
	&d_udplite_profile,
#if 0
	&rohc_decomp_rfc5225_ip_udp_rtp_profile,
#endif
	&rohc_decomp_rfc5225_ip_udp_profile,
	&rohc_decomp_rfc5225_ip_esp_profile,
	&rohc_decomp_rfc5225_ip_profile,
#if 0
	&rohc_decomp_rfc5225_ip_udplite_rtp_profile,
	&rohc_decomp_rfc5225_ip_udplite_profile,
#endif
};


/*
 * Definitions of private structures
 */

/**
 * @brief The stream information about a decompressed packet
 *
 * To be able to send some feedback to the compressor, the decompressor shall
 * (aside the decompression status itself) collect some information about
 * the packet being decompressed:
 *  \li the Context ID (CID) of the packet (even if context was not found)
 *  \li the CID type of the channel
 *  \li the ID of the decompression profile
 *  \li if context was found, the context mode
 *  \li if context was found, the context state
 *  \li if context was found, the SN (LSB bits) of the latest successfully
 *      decompressed packet
 *  \li the packet type if available
 */
struct rohc_decomp_stream
{
	rohc_cid_type_t cid_type;  /**< The CID type of the channel */
	bool cid_found;            /**< Whether the CID of the packet was found or not */
	rohc_cid_t cid;            /**< The CID of the packet */
	bool context_found;        /**< Whether the context was found or not */
	struct rohc_decomp_ctxt *context; /**< The decompression context, if found */
	rohc_profile_t profile_id; /**< The decompression profile (ROHC_PROFILE_GENERAL
	                                if not identified) */
	rohc_mode_t mode;          /**< The context mode (if context found) */
	bool do_change_mode;       /**< The context mode shall be advertised */
	rohc_decomp_state_t state; /**< The context state (if context found) */
	uint32_t sn_bits;          /**< The SN LSB bits (if context found) */
	size_t sn_bits_nr;         /**< The number of SN LSB bits (if context found) */
	rohc_packet_t packet_type; /**< The type of the decompressed packet */
	bool crc_failed;           /**< Whether the packet failed the CRC check or not */
};


/*
 * Prototypes of private functions
 */

static bool rohc_decomp_create_contexts(struct rohc_decomp *const decomp,
                                        const rohc_cid_t max_cid)
	__attribute__((nonnull(1), warn_unused_result));

static const struct rohc_decomp_profile *
	find_profile(const struct rohc_decomp *const decomp,
	             const rohc_profile_t profile_id)
	__attribute__((warn_unused_result, nonnull(1)));

static struct rohc_decomp_ctxt * context_create(struct rohc_decomp *decomp,
                                                const rohc_cid_t cid,
                                                const struct rohc_decomp_profile *const profile,
                                                const struct rohc_ts arrival_time)
	__attribute__((warn_unused_result, nonnull(1, 3)));
static struct rohc_decomp_ctxt * find_context(const struct rohc_decomp *const decomp,
                                              const size_t cid)
	__attribute__((nonnull(1), warn_unused_result));
static void context_free(struct rohc_decomp_ctxt *const context)
	__attribute__((nonnull(1)));

static int rohc_decomp_get_profile_index(const rohc_profile_t profile)
	__attribute__((warn_unused_result));

static rohc_status_t d_decode_header(struct rohc_decomp *decomp,
                                     const struct rohc_buf rohc_packet,
                                     struct rohc_buf *const uncomp_packet,
                                     struct rohc_buf *const rcvd_feedback,
                                     struct rohc_decomp_stream *const stream)
	__attribute__((nonnull(1, 3, 5), warn_unused_result));

static bool rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                   const uint8_t *packet,
                                   unsigned int len,
                                   rohc_cid_t *const cid,
                                   size_t *const add_cid_len,
                                   size_t *const large_cid_len)
	__attribute__((nonnull(1, 2, 4, 5, 6), warn_unused_result));

static void rohc_decomp_parse_padding(const struct rohc_decomp *const decomp,
                                      struct rohc_buf *const packet)
	__attribute__((nonnull(1, 2)));

static rohc_status_t rohc_decomp_find_context(struct rohc_decomp *const decomp,
                                              const uint8_t *const packet,
                                              const size_t packet_len,
                                              const rohc_cid_type_t cid,
                                              const size_t large_cid_len,
                                              const struct rohc_ts arrival_time,
                                              rohc_profile_t *const profile_id,
                                              struct rohc_decomp_ctxt **const context,
                                              bool *const context_created)
	__attribute__((warn_unused_result, nonnull(1, 2, 7, 8, 9)));

static rohc_status_t rohc_decomp_decode_pkt(struct rohc_decomp *const decomp,
                                            struct rohc_decomp_ctxt *const context,
                                            const struct rohc_buf rohc_packet,
                                            const size_t add_cid_len,
                                            const size_t large_cid_len,
                                            struct rohc_buf *const uncomp_packet,
                                            rohc_packet_t *const packet_type,
                                            bool *const do_change_mode)
	__attribute__((warn_unused_result, nonnull(1, 2, 6, 7, 8)));

static rohc_status_t rohc_decomp_try_decode_pkt(const struct rohc_decomp *const decomp,
                                                const struct rohc_decomp_ctxt *const context,
                                                const rohc_packet_t packet_type,
                                                const struct rohc_decomp_crc *const extr_crc_bits,
                                                const void *const extr_bits,
                                                const size_t payload_len,
                                                void *const decoded_values,
                                                struct rohc_buf *const uncomp_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5, 7, 8)));

static bool rohc_decomp_check_ir_crc(const struct rohc_decomp *const decomp,
                                     const struct rohc_decomp_ctxt *const context,
                                     const uint8_t *const rohc_hdr,
                                     const size_t rohc_hdr_len,
                                     const size_t add_cid_len,
                                     const size_t large_cid_len,
                                     const uint8_t crc_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static void rohc_decomp_stats_add_success(struct rohc_decomp_ctxt *const context,
                                          const size_t comp_hdr_len,
                                          const size_t uncomp_hdr_len)
	__attribute__((nonnull(1)));

static void rohc_decomp_update_context(struct rohc_decomp_ctxt *const context,
                                       const void *const decoded_values,
                                       const size_t payload_len,
                                       const struct rohc_ts pkt_arrival_time,
                                       bool *const do_change_mode)
	__attribute__((nonnull(1, 2, 5)));

/* functions to receive feedbacks for the same-site ROHC compressor */
static bool rohc_decomp_parse_feedbacks(struct rohc_decomp *const decomp,
                                        struct rohc_buf *const rohc_data,
                                        struct rohc_buf *const feedbacks)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static bool rohc_decomp_parse_feedback(struct rohc_decomp *const decomp,
                                       struct rohc_buf *const rohc_data,
                                       struct rohc_buf *const feedback,
                                       size_t *const feedback_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

/* function related to the transmission of feedback to the remote ROHC compressor */
static bool rohc_decomp_feedback_ack(struct rohc_decomp *const decomp,
                                     const struct rohc_decomp_stream *const stream,
                                     struct rohc_buf *const feedback)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static bool rohc_decomp_feedback_nack(struct rohc_decomp *const decomp,
                                      const struct rohc_decomp_stream *const stream,
                                      struct rohc_buf *const feedback)
	__attribute__((warn_unused_result, nonnull(1, 2)));

/* statistics-related functions */
static void rohc_decomp_reset_stats(struct rohc_decomp *const decomp)
	__attribute__((nonnull(1)));



/*
 * Public functions
 */


/**
 * @brief Find one decompression context thanks to its CID.
 *
 * @param decomp The ROHC decompressor
 * @param cid    The CID of the context to find out
 * @return       The context if found, NULL otherwise
 */
static struct rohc_decomp_ctxt * find_context(const struct rohc_decomp *const decomp,
                                              const rohc_cid_t cid)
{
	/* CID must be valid wrt MAX_CID */
	assert(cid <= decomp->medium.max_cid);
	return decomp->contexts[cid];
}


/**
 * @brief Create one new decompression context with profile specific data.
 *
 * @param decomp        The ROHC decompressor
 * @param cid           The CID of the new context
 * @param profile       The profile to be assigned with the new context
 * @param arrival_time  The time at which packet was received (0 if unknown,
 *                      or to disable time-related features in ROHC protocol)
 * @return              The new context if successful, NULL otherwise
 */
static struct rohc_decomp_ctxt * context_create(struct rohc_decomp *decomp,
                                                const rohc_cid_t cid,
                                                const struct rohc_decomp_profile *const profile,
                                                const struct rohc_ts arrival_time)
{
	struct rohc_decomp_ctxt *context;

	assert(cid <= ROHC_LARGE_CID_MAX);

	/* allocate memory for the decompression context */
	context = (struct rohc_decomp_ctxt *) malloc(sizeof(struct rohc_decomp_ctxt));
	if(context == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "cannot allocate memory for the contexts");
		goto error;
	}

	/* record the CID */
	context->cid = cid;

	/* associate the decompressor with the context */
	context->decompressor = decomp;

	/* associate the decompression profile with the context */
	context->profile = profile;

	/* initialize mode and state */
	context->mode = ROHC_U_MODE;
	context->state = ROHC_DECOMP_STATE_NC;

	/* counters and thresholds for feedbacks and downward state transitions */
	context->last_pkts_errors = 0;
	context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].needed = 0;
	context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent = 0;
	context->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].needed = 0;
	context->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].sent = 0;
	context->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].needed = 0;
	context->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].sent = 0;

	/* init the context for packet/context corrections upon CRC failures */
	/* at the beginning, no attempt to correct CRC failure */
	context->crc_corr.algo = ROHC_DECOMP_CRC_CORR_SN_NONE;
	context->crc_corr.counter = 0;
	/* arrival times for correction upon CRC failure */
	memset(context->crc_corr.arrival_times, 0,
	       sizeof(struct rohc_ts) * ROHC_MAX_ARRIVAL_TIMES);
	context->crc_corr.arrival_times_nr = 0;
	context->crc_corr.arrival_times_index = 0;

	/* init some statistics */
	context->num_recv_packets = 0;
	context->total_uncompressed_size = 0;
	context->total_compressed_size = 0;
	context->header_uncompressed_size = 0;
	context->header_compressed_size = 0;
	context->total_last_uncompressed_size = 0;
	context->total_last_compressed_size = 0;
	context->header_last_uncompressed_size = 0;
	context->header_last_compressed_size = 0;
	context->corrected_crc_failures = 0;
	context->corrected_sn_wraparounds = 0;
	context->corrected_wrong_sn_updates = 0;
	context->nr_lost_packets = 0;
	context->nr_misordered_packets = 0;
	context->is_duplicated = 0;

	context->first_used = arrival_time.sec;
	context->latest_used = arrival_time.sec;

	/* create the profile-specific parts of the decompression context (performed
	 * at the every end so that everything is initialized in context first) */
	if(!profile->new_context(context, &context->persist_ctxt, &context->volat_ctxt))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "failed to initialize the profile-specific parts of the "
		             "decompression context");
		goto destroy_context;
	}

	/* decompressor got one more context (for a short moment, decompressor
	 * might have MAX_CID + 2 contexts) */
	assert(decomp->num_contexts_used <= (decomp->medium.max_cid + 1));
	decomp->num_contexts_used++;

	return context;

destroy_context:
	zfree(context);
error:
	return NULL;
}


/**
 * @brief Destroy one decompression context and the profile specific data
 *        associated with it.
 *
 * @param context  The context to destroy
 */
static void context_free(struct rohc_decomp_ctxt *const context)
{
	assert(context->decompressor != NULL);
	assert(context->profile != NULL);

	rohc_debug(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
	           "free context with CID %zu", context->cid);

	/* destroy the profile-specific data */
	context->profile->free_context(context->persist_ctxt, &context->volat_ctxt);

	/* decompressor got one more context */
	assert(context->decompressor->num_contexts_used > 0);
	context->decompressor->num_contexts_used--;

	/* destroy the context itself */
	free(context);
}


/**
 * @brief Create a new ROHC decompressor
 *
 * Create a new ROHC decompressor with the given type of CIDs, MAX_CID, and
 * operational mode.
 *
 * @param cid_type  The type of Context IDs (CID) that the ROHC decompressor
 *                  shall operate with.\n
 *                  Accepted values are:
 *                    \li \ref ROHC_SMALL_CID for small CIDs
 *                    \li \ref ROHC_LARGE_CID for large CIDs
 * @param max_cid   The maximum value that the ROHC decompressor should use
 *                  for context IDs (CID). As CIDs starts with value 0, the
 *                  number of contexts is \e max_cid + 1.\n
 *                  Accepted values are:
 *                    \li [0, \ref ROHC_SMALL_CID_MAX] if \e cid_type is
 *                        \ref ROHC_SMALL_CID
 *                    \li [0, \ref ROHC_LARGE_CID_MAX] if \e cid_type is
 *                        \ref ROHC_LARGE_CID
 * @param mode      The operational mode that the ROHC decompressor shall target.\n
 *                  Accepted values are:
 *                    \li \ref ROHC_U_MODE for the Unidirectional mode,
 *                    \li \ref ROHC_O_MODE for the Bidirectional Optimistic
 *                        mode,
 *                    \li \ref ROHC_R_MODE for the Bidirectional Reliable mode
 *                        is not supported yet: specifying \ref ROHC_R_MODE is
 *                        an error.
 * @return          The created decompressor if successful,
 *                  NULL if creation failed
 *
 * @warning Don't forget to free decompressor memory with
 *          \ref rohc_decomp_free if rohc_decomp_new2 succeeded
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c create ROHC decompressor #1
 * \snippet example_rohc_decomp.c create ROHC decompressor #2
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c destroy ROHC decompressor
 *
 * @see rohc_decomp_free
 * @see rohc_decompress3
 * @see rohc_decomp_set_traces_cb2
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_disable_profiles
 * @see rohc_decomp_disable_profile
 * @see rohc_decomp_set_mrru
 * @see rohc_decomp_set_features
 */
struct rohc_decomp * rohc_decomp_new2(const rohc_cid_type_t cid_type,
                                      const rohc_cid_t max_cid,
                                      const rohc_mode_t mode)
{

	struct rohc_decomp *decomp;
	bool is_fine;
	size_t i;

	/* check input parameters */
	if(cid_type == ROHC_SMALL_CID)
	{
		/* use small CIDs in range [0, ROHC_SMALL_CID_MAX] */
		if(max_cid > ROHC_SMALL_CID_MAX)
		{
			goto error;
		}
	}
	else if(cid_type == ROHC_LARGE_CID)
	{
		/* use large CIDs in range [0, ROHC_LARGE_CID_MAX] */
		if(max_cid > ROHC_LARGE_CID_MAX)
		{
			goto error;
		}
	}
	else
	{
		/* unexpected CID type */
		goto error;
	}
	if(mode != ROHC_U_MODE && mode != ROHC_O_MODE && mode != ROHC_R_MODE)
	{
		/* unexpected operational mode */
		goto error;
	}
	else if(mode == ROHC_R_MODE)
	{
		/* R-mode is not supported yet */
		goto error;
	}

	/* allocate memory for the decompressor */
	decomp = (struct rohc_decomp *) malloc(sizeof(struct rohc_decomp));
	if(decomp == NULL)
	{
		goto error;
	}

	/* no trace callback during decompressor creation */
	decomp->trace_callback = NULL;
	decomp->trace_callback_priv = NULL;

	/* default feature set (empty for the moment) */
	decomp->features = ROHC_DECOMP_FEATURE_NONE;

	/* init decompressor medium */
	decomp->medium.cid_type = cid_type;
	decomp->medium.max_cid = max_cid;

	/* all decompression profiles are disabled by default */
	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		decomp->enabled_profiles[i] = false;
	}

	/* the operational mode the decompressor shall target for all its contexts */
	decomp->target_mode = mode;

	/* initialize the array of decompression contexts to its minimal value */
	decomp->contexts = NULL;
	decomp->num_contexts_used = 0;
	is_fine = rohc_decomp_create_contexts(decomp, decomp->medium.max_cid);
	if(!is_fine)
	{
		goto destroy_decomp;
	}
	decomp->last_context = NULL;

	/* counters and thresholds for feedbacks and downward state transitions */
	{
		const size_t rtt = 1000U; /* conservative 1-second RTT */
		const size_t pkt_period = 20U; /* one packet every 20 ms like for VoIP */
		const size_t prtt = rtt / pkt_period;
		is_fine = rohc_decomp_set_prtt(decomp, prtt);
		assert(is_fine);
		is_fine = rohc_decomp_set_rate_limits(decomp, 1, prtt, 30, 100, 30, 100);
		assert(is_fine);
		decomp->last_pkts_errors = 0;
		decomp->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].needed = 0;
		decomp->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent = 0;
		decomp->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].needed = 0;
		decomp->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].sent = 0;
		decomp->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].needed = 0;
		decomp->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].sent = 0;
	}

	/* no Reconstructed Reception Unit (RRU) at the moment */
	decomp->rru_len = 0;
	/* no segmentation by default */
	decomp->mrru = 0;

	/* init the tables for fast CRC computation */
	rohc_crc_init_table(decomp->crc_table_3, ROHC_CRC_TYPE_3);
	rohc_crc_init_table(decomp->crc_table_7, ROHC_CRC_TYPE_7);
	rohc_crc_init_table(decomp->crc_table_8, ROHC_CRC_TYPE_8);

	/* reset the decompressor statistics */
	rohc_decomp_reset_stats(decomp);

	return decomp;

destroy_decomp:
	free(decomp);
error:
	return NULL;
}


/**
 * @brief Destroy the given ROHC decompressor
 *
 * Destroy a ROHC decompressor that was successfully created with
 * \ref rohc_decomp_new2
 *
 * @param decomp  The decompressor to destroy
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c create ROHC decompressor #1
 * \snippet example_rohc_decomp.c create ROHC decompressor #2
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c destroy ROHC decompressor
 *
 * @see rohc_decomp_new2
 */
void rohc_decomp_free(struct rohc_decomp *const decomp)
{
	rohc_cid_t i;

	/* sanity check */
	if(decomp == NULL)
	{
		goto error;
	}
	assert(decomp->contexts != NULL);

	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "free ROHC decompressor");

	/* destroy all the contexts owned by the decompressor */
	for(i = 0; i <= decomp->medium.max_cid; i++)
	{
		if(decomp->contexts[i] != NULL)
		{
			context_free(decomp->contexts[i]);
		}
	}
	zfree(decomp->contexts);
	assert(decomp->num_contexts_used == 0);

	/* destroy the decompressor itself */
	free(decomp);

error:
	return;
}


/**
 * @brief Decompress the given ROHC packet into one uncompressed packet
 *
 * Decompress the given ROHC packet into an uncompressed packet. The
 * decompression always returns ROHC_OK in case of success. The caller shall
 * however be ready to handle several cases:
 *  \li the uncompressed packet \e uncomp_packet might be empty if the ROHC
 *      packet contained only feedback data or if the ROHC packet was not a
 *      final segment
 *  \li the received feedback \e rcvd_feedback might be empty if the ROHC
 *      packet doesn't contain at least one feedback item
 *
 * If \e feedback_send is not NULL, the decompression may return some feedback
 * information on it. In such a case, the caller is responsible to send it to
 * the compressor through any feedback channel.
 *
 * Time-related features in the ROHC protocol: set the \e rohc_packet.time
 * parameter to 0 if arrival time of the ROHC packet is unknown or to disable
 * the time-related features in the ROHC protocol.
 *
 * @param decomp              The ROHC decompressor
 * @param rohc_packet         The compressed packet to decompress
 * @param[out] uncomp_packet  The resulting uncompressed packet
 * @param[out] rcvd_feedback  The feedback received from the remote peer for
 *                            the same-side associated ROHC compressor through
 *                            the feedback channel:
 *                            \li If NULL, ignore the received feedback data
 *                            \li If not NULL, store the received feedback in
 *                                at the given address
 * @param[out] feedback_send  The feedback to be transmitted to the remote
 *                            compressor through the feedback channel:
 *                            \li If NULL, the decompression won't generate
 *                                feedback information for its compressor
 *                            \li If not NULL, may store the generated
 *                                feedback at the given address
 * @return                    Possible return values:
 *                            \li \ref ROHC_STATUS_OK if a decompressed packet
 *                                is returned
 *                            \li \ref ROHC_STATUS_NO_CONTEXT if no
 *                                 decompression context matches the CID
 *                                 stored in the given ROHC packet and the
 *                                 ROHC packet is not an IR packet
 *                            \li \ref ROHC_STATUS_OUTPUT_TOO_SMALL if the
 *                                output buffer is too small for the
 *                                compressed packet
 *                            \li \ref ROHC_STATUS_MALFORMED if the
 *                                decompression failed because the ROHC packet
 *                                is malformed
 *                            \li \ref ROHC_STATUS_BAD_CRC if the CRC detected
 *                                a transmission or decompression problem
 *                            \li \ref ROHC_STATUS_ERROR if another problem
 *                                occurred
 *
 * @ingroup rohc_decomp
 *
 * \par Example #1:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \snippet example_rohc_decomp.c define IP and ROHC packets
 * \code
	...
\endcode
 * \snippet example_rohc_decomp.c decompress ROHC packet #1
 * \snippet example_rohc_decomp.c decompress ROHC packet #2
 * \snippet example_rohc_decomp.c decompress ROHC packet #3
 *
 * @see rohc_decomp_set_mrru
 */
rohc_status_t rohc_decompress3(struct rohc_decomp *const decomp,
                               const struct rohc_buf rohc_packet,
                               struct rohc_buf *const uncomp_packet,
                               struct rohc_buf *const rcvd_feedback,
                               struct rohc_buf *const feedback_send)
{
	rohc_status_t status = ROHC_STATUS_ERROR; /* error status by default */
	struct rohc_decomp_stream stream;

	/* check inputs validity */
	if(decomp == NULL)
	{
		goto error;
	}
	if(rohc_buf_is_malformed(rohc_packet))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is malformed");
		goto error;
	}
	if(rohc_buf_is_empty(rohc_packet))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is empty");
		goto error;
	}
	if(uncomp_packet == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is NULL");
		goto error;
	}
	if(rohc_buf_is_malformed(*uncomp_packet))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is malformed");
		goto error;
	}
	if(!rohc_buf_is_empty(*uncomp_packet))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is not empty");
		goto error;
	}
	if(rcvd_feedback != NULL)
	{
		if(rohc_buf_is_malformed(*rcvd_feedback))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "given rcvd_feedback is malformed");
			goto error;
		}
		if(!rohc_buf_is_empty(*rcvd_feedback))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "given rcvd_feedback is not empty");
			goto error;
		}
	}
	if(feedback_send != NULL)
	{
		if(rohc_buf_is_malformed(*feedback_send))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "given feedback_send is malformed");
			goto error;
		}
		if(!rohc_buf_is_empty(*feedback_send))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "given feedback_send is not empty");
			goto error;
		}
	}

	decomp->stats.received++;
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "decompress the %zu-byte packet #%lu", rohc_packet.len,
	           decomp->stats.received);

	/* print compressed bytes */
	if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
	{
		rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
		                 ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
		                 "compressed data, max 100 bytes", rohc_packet);
	}

	/* decode ROHC header */
	status = d_decode_header(decomp, rohc_packet, uncomp_packet, rcvd_feedback,
	                         &stream);
	assert(status != ROHC_STATUS_SEGMENT);

	/* handle mode transitions if context was found and it is still valid */
	if(stream.context != NULL)
	{
		if(stream.context->mode == ROHC_U_MODE)
		{
			if(decomp->target_mode == ROHC_U_MODE)
			{
				rohc_debug(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
				           "stay in U-mode as requested by user");
			}
			else if(decomp->target_mode == ROHC_O_MODE)
			{
				rohc_debug(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
				           "transit from U-mode to O-mode as requested by user");
				stream.context->mode = ROHC_O_MODE;
				/* ACK(O), NACK(O) or STATIC-NACK(O) will transmit the mode
				 * transition to the remote compressor */
				stream.mode = ROHC_O_MODE;
				stream.do_change_mode = true;
			}
			else /* R-mode */
			{
				assert(0); /* TODO: R-mode not supported yet */
				status = ROHC_STATUS_ERROR;
				goto error;
			}
		}
		else if(stream.context->mode == ROHC_O_MODE)
		{
			if(decomp->target_mode == ROHC_U_MODE)
			{
				assert(0); /* TODO: O- to U-mode transition not supported yet */
				status = ROHC_STATUS_ERROR;
				goto error;
			}
			else if(decomp->target_mode == ROHC_O_MODE)
			{
				rohc_debug(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
				           "stay in O-mode as requested by user");
			}
			else /* R-mode */
			{
				assert(0); /* TODO: R-mode not supported yet */
				status = ROHC_STATUS_ERROR;
				goto error;
			}
		}
		else /* R-mode */
		{
			assert(0); /* TODO: R-mode not supported yet */
			status = ROHC_STATUS_ERROR;
			goto error;
		}
	}

	/* update statistics and send feedback if needed */
	if(status == ROHC_STATUS_OK)
	{
		/* print a trace to report success (the context may be NULL if packet
		 * was a feedback-only packet) */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
		           "packet decompression succeeded");

		/* do not update statistics and build positive feedback for feedback-only
		 * packets */
		if(uncomp_packet->len > 0)
		{
			/* update statistics */
			rohc_debug(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
			           "update decompressor and context statistics");
			assert(stream.context != NULL);
			stream.context->num_recv_packets++;
			stream.context->packet_type = stream.packet_type;
			stream.context->total_last_uncompressed_size = uncomp_packet->len;
			stream.context->total_uncompressed_size += uncomp_packet->len;
			stream.context->total_last_compressed_size = rohc_packet.len;
			stream.context->total_compressed_size += rohc_packet.len;
			decomp->stats.total_uncompressed_size += uncomp_packet->len;
			decomp->stats.total_compressed_size += rohc_packet.len;

			/* build positive feedback if asked by user and if needed by decompressor */
			if(!rohc_decomp_feedback_ack(decomp, &stream, feedback_send))
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
				             "failed to build positive feedback");
				status = ROHC_STATUS_ERROR;
				goto error;
			}
		}
	}
	else /* packet failed to be decompressed */
	{
		/* in case of failure, users shall get an empty decompressed packet */
		uncomp_packet->len = 0;

		rohc_warning(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
		             "packet decompression failed: %s (%d)",
		             rohc_strerror(status), status);

		/* update statistics */
		if(stream.context != NULL)
		{
			stream.context->num_recv_packets++;
		}
		switch(status)
		{
			case ROHC_STATUS_MALFORMED:
			case ROHC_STATUS_OUTPUT_TOO_SMALL:
			case ROHC_STATUS_ERROR:
				decomp->stats.failed_decomp++;
				break;
			case ROHC_STATUS_NO_CONTEXT:
				decomp->stats.failed_no_context++;
				break;
			case ROHC_STATUS_BAD_CRC:
				decomp->stats.failed_crc++;
				break;
			case ROHC_STATUS_OK: /* success codes shall not happen */
			case ROHC_STATUS_SEGMENT:
			default:
				assert(0);
				status = ROHC_STATUS_ERROR;
				goto error;
		}

		/* build negative feedback if asked by user and if needed by decompressor */
		if(!rohc_decomp_feedback_nack(decomp, &stream, feedback_send))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, stream.profile_id,
			             "failed to build negative feedback");
			status = ROHC_STATUS_ERROR;
			goto error;
		}
	}

error:
	return status;
}


/**
 * @brief Decompress the compressed headers.
 *
 * @param decomp              The ROHC decompressor
 * @param rohc_packet         The ROHC packet to decode
 * @param[out] uncomp_packet  The uncompressed packet
 * @param[out] rcvd_feedback  The feedback received from the remote peer for
 *                            the same-side associated ROHC compressor through
 *                            the feedback channel:
 *                            \li If NULL, ignore the received feedback data
 *                            \li If not NULL, store the received feedback in
 *                                at the given address
 * @param[out] stream         The information about the decompressed stream,
 *                            required for sending feedback to compressor
 * @return                    Possible return values:
 *                            \li ROHC_STATUS_OK if packet is successfully
 *                                decoded,
 *                            \li ROHC_STATUS_NO_CONTEXT if no matching
 *                                context was found and packet cannot create
 *                                a new context (or failed to do so),
 *                            \li ROHC_STATUS_MALFORMED if packet is
 *                                malformed,
 *                            \li ROHC_STATUS_BAD_CRC if a CRC error occurs,
 *                            \li ROHC_STATUS_ERROR if another error occurs
 */
static rohc_status_t d_decode_header(struct rohc_decomp *decomp,
                                     const struct rohc_buf rohc_packet,
                                     struct rohc_buf *const uncomp_packet,
                                     struct rohc_buf *const rcvd_feedback,
                                     struct rohc_decomp_stream *const stream)
{
	const struct rohc_decomp_profile *profile;
	bool is_new_context = false;
	size_t sn_feedback_min_bits;
	size_t add_cid_len;
	size_t large_cid_len;

	struct rohc_buf remain_rohc_data = rohc_packet;
	const uint8_t *walk;
	size_t remain_len;

	rohc_status_t status;

	/* at the beginning, context is not found yet but channel CID type is known */
	stream->profile_id = ROHC_PROFILE_GENERAL;
	stream->cid_type = decomp->medium.cid_type;
	stream->cid_found = false;
	stream->cid = SIZE_MAX;
	stream->context_found = false;
	stream->context = NULL;
	stream->mode = ROHC_UNKNOWN_MODE;
	stream->state = ROHC_DECOMP_STATE_UNKNOWN;
	stream->do_change_mode = false;
	stream->sn_bits = 0; /* must be set to 0 until we get some bits */
	stream->sn_bits_nr = 0;
	stream->packet_type = ROHC_PACKET_UNKNOWN;
	stream->crc_failed = false;

	/* empty ROHC packets are not considered as valid */
	if(remain_rohc_data.len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "ROHC packet too small (len = %zu, at least 1 byte "
		             "required)", remain_rohc_data.len);
		goto error_malformed;
	}

	/* skip padding bits if some are present */
	rohc_decomp_parse_padding(decomp, &remain_rohc_data);

	/* padding-only packets are not allowed according to RFC 3095, §5.2:
	 *   Padding is any number (zero or more) of padding octets.  Either of
	 *   Feedback or Header must be present. */
	if(remain_rohc_data.len == 0)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "padding-only packet is not allowed");
		goto error_malformed;
	}

	/* extract feedback items if present */
	if(!rohc_decomp_parse_feedbacks(decomp, &remain_rohc_data, rcvd_feedback))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "failed to decode feedback items at the beginning of the "
		             "ROHC packet");
		goto error_malformed;
	}
	if(rcvd_feedback != NULL)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "decompressor received %zu bytes of feedback for the "
		           "same-side associated compressor", rcvd_feedback->len);
	}
	walk = rohc_buf_data(remain_rohc_data);
	remain_len = remain_rohc_data.len;

	/* is there some data after feedback? */
	if(remain_rohc_data.len == 0)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "feedback-only packet, stop decompression");
		goto skip;
	}

	/* ROHC segment? */
	if(rohc_decomp_packet_is_segment(walk))
	{
		const bool is_final = !!GET_REAL(GET_BIT_0(walk));
		uint32_t crc_computed;

		/* skip the segment type byte */
		walk++;
		remain_len--;
		rohc_buf_pull(&remain_rohc_data, 1);

		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "ROHC packet is a %zu-byte %s segment", remain_len,
		           is_final ? "final" : "non-final");

		/* store all the remaining ROHC data in RRU */
		if((decomp->rru_len + remain_len) > decomp->mrru)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "invalid RRU: received segment is too large for MRRU "
			             "(%zu bytes already received, %zu bytes received, "
			             "MRRU = %zu bytes", decomp->rru_len, remain_len,
			             decomp->mrru);
			/* dicard RRU */
			decomp->rru_len = 0;
			goto error_malformed;
		}
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "append new segment to the %zd bytes we already received",
		           decomp->rru_len);
		memcpy(decomp->rru + decomp->rru_len, walk, remain_len);
		decomp->rru_len += remain_len;

		/* stop decoding here is not final segment */
		if(!is_final)
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "%zd bytes of RRU already received, wait for more "
			           "segments before decompressing RRU", decomp->rru_len);
			goto skip;
		}

		/* final segment received, let's check CRC */
		if(decomp->rru_len <= 4)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "invalid %zd-byte RRU: should be more than 4-byte long",
			             decomp->rru_len);
			/* discard RRU */
			decomp->rru_len = 0;
			goto error_malformed;
		}
		decomp->rru_len -= 4;
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "final segment received, check the 4-byte CRC of the "
		           "%zd-byte RRU", decomp->rru_len);
		crc_computed = crc_calc_fcs32(decomp->rru, decomp->rru_len,
		                              CRC_INIT_FCS32);
		if(memcmp(&crc_computed, decomp->rru + decomp->rru_len, 4) != 0)
		{
			uint32_t crc_packet;
			memcpy(&crc_packet, decomp->rru + decomp->rru_len, 4);
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "invalid %zd-byte RRU: bad CRC (packet = 0x%08x, "
			             "computed = 0x%08x)", decomp->rru_len,
			             rohc_ntoh32(crc_packet), rohc_ntoh32(crc_computed));
			/* discard RRU */
			decomp->rru_len = 0;
			goto error_crc;
		}

		/* CRC of segment is OK, let's decode RRU */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "final segment received, decode the %zd-byte RRU",
		           decomp->rru_len);
		walk = decomp->rru;
		remain_len = decomp->rru_len;
		remain_rohc_data.offset = 0;
		remain_rohc_data.data = decomp->rru;
		remain_rohc_data.len = decomp->rru_len;
		remain_rohc_data.max_len = decomp->rru_len;

		/* reset context for next RRU */
		decomp->rru_len = 0;
	}

	/* decode small or large CID */
	if(!rohc_decomp_decode_cid(decomp, walk, remain_len, &stream->cid,
	                           &add_cid_len, &large_cid_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "failed to decode small or large CID in packet");
		goto error_malformed;
	}
	stream->cid_found = true;

	/* check whether the decoded CID is allowed by the decompressor */
	if(stream->cid > decomp->medium.max_cid)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unexpected CID %zu received: MAX_CID was set to %zu",
		             stream->cid, decomp->medium.max_cid);
		goto error_no_context;
	}

	/* skip add-CID if present */
	walk += add_cid_len;
	remain_len -= add_cid_len;
	rohc_buf_pull(&remain_rohc_data, add_cid_len);

	/* find the context according to the CID found in CID,
	 * create it if needed (and possible) */
	status = rohc_decomp_find_context(decomp, walk, remain_len, stream->cid,
	                                  large_cid_len, rohc_packet.time,
	                                  &stream->profile_id, &stream->context,
	                                  &is_new_context);
	if(status == ROHC_STATUS_MALFORMED)
	{
		/* no additional feedback information to collect */
		goto error_malformed;
	}
	else if(status == ROHC_STATUS_NO_CONTEXT)
	{
		/* even if the context was not found/created, the profile ID might be available */
		goto error_no_context;
	}
	assert(status == ROHC_STATUS_OK);
	profile = stream->context->profile;
	decomp->last_context = stream->context;
	sn_feedback_min_bits = rohc_min(decomp->sn_feedback_min_bits,
	                                profile->msn_max_bits);
	rohc_decomp_debug(stream->context, "decode packet with profile '%s' (0x%04x)",
	                  rohc_get_profile_descr(profile->id), profile->id);

	/* collect information for sending feedback to decompressor */
	stream->context_found = true;
	stream->mode = stream->context->mode;
	stream->state = stream->context->state;
	if(!is_new_context)
	{
		stream->sn_bits = profile->get_sn(stream->context);
		stream->sn_bits_nr = sn_feedback_min_bits;
		rohc_decomp_debug(stream->context, "%zu bits required for SN in feedback "
		                  "(%zu bits required for RTT, %zu max)",
		                  sn_feedback_min_bits, decomp->sn_feedback_min_bits,
		                  profile->msn_max_bits);
	}

	/* detect the type of the ROHC packet */
	stream->packet_type = profile->detect_pkt_type(stream->context, walk, remain_len,
	                                               large_cid_len);
	if(stream->packet_type == ROHC_PACKET_UNKNOWN)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "failed to detect ROHC packet type");
		if(is_new_context)
		{
			context_free(stream->context);
			stream->context = NULL;
			decomp->last_context = NULL;
		}
		goto error_malformed;
	}
	rohc_decomp_debug(stream->context, "decode packet as '%s'",
	                  rohc_get_packet_descr(stream->packet_type));

	/* only packets that carry static information can be received in the
	 * No Context state, other cannot */
	if(stream->state == ROHC_DECOMP_STATE_NC &&
	   !rohc_packet_carry_static_info(stream->packet_type))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "CID %zu: packet '%s' (%d) does not carry static information, "
		             "it cannot be received in No Context state",
		             stream->cid, rohc_get_packet_descr(stream->packet_type),
		             stream->packet_type);
		if(is_new_context)
		{
			context_free(stream->context);
			stream->context = NULL;
			decomp->last_context = NULL;
		}
		goto error_malformed;
	}
	/* only packets carrying CRC-7 or CRC-8 can be received in the Static Context
	 * state, other cannot */
	else if(stream->state == ROHC_DECOMP_STATE_SC &&
	        !rohc_packet_carry_crc_7_or_8(stream->packet_type))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "CID %zu: packet '%s' (%d) does not carry 7- or 8-bit CRC, "
		             "it cannot be received in Static Context state",
		             stream->cid, rohc_get_packet_descr(stream->packet_type),
		             stream->packet_type);
		if(is_new_context)
		{
			context_free(stream->context);
			stream->context = NULL;
			decomp->last_context = NULL;
		}
		goto error_malformed;
	}
	/* all packet types are allowed in Full Context state */

	/* only IR or IR-CR packet can create a new context */
	assert(stream->packet_type == ROHC_PACKET_IR ||
	       stream->packet_type == ROHC_PACKET_IR_CR ||
	       !is_new_context);

	/* decode the packet thanks to the profile-specific routines
	 * (may change the initial assumption about the packet type) */
	status = rohc_decomp_decode_pkt(decomp, stream->context, remain_rohc_data,
	                                add_cid_len, large_cid_len, uncomp_packet,
	                                &stream->packet_type, &stream->do_change_mode);
	if(status != ROHC_STATUS_OK)
	{
		/* decompression failed, free resources if necessary */
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "failed to decompress packet (code = %d)", status);
		if(is_new_context)
		{
			context_free(stream->context);
			stream->context = NULL;
			decomp->last_context = NULL;
		}
		goto error;
	}

	/* decompression was successful, replace the existing context with the
	 * new one if necessary */
	if(is_new_context)
	{
		if(decomp->contexts[stream->cid] != NULL)
		{
			context_free(decomp->contexts[stream->cid]);
		}
		decomp->contexts[stream->cid] = stream->context;
	}

	/* get the SN of the latest packet successfully decompressed */
	stream->sn_bits = profile->get_sn(stream->context);
	stream->sn_bits_nr = sn_feedback_min_bits;
	rohc_decomp_debug(stream->context, "%zu bits required for SN in feedback "
	                  "(%zu bits required for RTT, %zu max)",
	                  sn_feedback_min_bits, decomp->sn_feedback_min_bits,
	                  profile->msn_max_bits);

skip:
	return ROHC_STATUS_OK;

error:
	stream->crc_failed = !!(status == ROHC_STATUS_BAD_CRC);
	decomp->last_context = NULL;
	return status;

error_crc:
	stream->crc_failed = true;
	decomp->last_context = NULL;
	return ROHC_STATUS_BAD_CRC;

error_malformed:
	decomp->last_context = NULL;
	return ROHC_STATUS_MALFORMED;

error_no_context:
	decomp->last_context = NULL;
	return ROHC_STATUS_NO_CONTEXT;
}


/**
 * @brief Decode one ROHC packet
 *
 * Steps:
 *  \li A. Parse the ROHC header
 *  \li B. For IR and IR-DYN packet, check for correct compressed header (CRC)
 *  \li C. Decode extracted bits
 *  \li D. Build uncompressed headers (and check for correct decompression
 *         for UO* packets)
 *  \li E. Copy the payload (if any)
 *  \li F. Update the compression context
 *
 * Steps C and D may be repeated if packet or context repair is attempted
 * upon CRC failure.
 *
 * @param decomp               The ROHC decompressor
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to decode
 * @param add_cid_len          The length of the optional Add-CID field
 * @param large_cid_len        The length of the optional large CID field
 * @param[out] uncomp_packet   The uncompressed packet
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] do_change_mode  Whether the profile context wants to change
 *                             its operational mode or not
 * @return                     ROHC_STATUS_OK if packet is successfully decoded,
 *                             ROHC_STATUS_MALFORMED if packet is malformed,
 *                             ROHC_STATUS_BAD_CRC if a CRC error occurs,
 *                             ROHC_STATUS_ERROR if an error occurs
 */
static rohc_status_t rohc_decomp_decode_pkt(struct rohc_decomp *const decomp,
                                            struct rohc_decomp_ctxt *const context,
                                            const struct rohc_buf rohc_packet,
                                            const size_t add_cid_len,
                                            const size_t large_cid_len,
                                            struct rohc_buf *const uncomp_packet,
                                            rohc_packet_t *const packet_type,
                                            bool *const do_change_mode)
{
	const struct rohc_decomp_profile *const profile = context->profile;
	struct rohc_decomp_crc *const extr_crc_bits = &context->volat_ctxt.crc;
	void *const extr_bits = context->volat_ctxt.extr_bits;
	void *const decoded_values = context->volat_ctxt.decoded_values;

	/* length of the parsed ROHC header and of the uncompressed headers */
	size_t rohc_hdr_len;
	size_t uncomp_hdr_len;

	/* ROHC and uncompressed payloads (they are the same) */
	const uint8_t *payload_data;
	size_t payload_len;

	/* Whether to attempt packet correction or not */
	bool try_decoding_again;

	/* helper variables for values returned by functions */
	bool parsing_ok;
	rohc_status_t status;

	assert(add_cid_len == 0 || add_cid_len == 1);
	assert(large_cid_len <= 2);
	assert((*packet_type) != ROHC_PACKET_UNKNOWN);

	/* A. Parse the ROHC header */

	rohc_decomp_debug(context, "parse packet type '%s' (%d)",
	                  rohc_get_packet_descr(*packet_type), *packet_type);

	/* let's parse the packet! */
	parsing_ok = profile->parse_pkt(context, rohc_packet, large_cid_len,
	                                packet_type, extr_crc_bits, extr_bits,
	                                &rohc_hdr_len);
	if(!parsing_ok)
	{
		rohc_decomp_warn(context, "failed to parse the %s header",
		                 rohc_get_packet_descr(*packet_type));
		status = ROHC_STATUS_MALFORMED;
		goto error;
	}

	/* ROHC base header and its optional extension is now fully parsed,
	 * remaining data is the payload */
	payload_data = rohc_buf_data(rohc_packet) + rohc_hdr_len;
	payload_len = rohc_packet.len - rohc_hdr_len;
	rohc_decomp_debug(context, "ROHC payload (length = %zu bytes) starts at "
	                  "offset %zu", payload_len, rohc_hdr_len);


	/*
	 * B. Check for correct compressed header (CRC)
	 *
	 * Use the CRC on compressed headers to check whether IR header was
	 * correctly received. The optional Add-CID is part of the CRC.
	 */

	if(rohc_packet_is_ir(*packet_type))
	{
		bool crc_ok;

		assert(extr_crc_bits->type == ROHC_CRC_TYPE_NONE);
		assert(extr_crc_bits->bits_nr == 8);

		crc_ok = rohc_decomp_check_ir_crc(decomp, context,
		                                  rohc_buf_data(rohc_packet) - add_cid_len,
		                                  add_cid_len + rohc_hdr_len, add_cid_len,
		                                  large_cid_len, extr_crc_bits->bits);
		if(!crc_ok)
		{
			rohc_decomp_warn(context, "CRC detected a transmission failure for "
			                 "%s packet", rohc_get_packet_descr(*packet_type));
			if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
			{
				rohc_dump_buf(decomp->trace_callback, decomp->trace_callback_priv,
				              ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING, "ROHC header",
				              rohc_buf_data(rohc_packet) - add_cid_len,
				              rohc_hdr_len + add_cid_len);
			}
#ifndef ROHC_NO_IR_CRC_CHECK
			status = ROHC_STATUS_BAD_CRC;
			goto error;
#endif
		}

		/* reset the correction attempt */
		context->crc_corr.counter = 0;
	}


	try_decoding_again = false;
	do
	{
		rohc_status_t decode_ret;

		if(try_decoding_again)
		{
			rohc_decomp_warn(context, "CID %zu: CRC repair: try decoding packet "
			                 "again with new assumptions", context->cid);
		}


		/* C. Decode extracted bits
		 * D. Build uncompressed headers & check for correct decompression
		 *
		 * All bits are now extracted from the packet, let's decode them,
		 * and then let's build the uncompressed headers with decoded fields.
		 *
		 * Use the CRC on decompressed headers to check whether decompression was
		 * correct.
		 */

		decode_ret = rohc_decomp_try_decode_pkt(decomp, context, *packet_type,
		                                        extr_crc_bits, extr_bits, payload_len,
		                                        decoded_values, uncomp_packet);
		if(decode_ret == ROHC_STATUS_OK)
		{
			/* uncompressed headers successfully built and CRC is correct,
			 * no need to try decoding with different values */
			if(context->crc_corr.algo == ROHC_DECOMP_CRC_CORR_SN_NONE)
			{
				rohc_decomp_debug(context, "CRC is correct");
			}
			else if((*packet_type) == ROHC_PACKET_IR)
			{
				rohc_decomp_debug(context, "CRC is correct, stop CRC repair");
				context->crc_corr.algo = ROHC_DECOMP_CRC_CORR_SN_NONE;
				context->crc_corr.counter = 0;
			}
			else
			{
				rohc_decomp_debug(context, "CID %zu: CRC repair: CRC is correct",
				                  context->cid);
				try_decoding_again = false;
			}
		}
		else if(decode_ret == ROHC_STATUS_BAD_CRC)
		{
			/* uncompressed headers successfully built but CRC is incorrect,
			 * try decoding with different values (repair) */

			/* CRC for IR and IR-DYN packets checked before, so cannot fail here */
			assert(rohc_packet_is_ir(*packet_type) == false);

			/* attempt a context/packet repair */
			try_decoding_again =
				profile->attempt_repair(decomp, context, rohc_packet.time,
				                        &context->crc_corr, extr_bits);

			/* report CRC failure if attempt is not possible */
			if(!try_decoding_again)
			{
				/* uncompressed headers successfully built, CRC is incorrect, repair
				 * was disabled or attempted without any success, so give up */
				rohc_decomp_warn(context, "CID %zu: failed to build uncompressed "
				                 "headers (CRC failure)", context->cid);
				if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
				{
					rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
					                 ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING,
					                 "compressed headers", rohc_packet);
				}
				status = ROHC_STATUS_BAD_CRC;
				goto error;
			}
		}
		else if(decode_ret != ROHC_STATUS_OK)
		{
			if((decomp->features & ROHC_DECOMP_FEATURE_DUMP_PACKETS) != 0)
			{
				rohc_dump_packet(decomp->trace_callback, decomp->trace_callback_priv,
				                 ROHC_TRACE_DECOMP, ROHC_TRACE_WARNING,
				                 "compressed headers", rohc_packet);
			}
			status = decode_ret;
			goto error;
		}
	}
	while(try_decoding_again);

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(context->crc_corr.algo != ROHC_DECOMP_CRC_CORR_SN_NONE)
	{
		if(context->crc_corr.counter > 1)
		{
			/* update context with decoded values even if we drop the packet */
			rohc_decomp_update_context(context, decoded_values, payload_len,
			                           rohc_packet.time, do_change_mode);

			context->crc_corr.counter--;
			rohc_decomp_warn(context, "CID %zu: CRC repair: throw away packet, "
			                 "still %zu CRC-valid packets required",
			                 context->cid, context->crc_corr.counter);

			status = ROHC_STATUS_BAD_CRC;
			goto error;
		}
		else if(context->crc_corr.counter == 1)
		{
			rohc_decomp_warn(context, "CID %zu: CRC repair: correction is "
			                 "successful, keep packet", context->cid);
			context->corrected_crc_failures++;
			decomp->stats.corrected_crc_failures++;
			switch(context->crc_corr.algo)
			{
				case ROHC_DECOMP_CRC_CORR_SN_WRAP:
					context->corrected_sn_wraparounds++;
					decomp->stats.corrected_sn_wraparounds++;
					break;
				case ROHC_DECOMP_CRC_CORR_SN_UPDATES:
					context->corrected_wrong_sn_updates++;
					decomp->stats.corrected_wrong_sn_updates++;
					break;
				case ROHC_DECOMP_CRC_CORR_SN_NONE:
				default:
					rohc_error(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					           "CID %zu: CRC repair: unsupported repair algorithm %d",
					           context->cid, context->crc_corr.algo);
					assert(0);
					status = ROHC_STATUS_ERROR;
					goto error;
			}
			context->crc_corr.algo = ROHC_DECOMP_CRC_CORR_SN_NONE;
			context->crc_corr.counter--;
		}
	}
	uncomp_hdr_len = uncomp_packet->len;
	rohc_buf_pull(uncomp_packet, uncomp_hdr_len);


	/* E. Copy the payload (if any) */

	if((rohc_hdr_len + payload_len) != rohc_packet.len)
	{
		rohc_decomp_warn(context, "ROHC %s header (%zu bytes) and payload "
		                 "(%zu bytes) do not match the full ROHC packet "
		                 "(%zu bytes)", rohc_get_packet_descr(*packet_type),
		                 rohc_hdr_len, payload_len, rohc_packet.len);
		status = ROHC_STATUS_ERROR;
		goto error;
	}
	if(rohc_buf_avail_len(*uncomp_packet) < payload_len)
	{
		rohc_decomp_warn(context, "uncompressed packet too small (%zu bytes "
		                 "max) for the %zu-byte payload",
		                 rohc_buf_avail_len(*uncomp_packet), payload_len);
		status = ROHC_STATUS_OUTPUT_TOO_SMALL;
		goto error;
	}
	if(payload_len != 0)
	{
		rohc_buf_append(uncomp_packet, payload_data, payload_len);
		rohc_buf_pull(uncomp_packet, payload_len);
	}
	/* unhide the uncompressed headers and payload */
	rohc_buf_push(uncomp_packet, uncomp_hdr_len + payload_len);
	rohc_decomp_debug(context, "uncompressed packet length = %zu bytes",
	                  uncomp_packet->len);


	/* F. Update the compression context
	 *
	 * Once CRC check is done, update the compression context with the values
	 * that were decoded earlier.
	 *
	 * TODO: check what fields shall be updated in the context
	 */

	/* we are either already in full context state or we can transit
	 * through it */
	if(context->state != ROHC_DECOMP_STATE_FC)
	{
		rohc_decomp_debug(context, "change from state %d to state %d",
		                  context->state, ROHC_DECOMP_STATE_FC);
		context->state = ROHC_DECOMP_STATE_FC;
	}

	/* update context with decoded values */
	rohc_decomp_update_context(context, decoded_values, payload_len,
	                           rohc_packet.time, do_change_mode);

	/* update statistics */
	rohc_decomp_stats_add_success(context, rohc_hdr_len, uncomp_hdr_len);

	/* decompression is successful */
	status = ROHC_STATUS_OK;

error:
	return status;
}


/**
 * @brief Try to decode one ROHC packet
 *
 * Steps:
 *  \li A. Decode extracted bits
 *  \li B. Build uncompressed headers (and check for correct decompression
 *         for UO* packets)
 *
 * @param decomp               The ROHC decompressor
 * @param context              The decompression context
 * @param packet_type          The type of the ROHC packet to parse
 * @param extr_crc_bits        The CRC bits extracted from the ROHC header
 * @param extr_bits            The bits extracted from the ROHC header
 * @param payload_len          The length of the packet payload (in bytes)
 * @param[out] decoded_values  The values decoded from extracted bits
 * @param[out] uncomp_packet   The uncompressed packet
 * @return                     ROHC_STATUS_OK if packet is successfully decoded,
 *                             ROHC_STATUS_MALFORMED if packet is malformed,
 *                             ROHC_STATUS_BAD_CRC if a CRC error occurs,
 *                             ROHC_STATUS_ERROR if an error occurs
 */
static rohc_status_t rohc_decomp_try_decode_pkt(const struct rohc_decomp *const decomp,
                                                const struct rohc_decomp_ctxt *const context,
                                                const rohc_packet_t packet_type,
                                                const struct rohc_decomp_crc *const extr_crc_bits,
                                                const void *const extr_bits,
                                                const size_t payload_len,
                                                void *const decoded_values,
                                                struct rohc_buf *const uncomp_packet)
{
	const struct rohc_decomp_profile *const profile = context->profile;
	size_t uncomp_hdr_len; /* length of the uncompressed headers */
	rohc_status_t status;

	assert(packet_type != ROHC_PACKET_UNKNOWN);

	/* A. Decode extracted bits
	 *
	 * All bits are now extracted from the packet, let's decode them.
	 */

	status = profile->decode_bits(context, extr_bits, payload_len, decoded_values);
	if(status != ROHC_STATUS_OK)
	{
		rohc_decomp_warn(context, "failed to decode values from bits extracted "
		                 "from ROHC header");
		goto error;
	}

	/* B. Build uncompressed headers & check for correct decompression
	 *
	 * All fields are now decoded, let's build the uncompressed headers.
	 *
	 * Use the CRC on decompressed headers to check whether decompression was
	 * correct.
	 */

	/* build the uncompressed headers */
	status = profile->build_hdrs(decomp, context, packet_type, extr_crc_bits,
	                             decoded_values, payload_len,
	                             uncomp_packet, &uncomp_hdr_len);
	if(status != ROHC_STATUS_OK)
	{
		rohc_decomp_warn(context, "CID %zu: failed to build uncompressed headers: %s",
		                 context->cid, rohc_strerror(status));
		goto error;
	}

error:
	return status;
}


/**
 * @brief Check whether the CRC on IR or IR-DYN header is correct or not
 *
 * The CRC for IR/IR-DYN headers is always CRC-8. It is computed on the
 * whole compressed header (payload excluded, but any CID bits included).
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param rohc_hdr        The compressed IR or IR-DYN header
 * @param rohc_hdr_len    The length (in bytes) of the compressed header
 * @param add_cid_len     The length of the optional Add-CID field
 * @param large_cid_len   The length of the optional large CID field
 * @param crc_packet      The CRC extracted from the ROHC header
 * @return                true if the CRC is correct, false otherwise
 */
static bool rohc_decomp_check_ir_crc(const struct rohc_decomp *const decomp,
                                     const struct rohc_decomp_ctxt *const context,
                                     const uint8_t *const rohc_hdr,
                                     const size_t rohc_hdr_len,
                                     const size_t add_cid_len,
                                     const size_t large_cid_len,
                                     const uint8_t crc_packet)
{
	const uint8_t *crc_table;
	const rohc_crc_type_t crc_type = ROHC_CRC_TYPE_8;
	const uint8_t crc_zero[] = { 0x00 };
	unsigned int crc_comp; /* computed CRC */

	assert(rohc_hdr_len >= (add_cid_len + 2 + large_cid_len + 1));

	crc_table = decomp->crc_table_8;

	/* ROHC header before CRC field:
	 * optional Add-CID + IR type + Profile ID + optional large CID */
	crc_comp = crc_calculate(crc_type, rohc_hdr,
	                         add_cid_len + 2 + large_cid_len,
	                         CRC_INIT_8, crc_table);

	/* all profiles but the Uncompressed profile compute their CRC through the
	 * zeroed CRC field and the rest of the ROHC header */
	if(context->profile->id != ROHC_PROFILE_UNCOMPRESSED)
	{
		/* zeroed CRC field */
		crc_comp = crc_calculate(crc_type, crc_zero, 1, crc_comp, crc_table);

		/* ROHC header after CRC field */
		crc_comp = crc_calculate(crc_type,
		                         rohc_hdr + add_cid_len + 2 + large_cid_len + 1,
		                         rohc_hdr_len - add_cid_len - 2 - large_cid_len - 1,
		                         crc_comp, crc_table);
	}

	rohc_decomp_debug(context, "CRC-%d on compressed %zu-byte ROHC header = "
	                  "0x%x", crc_type, rohc_hdr_len, crc_comp);

	/* does the computed CRC match the one in packet? */
	if(crc_comp != crc_packet)
	{
		rohc_decomp_warn(context, "CRC failure (computed = 0x%02x, packet = "
		                 "0x%02x)", crc_comp, crc_packet);
		goto error;
	}

	/* computed CRC matches the one in packet */
	return true;

error:
	return false;
}


/**
 * @brief Update context with decoded values
 *
 * @param context              The decompression context
 * @param decoded              The decoded values to update in the context
 * @param payload_len          The length of the packet payload
 * @param pkt_arrival_time     The arrival time of the decoded ROHC packet
 * @param[out] do_change_mode  Whether the context wants to change its
 *                             operational mode or not
 */
static void rohc_decomp_update_context(struct rohc_decomp_ctxt *const context,
                                       const void *const decoded,
                                       const size_t payload_len,
                                       const struct rohc_ts pkt_arrival_time,
                                       bool *const do_change_mode)
{
	struct rohc_decomp_crc_corr_ctxt *const crc_corr = &context->crc_corr;

	/* call the profile-specific callback */
	context->profile->update_ctxt(context, decoded, payload_len, do_change_mode);

	/* update arrival time */
	crc_corr->arrival_times[crc_corr->arrival_times_index] = pkt_arrival_time;
	crc_corr->arrival_times_index =
		(crc_corr->arrival_times_index + 1) % ROHC_MAX_ARRIVAL_TIMES;
	crc_corr->arrival_times_nr =
		rohc_min(crc_corr->arrival_times_nr + 1, ROHC_MAX_ARRIVAL_TIMES);
}


/**
 * @brief Build a positive ACK feedback
 *
 * @param decomp         The ROHC decompressor
 * @param infos          The information collected on the successfully
 *                       decompressed packet
 * @param[out] feedback  The feedback to be transmitted to the remote
 *                       compressor through the feedback channel
 * @return               true if the ACK feedback was successfully built
 *                       (may be 0 byte), false if a problem occurred
 */
static bool rohc_decomp_feedback_ack(struct rohc_decomp *const decomp,
                                     const struct rohc_decomp_stream *const infos,
                                     struct rohc_buf *const feedback)
{
	const char mode_short[ROHC_R_MODE + 1] = { '?', 'U', 'O', 'R' };
	bool do_build_ack = false;
	size_t k;

	assert(infos->cid_found);
	assert(infos->context_found);

	rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
	           "CID %zu: %s: %s state: %s packet successfully decompressed",
	           infos->cid, rohc_get_mode_descr(infos->mode),
	           rohc_decomp_get_state_descr(infos->state),
	           rohc_get_packet_descr(infos->packet_type));

	/* update all the stats about the feedbacks */
	decomp->last_pkts_errors <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].needed <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].needed <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].sent <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].needed <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].sent <<= 1;
	infos->context->last_pkts_errors <<= 1;
	infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].needed <<= 1;
	infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent <<= 1;
	infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].needed <<= 1;
	infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].sent <<= 1;
	infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].needed <<= 1;
	infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].sent <<= 1;

	/* force sending an ACK if compressor/decompressor modes mismatch or
	 * if decompressor just changed its operational mode */
	if(infos->do_change_mode)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "force positive ACK because mode changed or compressor "
		           "reported a different mode");
		do_build_ack = true;
	}
	/* check if the decompressor shall build a positive feedback */
	else if(infos->mode == ROHC_U_MODE)
	{
		/* send ACK(U) with rate-limiting as stated in RFC 3095, §5.3.1.3:
		 *   To improve performance for the Unidirectional mode over a link that
		 *   does have a feedback channel, the decompressor MAY send an
		 *   acknowledgment when decompression succeeds.  Setting the mode
		 *   parameter in the ACK packet to U indicates that the compressor is to
		 *   stay in Unidirectional mode. [...] If IR packets continue to arrive,
		 *   the decompressor MAY repeat the ACK(U), but it SHOULD NOT repeat the
		 *   ACK(U) continuously.*/
		do_build_ack = true;
	}
	else if(infos->mode == ROHC_O_MODE)
	{
		/* feedback logic for O-mode is described in RFC 3095, §5.4.2.2 */

		/* all states: when an IR packet is correctly decompressed, send an ACK(O) */
		if(infos->packet_type == ROHC_PACKET_IR)
		{
			do_build_ack = true;
		}
		/* SC state:
		 *  - when a type 2 or an IR-DYN packet is correctly decompressed,
		 *    optionally send an ACK(O)
		 * FC state:
		 *  - when a type 2 or an IR-DYN packet is correctly decompressed,
		 *    optionally send an ACK(O)
		 *  - when a type 0 or 1 packet is correctly decompressed, no
		 *    feedback is sent */
		else if(infos->state != ROHC_DECOMP_STATE_NC &&
		        rohc_packet_carry_crc_7_or_8(infos->packet_type))
		{
			do_build_ack = true;
		}
	}
	else /* R-mode */
	{
		assert(0); /* TODO: R-mode not implemented yet */
		goto error;
	}

	/* stop now if no ACK is required */
	if(!do_build_ack)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "no need to send a positive ACK");
		goto skip;
	}

	/* rate-limit the ACKs */
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].needed |= 1;
	infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].needed |= 1;
	k = __builtin_popcount(infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent) * 100;
	if(k >= decomp->ack_rate_limits.speed.threshold)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "do not send a positive ACK because of rate-limiting (%zu of 3200 "
		           "with threshold %zu)", k, decomp->ack_rate_limits.speed.threshold);
		goto skip;
	}
	rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
	           "should send a positive ACK now (CID = %zu, current mode = %d, "
	           "target mode = %d, at least %zu bits of SN 0x%x, rate-limiting = "
	           "%zu of 3200 with threshold %zu)", infos->cid, infos->mode,
	           decomp->target_mode, infos->sn_bits_nr, infos->sn_bits,
	           k, decomp->ack_rate_limits.speed.threshold);
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent |= 1;
	infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent |= 1;

	/* prepare feedback packet if asked by user */
	if(feedback == NULL)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "user choose not to use a feedback channel, do not build any "
		           "feedback packet");
	}
	else
	{
		rohc_feedback_crc_t crc_present;
		struct d_feedback sfeedback;
		uint8_t *feedbackp;
		size_t feedbacksize;
		size_t feedback_hdr_len;

		/* FEEDBACK-1 or FEEDBACK-2 ? */
		if(infos->profile_id == ROHC_PROFILE_UNCOMPRESSED ||
		   (!infos->do_change_mode && infos->sn_bits_nr != 0 && infos->sn_bits_nr <= 8))
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			           "use FEEDBACK-1 as positive feedback");
			f_feedback1(infos->sn_bits, &sfeedback);
			crc_present = ROHC_FEEDBACK_WITH_NO_CRC;
		}
		else
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			           "use FEEDBACK-2 as positive ACK(%c) feedback",
			           mode_short[infos->mode]);
			if(!f_feedback2(infos->profile_id, ROHC_FEEDBACK_ACK, infos->mode,
			                infos->sn_bits, infos->sn_bits_nr, &sfeedback))
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
				             "failed to build the ACK feedback");
				goto error;
			}

			/* use CRC option if mode change requested */
			if(infos->profile_id == ROHC_PROFILE_TCP)
			{
				/* CRC is present in base header for TCP profile */
				crc_present = ROHC_FEEDBACK_WITH_CRC_BASE_TCP;
			}
			else if(rohc_profile_is_rohcv2(infos->profile_id))
			{
				/* CRC is present in base header for ROHCv2 profiles */
				crc_present = ROHC_FEEDBACK_WITH_CRC_BASE;
			}
			else if(infos->do_change_mode)
			{
				crc_present = ROHC_FEEDBACK_WITH_CRC_OPT;
			}
			else
			{
				crc_present = ROHC_FEEDBACK_WITH_NO_CRC;
			}
		}

		/* build the feedback packet */
		feedbackp = f_wrap_feedback(&sfeedback, infos->cid, infos->cid_type,
		                            crc_present, decomp->crc_table_8, &feedbacksize);
		if(feedbackp == NULL)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			             "failed to wrap the ACK feedback");
			goto error;
		}

		/* copy the feedback to the buffer provided by the user */
		/* TODO: build feedback directly into the provided buffer */
		feedback_hdr_len = 1 + (feedbacksize < 8 ? 0 : 1);
		if((feedback_hdr_len + feedbacksize) <= rohc_buf_avail_len(*feedback))
		{
			if(feedbacksize < 8)
			{
				rohc_buf_byte(*feedback) = 0xf0 | feedbacksize;
			}
			else
			{
				rohc_buf_byte(*feedback) = 0xf0;
				rohc_buf_byte_at(*feedback, 1) = feedbacksize;
			}
			feedback->len += feedback_hdr_len;
			rohc_buf_append(feedback, feedbackp, feedbacksize);
		}

		if(feedback->len > 0)
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			           "decompressor built a %zu-byte positive feedback "
			           "(header = %zu bytes, data = %zu bytes)", feedback->len,
			           feedback_hdr_len, feedbacksize);
		}

		/* destroy the temporary feedback buffer */
		free(feedbackp);
	}

skip:
	return true;

error:
	return false;
}


/**
 * @brief Build a negative ACK feedback
 *
 * There are two types of negative feedback: NACK and STATIC-NACK.
 *
 * @param decomp         The ROHC decompressor
 * @param infos          The information collected on the failed
 *                       decompressed packet
 * @param[out] feedback  The feedback to be transmitted to the remote
 *                       compressor through the feedback channel (may be NULL)
 * @return               true if the ACK feedback was successfully built
 *                       (may be 0 byte), false if a problem occurred
 */
static bool rohc_decomp_feedback_nack(struct rohc_decomp *const decomp,
                                      const struct rohc_decomp_stream *const infos,
                                      struct rohc_buf *const feedback)
{
	bool do_downward_transition = false;
	bool do_build_ack = false;
	enum rohc_feedback_ack_type ack_type;
	size_t threshold_too_quickly;
	size_t k_too_quickly;
	size_t k_too_many;

	/* update all the stats about the feedbacks */
	decomp->last_pkts_errors <<= 1;
	decomp->last_pkts_errors |= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].needed <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].needed <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].sent <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].needed <<= 1;
	decomp->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].sent <<= 1;
	if(infos->context != NULL)
	{
		infos->context->last_pkts_errors <<= 1;
		infos->context->last_pkts_errors |= 1;
		infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].needed <<= 1;
		infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_ACK].sent <<= 1;
		infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].needed <<= 1;
		infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_NACK].sent <<= 1;
		infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].needed <<= 1;
		infos->context->last_pkt_feedbacks[ROHC_FEEDBACK_STATIC_NACK].sent <<= 1;
	}

	/* the decompressor cannot warn the compressor if the CID is not identified
	 * (this happens only if packet is malformed) */
	if(!infos->cid_found)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "do not perform downward state transition nor send negative "
		           "feedback to compressor since CID was not identified");
		goto skip;
	}

	if(infos->context_found)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "CID %zu: %s: %s state: %s packet %s", infos->cid,
		           rohc_get_mode_descr(infos->mode),
		           rohc_decomp_get_state_descr(infos->state),
		           rohc_get_packet_descr(infos->packet_type),
		           infos->crc_failed ? "failed the CRC check" : "received");
	}
	else
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "CID %zu: packet failed to be parsed", infos->cid);
	}

	/* check if the decompressor shall build a negative feedback */
	if(infos->profile_id == ROHC_PROFILE_UNCOMPRESSED)
	{
		/* the Uncompressed profile does not use negative feedback nor FEEDBACK-2 */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "do not perform downward state transition nor send negative "
		           "feedback for the Uncompressed profile");
		goto skip;
	}
	else if(!infos->context_found)
	{
		/* RFC says nothing about negative feedbacks for malformed packets, but
		 * it seems useful to tell the compressor to got back to lower states
		 * if a packet failed to be parsed */
		ack_type = ROHC_FEEDBACK_STATIC_NACK;
		do_downward_transition = false; /* impossible w/o context */
		do_build_ack = !!(decomp->target_mode > ROHC_U_MODE);
	}
	else if(infos->mode == ROHC_U_MODE)
	{
		/* U-mode does not use negative feedback */
		ack_type = ROHC_FEEDBACK_NACK;
		do_downward_transition = true;
		do_build_ack = false;
	}
	else if(infos->mode == ROHC_O_MODE)
	{
		/* feedback logic for O-mode is described in RFC 3095, §5.4.2.2 */

		/* NC state: when receiving a type 0, 1, 2 or IR-DYN packet, or an IR
		 * packet has failed the CRC check, send a STATIC-NACK(O), subject to the
		 * considerations at the beginning of section 5.7.6 */
		if(infos->state == ROHC_DECOMP_STATE_NC)
		{
			ack_type = ROHC_FEEDBACK_STATIC_NACK;
			do_downward_transition = true;
			do_build_ack = true;
		}
		/* SC state:
		 *  - when a type 0 or 1 packet is received, treat it as a mismatching
		 *    CRC and use the logic of section 5.3.2.2.3 to decide if a NACK(O)
		 *    should be sent
		 *  - when decompression of a type 2 packet, an IR-DYN packet or an
		 *    IR packet has failed, use the logic of section 5.3.2.2.3 to
		 *    decide if a STATIC-NACK(O) should be sent */
		else if(infos->state == ROHC_DECOMP_STATE_SC)
		{
			if(!rohc_packet_carry_crc_7_or_8(infos->packet_type))
			{
				ack_type = ROHC_FEEDBACK_NACK;
				do_downward_transition = true;
				do_build_ack = true;
			}
			else
			{
				ack_type = ROHC_FEEDBACK_STATIC_NACK;
				do_downward_transition = true;
				do_build_ack = true;
			}
		}
		/* FC state: when any packet fails the CRC check, use the logic of
		 * 5.3.2.2.3 to decide if a NACK(O) should be sent */
		else
		{
			ack_type = ROHC_FEEDBACK_NACK;
			do_downward_transition = true;
			do_build_ack = true;
		}
	}
	else /* R-mode */
	{
		assert(0); /* TODO: R-mode not implemented yet */
		goto error;
	}

	/* stop now if no downward state transition nor NACK is required */
	if(!do_build_ack && !do_downward_transition)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "no need to perform a downward state transition nor send a "
		           "negative ACK");
		goto skip;
	}
	assert(ack_type == ROHC_FEEDBACK_NACK || ack_type == ROHC_FEEDBACK_STATIC_NACK);

	/* rate-limit the downward state transitions and NACKs */
	if(infos->context != NULL)
	{
		decomp->last_pkt_feedbacks[ack_type].needed |= 1;
		infos->context->last_pkt_feedbacks[ack_type].needed |= 1;
		k_too_quickly = __builtin_popcount(infos->context->last_pkts_errors) * 100;
		k_too_many = __builtin_popcount(infos->context->last_pkt_feedbacks[ack_type].sent) * 100;
	}
	else
	{
		decomp->last_pkt_feedbacks[ack_type].needed |= 1;
		k_too_quickly = __builtin_popcount(decomp->last_pkts_errors) * 100;
		k_too_many = __builtin_popcount(decomp->last_pkt_feedbacks[ack_type].sent) * 100;
	}
	if(ack_type == ROHC_FEEDBACK_NACK)
	{
		threshold_too_quickly = decomp->ack_rate_limits.nack.threshold;
	}
	else
	{
		threshold_too_quickly = decomp->ack_rate_limits.static_nack.threshold;
	}
	if(k_too_quickly < threshold_too_quickly)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "avoid sending feedback too quickly (%zu of 3200 with threshold %zu)",
		           k_too_quickly, threshold_too_quickly);

		/* force sending a negative ACK if compressor/decompressor modes mismatch
		 * or if decompressor just changed its operational mode */
		if(do_build_ack && infos->do_change_mode)
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			           "force negative ACK because mode changed or compressor "
			           "reported a different mode");
			do_build_ack = true;
		}
		else
		{
			do_build_ack = false;
		}
		do_downward_transition = false;
	}
	else if(k_too_quickly >= (threshold_too_quickly + 100) &&
	        k_too_many >= decomp->ack_rate_limits.speed.threshold)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "rate-limiting successive feedbacks (%zu of 3200 with threshold "
		           "%zu)", k_too_many, decomp->ack_rate_limits.speed.threshold);

		/* force sending a negative ACK if compressor/decompressor modes mismatch
		 * or if decompressor just changed its operational mode */
		if(do_build_ack && infos->do_change_mode)
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			           "force negative ACK because mode changed or compressor "
			           "reported a different mode");
			do_build_ack = true;
		}
		else
		{
			do_build_ack = false;
		}
		do_downward_transition = false;
	}

	/* update information if feedback is sent or downward transition taken */
	if(do_build_ack || do_downward_transition)
	{
		decomp->last_pkt_feedbacks[ack_type].sent |= 1;
		if(infos->context != NULL)
		{
			infos->context->last_pkt_feedbacks[ack_type].sent |= 1;
		}
	}

	/* prepare feedback packet if needed and asked by user */
	if(!do_build_ack)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "do not send a negative ACK");
	}
	else if(feedback == NULL)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "user choose not to use a feedback channel, do not build any "
		           "feedback packet");
	}
	else
	{
		rohc_feedback_crc_t crc_present;
		struct d_feedback sfeedback;
		uint8_t *feedbackp;
		size_t feedbacksize;
		size_t feedback_hdr_len;

		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "should send a negative ACK (CID = %zu, NACK type = %d, current "
		           "mode = %d, target mode = %d, at least %zu bits of SN 0x%x, "
		           "rate-limiting = %zu of 3200 with threshold %zu and %zu of 3200 "
		           "with threshold %zu)", infos->cid, ack_type, infos->mode,
		           decomp->target_mode, infos->sn_bits_nr, infos->sn_bits,
		           k_too_quickly, threshold_too_quickly,
		           k_too_many, decomp->ack_rate_limits.speed.threshold);

		/* prepare FEEDBACK-2 */
		if(!f_feedback2(infos->profile_id, ack_type, infos->mode, infos->sn_bits,
		                infos->sn_bits_nr, &sfeedback))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			             "failed to build the (STATIC-)NACK feedback");
			goto error;
		}
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "FEEDBACK-2 is %d-byte long", sfeedback.size);

		/* use CRC option if mode change requested */
		if(infos->profile_id == ROHC_PROFILE_TCP)
		{
			crc_present = ROHC_FEEDBACK_WITH_CRC_BASE_TCP;
		}
		else if(rohc_profile_is_rohcv2(infos->profile_id))
		{
			crc_present = ROHC_FEEDBACK_WITH_CRC_BASE;
		}
		else if(infos->do_change_mode)
		{
			crc_present = ROHC_FEEDBACK_WITH_CRC_OPT;
		}
		else
		{
			crc_present = ROHC_FEEDBACK_WITH_NO_CRC;
		}

		/* build the feedback packet */
		feedbackp = f_wrap_feedback(&sfeedback, infos->cid, infos->cid_type,
		                            crc_present, decomp->crc_table_8, &feedbacksize);
		if(feedbackp == NULL)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			             "failed to wrap the (STATIC-)NACK feedback");
			goto error;
		}

		/* copy the feedback to the buffer provided by the user */
		/* TODO: build feedback directly into the provided buffer */
		feedback_hdr_len = 1 + (feedbacksize < 8 ? 0 : 1);
		if((feedback_hdr_len + feedbacksize) <= rohc_buf_avail_len(*feedback))
		{
			if(feedbacksize < 8)
			{
				rohc_buf_byte(*feedback) = 0xf0 | feedbacksize;
			}
			else
			{
				rohc_buf_byte(*feedback) = 0xf0;
				rohc_buf_byte_at(*feedback, 1) = feedbacksize;
			}
			feedback->len += feedback_hdr_len;
			rohc_buf_append(feedback, feedbackp, feedbacksize);
		}

		if(feedback->len > 0)
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			           "decompressor built a %zu-byte negative feedback (%zu bytes "
			           "of header + %zu bytes of data)", feedback->len,
			           feedback_hdr_len, feedbacksize);
		}

		/* destroy the temporary feedback buffer */
		free(feedbackp);
	}

	/* upon decompression failure, perform downward transitions if context is
	 * still available (new contexts are destroyed upon decompression error) */
	if(!do_downward_transition || infos->context == NULL)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "do not perform a downward state transition");
	}
	else
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
		           "perform a downward state transition now (CID = %zu, NACK "
		           "type = %d, current mode = %d, target mode = %d, rate-limiting "
		           "= %zu of 3200 with threshold %zu and %zu of 3200 with "
		           "threshold %zu)", infos->cid, ack_type, infos->mode,
		           decomp->target_mode, k_too_quickly, threshold_too_quickly,
		           k_too_many, decomp->ack_rate_limits.speed.threshold);

		if(infos->state == ROHC_DECOMP_STATE_SC)
		{
			rohc_info(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			          "change from state %d to state %d because of error(s)",
			          infos->state, ROHC_DECOMP_STATE_NC);
			infos->context->state = ROHC_DECOMP_STATE_NC;
		}
		else if(infos->state == ROHC_DECOMP_STATE_FC)
		{
			rohc_info(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			          "change from state %d to state %d because of error(s)",
			          infos->state, ROHC_DECOMP_STATE_SC);
			infos->context->state = ROHC_DECOMP_STATE_SC;
		}
		else
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, infos->profile_id,
			           "stay in state %d because of error(s)", infos->context->state);
		}
	}

skip:
	return true;

error:
	return false;
}


/**
 * @brief Update statistics upon successful decompression
 *
 * @param context         The decompression context
 * @param comp_hdr_len    The length (in bytes) of the compressed header
 * @param uncomp_hdr_len  The length (in bytes) of the uncompressed header
 */
static void rohc_decomp_stats_add_success(struct rohc_decomp_ctxt *const context,
                                          const size_t comp_hdr_len,
                                          const size_t uncomp_hdr_len)
{
	context->header_last_compressed_size = comp_hdr_len;
	context->header_compressed_size += comp_hdr_len;
	context->header_last_uncompressed_size = uncomp_hdr_len;
	context->header_uncompressed_size += uncomp_hdr_len;
}


/**
 * @brief Reset all the statistics of the given ROHC decompressor
 *
 * @param decomp The ROHC decompressor
 */
static void rohc_decomp_reset_stats(struct rohc_decomp *const decomp)
{
	decomp->stats.received = 0;
	decomp->stats.failed_crc = 0;
	decomp->stats.failed_no_context = 0;
	decomp->stats.failed_decomp = 0;
	decomp->stats.total_uncompressed_size = 0;
	decomp->stats.total_compressed_size = 0;
	decomp->stats.corrected_crc_failures = 0;
	decomp->stats.corrected_sn_wraparounds = 0;
	decomp->stats.corrected_wrong_sn_updates = 0;
}


/**
 * @brief Give a description for the given ROHC decompression context state
 *
 * Give a description for the given ROHC decompression context state.
 *
 * The descriptions are not part of the API. They may change between
 * releases without any warning. Do NOT use them for other means that
 * providing to users a textual description of decompression context states
 * used by the library. If unsure, ask on the mailing list.
 *
 * @param state  The decompression context state to get a description for
 * @return       A string that describes the given decompression context state
 *
 * @ingroup rohc_decomp
 */
const char * rohc_decomp_get_state_descr(const rohc_decomp_state_t state)
{
	switch(state)
	{
		case ROHC_DECOMP_STATE_NC:
			return "No Context";
		case ROHC_DECOMP_STATE_SC:
			return "Static Context";
		case ROHC_DECOMP_STATE_FC:
			return "Full Context";
		case ROHC_DECOMP_STATE_UNKNOWN:
		default:
			return "no description";
	}
}


/**
 * @brief Get some information about the last decompressed packet
 *
 * Get some information about the last decompressed packet.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_decomp_last_packet_info_t structure with the \e version_major
 * and \e version_minor fields set to one of the following supported
 * versions:
 *  - Major 0, minor 0
 *  - Major 0, minor 1
 *  - Major 0, minor 2
 *
 * See \ref rohc_decomp_last_packet_info_t for details about fields that
 * are supported in the above versions.
 *
 * @param decomp        The ROHC decompressor to get information from
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_last_packet_info_t
 */
bool rohc_decomp_get_last_packet_info(const struct rohc_decomp *const decomp,
                                      rohc_decomp_last_packet_info_t *const info)
{
	if(decomp == NULL)
	{
		goto error;
	}

	if(decomp->last_context == NULL)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "last context found in decompressor is not valid");
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "structure for last packet information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major != 0)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for last "
		           "packet information", info->version_major);
		goto error;
	}

	/* base fields for major version 0 */
	info->context_mode = decomp->last_context->mode;
	info->context_state = decomp->last_context->state;
	info->profile_id = decomp->last_context->profile->id;
	info->nr_lost_packets = decomp->last_context->nr_lost_packets;
	info->nr_misordered_packets = decomp->last_context->nr_misordered_packets;
	info->is_duplicated = decomp->last_context->is_duplicated;

	if(info->version_minor != 0 &&
	   info->version_minor != 1 &&
	   info->version_minor != 2)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unsupported minor version (%u) of the structure for "
		           "last packet information", info->version_minor);
		goto error;
	}

	/* new fields in 0.1 */
	if(info->version_minor >= 1)
	{
		info->corrected_crc_failures =
			decomp->last_context->corrected_crc_failures;
		info->corrected_sn_wraparounds =
			decomp->last_context->corrected_sn_wraparounds;
		info->corrected_wrong_sn_updates =
			decomp->last_context->corrected_wrong_sn_updates;
		info->packet_type = decomp->last_context->packet_type;
	}

	/* new fields in 0.2 */
	if(info->version_minor >= 2)
	{
		info->total_last_comp_size =
			decomp->last_context->total_last_compressed_size;
		info->header_last_comp_size =
			decomp->last_context->header_last_compressed_size;
		info->total_last_uncomp_size =
			decomp->last_context->total_last_uncompressed_size;
		info->header_last_uncomp_size =
			decomp->last_context->header_last_uncompressed_size;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get some information about the given decompression context
 *
 * Get some information about the given decompression context.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_decomp_context_info_t structure with the \e version_major
 * and \e version_minor fields set to one of the following supported
 * versions:
 *  - Major 0, minor 0
 *
 * See \ref rohc_decomp_context_info_t for details about fields that
 * are supported in the above versions.
 *
 * @param decomp        The ROHC decompressor to get information from
 * @param cid           The Context ID to get information for
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_context_info_t
 */
bool rohc_decomp_get_context_info(const struct rohc_decomp *const decomp,
                                  const rohc_cid_t cid,
                                  rohc_decomp_context_info_t *const info)
{
	if(decomp == NULL)
	{
		goto error;
	}

	if(cid > decomp->medium.max_cid)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "decompressor does not handle CID %zu since MAX_CID is %zu",
		           cid, decomp->medium.max_cid);
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "structure for context information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		if(decomp->contexts[cid] == NULL)
		{
			info->packets_nr = 0;
			info->comp_bytes_nr = 0;
			info->uncomp_bytes_nr = 0;
			info->corrected_crc_failures = 0;
			info->corrected_sn_wraparounds = 0;
			info->corrected_wrong_sn_updates = 0;
		}
		else
		{
			info->packets_nr = decomp->contexts[cid]->num_recv_packets;
			info->comp_bytes_nr = decomp->contexts[cid]->total_compressed_size;
			info->uncomp_bytes_nr = decomp->contexts[cid]->total_uncompressed_size;
			info->corrected_crc_failures =
				decomp->contexts[cid]->corrected_crc_failures;
			info->corrected_sn_wraparounds =
				decomp->contexts[cid]->corrected_sn_wraparounds;
			info->corrected_wrong_sn_updates =
				decomp->contexts[cid]->corrected_wrong_sn_updates;
		}

		/* new fields added by minor versions */
		if(info->version_minor > 0)
		{
			rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "unsupported minor version (%u) of the structure for "
			           "context information", info->version_minor);
			goto error;
		}
	}
	else
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for context"
		           "information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get some general information about the decompressor
 *
 * Get some general information about the decompressor.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_decomp_general_info_t structure with the \e version_major and
 * \e version_minor fields set to one of the following supported versions:
 *  - Major 0, minor 0
 *
 * See the \ref rohc_decomp_general_info_t structure for details about fields
 * that are supported in the above versions.
 *
 * @param decomp        The ROHC decompressor to get information from
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_general_info_t
 */
bool rohc_decomp_get_general_info(const struct rohc_decomp *const decomp,
                                  rohc_decomp_general_info_t *const info)
{
	if(decomp == NULL)
	{
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "structure for general information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		info->contexts_nr = decomp->num_contexts_used;
		info->packets_nr = decomp->stats.received;
		info->comp_bytes_nr = decomp->stats.total_compressed_size;
		info->uncomp_bytes_nr = decomp->stats.total_uncompressed_size;

		/* new fields added by minor versions */
		switch(info->version_minor)
		{
			case 0:
				/* nothing to add */
				break;
			case 1:
				/* new fields in 0.1 */
				info->corrected_crc_failures = decomp->stats.corrected_crc_failures;
				info->corrected_sn_wraparounds =
					decomp->stats.corrected_sn_wraparounds;
				info->corrected_wrong_sn_updates =
					decomp->stats.corrected_wrong_sn_updates;
				break;
			default:
				rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "unsupported minor version (%u) of the structure for "
				           "general information", info->version_minor);
				goto error;
		}
	}
	else
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for "
		           "general information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Get the CID type that the decompressor uses
 *
 * Get the CID type that the decompressor currently uses.
 *
 * @param decomp         The ROHC decompressor
 * @param[out] cid_type  The current CID type among \ref ROHC_SMALL_CID and
 *                       \ref ROHC_LARGE_CID
 * @return               true if the CID type was successfully retrieved,
 *                       false otherwise
 *
 * @ingroup rohc_decomp
 */
bool rohc_decomp_get_cid_type(const struct rohc_decomp *const decomp,
                              rohc_cid_type_t *const cid_type)
{
	if(decomp == NULL || cid_type == NULL)
	{
		goto error;
	}

	*cid_type = decomp->medium.cid_type;
	return true;

error:
	return false;
}


/**
 * @brief Get the maximal CID value the decompressor uses
 *
 * Get the maximal CID value the decompressor uses, ie. the \e MAX_CID
 * parameter defined in RFC 3095.
 *
 * @param decomp        The ROHC decompressor
 * @param[out] max_cid  The current maximal CID value
 * @return              true if MAX_CID was successfully retrieved,
 *                      false otherwise
 *
 * @ingroup rohc_decomp
 */
bool rohc_decomp_get_max_cid(const struct rohc_decomp *const decomp,
                             size_t *const max_cid)
{
	if(decomp == NULL || max_cid == NULL)
	{
		goto error;
	}

	*max_cid = decomp->medium.max_cid;
	return true;

error:
	return false;
}


/**
 * @brief Set the Maximum Reconstructed Reception Unit (MRRU).
 *
 * Set the Maximum Reconstructed Reception Unit (MRRU).
 *
 * The MRRU is the largest cumulative length (in bytes) of the ROHC segments
 * that are parts of the same ROHC packet. In short, the ROHC decompressor
 * does not expect to reassemble ROHC segments whose total length is larger
 * than MRRU. So, the ROHC compressor shall not segment ROHC packets greater
 * than the MRRU.
 *
 * The MRRU value must be in range [0 ; \ref ROHC_MAX_MRRU]. Remember that the
 * MRRU includes the 32-bit CRC that protects it.
 * If set to 0, segmentation is disabled as no segment headers are allowed
 * on the channel. Every received segment will be dropped.
 *
 * According to RF5225 §6.1, ROHC segmentation cannot be enabled if any
 * ROHCv2 profile is also enabled.
 *
 * If segmentation is enabled and used by the compressor, the function
 * \ref rohc_decompress3 will return ROHC_OK and one empty uncompressed packet
 * upon decompression until the last segment is received (or a non-segment is
 * received). Decompressed data will be returned at that time.
 *
 * @warning Changing the MRRU value while library is used may lead to
 *          destruction of the current RRU.
 *
 * @param decomp  The ROHC decompressor
 * @param mrru    The new MRRU value (in bytes)
 * @return        true if the MRRU was successfully set, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet test_segment.c define ROHC decompressor
 * \code
        size_t mrru = 500;
        ...
\endcode
 * \snippet test_segment.c create ROHC decompressor
 * \code
        ...
\endcode
 * \snippet test_segment.c set decompressor MRRU
 * \code
        ...
\endcode
 *
 * @see rohc_decomp_get_mrru
 * @see rohc_decompress3
 * @see rohc_comp_set_mrru
 * @see rohc_comp_get_mrru
 */
bool rohc_decomp_set_mrru(struct rohc_decomp *const decomp,
                          const size_t mrru)
{
	size_t idx;

	/* decompressor must be valid */
	if(decomp == NULL)
	{
		/* cannot print a trace without a valid decompressor */
		goto error;
	}

	/* new MRRU value must be in range [0, ROHC_MAX_MRRU] */
	if(mrru > ROHC_MAX_MRRU)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unexpected MRRU value: must be in range [0, %d]",
		             ROHC_MAX_MRRU);
		goto error;
	}

	/* RFC5225, §6.1:
	 * The compressor MUST NOT use ROHC segmentation (see Section 5.2.5 of
	 * [RFC4995]), i.e., the Maximum Reconstructed Reception Unit (MRRU)
	 * MUST be set to 0, if the configuration of the ROHC channel contains
	 * at least one ROHCv2 profile in the list of supported profiles (i.e.,
	 * the PROFILES parameter) and if the channel cannot guarantee in-order
	 * delivery of packets between compression endpoints.
	 */
	if(mrru > 0)
	{
		for(idx = 0; idx < D_NUM_PROFILES; idx++)
		{
			if(decomp->enabled_profiles[idx] &&
			   rohc_profile_is_rohcv2(rohc_decomp_profiles[idx]->id))
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				             "failed to set MRRU to %zu bytes: segmentation is not "
				             "compatible with ROHCv2 profile 0x%04x that is enabled",
				             mrru, rohc_decomp_profiles[idx]->id);
				goto error;
			}
		}
	}

	/* set new MRRU */
	decomp->mrru = mrru;
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "MRRU is now set to %zd", decomp->mrru);

	return true;

error:
	return false;
}


/**
 * @brief Get the Maximum Reconstructed Reception Unit (MRRU).
 *
 * Get the current Maximum Reconstructed Reception Unit (MRRU).
 *
 * The MRRU is the largest cumulative length (in bytes) of the ROHC segments
 * that are parts of the same ROHC packet. In short, the ROHC decompressor
 * does not expect to reassemble ROHC segments whose total length is larger
 * than MRRU. So, the ROHC compressor shall not segment ROHC packets greater
 * than the MRRU.
 *
 * The MRRU value must be in range [0 ; \ref ROHC_MAX_MRRU]. Remember that the
 * MRRU includes the 32-bit CRC that protects it.
 * If MRRU value is 0, segmentation is disabled.
 *
 * If segmentation is enabled and used by the compressor, the function
 * \ref rohc_decompress3 will return ROHC_OK and one empty uncompressed packet
 * upon decompression until the last segment is received (or a non-segment is
 * received). Decompressed data will be returned at that time.
 *
 * @param decomp     The ROHC decompressor
 * @param[out] mrru  The current MRRU value (in bytes)
 * @return           true if MRRU was successfully retrieved, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_set_mrru
 * @see rohc_decompress3
 * @see rohc_comp_set_mrru
 * @see rohc_comp_get_mrru
 */
bool rohc_decomp_get_mrru(const struct rohc_decomp *const decomp,
                          size_t *const mrru)
{
	if(decomp == NULL || mrru == NULL)
	{
		goto error;
	}

	*mrru = decomp->mrru;
	return true;

error:
	return false;
}


/**
 * @brief Set the number of packets sent during one Round-Trip Time (RTT).
 *
 * Set the maximum number of packets sent in worst case by the remote ROHC
 * compressor for one given stream (ie. one compression/decompression context)
 * during one Round-Trip Time (RTT).
 *
 * The number of packets sent by the remote ROHC compressor is used to estimate
 * how many SN bits those feedbacks shall transmit to avoid any ambiguity at
 * compressor about the ROHC packet that is (n)acknowledged by the decompressor.
 *
 * The pRTT value must be in range [0 ; SIZE_MAX/2[. If set to 0, all SN bits
 * are always transmitted.
 *
 * The default value is 50 packets / RTT, ie. a RTT of 1 second with one packet
 * transmitted every 20 milliseconds (classic VoIP stream). If your network
 * streams and conditions differ, change the default value.
 *
 * @param decomp  The ROHC decompressor
 * @param prtt    The number of packets sent during one RTT
 * @return        true if the new value was successfully set, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet test_feedback2.c define ROHC decompressor
 * \code
        rohc_cid_type_t cid_type = ROHC_SMALL_CID;
        rohc_cid_t max_cid = ROHC_SMALL_CID_MAX;
        ...
\endcode
 * \snippet test_feedback2.c create ROHC decompressor
 * \code
        ...
\endcode
 * \snippet test_feedback2.c set decompressor pRTT
 * \code
        ...
\endcode
 *
 * @see rohc_decomp_get_prtt
 * @see rohc_decompress3
 */
bool rohc_decomp_set_prtt(struct rohc_decomp *const decomp,
                          const size_t prtt)
{
	/* decompressor must be valid */
	if(decomp == NULL)
	{
		/* cannot print a trace without a valid decompressor */
		goto error;
	}

	/* new pRTT must be in range [0, SIZE_MAX] */
	if(prtt >= (SIZE_MAX / 2))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unexpected pRTT value: must be in range [0, %zu]",
		             SIZE_MAX);
		goto error;
	}

	/* set new pRTT */
	decomp->prtt = prtt;
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "pRTT is now set to %zu", decomp->prtt);

	/* compute the minimum number of SN bits to transmit to the remote
	 * compressor in the positive or negative feedbacks in order to avoid
	 * any ambiguity at compressor about the ROHC packet that is
	 * (n)acknowledged by the decompressor */
	decomp->sn_feedback_min_bits = sizeof(uint32_t) * 8;
	if(decomp->prtt != 0)
	{
		decomp->sn_feedback_min_bits -= __builtin_clz(decomp->prtt);
	}

	return true;

error:
	return false;
}


/**
 * @brief Get the number of packets sent during one Round-Trip Time (RTT).
 *
 * Get the maximum number of packets sent in worst case by the remote ROHC
 * compressor for one given stream (ie. one compression/decompression context)
 * during one Round-Trip Time (RTT).
 *
 * The number of packets sent by the remote ROHC compressor is used to estimate
 * how many SN bits those feedbacks shall transmit to avoid any ambiguity at
 * compressor about the ROHC packet that is (n)acknowledged by the decompressor.
 *
 * The pRTT value must be in range [0 ; SIZE_MAX/2[. If set to 0, all SN bits
 * are always transmitted.
 *
 * The default value is 50 packets / RTT, ie. a RTT of 1 second with one packet
 * transmitted every 20 milliseconds (classic VoIP stream). If your network
 * streams and conditions differ, change the default value.
 *
 * @param decomp     The ROHC decompressor
 * @param[out] prtt  The number of packets sent during one RTT
 * @return           true if pRTT was successfully retrieved, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_set_prtt
 * @see rohc_decompress3
 */
bool rohc_decomp_get_prtt(const struct rohc_decomp *const decomp,
                          size_t *const prtt)
{
	if(decomp == NULL || prtt == NULL)
	{
		goto error;
	}

	*prtt = decomp->prtt;
	return true;

error:
	return false;
}


/**
 * @brief Set the rate limits for feedbacks
 *
 * Set the rate limits for positive feedbacks (ACK) and negative feedbacks (NACK
 * and STATIC-NACK).
 *
 * There are 3 different rate limits:
 *  \li the rate limit to avoid sending the same type of feedback too often:
 *      it applies to all feedback types (ACK, NACK, STATIC-NACK) and it is
 *      specified by the parameters \e k and \e n ;
 *  \li the rate limit to avoid sending NACKs too quickly after a sporadic CRC
 *      failure: it is specified by the parameters \e k_1 and \e n_1 ;
 *  \li the rate limit to avoid sending STATIC-NACKs too quickly after a sporadic
 *      CRC failure: it is specified by the parameters \e k_2 and \e n_2 ;
 *
 * In all 3 cases above, the \e k/k_1/k_2 and \e n/n_1/n_2 parameters define
 * 3 ratios of packets:
 *  \li a feedback is sent every \e k packets out of \e n packets that cause
 *      the same feedback type to be sent ;
 *  \li a NACK is not sent before \e k_1 packets out of \e n_1 packets failed
 *      because of a CRC failure in the Full Context state ;
 *  \li a STATIC-NACK is not sent before \e k_1 packets out of \e n_1 packets
 *      failed because of a CRC failure in the Static Context state ;
 *
 * The default values are:
 *  \li k   =  1 and n   = default pRTT (see rohc_decomp_set_prtt for details)
 *  \li k_1 = 30 and n_1 = 100, ie. 30%
 *  \li k_2 = 30 and n_2 = 100, ie. 30%
 *
 * If your network streams and conditions differ, change the default value.
 *
 * The n/n_1/n_2 values shall not be zero.
 *
 * @param decomp  The ROHC decompressor
 * @param k       The k rate-limit parameter to avoid sending feedback too often
 * @param n       The n rate-limit parameter to avoid sending feedback too often
 * @param k_1     The k_1 rate-limit parameter to avoid sending NACKs too quickly
 * @param n_1     The n_1 rate-limit parameter to avoid sending NACKs too quickly
 * @param k_2     The k_2 rate-limit parameter to avoid sending STATIC-NACKs too quickly
 * @param n_2     The n_2 rate-limit parameter to avoid sending STATIC-NACKs too quickly
 * @return        true if the new values were successfully set, false otherwise
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet test_lost_packet.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet test_lost_packet.c create ROHC decompressor
 * \code
        ...
\endcode
 * \snippet test_lost_packet.c set decompressor rate limits
 * \code
        ...
\endcode
 *
 * @see rohc_decomp_get_rate_limits
 * @see rohc_decomp_set_prtt
 * @see rohc_decomp_get_prtt
 * @see rohc_decompress3
 */
bool rohc_decomp_set_rate_limits(struct rohc_decomp *const decomp,
                                 const size_t k, const size_t n,
                                 const size_t k_1, const size_t n_1,
                                 const size_t k_2, const size_t n_2)
{
	/* decompressor must be valid */
	if(decomp == NULL)
	{
		/* cannot print a trace without a valid decompressor */
		goto error;
	}

	/* n values are used as divisors */
	if(n == 0 || n_1 == 0 || n_2 == 0)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "rate-limits n/n_1/n_2 shall not be 0");
		goto error;
	}

	/* set new rate-limits */
	decomp->ack_rate_limits.speed.k = k;
	decomp->ack_rate_limits.speed.n = n;
	decomp->ack_rate_limits.nack.k = k_1;
	decomp->ack_rate_limits.nack.n = n_1;
	decomp->ack_rate_limits.static_nack.k = k_2;
	decomp->ack_rate_limits.static_nack.n = n_2;

	/* compute the rate-limit thresholds */
	decomp->ack_rate_limits.speed.threshold =
		decomp->ack_rate_limits.speed.k * 32 * 100 / decomp->ack_rate_limits.speed.n;
	decomp->ack_rate_limits.nack.threshold =
		decomp->ack_rate_limits.nack.k * 32 * 100 / decomp->ack_rate_limits.nack.n;
	decomp->ack_rate_limits.static_nack.threshold =
		decomp->ack_rate_limits.static_nack.k * 32 * 100 /
		decomp->ack_rate_limits.static_nack.n;

	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "rate-limits are now set to: %zu/%zu (all), %zu/%zu (NACK), "
	           "%zu/%zu (STATIC-NACK)",
	           decomp->ack_rate_limits.speed.k, decomp->ack_rate_limits.speed.n,
	           decomp->ack_rate_limits.nack.k, decomp->ack_rate_limits.nack.n,
	           decomp->ack_rate_limits.static_nack.k,
	           decomp->ack_rate_limits.static_nack.n);

	return true;

error:
	return false;
}


/**
 * @brief Get the rate limits for feedbacks currently configured
 *
 * Get the rate limits for positive feedbacks (ACK) and negative feedbacks (NACK
 * and STATIC-NACK).
 *
 * There are 3 different rate limits:
 *  \li the rate limit to avoid sending the same type of feedback too often:
 *      it applies to all feedback types (ACK, NACK, STATIC-NACK) and it is
 *      specified by the parameters \e k and \e n ;
 *  \li the rate limit to avoid sending NACKs too quickly after a sporadic CRC
 *      failure: it is specified by the parameters \e k_1 and \e n_1 ;
 *  \li the rate limit to avoid sending STATIC-NACKs too quickly after a sporadic
 *      CRC failure: it is specified by the parameters \e k_2 and \e n_2 ;
 *
 * In all 3 cases above, the \e k/k_1/k_2 and \e n/n_1/n_2 parameters define
 * 3 ratios of packets:
 *  \li a feedback is sent every \e k packets out of \e n packets that cause
 *      the same feedback type to be sent ;
 *  \li a NACK is not sent before \e k_1 packets out of \e n_1 packets failed
 *      because of a CRC failure in the Full Context state ;
 *  \li a STATIC-NACK is not sent before \e k_1 packets out of \e n_1 packets
 *      failed because of a CRC failure in the Static Context state ;
 *
 * The default values are:
 *  \li k   =  1 and n   = default pRTT (see rohc_decomp_set_prtt for details)
 *  \li k_1 = 30 and n_1 = 100, ie. 30%
 *  \li k_2 = 30 and n_2 = 100, ie. 30%
 *
 * If your network streams and conditions differ, change the default value.
 *
 * @param decomp    The ROHC decompressor
 * @param[out] k    The k rate-limit parameter to avoid sending feedback too often
 * @param[out] n    The n rate-limit parameter to avoid sending feedback too often
 * @param[out] k_1  The k_1 rate-limit param. to avoid sending NACKs too quickly
 * @param[out] n_1  The n_1 rate-limit param. to avoid sending NACKs too quickly
 * @param[out] k_2  The k_2 rate-limit param. to avoid sending STATIC-NACKs too quickly
 * @param[out] n_2  The n_2 rate-limit param. to avoid sending STATIC-NACKs too quickly
 * @return          true if rate-limits were successfully retrieved,
 *                  false otherwise
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_set_rate_limits
 * @see rohc_decomp_set_prtt
 * @see rohc_decomp_get_prtt
 * @see rohc_decompress3
 */
bool rohc_decomp_get_rate_limits(const struct rohc_decomp *const decomp,
                                 size_t *const k, size_t *const n,
                                 size_t *const k_1, size_t *const n_1,
                                 size_t *const k_2, size_t *const n_2)
{
	if(decomp == NULL ||
	   k == NULL || n == NULL ||
	   k_1 == NULL || n_1 == NULL ||
	   k_2 == NULL || n_2 == NULL)
	{
		goto error;
	}

	*k = decomp->ack_rate_limits.speed.k;
	*n = decomp->ack_rate_limits.speed.n;
	*k_1 = decomp->ack_rate_limits.nack.k;
	*n_1 = decomp->ack_rate_limits.nack.n;
	*n_2 = decomp->ack_rate_limits.static_nack.n;
	*k_2 = decomp->ack_rate_limits.static_nack.k;

	return true;

error:
	return false;
}


/**
 * @brief Enable/disable features for ROHC decompressor
 *
 * Enable/disable features for ROHC decompressor. Features control whether
 * mechanisms defined as optional by RFCs are enabled or not.
 *
 * Available features are listed by \ref rohc_decomp_features_t. They may be
 * combined by XOR'ing them together.
 *
 * @warning Changing the feature set while library is used is not supported
 *
 * @param decomp    The ROHC decompressor
 * @param features  The feature set to enable/disable
 * @return          true if the feature set was successfully enabled/disabled,
 *                  false if a problem occurred
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_features_t
 */
bool rohc_decomp_set_features(struct rohc_decomp *const decomp,
                              const rohc_decomp_features_t features)
{
	const rohc_decomp_features_t all_features =
		ROHC_DECOMP_FEATURE_CRC_REPAIR |
		ROHC_DECOMP_FEATURE_DUMP_PACKETS;

	/* decompressor must be valid */
	if(decomp == NULL)
	{
		/* cannot print a trace without a valid decompressor */
		goto error;
	}

	/* reject unsupported features */
	if((features & all_features) != features)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "feature set 0x%x is not supported (supported features "
		             "set is 0x%x)", features, all_features);
		goto error;
	}

	/* record new feature set */
	decomp->features = features;

	return true;

error:
	return false;
}


/**
 * @brief Get profile index if profile exists
 *
 * @param profile  The profile to enable
 * @return         The profile index if the profile exists,
 *                 -1 if the profile does not exist
 */
static int rohc_decomp_get_profile_index(const rohc_profile_t profile)
{
	size_t idx;

	/* search for the profile location */
	for(idx = 0; idx < D_NUM_PROFILES; idx++)
	{
		if(rohc_decomp_profiles[idx]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(idx == D_NUM_PROFILES)
	{
		goto error;
	}

	return idx;

error :
	return -1;
}


/**
 * @brief Is the given decompression profile enabled for a decompressor?
 *
 * Is the given decompression profile enabled or disabled for a decompressor?
 *
 * @param decomp   The ROHC decompressor
 * @param profile  The profile to ask status for
 * @return         Possible return values:
 *                  \li true if the profile exists and is enabled,
 *                  \li false if the decompressor is not valid, the profile
 *                      does not exist, or the profile is disabled
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_disable_profile
 * @see rohc_decomp_disable_profiles
 */
bool rohc_decomp_profile_enabled(const struct rohc_decomp *const decomp,
                                 const rohc_profile_t profile)
{
	size_t profile_idx;
	int ret;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	ret = rohc_decomp_get_profile_index(profile);
	if(ret < 0)
	{
		goto error;
	}
	profile_idx = ret;

	/* return profile status */
	return decomp->enabled_profiles[profile_idx];

error:
	return false;
}


/**
 * @brief Enable a decompression profile for a decompressor
 *
 * Enable a decompression profiles for a decompressor.
 *
 * The ROHC decompressor does not use the decompression profiles that are not
 * enabled. Thus not enabling a profile might cause the decompressor to reject
 * streams. Decompression will always fail if no profile at all is enabled.
 *
 * If the profile is already enabled, nothing is performed and success is
 * reported.
 *
 * The ROHCv1 and ROHCv2 profiles are incompatible. The same profile cannot
 * be enabled in both versions 1 and 2.
 *
 * @param decomp   The ROHC decompressor
 * @param profile  The profile to enable
 * @return         true if the profile exists,
 *                 false if the profile does not exist
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c enable ROHC decompression profile
 * \code
        ...
\endcode
 *
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_disable_profile
 * @see rohc_decomp_disable_profiles
 */
bool rohc_decomp_enable_profile(struct rohc_decomp *const decomp,
                                const rohc_profile_t profile)
{
	size_t profile_idx;
	int ret;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	ret = rohc_decomp_get_profile_index(profile);
	if(ret < 0)
	{
		goto error;
	}
	profile_idx = ret;

	/* the same profile cannot be enabled in both ROHCv1 and ROHCv2 versions:
	 * check if the corresponding profile in the other ROHC version is already
	 * enabled or not */
	if(rohc_decomp_profile_enabled(decomp, rohc_profile_get_other_version(profile)))
	{
		goto error;
	}

	/* RFC5225, §6.1:
	 * The compressor MUST NOT use ROHC segmentation (see Section 5.2.5 of
	 * [RFC4995]), i.e., the Maximum Reconstructed Reception Unit (MRRU)
	 * MUST be set to 0, if the configuration of the ROHC channel contains
	 * at least one ROHCv2 profile in the list of supported profiles (i.e.,
	 * the PROFILES parameter) and if the channel cannot guarantee in-order
	 * delivery of packets between compression endpoints.
	 */
	if(rohc_profile_is_rohcv2(profile) && decomp->mrru > 0)
	{
		goto error;
	}

	/* mark the profile as enabled */
	decomp->enabled_profiles[profile_idx] = true;
	rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	          "ROHC decompression profile (ID = 0x%04x) enabled", profile);

	return true;

error:
	return false;
}


/**
 * @brief Disable a decompression profile for a decompressor
 *
 * Disable a decompression profiles for a decompressor.
 *
 * The ROHC decompressor does not use the decompression profiles that were
 * disabled. Thus disabling a profile might cause the decompressor to reject
 * streams. Decompression will always fail if no profile at all is enabled.
 *
 * If the profile is already disabled, nothing is performed and success is
 * reported.
 *
 * @param decomp   The ROHC decompressor
 * @param profile  The profile to disable
 * @return         true if the profile exists,
 *                 false if the profile does not exist
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_disable_profiles
 */
bool rohc_decomp_disable_profile(struct rohc_decomp *const decomp,
                                 const rohc_profile_t profile)
{
	size_t profile_idx;
	int ret;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	ret = rohc_decomp_get_profile_index(profile);
	if(ret < 0)
	{
		goto error;
	}
	profile_idx = ret;

	/* mark the profile as disabled */
	decomp->enabled_profiles[profile_idx] = false;
	rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	          "ROHC decompression profile (ID = 0x%04x) disabled", profile);

	return true;

error:
	return false;
}


/**
 * @brief Enable several decompression profiles for a decompressor
 *
 * Enable several decompression profiles for a decompressor. The list of
 * profiles to enable shall stop with -1.
 *
 * The ROHC decompressor does not use the decompression profiles that are not
 * enabled. Thus not enabling a profile might cause the decompressor to reject
 * streams. Decompression will always fail if no profile at all is enabled.
 *
 * If one or more of the profiles are already enabled, nothing is performed
 * and success is reported.
 *
 * @param decomp  The ROHC decompressor
 * @param ...     The sequence of decompression profiles to enable, the
 *                sequence shall be terminated by -1
 * @return        true if all of the profiles exist,
 *                false if at least one of the profiles does not exist
 *
 * @ingroup rohc_decomp
 *
 * \par Example:
 * \snippet example_rohc_decomp.c define ROHC decompressor
 * \code
        ...
\endcode
 * \snippet example_rohc_decomp.c enable ROHC decompression profiles
 * \code
        ...
\endcode
 *
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_disable_profile
 * @see rohc_decomp_disable_profiles
 */
bool rohc_decomp_enable_profiles(struct rohc_decomp *const decomp,
                                 ...)
{
	va_list profiles;
	int profile_id;
	size_t err_nr = 0;
	bool is_ok;

	if(decomp == NULL)
	{
		goto error;
	}

	va_start(profiles, decomp);

	while((profile_id = va_arg(profiles, int)) >= 0)
	{
		is_ok = rohc_decomp_enable_profile(decomp, profile_id);
		if(!is_ok)
		{
			err_nr++;
		}
	}

	va_end(profiles);

	return (err_nr == 0);

error:
	return false;
}


/**
 * @brief Disable several decompression profiles for a decompressor
 *
 * Disable several decompression profiles for a decompressor. The list of
 * profiles to disable shall stop with -1.
 *
 * The ROHC decompressor does not use the decompression profiles that were
 * disabled. Thus disabling a profile might cause the decompressor to reject
 * streams. Decompression will always fail if no profile at all is enabled.
 *
 * If one or more of the profiles are already disabled, nothing is performed
 * and success is reported.
 *
 * @param decomp  The ROHC decompressor
 * @param ...     The sequence of decompression profiles to disable, the
 *                sequence shall be terminated by -1
 * @return        true if all of the profiles exist,
 *                false if at least one of the profiles does not exist
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_enable_profile
 * @see rohc_decomp_enable_profiles
 * @see rohc_decomp_disable_profile
 */
bool rohc_decomp_disable_profiles(struct rohc_decomp *const decomp,
                                  ...)
{
	va_list profiles;
	int profile_id;
	size_t err_nr = 0;
	bool is_ok;

	if(decomp == NULL)
	{
		goto error;
	}

	va_start(profiles, decomp);

	while((profile_id = va_arg(profiles, int)) >= 0)
	{
		is_ok = rohc_decomp_disable_profile(decomp, profile_id);
		if(!is_ok)
		{
			err_nr++;
		}
	}

	va_end(profiles);

	return (err_nr == 0);

error:
	return false;
}


/**
 * @brief Set the callback function used to manage traces in decompressor
 *
 * Set the user-defined callback function used to manage traces in the
 * decompressor.
 *
 * The function will be called by the ROHC library every time it wants to
 * print something related to decompression, from errors to debug. User may
 * thus decide what traces are interesting (filter on \e level, source
 * \e entity, or \e profile) and what to do with them (print on console,
 * storage in file, syslog...).
 *
 * @warning The callback can not be modified after library initialization
 *
 * @param decomp     The ROHC decompressor
 * @param callback   Two possible cases:
 *                     \li The callback function used to manage traces
 *                     \li NULL to remove the previous callback
 * @param priv_ctxt  An optional private context, may be NULL
 * @return           true on success, false otherwise
 *
 * @ingroup rohc_decomp
 */
bool rohc_decomp_set_traces_cb2(struct rohc_decomp *decomp,
                                rohc_trace_callback2_t callback,
                                void *const priv_ctxt)
{
	/* check decompressor validity */
	if(decomp == NULL)
	{
		/* cannot print a trace without a valid decompressor */
		goto error;
	}

	/* refuse to set a new trace callback if decompressor is in use */
	if(decomp->stats.received > 0)
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL, "unable to "
		           "modify the trace callback after initialization");
		goto error;
	}

	/* replace current trace callback by the new one */
	decomp->trace_callback = callback;
	decomp->trace_callback_priv = priv_ctxt;

	return true;

error:
	return false;
}


/*
 * Private functions
 */


/**
 * @brief Find the ROHC profile with the given profile ID.
 *
 * @param decomp      The ROHC decompressor
 * @param profile_id  The profile ID to search for
 * @return            The matching ROHC profile if found and enabled,
 *                    NULL if not found or disabled
 */
static const struct rohc_decomp_profile * find_profile(const struct rohc_decomp *const decomp,
                                                       const rohc_profile_t profile_id)
{
	size_t i;

	/* search for the profile within the enabled profiles */
	for(i = 0;
	    i < D_NUM_PROFILES && rohc_decomp_profiles[i]->id != profile_id;
	    i++)
	{
	}

	if(i >= D_NUM_PROFILES)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "decompression profile with ID 0x%04x not found",
		             profile_id);
		return NULL;
	}

	if(!decomp->enabled_profiles[i])
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "decompression profile with ID 0x%04x disabled",
		             profile_id);
		return NULL;
	}

	return rohc_decomp_profiles[i];
}


/**
 * @brief Decode the CID of a packet
 *
 * @param decomp              The ROHC decompressor
 * @param packet              The ROHC packet to extract CID from
 * @param len                 The size of the ROHC packet
 * @param[out] cid            The Context ID (CID) extracted from the ROHC packet
 * @param[out] add_cid_len    The length of add-CID in ROHC packet
 * @param[out] large_cid_len  The length of large CID in ROHC packet
 * @return                    true in case of success, false in case of failure
 */
static bool rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                   const uint8_t *packet,
                                   unsigned int len,
                                   rohc_cid_t *const cid,
                                   size_t *const add_cid_len,
                                   size_t *const large_cid_len)
{
	/* is feedback data is large enough to read add-CID or first byte
	   of large CID ? */
	if(len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "feedback data too short for add-CID or large CID");
		goto error;
	}

	if(decomp->medium.cid_type == ROHC_SMALL_CID)
	{
		/* small CID */
		*large_cid_len = 0;

		/* if add-CID is present, extract the CID value */
		*cid = rohc_add_cid_decode(packet, len);
		if((*cid) == UINT8_MAX)
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "no add-CID found, CID defaults to 0");
			*add_cid_len = 0;
			*cid = 0;
		}
		else
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "add-CID present (0x%x) contains CID = %zu",
			           packet[0], *cid);
			*add_cid_len = 1;
		}
	}
	else if(decomp->medium.cid_type == ROHC_LARGE_CID)
	{
		uint32_t large_cid;
		size_t large_cid_bits_nr;

		/* large CID */
		*add_cid_len = 0;

		/* skip the first byte of packet located just before the large CID */
		packet++;
		len--;

		/* decode SDVL-encoded large CID
		 * (only 1-byte and 2-byte SDVL fields are allowed) */
		*large_cid_len = sdvl_decode(packet, len, &large_cid, &large_cid_bits_nr);
		if((*large_cid_len) != 1 && (*large_cid_len) != 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to decode SDVL-encoded large CID field");
			goto error;
		}
		*cid = large_cid & 0xffff;
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "%zu-byte large CID = %zu", *large_cid_len, *cid);
	}
	else
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unexpected CID type (%d), should not happen",
		           decomp->medium.cid_type);
		assert(0);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Parse padding bits if some are present
 *
 * @param decomp       The ROHC decompressor
 * @param packet       The ROHC packet to parse
 */
static void rohc_decomp_parse_padding(const struct rohc_decomp *const decomp,
                                      struct rohc_buf *const packet)
{
	size_t padding_length = 0;

	/* remove all padded bytes */
	while(packet->len > 0 &&
	      rohc_decomp_packet_is_padding(rohc_buf_data(*packet)))
	{
		rohc_buf_pull(packet, 1);
		padding_length++;
	}
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "skip %zu byte(s) of padding", padding_length);
}


/**
 * @brief Find the context for the given ROHC packet
 *
 * If packet is an IR(-DYN) packet, parse it for the profile ID.
 * Searche for the context with the given CID.
 * Create a new context if needed.
 *
 * @param decomp                The ROHC decompressor
 * @param packet                The ROHC packet to parse
 * @param packet_len            The length (in bytes) of the ROHC packet
 * @param cid                   The CID that was parsed from ROHC packet
 * @param large_cid_len         The length (in bytes) of the Large CID that was
 *                              parsed from ROHC packet
 * @param arrival_time          The time at which the ROHC packet was received
 * @param[out] profile_id       The profile ID parsed from the ROHC packet
 * @param[out] context          The decompression context for the given ROHC packet
 * @param[out] context_created  Whether the packet has just been created or not
 * @return                      Possible return values:
 *                              \li ROHC_STATUS_OK if context was found,
 *                              \li ROHC_STATUS_NO_CONTEXT if no matching
 *                                  context was found and packet cannot create
 *                                  a new context (or failed to do so),
 *                              \li ROHC_STATUS_MALFORMED if packet is
 *                                  malformed
 */
static rohc_status_t rohc_decomp_find_context(struct rohc_decomp *const decomp,
                                              const uint8_t *const packet,
                                              const size_t packet_len,
                                              const rohc_cid_type_t cid,
                                              const size_t large_cid_len,
                                              const struct rohc_ts arrival_time,
                                              rohc_profile_t *const profile_id,
                                              struct rohc_decomp_ctxt **const context,
                                              bool *const context_created)
{
	const uint8_t *remain_data = packet;
	size_t remain_len = packet_len;
	bool new_context_needed = false;
	bool is_packet_ir_dyn;
	bool is_packet_ir_cr;
	bool is_packet_ir;

	assert(large_cid_len <= 2);

	*profile_id = ROHC_PROFILE_GENERAL;
	*context = NULL;
	*context_created = false;

	/* we need at least 1 byte for packet type */
	if(remain_len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "ROHC packet too small to read the first byte that "
		             "contains the packet type (len = %zu)", remain_len);
		goto error_malformed;
	}

	/* get the profile ID from IR and IR-DYN packets */
	is_packet_ir = rohc_decomp_packet_is_ir(remain_data, remain_len);
	is_packet_ir_dyn = rohc_decomp_packet_is_irdyn(remain_data, remain_len);
	if(is_packet_ir || is_packet_ir_dyn)
	{
		const uint8_t pkt_type = remain_data[0];
		uint8_t pkt_profile_id;

		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "ROHC packet is an IR, IR-CR or IR-DYN packet");

		/* skip the type octet */
		remain_data++;
		remain_len--;

		/* skip the large CID octets if any*/
		remain_data += large_cid_len;
		remain_len -= large_cid_len;

		/* get the profile ID */
		if(remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "ROHC packet too small to read the profile ID byte "
			             "(len = %zu)", remain_len);
			goto error_malformed;
		}
		pkt_profile_id = remain_data[0];
		remain_data++;
		remain_len--;
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "profile octet 0x%02x found in IR(-CR|-DYN) packet",
		           pkt_profile_id);

		/* ROHCv1 or ROHCv2? use ROHCv2 if profile exists and is enabled */
		if(rohc_decomp_profile_enabled(decomp, 0x0100 + pkt_profile_id))
		{
			*profile_id = 0x0100 + pkt_profile_id; /* ROHCv2 profile */
		}
		else
		{
			*profile_id = pkt_profile_id; /* ROHCv1 profile */
		}
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "profile ID 0x%04x found in IR(-CR|-DYN) packet", *profile_id);

		is_packet_ir_cr = !!((*profile_id) == ROHC_PROFILE_TCP && (pkt_type & 0x01) == 0);
		is_packet_ir = (is_packet_ir && !is_packet_ir_cr);
	}
	else
	{
		is_packet_ir_cr = false;
	}

	/* find the context associated with the CID */
	*context = find_context(decomp, cid);
	if((*context) == NULL)
	{
		/* the decompression context did not exist yet */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "context with CID %u not found", cid);

		/* only IR packets can create new contexts */
		if(!is_packet_ir && !is_packet_ir_cr)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "only IR or IR-CR packets can create a new context with CID %u", cid);
			goto error_no_context;
		}

		/* IR or IR-CR shall create a new context */
		new_context_needed = true;
	}
	else
	{
		/* the decompression context did exist */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "context with CID %u found", cid);

		/* for IR(-CR|-DYN) packets, check whether the packet redefines the profile
		 * associated with the context */
		if((is_packet_ir || is_packet_ir_cr || is_packet_ir_dyn) &&
		   (*context)->profile->id != (*profile_id))
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "IR(-CR|-DYN) packet redefines the profile associated to the "
			           "context with CID %u: %s (0x%04x) -> %s (0x%04x)", cid,
			           rohc_get_profile_descr((*context)->profile->id),
			           (*context)->profile->id,
			           rohc_get_profile_descr(*profile_id), *profile_id);
			if(is_packet_ir || is_packet_ir_cr)
			{
				/* IR(-CR) packets: profile switching is handled by re-creating the
				 * context from scratch */
				new_context_needed = true;
			}
			else
			{
				/* IR-CR or IR-DYN packet: TODO: profile switching is not implemented
				 * yet, send a STATIC-NACK to the compressor so that it fallbacks on
				 * sending an IR packet instead of the IR-DYN packet */
				goto error_no_context;
			}
		}
	}

	/* create a new context if needed */
	if(new_context_needed)
	{
		const struct rohc_decomp_profile *profile;

		/* find the profile specified in the ROHC packet */
		profile = find_profile(decomp, *profile_id);
		if(profile == NULL)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to find profile identified by ID 0x%04x",
			             *profile_id);
			goto error_no_context;
		}

		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "create new context with CID %u and profile '%s' (0x%04x)",
		           cid, rohc_get_profile_descr(*profile_id), *profile_id);
		*context = context_create(decomp, cid, profile, arrival_time);
		if((*context) == NULL)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to create a new context with CID %u and "
			             "profile 0x%04x", cid, *profile_id);
			goto error_no_context;
		}
		*context_created = true;
	}
	else
	{
		*profile_id = (*context)->profile->id;
	}
	assert((*context)->profile != NULL);

	return ROHC_STATUS_OK;

error_malformed:
	return ROHC_STATUS_MALFORMED;
error_no_context:
	return ROHC_STATUS_NO_CONTEXT;
}


/**
 * @brief Parse zero or more feedback items from the given ROHC data
 *
 * @param decomp              The ROHC decompressor
 * @param rohc_data           The ROHC data to parse for feedback items
 * @param[out] feedbacks      The parsed feedback items, may be NULL if one
 *                            don't want to retrieve the feedback items
 * @return                    true if parsing of feedback items is successful,
 *                            false if at least one feedback is malformed
 */
static bool rohc_decomp_parse_feedbacks(struct rohc_decomp *const decomp,
                                        struct rohc_buf *const rohc_data,
                                        struct rohc_buf *const feedbacks)
{
	size_t feedbacks_nr = 0;
	size_t feedbacks_full_len = 0; /* full feedbacks length */
	size_t feedbacks_len = 0;      /* maybe truncated feedbacks length */

	/* no feedback parsed for the moment */
	assert(feedbacks == NULL || rohc_buf_is_empty(*feedbacks));

	/* parse as much feedback data as possible */
	while(rohc_data->len > 0 &&
	      rohc_packet_is_feedback(rohc_buf_byte(*rohc_data)))
	{
		size_t feedback_len = 0;

		feedbacks_nr++;

		/* decode one feedback packet */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "parse feedback item #%zu at offset %zu in ROHC packet",
		           feedbacks_nr, feedbacks_full_len);
		if(!rohc_decomp_parse_feedback(decomp, rohc_data, feedbacks, &feedback_len))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to parse feedback item #%zu at offset %zu in "
			             "ROHC packet", feedbacks_nr, feedbacks_full_len);
			goto error;
		}
		feedbacks_full_len += feedback_len;

		/* hide the feedback */
		if(feedbacks != NULL)
		{
			feedbacks_len += feedbacks->len;
			rohc_buf_pull(feedbacks, feedbacks->len);
		}
	}

	/* unhide all feedbacks */
	if(feedbacks != NULL)
	{
		rohc_buf_push(feedbacks, feedbacks_len);
	}

	return true;

error:
	return false;
}


/**
 * @brief Parse a feedback item from the given ROHC data
 *
 * @param decomp             The ROHC decompressor
 * @param rohc_data          The ROHC data to parse for one feedback item
 * @param[out] feedback      The retrieved feedback (header and data included),
 *                           may be NULL if one don't want to retrieve the
 *                           feedback item
 * @param[out] feedback_len  The length of the parsed feedback (maybe be different
 *                           from feedback->len if feedback was NULL or full)
 * @return                   true if feedback parsing was successful,
 *                           false if feedback is malformed
 */
static bool rohc_decomp_parse_feedback(struct rohc_decomp *const decomp,
                                       struct rohc_buf *const rohc_data,
                                       struct rohc_buf *const feedback,
                                       size_t *const feedback_len)
{
	size_t feedback_hdr_len;
	size_t feedback_data_len;
	bool is_ok;

	/* compute the length of the feedback item */
	is_ok = rohc_feedback_get_size(*rohc_data, &feedback_hdr_len,
	                               &feedback_data_len);
	if(!is_ok)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "failed to parse a feedback item");
		goto error;
	}
	*feedback_len = feedback_hdr_len + feedback_data_len;
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "feedback found (header = %zu bytes, data = %zu bytes)",
	           feedback_hdr_len, feedback_data_len);

	/* reject feedback item if it doesn't fit in the available ROHC data */
	if((*feedback_len) > rohc_data->len)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "the %zu-byte feedback is too large for the %zu-byte "
		             "remaining ROHC data", *feedback_len, rohc_data->len);
		goto error;
	}

	/* copy the feedback item in order to return it user if he/she asked for */
	if(feedback != NULL)
	{
		if((feedback->len + (*feedback_len)) > rohc_buf_avail_len(*feedback))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to store %zu-byte feedback into the buffer given "
			             "by the user, only %zu bytes still available: ignore "
			             "feedback", *feedback_len, rohc_buf_avail_len(*feedback));
		}
		else
		{
			rohc_buf_append(feedback, rohc_buf_data(*rohc_data), *feedback_len);
		}
	}

	/* skip the feedback item in the ROHC packet */
	rohc_buf_pull(rohc_data, *feedback_len);

	return true;

error:
	return false;
}


/**
 * @brief Create the array of decompression contexts
 *
 * The maximum size of the array is \ref ROHC_LARGE_CID_MAX + 1.
 *
 * @param decomp   The ROHC decompressor
 * @param max_cid  The MAX_CID value to used
 * @return         true if the contexts were created, false otherwise
 */
static bool rohc_decomp_create_contexts(struct rohc_decomp *const decomp,
                                        const rohc_cid_t max_cid)
{
	assert(max_cid <= ROHC_LARGE_CID_MAX);

	/* allocate memory for the new context array */
	decomp->contexts = calloc(max_cid + 1, sizeof(struct rohc_decomp_ctxt *));
	if(decomp->contexts == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "cannot allocate memory for the contexts");
		return false;
	}
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "room for %zu decompression contexts created", max_cid + 1);

	return true;
}

