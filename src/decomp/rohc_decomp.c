/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013,2014 Viveris Technologies
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

#ifndef __KERNEL__
#  include <string.h>
#endif
#include <stdarg.h>
#include <assert.h>


extern const struct rohc_decomp_profile d_uncomp_profile,
                                        d_udp_profile,
                                        d_ip_profile,
                                        d_udplite_profile,
                                        d_esp_profile,
                                        d_rtp_profile,
                                        d_tcp_profile;


/**
 * @brief The decompression parts of the ROHC profiles.
 */
static const struct rohc_decomp_profile *const
	rohc_decomp_profiles[D_NUM_PROFILES] =
{
	&d_uncomp_profile,
	&d_rtp_profile,
	&d_udp_profile,
	&d_esp_profile,
	&d_ip_profile,
	&d_tcp_profile,
	&d_udplite_profile,
};


/*
 * Definitions of private structures
 */

/**
 * @brief Decompression-related data.
 *
 * This object stores the information related to the decompression of one
 * ROHC packet (CID and context for example). The lifetime of this object is
 * the time needed to decompress one single packet.
 */
struct d_decode_data
{
	/// The Context ID of the context to which the packet is related
	rohc_cid_t cid;
	/// Whether the ROHC packet uses add-CID or not
	int addcidUsed;
	/// The size (in bytes) of the large CID field
	unsigned int large_cid_size;
	/// The context to which the packet is related
	struct rohc_decomp_ctxt *active;
};


/*
 * Prototypes of private functions
 */

static bool rohc_decomp_create_contexts(struct rohc_decomp *const decomp,
                                        const rohc_cid_t max_cid)
	__attribute__((nonnull(1), warn_unused_result));

static rohc_status_t d_decode_header(struct rohc_decomp *decomp,
                                     const struct rohc_buf rohc_packet,
                                     struct rohc_buf *const uncomp_packet,
                                     struct rohc_buf *const rcvd_feedback,
                                     struct d_decode_data *ddata,
                                     rohc_packet_t *const packet_type)
	__attribute__((nonnull(1, 3, 5, 6), warn_unused_result));

static const struct rohc_decomp_profile *
	find_profile(const struct rohc_decomp *const decomp,
	             const rohc_profile_t profile_id)
	__attribute__((warn_unused_result));

static struct rohc_decomp_ctxt * context_create(struct rohc_decomp *decomp,
                                                const rohc_cid_t cid,
                                                const struct rohc_decomp_profile *const profile,
                                                const struct rohc_ts arrival_time);
static struct rohc_decomp_ctxt *
	find_context(const struct rohc_decomp *const decomp, const size_t cid)
	__attribute__((nonnull(1), warn_unused_result));
static void context_free(struct rohc_decomp_ctxt *const context);

static bool rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                   const unsigned char *packet,
                                   unsigned int len,
                                   struct d_decode_data *ddata)
	__attribute__((warn_unused_result));

static void rohc_decomp_parse_padding(const struct rohc_decomp *const decomp,
                                      struct rohc_buf *const packet)
	__attribute__((nonnull(1, 2)));

/* feedback-related functions */
static bool rohc_decomp_parse_feedbacks(struct rohc_decomp *const decomp,
                                        struct rohc_buf *const rohc_data,
                                        struct rohc_buf *const feedbacks)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static bool rohc_decomp_parse_feedback(struct rohc_decomp *const decomp,
                                       struct rohc_buf *const rohc_data,
                                       struct rohc_buf *const feedback)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static void d_operation_mode_feedback(struct rohc_decomp *decomp,
                                      const rohc_status_t rohc_status,
                                      const uint16_t cid,
                                      const rohc_cid_type_t cid_type,
                                      int mode,
                                      struct rohc_decomp_ctxt *context,
                                      struct rohc_buf *const feedback_send);
static void d_optimistic_feedback(struct rohc_decomp *decomp,
                                  const rohc_status_t rohc_status,
                                  const rohc_cid_t cid,
                                  const rohc_cid_type_t cid_type,
                                  struct rohc_decomp_ctxt *context,
                                  struct rohc_buf *const feedback_send);

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
static struct rohc_decomp_ctxt *
	find_context(const struct rohc_decomp *const decomp, const rohc_cid_t cid)
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

	assert(decomp != NULL);
	assert(cid <= ROHC_LARGE_CID_MAX);
	assert(profile != NULL);

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
	context->do_change_mode = false;
	context->curval = 0;

	/* init some statistics */
	context->num_recv_packets = 0;
	context->total_uncompressed_size = 0;
	context->total_compressed_size = 0;
	context->header_uncompressed_size = 0;
	context->header_compressed_size = 0;
	context->corrected_crc_failures = 0;
	context->corrected_sn_wraparounds = 0;
	context->corrected_wrong_sn_updates = 0;
	context->nr_lost_packets = 0;
	context->nr_misordered_packets = 0;
	context->is_duplicated = 0;

	context->first_used = arrival_time.sec;
	context->latest_used = arrival_time.sec;

	/* profile-specific data (created at the every end so that everything
	   is initialized in context first) */
	context->specific = profile->new_context(context);
	if(context->specific == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "cannot allocate profile-specific data");
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
	assert(context != NULL);
	assert(context->decompressor != NULL);
	assert(context->profile != NULL);
	assert(context->specific != NULL);

	rohc_debug(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
	           "free context with CID %zu", context->cid);

	/* destroy the profile-specific data */
	context->profile->free_context(context->specific);

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
 * @param mode      The operational mode that the ROHC decompressor shall
 *                  transit to.\n
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
	decomp->trace_callback2 = NULL;
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

	/* initialize the array of decompression contexts to its minimal value */
	decomp->contexts = NULL;
	decomp->num_contexts_used = 0;
	is_fine = rohc_decomp_create_contexts(decomp, decomp->medium.max_cid);
	if(!is_fine)
	{
		goto destroy_decomp;
	}
	decomp->last_context = NULL;

	decomp->maxval = 300;
	decomp->errval = 100;
	decomp->okval = 12;
	decomp->curval = 0;

	/* no Reconstructed Reception Unit (RRU) at the moment */
	decomp->rru_len = 0;
	/* no segmentation by default */
	decomp->mrru = 0;

	/* init the tables for fast CRC computation */
	is_fine = rohc_crc_init_table(decomp->crc_table_3, ROHC_CRC_TYPE_3);
	if(is_fine != true)
	{
		goto destroy_contexts;
	}
	is_fine = rohc_crc_init_table(decomp->crc_table_7, ROHC_CRC_TYPE_7);
	if(is_fine != true)
	{
		goto destroy_contexts;
	}
	is_fine = rohc_crc_init_table(decomp->crc_table_8, ROHC_CRC_TYPE_8);
	if(is_fine != true)
	{
		goto destroy_contexts;
	}

	/* reset the decompressor statistics */
	rohc_decomp_reset_stats(decomp);

	return decomp;

destroy_contexts:
	free(decomp->contexts);
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
 * \par Time-related features in the ROHC protocol:
 * Set the \e rohc_packet.time parameter to 0 if arrival time of the ROHC
 * packet is unknown or to disable the time-related features in the ROHC
 * protocol.
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
	struct d_decode_data ddata = { 0, 0, 0, NULL };
	rohc_packet_t packet_type;
	rohc_status_t status = ROHC_STATUS_ERROR; /* error status by default */

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

#if ROHC_EXTRA_DEBUG == 1
	/* print compressed bytes */
	rohc_dump_packet(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	                 decomp->trace_callback,
#endif
	                 decomp->trace_callback2, decomp->trace_callback_priv,
	                 ROHC_TRACE_DECOMP, ROHC_TRACE_DEBUG,
	                 "compressed data, max 100 bytes", rohc_packet);
#endif

	/* decode ROHC header */
	status = d_decode_header(decomp, rohc_packet, uncomp_packet, rcvd_feedback,
	                         &ddata, &packet_type);
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "d_decode_header returned code %d", status);

	/* in case of failure, users shall get an empty decompressed packet */
	if(status != ROHC_STATUS_OK)
	{
		uncomp_packet->len = 0;
	}

	/* update statistics and send feedback if needed */
	switch(status)
	{
		case ROHC_STATUS_MALFORMED:
		case ROHC_STATUS_OUTPUT_TOO_SMALL:
		case ROHC_STATUS_ERROR:
		{
			if(ddata.active != NULL)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ddata.active->profile->id,
				             "packet decompression failed: %s (%d)",
				             rohc_strerror(status), status);
			}
			else
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				             "packet decompression failed: %s (%d)",
				             rohc_strerror(status), status);
			}

			/* update statistics */
			if(ddata.active != NULL)
			{
				ddata.active->num_recv_packets++;
			}
			decomp->stats.failed_decomp++;

			/* feedback rate-limiting */
			if(ddata.active != NULL)
			{
				ddata.active->curval += decomp->errval;
				if(((unsigned int) ddata.active->curval) >= decomp->maxval)
				{
					ddata.active->curval = 0;
					d_operation_mode_feedback(decomp, ROHC_STATUS_MALFORMED,
					                          ddata.cid, decomp->medium.cid_type,
					                          ddata.active->mode, ddata.active,
					                          feedback_send);
				}
			}
			break;
		}

		case ROHC_STATUS_NO_CONTEXT:
		{
			/* the context may not be NULL if a UO* packet packet is received in
			 * No Context state for example, force it to NULL */
			ddata.active = NULL;
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "no context found for packet decompression");

			/* update statistics */
			decomp->stats.failed_no_context++;

			/* feedback rate-limiting */
			decomp->curval += decomp->errval;
			if(((unsigned int) decomp->curval) >= decomp->maxval)
			{
				decomp->curval = 0;
				d_operation_mode_feedback(decomp, ROHC_STATUS_NO_CONTEXT,
				                          ddata.cid, decomp->medium.cid_type,
				                          ROHC_O_MODE, NULL, feedback_send);
			}
			break;
		}

		case ROHC_STATUS_BAD_CRC:
		{
			/* active context may be NULL if IR packet created a new context then
			 * failed CRC check (the context is destroyed) */
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "packet decompression failed because of malformed "
			             "packet or bad CRC");

			/* update statistics */
			if(ddata.active != NULL)
			{
				ddata.active->num_recv_packets++;
			}
			decomp->stats.failed_crc++;

			/* feedback rate-limiting */
			if(ddata.active != NULL)
			{
				ddata.active->curval += decomp->errval;
				rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "feedback curr %d", ddata.active->curval);
				rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "feedback max %d", decomp->maxval);
				if(((unsigned int) ddata.active->curval) >= decomp->maxval)
				{
					ddata.active->curval = 0;
					d_operation_mode_feedback(decomp, ROHC_STATUS_BAD_CRC,
					                          ddata.cid, decomp->medium.cid_type,
					                          ddata.active->mode, ddata.active,
					                          feedback_send);
				}
			}
			break;
		}

		case ROHC_STATUS_OK:
		{
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "packet decompression succeeded");

			/* update statistics */
			if(uncomp_packet->len > 0)
			{
				assert(ddata.active != NULL);
				ddata.active->num_recv_packets++;
				ddata.active->packet_type = packet_type;
				ddata.active->total_uncompressed_size += uncomp_packet->len;
				ddata.active->total_compressed_size += rohc_packet.len;
				decomp->stats.total_uncompressed_size += uncomp_packet->len;
				decomp->stats.total_compressed_size += rohc_packet.len;

				/* feedback rate-limiting */
				decomp->curval -= decomp->okval; /* framework (S-NACK) */
				ddata.active->curval -= decomp->okval; /* context (NACK) */
				rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "feedback curr %d", ddata.active->curval);
				if(decomp->curval < 0)
				{
					decomp->curval = 0;
				}
				if(ddata.active->curval < 0)
				{
					ddata.active->curval = 0;
				}
				rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "feedback curr %d", ddata.active->curval);
				if(ddata.active->mode == ROHC_U_MODE ||
				   ddata.active->do_change_mode)
				{
					if(ddata.active->mode == ROHC_U_MODE)
					{
						/* switch active context to O-mode */
						ddata.active->mode = ROHC_O_MODE;
					}
					d_operation_mode_feedback(decomp, ROHC_STATUS_OK, ddata.cid,
					                          decomp->medium.cid_type,
					                          ddata.active->mode, ddata.active,
					                          feedback_send);
				}
			}
			break;
		}

		default:
		{
			assert(0); /* should not happen */
			break;
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
 * @param[out] ddata          Decompression-related data (e.g. the context)
 * @param[out] packet_type    The type of the decompressed ROHC packet
 * @return                    Possible return values:
 *                            \li ROHC_STATUS_OK if packet is successfully
 *                                decoded,
 *                            \li ROHC_STATUS_NO_CONTEXT if no matching
 *                                context was found and packet cannot create
 *                                a new context,
 *                            \li ROHC_STATUS_MALFORMED if packet is
 *                                malformed,
 *                            \li ROHC_STATUS_BAD_CRC if a CRC error occurs,
 *                            \li ROHC_STATUS_ERROR if another error occurs
 */
static rohc_status_t d_decode_header(struct rohc_decomp *decomp,
                                     const struct rohc_buf rohc_packet,
                                     struct rohc_buf *const uncomp_packet,
                                     struct rohc_buf *const rcvd_feedback,
                                     struct d_decode_data *ddata,
                                     rohc_packet_t *const packet_type)
{
	bool is_new_context = false;
	const struct rohc_decomp_profile *profile;
	struct rohc_buf remain_rohc_data = rohc_packet;
	const uint8_t *walk;
	size_t remain_len;
	rohc_status_t status;

	assert(decomp != NULL);
	assert(ddata != NULL);
	assert(packet_type != NULL);

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
	if(!rohc_decomp_decode_cid(decomp, walk, remain_len, ddata))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "failed to decode small or large CID in packet");
		goto error_malformed;
	}

	/* check whether the decoded CID is allowed by the decompressor */
	if(ddata->cid > decomp->medium.max_cid)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unexpected CID %zu received: MAX_CID was set to %zu",
		             ddata->cid, decomp->medium.max_cid);
		goto error_no_context;
	}

	/* skip add-CID if present */
	if(ddata->addcidUsed)
	{
		walk++;
		remain_len--;
		rohc_buf_pull(&remain_rohc_data, 1);
	}

	/* we need at least 1 byte for packet type */
	if(remain_len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "ROHC packet too small to read the first byte that "
		             "contains the packet type (len = %zu)", remain_len);
		goto error_malformed;
	}

	/* is the ROHC packet an IR packet? */
	if(rohc_decomp_packet_is_ir(walk, remain_len))
	{
		uint8_t profile_id;

		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "ROHC packet is an IR packet");

		/* we need at least 1 byte after the large CID bytes for profile ID */
		if(remain_len <= (ddata->large_cid_size + 1))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "ROHC packet too small to read the profile ID byte "
			             "(len = %zu)", remain_len);
			goto error_malformed;
		}

		/* find the profile specified in the ROHC packet */
		profile_id = walk[1 + ddata->large_cid_size];
		profile = find_profile(decomp, profile_id);
		if(profile == NULL)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to find profile identified by ID 0x%04x",
			             profile_id);
			goto error_no_context;
		}
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "profile with ID 0x%04x found in IR packet", profile_id);

		if(decomp->contexts[ddata->cid] != NULL &&
		   decomp->contexts[ddata->cid]->profile->id == profile->id)
		{
			/* the decompression context associated with the CID already exists
			 * and the context profile and the packet profile match. */
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "context with CID %zu already exists and matches profile "
			           "0x%04x found in IR packet", ddata->cid, profile_id);
			ddata->active = decomp->contexts[ddata->cid];
		}
		else
		{
			/* the decompression context does not exist or the profiles do not
			 * match, create a new context */
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "context with CID %zu either does not already exist or "
			           "does not match profile 0x%04x found in IR packet",
			           ddata->cid, profile_id);
			ddata->active = context_create(decomp, ddata->cid, profile,
			                               rohc_packet.time);
			if(!ddata->active)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				             "failed to create a new context with CID %zu and "
				             "profile 0x%04x", ddata->cid, profile_id);
				goto error_no_context;
			}
			is_new_context = true;
		}
	}
	else /* the ROHC packet is not an IR packet */
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "ROHC packet is not an IR packet");

		/* find the context associated with the CID */
		ddata->active = find_context(decomp, ddata->cid);
		if(!ddata->active)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "context with CID %zu either does not exist or no "
			             "profile is associated with the context", ddata->cid);
			goto error_no_context;
		}
		assert(ddata->active->profile != NULL);

		/* context is valid */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "context with CID %zu found", ddata->cid);

		/* is the ROHC packet an IR-DYN packet? */
		if(rohc_decomp_packet_is_irdyn(walk, remain_len))
		{
			uint8_t profile_id;

			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "ROHC packet is an IR-DYN packet");

			/* we need at least 1 byte after the large CID for profile ID */
			if(remain_len <= (ddata->large_cid_size + 1))
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				             "ROHC packet too small to read the profile ID "
				             "byte (len = %zu)", remain_len);
				goto error_malformed;
			}

			/* find the profile specified in the ROHC packet */
			profile_id = walk[ddata->large_cid_size + 1];
			profile = find_profile(decomp, profile_id);
			if(profile == NULL)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				             "failed to find profile identified by ID 0x%04x",
				             profile_id);
				goto error_no_context;
			}

			/* if IR-DYN changes profile, make the decompressor transit to the
			 * No Context state */
			if(profile != ddata->active->profile)
			{
				decomp->curval = decomp->maxval;
				rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "IR-DYN changed profile, sending S-NACK");
				goto error_no_context;
			}
		}

		profile = ddata->active->profile;
	}
	ddata->active->latest_used = rohc_packet.time.sec;
	decomp->last_context = ddata->active;

 	/* detect the type of the ROHC packet */
	*packet_type = profile->detect_pkt_type(ddata->active, walk, remain_len,
	                                        ddata->large_cid_size);
	if((*packet_type) == ROHC_PACKET_UNKNOWN)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "failed to detect ROHC packet type");
		if(is_new_context)
		{
			context_free(ddata->active);
			ddata->active = NULL;
			decomp->last_context = NULL;
		}
		goto error_malformed;
	}
	rohc_decomp_debug(ddata->active, "decode packet as '%s'",
	                  rohc_get_packet_descr(*packet_type));

	/* only the IR packet can be received in the No Context state,
	 * the IR-DYN, UO-0, UO-1 or UOR-2 can not. */
	if((*packet_type) != ROHC_PACKET_IR &&
	   ddata->active->state == ROHC_DECOMP_STATE_NC)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "non-IR packet (%d) cannot be received in No Context state",
		             *packet_type);
		if(is_new_context)
		{
			context_free(ddata->active);
			ddata->active = NULL;
			decomp->last_context = NULL;
		}
		goto error_no_context;
	}

	/* only IR packet can create a new context */
	assert((*packet_type) == ROHC_PACKET_IR || !is_new_context);

	/* decode the packet thanks to the profile-specific routines */
	status = profile->decode(decomp, ddata->active, remain_rohc_data,
	                         ddata->addcidUsed, ddata->large_cid_size,
	                         uncomp_packet, packet_type);
	if(status != ROHC_STATUS_OK)
	{
		/* decompression failed, free ressources if necessary */
		rohc_warning(decomp, ROHC_TRACE_DECOMP, profile->id,
		             "failed to decompress packet (code = %d)", status);
		if(is_new_context)
		{
			context_free(ddata->active);
			ddata->active = NULL;
			decomp->last_context = NULL;
		}
		goto error;
	}

	/* decompression was successful, replace the existing context with the
	 * new one if necessary */
	if(is_new_context)
	{
		if(decomp->contexts[ddata->cid] != NULL)
		{
			context_free(decomp->contexts[ddata->cid]);
		}
		decomp->contexts[ddata->cid] = ddata->active;
	}

skip:
	return ROHC_STATUS_OK;

error:
	decomp->last_context = NULL;
	return status;

error_crc:
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
 * @brief Send feedback in Optimistic Mode.
 *
 * @param decomp       The ROHC decompressor
 * @param rohc_status  The type of feedback to send:
 *                      \li ROHC_STATUS_OK = OK (ack),
 *                      \li ROHC_STATUS_NO_CONTEXT = ContextInvalid (S-nack),
 *                      \li ROHC_STATUS_MALFORMED = PackageFailed (Nack)
 * @param cid          The Context ID (CID) to which the feedback is related
 * @param cid_type     The type of CID used for the feedback
 * @param context      The context to which the feedback is related
 * @param[out] feedback_send  The feedback to be transmitted to the remote
 *                            compressor through the feedback channel:
 *                            \li If NULL, the decompression won't generate
 *                                feedback information for its compressor
 *                            \li If not NULL, may store the generated
 *                                feedback at the given address
 */
static void d_optimistic_feedback(struct rohc_decomp *decomp,
                                  const rohc_status_t rohc_status,
                                  const rohc_cid_t cid,
                                  const rohc_cid_type_t cid_type,
                                  struct rohc_decomp_ctxt *context,
                                  struct rohc_buf *const feedback_send)
{
	struct d_feedback sfeedback;
	uint8_t *feedback;
	size_t feedbacksize;

	if(context == NULL)
	{
		assert(rohc_status == ROHC_STATUS_NO_CONTEXT);
	}

	/* check associated compressor availability */
	if(context != NULL && context->mode == ROHC_U_MODE)
	{
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "no associated compressor, do not sent feedback");

		/* only change state if needed */
		if(rohc_status == ROHC_STATUS_MALFORMED ||
		   rohc_status == ROHC_STATUS_BAD_CRC)
		{
			if(context->state == ROHC_DECOMP_STATE_SC)
			{
				rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				          "U-mode: change from state %d to state %d because "
				          "of error(s)", context->state, ROHC_DECOMP_STATE_NC);
				context->state = ROHC_DECOMP_STATE_NC;
			}
			else if(context->state == ROHC_DECOMP_STATE_FC)
			{
				rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				          "U-mode: change from state %d to state %d because "
				          "of error(s)", context->state, ROHC_DECOMP_STATE_SC);
				context->state = ROHC_DECOMP_STATE_SC;
			}
		}

		goto skip;
	}

	/* check CID wrt CID type */
	if(decomp->medium.cid_type == ROHC_SMALL_CID && cid > ROHC_SMALL_CID_MAX)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unexpected small CID %zu: not in range [0, %d]", cid,
		             ROHC_SMALL_CID_MAX);
		return;
	}
	else if(cid > ROHC_LARGE_CID_MAX) /* large CID */
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unexpected large CID %zu: not in range [0, %d]", cid,
		             ROHC_LARGE_CID_MAX);
		return;
	}

	/* check CID wrt MAX_CID */
	if(cid > decomp->medium.max_cid)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unexpected CID %zu: not in range [0, %zu]", cid,
		             decomp->medium.max_cid);
		return;
	}

	switch(rohc_status)
	{
		case ROHC_STATUS_OK:
			/* create an ACK feedback */
			rohc_debug(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			           "send an ACK feedback");
			if(!f_feedback2(ROHC_ACK_TYPE_ACK, context->mode,
			                context->profile->get_sn(context), &sfeedback))
			{
				rohc_decomp_warn(context, "failed to build the ACK feedback");
				return;
			}
			feedback = f_wrap_feedback(&sfeedback, cid, cid_type,
			                           ROHC_FEEDBACK_WITH_CRC,
			                           decomp->crc_table_8, &feedbacksize);
			if(feedback == NULL)
			{
				rohc_decomp_warn(context, "failed to wrap the ACK feedback");
				return;
			}

			if(feedback_send != NULL)
			{
				const size_t hdr_len = 1 + (feedbacksize < 8 ? 0 : 1);
				if((hdr_len + feedbacksize) <= rohc_buf_avail_len(*feedback_send))
				{
					if(feedbacksize < 8)
					{
						rohc_buf_byte(*feedback_send) = 0xf0 | feedbacksize;
					}
					else
					{
						rohc_buf_byte(*feedback_send) = 0xf0;
						rohc_buf_byte_at(*feedback_send, 1) = feedbacksize;
					}
					feedback_send->len += hdr_len;
					rohc_buf_append(feedback_send, feedback, feedbacksize);
				}
			}

			/* destroy the feedback */
			zfree(feedback);
			break;

		case ROHC_STATUS_NO_CONTEXT:
			/* create a STATIC NACK feedback */
			rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			          "send a STATIC-NACK feedback for CID %zu", cid);
			if(!f_feedback2(ROHC_ACK_TYPE_STATIC_NACK, ROHC_O_MODE,
			                0 /* unknown SN */, &sfeedback))
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				             "failed to build the STATIC-NACK feedback");
				return;
			}
			if(!f_add_option(&sfeedback, ROHC_FEEDBACK_OPT_SN_NOT_VALID, NULL, 0))
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				             "failed to add the SN-NOT-VALID option to the "
				             "STATIC-NACK feedback");
				return;
			}
			feedback = f_wrap_feedback(&sfeedback, cid, cid_type,
			                           ROHC_FEEDBACK_WITH_CRC,
			                           decomp->crc_table_8, &feedbacksize);
			if(feedback == NULL)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				             "failed to wrap the STATIC-NACK feedback");
				return;
			}

			if(feedback_send != NULL)
			{
				const size_t hdr_len = 1 + (feedbacksize < 8 ? 0 : 1);
				if((hdr_len + feedbacksize) <= rohc_buf_avail_len(*feedback_send))
				{
					if(feedbacksize < 8)
					{
						rohc_buf_byte(*feedback_send) = 0xf0 | feedbacksize;
					}
					else
					{
						rohc_buf_byte(*feedback_send) = 0xf0;
						rohc_buf_byte_at(*feedback_send, 1) = feedbacksize;
					}
					feedback_send->len += hdr_len;
					rohc_buf_append(feedback_send, feedback, feedbacksize);
				}
			}

			/* destroy the feedback */
			zfree(feedback);
			break;

		case ROHC_STATUS_MALFORMED:
		case ROHC_STATUS_BAD_CRC:
		case ROHC_STATUS_OUTPUT_TOO_SMALL:
			switch(context->state)
			{
				case ROHC_DECOMP_STATE_NC:
					/* create a STATIC-NACK feedback */
					rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					          "send a STATIC-NACK feedback for CID %zu", cid);
					if(!f_feedback2(ROHC_ACK_TYPE_STATIC_NACK, context->mode,
					                context->profile->get_sn(context), &sfeedback))
					{
						rohc_decomp_warn(context, "failed to build the STATIC-NACK "
						                 "feedback");
						return;
					}
					feedback = f_wrap_feedback(&sfeedback, cid, cid_type,
					                           ROHC_FEEDBACK_WITH_CRC,
					                           decomp->crc_table_8, &feedbacksize);
					if(feedback == NULL)
					{
						rohc_decomp_warn(context, "failed to create a STATIC-NACK "
						                 "feedback");
						return;
					}

					if(feedback_send != NULL)
					{
						const size_t hdr_len = 1 + (feedbacksize < 8 ? 0 : 1);
						if((hdr_len + feedbacksize) <= rohc_buf_avail_len(*feedback_send))
						{
							if(feedbacksize < 8)
							{
								rohc_buf_byte(*feedback_send) = 0xf0 | feedbacksize;
							}
							else
							{
								rohc_buf_byte(*feedback_send) = 0xf0;
								rohc_buf_byte_at(*feedback_send, 1) = feedbacksize;
							}
							feedback_send->len += hdr_len;
							rohc_buf_append(feedback_send, feedback, feedbacksize);
						}
					}

					/* destroy the feedback */
					zfree(feedback);
					break;

				case ROHC_DECOMP_STATE_SC:
				case ROHC_DECOMP_STATE_FC:
					/* create a NACK feedback */
					rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					          "send a NACK feedback for CID %zu", cid);
					if(!f_feedback2(ROHC_ACK_TYPE_NACK, context->mode,
					                context->profile->get_sn(context), &sfeedback))
					{
						rohc_decomp_warn(context, "failed to build the NACK feedback");
						return;
					}
					feedback = f_wrap_feedback(&sfeedback, cid, cid_type,
					                           ROHC_FEEDBACK_WITH_CRC,
					                           decomp->crc_table_8, &feedbacksize);
					if(feedback == NULL)
					{
						rohc_decomp_warn(context, "failed to create the NACK feedback");
						return;
					}

					if(feedback_send != NULL)
					{
						const size_t hdr_len = 1 + (feedbacksize < 8 ? 0 : 1);
						if((hdr_len + feedbacksize) <= rohc_buf_avail_len(*feedback_send))
						{
							if(feedbacksize < 8)
							{
								rohc_buf_byte(*feedback_send) = 0xf0 | feedbacksize;
							}
							else
							{
								rohc_buf_byte(*feedback_send) = 0xf0;
								rohc_buf_byte_at(*feedback_send, 1) = feedbacksize;
							}
							feedback_send->len += hdr_len;
							rohc_buf_append(feedback_send, feedback, feedbacksize);
						}
					}

					/* change state */
					if(context->state == ROHC_DECOMP_STATE_SC)
					{
						rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
						          "change from state %d to state %d because of "
						          "decompression error(s)", context->state,
						          ROHC_DECOMP_STATE_NC);
						context->state = ROHC_DECOMP_STATE_NC;
					}
					if(context->state == ROHC_DECOMP_STATE_FC)
					{
						rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
						          "change from state %d to state %d because of "
						          "decompression error(s)", context->state,
						          ROHC_DECOMP_STATE_SC);
						context->state = ROHC_DECOMP_STATE_SC;
					}

					/* destroy the feedback */
					zfree(feedback);
					break;

				default:
					rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
					             "unknown state value (%d), should not happen",
					             context->state);
					break;
			}
			break;

		case ROHC_STATUS_SEGMENT:
			assert(0); /* should never happen */
			break;

		case ROHC_STATUS_ERROR:
			/* TODO: handle this case */
			break;
	}

skip:
	;
}


/**
 * @brief Send feedback depending on the mode: Unidirectional, Optimistic or Reliable.
 *
 * @param decomp       The ROHC decompressor
 * @param rohc_status  The type of feedback to send:
 *                      \li ROHC_STATUS_OK = OK (ack),
 *                      \li ROHC_STATUS_NO_CONTEXT = ContextInvalid (S-nack),
 *                      \li ROHC_STATUS_MALFORMED = PackageFailed (Nack)
 * @param cid          The Context ID (CID) to which the feedback is related
 * @param cid_type     The type of CID used for the feedback
 * @param mode         The mode in which the ROHC decompressor operates:
 *                     ROHC_U_MODE, ROHC_O_MODE or ROHC_R_MODE
 * @param context      The context to which the feedback is related
 * @param[out] feedback_send  The feedback to be transmitted to the remote
 *                            compressor through the feedback channel:
 *                            \li If NULL, the decompression won't generate
 *                                feedback information for its compressor
 *                            \li If not NULL, may store the generated
 *                                feedback at the given address
 */
static void d_operation_mode_feedback(struct rohc_decomp *decomp,
                                      const rohc_status_t rohc_status,
                                      const uint16_t cid,
                                      const rohc_cid_type_t cid_type,
                                      int mode,
                                      struct rohc_decomp_ctxt *context,
                                      struct rohc_buf *const feedback_send)
{
	switch(mode)
	{
		case ROHC_U_MODE:
			/* no feedback needed */
			//break;

		case ROHC_O_MODE:
			d_optimistic_feedback(decomp, rohc_status, cid, cid_type, context,
			                      feedback_send);
			break;

		case ROHC_R_MODE:
			/* TODO: send feedback (not implemented) */
			break;
	}
}


/**
 * @brief Reset all the statistics of the given ROHC decompressor
 *
 * @param decomp The ROHC decompressor
 */
static void rohc_decomp_reset_stats(struct rohc_decomp *const decomp)
{
	assert(decomp != NULL);
	decomp->stats.received = 0;
	decomp->stats.failed_crc = 0;
	decomp->stats.failed_no_context = 0;
	decomp->stats.failed_decomp = 0;
	decomp->stats.total_compressed_size = 0;
	decomp->stats.total_uncompressed_size = 0;
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
		default:
			assert(0);
#if defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
			return "no description";
#endif
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
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		info->context_mode = decomp->last_context->mode;
		info->context_state = decomp->last_context->state;
		info->profile_id = decomp->last_context->profile->id;
		info->nr_lost_packets = decomp->last_context->nr_lost_packets;
		info->nr_misordered_packets = decomp->last_context->nr_misordered_packets;
		info->is_duplicated = decomp->last_context->is_duplicated;

		/* new fields added by minor versions */
		switch(info->version_minor)
		{
			case 0:
				/* nothing to add */
				break;
			case 1:
				/* new fields in 0.1 */
				info->corrected_crc_failures =
					decomp->last_context->corrected_crc_failures;
				info->corrected_sn_wraparounds =
					decomp->last_context->corrected_sn_wraparounds;
				info->corrected_wrong_sn_updates =
					decomp->last_context->corrected_wrong_sn_updates;
				info->packet_type = decomp->last_context->packet_type;
				break;
			default:
				rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
				           "unsupported minor version (%u) of the structure for "
				           "last packet information", info->version_minor);
				goto error;
		}
	}
	else
	{
		rohc_error(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for last "
		           "packet information", info->version_major);
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
		if(info->version_minor > 0)
		{
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
		ROHC_DECOMP_FEATURE_CRC_REPAIR | \
		ROHC_DECOMP_FEATURE_COMPAT_1_6_x;

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
	size_t i;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		if(rohc_decomp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == D_NUM_PROFILES)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC decompression profile (ID = %d)", profile);
		goto error;
	}

	/* return profile status */
	return decomp->enabled_profiles[i];

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
	size_t i;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		if(rohc_decomp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == D_NUM_PROFILES)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC decompression profile (ID = %d)", profile);
		goto error;
	}

	/* mark the profile as enabled */
	decomp->enabled_profiles[i] = true;
	rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	          "ROHC decompression profile (ID = %d) enabled", profile);

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
	size_t i;

	if(decomp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		if(rohc_decomp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == D_NUM_PROFILES)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC decompression profile (ID = %d)", profile);
		goto error;
	}

	/* mark the profile as disabled */
	decomp->enabled_profiles[i] = false;
	rohc_info(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	          "ROHC decompression profile (ID = %d) disabled", profile);

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
	decomp->trace_callback2 = callback;
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
static const struct rohc_decomp_profile *
	find_profile(const struct rohc_decomp *const decomp,
	             const rohc_profile_t profile_id)
{
	size_t i;

	assert(decomp != NULL);

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
 * @param decomp  The ROHC decompressor
 * @param packet  The ROHC packet to extract CID from
 * @param len     The size of the ROHC packet
 * @param ddata   IN/OUT: decompression-related data (e.g. the context)
 * @return        true in case of success, false in case of failure
 */
static bool rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                   const unsigned char *packet,
                                   unsigned int len,
                                   struct d_decode_data *ddata)
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
		ddata->large_cid_size = 0;

		/* if add-CID is present, extract the CID value */
		if(rohc_add_cid_is_present(packet))
		{
			ddata->addcidUsed = 1;
			ddata->cid = rohc_add_cid_decode(packet);
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "add-CID present (0x%x) contains CID = %zu",
			           packet[0], ddata->cid);
		}
		else
		{
			/* no add-CID, CID defaults to 0 */
			ddata->addcidUsed = 0;
			ddata->cid = 0;
			rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			           "no add-CID found, CID defaults to 0");
		}
	}
	else if(decomp->medium.cid_type == ROHC_LARGE_CID)
	{
		uint32_t large_cid;
		size_t large_cid_bits_nr;

		/* large CID */
		ddata->addcidUsed = 0;

		/* skip the first byte of packet located just before the large CID */
		packet++;
		len--;

		/* decode SDVL-encoded large CID
		 * (only 1-byte and 2-byte SDVL fields are allowed) */
		ddata->large_cid_size = sdvl_decode(packet, len,
		                                    &large_cid, &large_cid_bits_nr);
		if(ddata->large_cid_size != 1 && ddata->large_cid_size != 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to decode SDVL-encoded large CID field");
			goto error;
		}
		ddata->cid = large_cid;
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "%u-byte large CID = %zu", ddata->large_cid_size, ddata->cid);
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
	size_t feedbacks_len = 0;

	/* no feedback parsed for the moment */
	assert(feedbacks == NULL || rohc_buf_is_empty(*feedbacks));

	/* parse as much feedback data as possible */
	while(rohc_data->len > 0 &&
	      rohc_packet_is_feedback(rohc_buf_byte(*rohc_data)))
	{
		feedbacks_nr++;

		/* decode one feedback packet */
		rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		           "parse feedback item #%zu at offset %zu in ROHC packet",
		           feedbacks_nr, feedbacks_len);
		if(!rohc_decomp_parse_feedback(decomp, rohc_data, feedbacks))
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
			             "failed to parse feedback item #%zu at offset %zu in "
			             "ROHC packet", feedbacks_nr, feedbacks_len);
			goto error;
		}

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
 * @param decomp         The ROHC decompressor
 * @param rohc_data      The ROHC data to parse for one feedback item
 * @param[out] feedback  The retrieved feedback (header and data included),
 *                       may be NULL if one don't want to retrieve the
 *                       feedback item
 * @return               true if feedback parsing was successful,
 *                       false if feedback is malformed
 */
static bool rohc_decomp_parse_feedback(struct rohc_decomp *const decomp,
                                       struct rohc_buf *const rohc_data,
                                       struct rohc_buf *const feedback)
{
	size_t feedback_hdr_len;
	size_t feedback_data_len;
	size_t feedback_len;
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
	feedback_len = feedback_hdr_len + feedback_data_len;
	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "feedback found (header = %zu bytes, data = %zu bytes)",
	           feedback_hdr_len, feedback_data_len);

	/* reject feedback item if it doesn't fit in the available ROHC data */
	if(feedback_len > rohc_data->len)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "the %zu-byte feedback is too large for the %zu-byte "
		             "remaining ROHC data", feedback_len, rohc_data->len);
		goto error;
	}

	/* copy the feedback item in order to return it user if he/she asked for */
	if(feedback != NULL)
	{
		rohc_buf_append(feedback, rohc_buf_data(*rohc_data), feedback_len);
	}

	/* skip the feedback item in the ROHC packet */
	rohc_buf_pull(rohc_data, feedback_len);

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
 * @param max_cid  The MAX_CID value to used (may be different from the one
 *                 in decompressor if the MAX_CID value is being changed)
 * @return         true if the contexts were created, false otherwise
 */
static bool rohc_decomp_create_contexts(struct rohc_decomp *const decomp,
                                        const rohc_cid_t max_cid)
{
	struct rohc_decomp_ctxt **new_contexts;

	assert(decomp != NULL);
	assert(max_cid <= ROHC_LARGE_CID_MAX);

	/* allocate memory for the new context array */
	new_contexts = calloc(max_cid + 1, sizeof(struct rohc_decomp_ctxt *));
	if(new_contexts == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
		             "cannot allocate memory for the contexts");
		return false;
	}

	/* move as many existing contexts as possible if needed */
	if(decomp->contexts != NULL)
	{
		size_t i;

		/* move existing contexts in range [0, new MAX_CID] */
		memcpy(new_contexts, decomp->contexts,
		       (rohc_min(decomp->medium.max_cid, max_cid) + 1) *
		       sizeof(struct rohc_decomp_ctxt *));

		/* free existing contexts in range ]new MAX_CID, old MAX_CID] */
		for(i = max_cid + 1; i <= decomp->medium.max_cid; i++)
		{
			if(decomp->contexts[i] != NULL)
			{
				context_free(decomp->contexts[i]);
			}
		}
		assert(decomp->num_contexts_used <= (max_cid + 1));

		zfree(decomp->contexts);
	}
	decomp->contexts = new_contexts;

	rohc_debug(decomp, ROHC_TRACE_DECOMP, ROHC_PROFILE_GENERAL,
	           "room for %zu decompression contexts created", max_cid + 1);

	return true;
}

