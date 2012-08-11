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
 * @file rohc_decomp.c
 * @brief ROHC decompression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 */

/**
 * @defgroup rohc_decomp ROHC decompression API
 */

#include "rohc_decomp.h"
#include "rohc_traces.h"
#include "rohc_time.h"
#include "rohc_utils.h"
#include "rohc_debug.h"
#include "feedback.h"
#include "wlsb.h"
#include "decode.h"
#include "crc.h"

#include <assert.h>


extern struct d_profile d_uncomp_profile,
                        d_udp_profile,
                        d_ip_profile,
                        d_udplite_profile,
                        d_rtp_profile;


/**
 * @brief The decompression parts of the ROHC profiles.
 */
static struct d_profile *d_profiles[D_NUM_PROFILES] =
{
	&d_uncomp_profile,
	&d_udp_profile,
	&d_ip_profile,
	&d_udplite_profile,
	&d_rtp_profile,
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
	uint16_t cid;
	/// Whether the ROHC packet uses add-CID or not
	int addcidUsed;
	/// The size (in bytes) of the large CID field
	unsigned int large_cid_size;
	/// The context to which the packet is related
	struct d_context *active;
};


/*
 * Prototypes of private functions
 */

static bool rohc_decomp_create_contexts(struct rohc_decomp *const decomp,
                                        const size_t max_cid);

int d_decode_header(struct rohc_decomp *decomp,
                    unsigned char *ibuf,
                    int isize,
                    unsigned char *obuf,
                    int osize,
                    struct d_decode_data *ddata);

static struct d_profile * find_profile(int id);

static int rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                  unsigned char *packet,
                                  unsigned int len,
                                  struct d_decode_data *ddata);

/* feedback-related functions */
static int d_decode_feedback_first(struct rohc_decomp *decomp,
                                   unsigned char *packet,
                                   unsigned int size,
                                   unsigned int *parsed_size);
static int d_decode_feedback(struct rohc_decomp *decomp,
                             unsigned char *packet,
                             unsigned int len,
                             unsigned int *feedback_size);
void d_operation_mode_feedback(struct rohc_decomp *decomp,
                               int rohc_status,
                               const uint16_t cid,
                               int addcidUsed,
                               const rohc_cid_type_t cid_type,
                               int mode,
                               struct d_context *context);


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
struct d_context * find_context(struct rohc_decomp *decomp, int cid)
{
	/* CID must be valid wrt MAX_CID */
	assert(cid >= 0 && cid <= decomp->medium.max_cid);
	return decomp->contexts[cid];
}


/**
 * @brief Create one new decompression context with profile specific data.
 *
 * @param decomp   The ROHC decompressor
 * @param with_cid The CID of the new context (not implemented)
 * @param profile  The profile to be assigned with the new context
 * @return         The new context if successful, NULL otherwise
 */
struct d_context * context_create(struct rohc_decomp *decomp, int with_cid,
                                  struct d_profile *profile)
{
	struct d_context *context;

	/* allocate memory for the decompression context */
	context = (struct d_context *) malloc(sizeof(struct d_context));
	if(context == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the context\n");
		goto error;
	}

	/* associate the decompression profile with the context */
	context->profile = profile;

	/* initialize mode and state */
	context->mode = U_MODE;
	context->state = NO_CONTEXT;
	context->curval = 0;

	/* profile-specific data */
	context->specific = profile->allocate_decode_data();
	if(context->specific == NULL)
	{
		rohc_debugf(0, "cannot allocate profile-specific data\n");
		goto destroy_context;
	}

	/* init some statistics */
	context->num_recv_packets = 0;
	context->total_uncompressed_size = 0;
	context->total_compressed_size = 0;
	context->header_uncompressed_size = 0;
	context->header_compressed_size = 0;
	context->num_recv_ir = 0;
	context->num_recv_ir_dyn = 0;
	context->num_sent_feedbacks = 0;
	context->num_decomp_failures = 0;
	context->num_decomp_repairs = 0;

	context->first_used = get_milliseconds();
	context->latest_used = get_milliseconds();

	/* create 4 W-LSB windows */
	context->total_16_uncompressed = c_create_wlsb(32, 16, ROHC_LSB_SHIFT_STATS);
	if(context->total_16_uncompressed == NULL)
	{
		rohc_debugf(0, "cannot create the total_16_uncompressed W-LSB window\n");
		goto destroy_profile_data;
	}

	context->total_16_compressed = c_create_wlsb(32, 16, ROHC_LSB_SHIFT_STATS);
	if(context->total_16_compressed == NULL)
	{
		rohc_debugf(0, "cannot create the total_16_compressed W-LSB window\n");
		goto destroy_window_tu;
	}

	context->header_16_uncompressed = c_create_wlsb(32, 16, ROHC_LSB_SHIFT_STATS);
	if(context->header_16_uncompressed == NULL)
	{
		rohc_debugf(0, "cannot create the header_16_uncompressed W-LSB window\n");
		goto destroy_window_tc;
	}

	context->header_16_compressed = c_create_wlsb(32, 16, ROHC_LSB_SHIFT_STATS);
	if(context->header_16_compressed == NULL)
	{
		rohc_debugf(0, "cannot create the header_16_compressed W-LSB window\n");
		goto destroy_window_hu;
	}

	return context;

destroy_window_hu:
	c_destroy_wlsb(context->header_16_uncompressed);
destroy_window_tc:
	c_destroy_wlsb(context->total_16_compressed);
destroy_window_tu:
	c_destroy_wlsb(context->total_16_uncompressed);
destroy_profile_data:
	profile->free_decode_data(context->specific);
destroy_context:
	zfree(context);
error:
	return NULL;
}


/**
 * @brief Destroy one decompression context and the profile specific data associated
 *        with it.
 *
 * @param context  The context to destroy
 */
void context_free(struct d_context *context)
{
	if(context != NULL)
	{
		/* destroy the profile-specific data */
		context->profile->free_decode_data(context->specific);

		/* destroy the W-LSb windows */
		c_destroy_wlsb(context->total_16_uncompressed);
		c_destroy_wlsb(context->total_16_compressed);
		c_destroy_wlsb(context->header_16_uncompressed);
		c_destroy_wlsb(context->header_16_compressed);

		/* destroy the context itself */
		zfree(context);
	}
}


/**
 * @brief Create one ROHC decompressor.
 *
 * @param compressor  \li The ROHC compressor to associate the decompressor with
 *                    \li NULL to disable feedback and force undirectional mode
 * @return            The newly-created decompressor if successful,
 *                    NULL otherwise
 *
 * @ingroup rohc_decomp
 */
struct rohc_decomp * rohc_alloc_decompressor(struct rohc_comp *compressor)
{
	struct rohc_decomp *decomp;
	bool is_fine;

	/* allocate memory for the decompressor */
	decomp = (struct rohc_decomp *) malloc(sizeof(struct rohc_decomp));
	if(decomp == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the decompressor\n");
		goto error;
	}

	/* init decompressor medium */
	decomp->medium.cid_type = ROHC_SMALL_CID;
	decomp->medium.max_cid = ROHC_SMALL_CID_MAX;

	/* associate the compressor and the decompressor */
	decomp->compressor = compressor;

	/* initialize the array of decompression contexts to its minimal value */
	decomp->contexts = NULL;
	is_fine = rohc_decomp_create_contexts(decomp, decomp->medium.max_cid);
	if(!is_fine)
	{
		rohc_debugf(0, "failed to allocate %d decompression contexts\n",
		            decomp->medium.max_cid + 1);
		goto destroy_decomp;
	}
	decomp->last_context = NULL;

	decomp->maxval = 300;
	decomp->errval = 100;
	decomp->okval = 12;
	decomp->curval = 0;

	/* init the tables for fast CRC computation */
	is_fine = rohc_crc_init_table(decomp->crc_table_2, ROHC_CRC_TYPE_2);
	if(is_fine != true)
	{
		goto destroy_contexts;
	}
	is_fine = rohc_crc_init_table(decomp->crc_table_3, ROHC_CRC_TYPE_3);
	if(is_fine != true)
	{
		goto destroy_contexts;
	}
	is_fine = rohc_crc_init_table(decomp->crc_table_6, ROHC_CRC_TYPE_6);
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
	clear_statistics(decomp);

	return decomp;

destroy_contexts:
	zfree(decomp->contexts);
destroy_decomp:
	zfree(decomp);
error:
	return NULL;
}


/**
 * @brief Destroy one ROHC decompressor.
 *
 * @param decomp  The decompressor to destroy
 *
 * @ingroup rohc_decomp
 */
void rohc_free_decompressor(struct rohc_decomp *decomp)
{
	int i;

	if(decomp == NULL)
	{
		rohc_debugf(0, "invalid decompressor\n");
		return;
	}

	/* destroy all the contexts owned by the decompressor */
	assert(decomp->contexts != NULL);
	for(i = 0; i <= decomp->medium.max_cid; i++)
	{
		if(decomp->contexts[i] != NULL)
		{
			context_free(decomp->contexts[i]);
		}
	}
	zfree(decomp->contexts);

	/* destroy the decompressor itself */
	zfree(decomp);
}


/**
 * @brief Decompress a ROHC packet.
 *
 * @param decomp The ROHC decompressor
 * @param ibuf   The ROHC packet to decompress
 * @param isize  The size of the ROHC packet
 * @param obuf   The buffer where to store the decompressed packet
 * @param osize  The size of the buffer for the decompressed packet
 * @return       The size of the decompressed packet
 *
 * @ingroup rohc_decomp
 */
int rohc_decompress(struct rohc_decomp *decomp,
                    unsigned char *ibuf, int isize,
                    unsigned char *obuf, int osize)
{
	int ret;
	struct d_decode_data ddata = { 0, 0, 0, NULL };

	decomp->stats.received++;
	rohc_debugf(1, "decompress the %d-byte packet #%u\n",
	            isize, decomp->stats.received);

	ret = d_decode_header(decomp, ibuf, isize, obuf, osize, &ddata);
	if(ddata.active == NULL &&
	   (ret == ROHC_ERROR_PACKET_FAILED ||
	    ret == ROHC_ERROR ||
	    ret == ROHC_ERROR_CRC))
	{
		ret = ROHC_ERROR_NO_CONTEXT;
	}

	if(ddata.active != NULL)
	{
		ddata.active->num_recv_packets++;
		rohc_debugf(2, "state in decompressor = %d\n", ddata.active->state);
	}

	if(ret >= 0)
	{
		/* ROHC packet was successfully decompressed, update statistics */
		assert(ddata.active != NULL);
		ddata.active->total_uncompressed_size += ret;
		ddata.active->total_compressed_size += isize;
		c_add_wlsb(ddata.active->total_16_uncompressed, 0, ret);
		c_add_wlsb(ddata.active->total_16_compressed, 0, isize);
	}
	else if(ddata.active)
	{
		/* ROHC packet failed to be decompressed, but a decompression context
		 * was identified, so update statistics */
		ddata.active->num_decomp_failures++;
	}

	/* update statistics and send feedback if needed */
	switch(ret)
	{
		case ROHC_ERROR_PACKET_FAILED:
		case ROHC_ERROR:
			decomp->stats.failed_decomp++;
			ddata.active->curval += decomp->errval;
			if(ddata.active->curval >= decomp->maxval)
			{
				ddata.active->curval = 0;
				d_operation_mode_feedback(decomp, ROHC_ERROR_PACKET_FAILED,
				                          ddata.cid, ddata.addcidUsed,
				                          decomp->medium.cid_type,
				                          ddata.active->mode,
				                          ddata.active);
			}
			break;

		case ROHC_ERROR_NO_CONTEXT:
			decomp->stats.failed_no_context++;
			decomp->curval += decomp->errval;
			if(decomp->curval >= decomp->maxval)
			{
				decomp->curval = 0;
				d_operation_mode_feedback(decomp, ROHC_ERROR_NO_CONTEXT, ddata.cid,
				                          ddata.addcidUsed,
				                          decomp->medium.cid_type,
				                          O_MODE, NULL);
			}
			break;

		case ROHC_FEEDBACK_ONLY:
			decomp->stats.feedbacks++;
			break;

		case ROHC_ERROR_CRC:
			decomp->stats.failed_crc++;
			ddata.active->curval += decomp->errval;
			rohc_debugf(2, "feedback curr %d\n", ddata.active->curval);
			rohc_debugf(2, "feedback max %d\n", decomp->maxval);
			if(ddata.active->curval >= decomp->maxval)
			{
				ddata.active->curval = 0;
				d_operation_mode_feedback(decomp, ROHC_ERROR_CRC, ddata.cid,
				                          ddata.addcidUsed,
				                          decomp->medium.cid_type,
				                          ddata.active->mode, ddata.active);
			}
			break;

		default: /* ROHC_OK */
			decomp->curval -= decomp->okval; /* framework (S-NACK) */
			ddata.active->curval -= decomp->okval; /* context (NACK) */
			rohc_debugf(2, "feedback curr %d\n", ddata.active->curval);
			if(decomp->curval < 0)
			{
				decomp->curval = 0;
			}

			if(ddata.active->curval < 0)
			{
				ddata.active->curval = 0;
			}

			rohc_debugf(2, "feedback curr %d\n", ddata.active->curval);
			if(decomp->compressor != NULL && ddata.active->mode == U_MODE)
			{
				/* switch active context to O-mode */
				ddata.active->mode = O_MODE;
				d_operation_mode_feedback(decomp, ROHC_OK, ddata.cid,
				                          ddata.addcidUsed,
				                          decomp->medium.cid_type,
				                          ddata.active->mode,
				                          ddata.active);
			}
			break;
	}

	return ret;
}


/**
 * @brief Decompress both large and small CID packets.
 *
 * @deprecated do not use this function anymore,
 *             use rohc_decomp_set_cid_type() and rohc_decomp_set_max_cid()
 *             instead
 *
 * @param decomp The ROHC decompressor
 * @param ibuf   The ROHC packet to decompress
 * @param isize  The size of the ROHC packet
 * @param obuf   The buffer where to store the decompressed packet
 * @param osize  The size of the buffer for the decompressed packet
 * @param large  Whether the packet use large CID or not
 * @return       The size of the decompressed packet
 *
 * @ingroup rohc_decomp
 */
int rohc_decompress_both(struct rohc_decomp *decomp,
                         unsigned char *ibuf, int isize,
                         unsigned char *obuf, int osize,
                         int large)
{
	bool is_ok;

	/* change CID type on the fly */
	is_ok = rohc_decomp_set_cid_type(decomp,
	                                 large ? ROHC_LARGE_CID : ROHC_SMALL_CID);
	if(!is_ok)
	{
		return ROHC_ERROR;
	}

	/* decompress the packet with the new CID type */
	return rohc_decompress(decomp, ibuf, isize, obuf, osize);
}


/**
 * @brief Decompress the compressed headers.
 *
 * @param decomp The ROHC decompressor
 * @param ibuf   The ROHC packet to decompress
 * @param isize  The size of the ROHC packet
 * @param obuf   The buffer where to store the decompressed packet
 * @param osize  The size of the buffer for the decompressed packet
 * @param ddata  Decompression-related data (e.g. the context)
 * @return       The size of the decompressed packet
 */
int d_decode_header(struct rohc_decomp *decomp,
                    unsigned char *ibuf, int isize,
                    unsigned char *obuf, int osize,
                    struct d_decode_data *ddata)
{
	int size, casenew = 0;
	struct d_profile *profile;
	unsigned char *walk = ibuf;
	unsigned int feedback_size;
	int status;

	if(isize < 1)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d, at least 1 byte "
		            "required)\n", isize);
		return ROHC_ERROR_NO_CONTEXT;
	}

	/* decode feedback if present */
	status = d_decode_feedback_first(decomp, walk, isize, &feedback_size);
	if(status != ROHC_OK)
	{
		rohc_debugf(0, "failed to decode feedback at the beginning "
		            "of the packet\n");
		return status;
	}
	assert(feedback_size <= isize);
	walk += feedback_size;
	isize -= feedback_size;

	/* is there some data after feedback? */
	if(isize <= 0)
	{
		rohc_debugf(1, "feedback-only packet, stop decompression\n");
		return ROHC_FEEDBACK_ONLY;
	}

	/* decode small or large CID */
	status = rohc_decomp_decode_cid(decomp, walk, isize, ddata);
	if(status != ROHC_OK)
	{
		rohc_debugf(0, "failed to decode small or large CID in packet\n");
		return status;
	}

	/* check whether the decoded CID is allowed by the decompressor */
	if(ddata->cid > decomp->medium.max_cid)
	{
		rohc_debugf(0, "unexpected CID %d received: MAX_CID was set to %d\n",
		            ddata->cid, decomp->medium.max_cid);
		return ROHC_ERROR_NO_CONTEXT;
	}

	/* skip add-CID if present */
	if(ddata->addcidUsed)
	{
		walk++;
		isize--;
	}

	/* is the ROHC packet an IR packet? */
	if(d_is_ir(walk, isize))
	{
		uint8_t profile_id;

		rohc_debugf(1, "ROHC packet is an IR packet\n");

		/* find the profile specified in the ROHC packet (no length check here
		 * since the length of the ROHC data was already checked in function
		 * rohc_decomp_decode_cid) */
		profile_id = walk[1 + ddata->large_cid_size];
		profile = find_profile(profile_id);
		if(profile == NULL)
		{
			rohc_debugf(0, "failed to find profile identified by 0x%04x\n",
			            profile_id);
			return ROHC_ERROR_NO_CONTEXT;
		}
		rohc_debugf(1, "profile 0x%04x found in IR packet\n", profile_id);

		if(decomp->contexts[ddata->cid] != NULL &&
		   decomp->contexts[ddata->cid]->profile == profile)
		{
			/* the decompression context associated with the CID already exists
			 * and the context profile and the packet profile match. */
			rohc_debugf(2, "context with CID %d already exists and matches profile "
			            "0x%04x found in IR packet\n", ddata->cid, profile_id);
			ddata->active = decomp->contexts[ddata->cid];
			decomp->contexts[ddata->cid] = NULL;
		}
		else
		{
			/* the decompression context does not exist or the profiles do not match,
			 * create a new context */
			rohc_debugf(2, "context with CID %d either does not already exist or "
			            "does not match profile 0x%04x found in IR packet\n",
			            ddata->cid, profile_id);
			casenew = 1;
			ddata->active = context_create(decomp, ddata->cid, profile);
			if(!ddata->active)
			{
				rohc_debugf(0, "failed to create a new context with CID %d and "
				            "profile 0x%04x\n", ddata->cid, profile_id);
				return ROHC_ERROR_NO_CONTEXT;
			}
		}

		decomp->last_context = ddata->active;
		ddata->active->num_recv_ir++;

		/* decode the IR packet thanks to the profile-specific routines */
		size = ddata->active->profile->decode_ir(decomp, ddata->active,
		                                         walk, isize,
		                                         ddata->large_cid_size,
		                                         ddata->addcidUsed,
		                                         obuf);
		if(size > 0)
		{
			/* the IR decompression was successful,
			 * replace the existing context with the new one */
			rohc_debugf(2, "%d bytes of payload copied to uncompressed packet\n", size);
			context_free(decomp->contexts[ddata->cid]);
			decomp->contexts[ddata->cid] = ddata->active;
			return size;
		}

		/* the IR decompression failed, free ressources if necessary */
		rohc_debugf(0, "failed to decompress IR packet (code = %d)\n", size);
		if(casenew)
		{
			context_free(ddata->active);
		}
		else
		{
			decomp->contexts[ddata->cid] = ddata->active;
		}

		return size;
	}
	else /* the ROHC packet is not an IR packet */
	{
		rohc_debugf(1, "ROHC packet is not an IR packet\n");

		/* find the context associated with the CID */
		ddata->active = find_context(decomp, ddata->cid);

		/* is the context valid? */
		if(!ddata->active || !ddata->active->profile)
		{
			rohc_debugf(0, "context with CID %d either does not exist or no profile "
			            "is associated with the context\n", ddata->cid);
			return ROHC_ERROR_NO_CONTEXT;
		}
		else
		{
			/* context is valid */
			rohc_debugf(1, "context with CID %d found\n", ddata->cid);
			ddata->active->latest_used = get_milliseconds();
			decomp->last_context = ddata->active;

			/* is the ROHC packet an IR-DYN packet? */
			if(d_is_irdyn(walk, isize))
			{
				rohc_debugf(1, "ROHC packet is an IR-DYN packet\n");
				ddata->active->num_recv_ir_dyn++;

				/* find the profile specified in the ROHC packet (no length check
				 * here since the length of the ROHC data was already checked in
				 * function rohc_decomp_decode_cid) */
				profile = find_profile(walk[ddata->large_cid_size + 1]);

				/* if IR-DYN changes profile, make the decompressor
				 * transit to the NO_CONTEXT state */
				if(profile != ddata->active->profile)
				{
					decomp->curval = decomp->maxval;
					rohc_debugf(2, "IR-DYN changed profile, sending S-NACK\n");
					return ROHC_ERROR_NO_CONTEXT;
				}
			}

			/* decode the IR-DYN or UO* packet thanks to the
			 * profile-specific routines */
			return ddata->active->profile->decode(decomp, ddata->active,
			                                      walk, isize,
		                                         ddata->addcidUsed,
		                                         ddata->large_cid_size,
		                                         obuf);
		}

	} /* end of 'the ROHC packet is not an IR packet' */

	return ROHC_ERROR_NO_CONTEXT;
}


/**
 * @brief Send feedback in Optimistic Mode.
 *
 * @param decomp       The ROHC decompressor
 * @param rohc_status  The type of feedback to send: 0 = OK (ack),
 *                     -1 = ContextInvalid (S-nack), -2 = PackageFailed (Nack)
 * @param cid          The Context ID (CID) to which the feedback is related
 * @param addcidUsed   Whether add-CID is used or not
 * @param cid_type     The type of CID used for the feedback
 * @param context      The context to which the feedback is related
 */
void d_optimistic_feedback(struct rohc_decomp *decomp,
                           int rohc_status,
                           const uint16_t cid,
                           int addcidUsed,
                           const rohc_cid_type_t cid_type,
                           struct d_context *context)
{
	struct d_feedback sfeedback;
	unsigned char *feedback;
	int feedbacksize;
	int ret;

	assert(cid >= 0);

	/* check associated compressor availability */
	if(decomp->compressor == NULL)
	{
		rohc_debugf(1, "no associated compressor, do not sent feedback\n");

		/* only change state if needed */
		if(rohc_status == ROHC_ERROR_PACKET_FAILED ||
		   rohc_status == ROHC_ERROR_CRC)
		{
			if(context->state == STATIC_CONTEXT)
			{
				context->state = NO_CONTEXT;
			}
			else if(context->state == FULL_CONTEXT)
			{
				context->state = STATIC_CONTEXT;
			}
		}

		goto skip;
	}

	/* check CID wrt CID type */
	if(decomp->medium.cid_type == ROHC_SMALL_CID && cid > ROHC_SMALL_CID_MAX)
	{
		rohc_debugf(0, "unexpected small CID %d: not in range [0, %d]\n", cid,
		            ROHC_SMALL_CID_MAX);
		return;
	}
	else if(cid > ROHC_LARGE_CID_MAX) /* large CID */
	{
		rohc_debugf(0, "unexpected large CID %d: not in range [0, %d]\n", cid,
		            ROHC_LARGE_CID_MAX);
		return;
	}

	/* check CID wrt MAX_CID if context was found */
	if(rohc_status != ROHC_ERROR_NO_CONTEXT)
	{
		if(cid < 0 || cid > decomp->medium.max_cid)
		{
			rohc_debugf(0, "unexpected CID %d: not in range [0, %d]\n", cid,
			            decomp->medium.max_cid);
			return;
		}
	}

	switch(rohc_status)
	{
		case ROHC_OK:
			/* create an ACK feedback */
			rohc_debugf(1, "send an ACK feedback\n");
			ret = f_feedback2(ACKTYPE_ACK, context->mode,
			                  context->profile->get_sn(context), &sfeedback);
			if(ret != ROHC_OK)
			{
				rohc_debugf(0, "failed to build the ACK feedback\n");
				return;
			}
			feedback = f_wrap_feedback(&sfeedback, cid, cid_type,
			                           WITH_CRC, decomp->crc_table_8,
			                           &feedbacksize);
			if(feedback == NULL)
			{
				rohc_debugf(0, "failed to wrap the ACK feedback\n");
				return;
			}

			/* send the feedback via the compressor associated
			 * with the decompressor */
			context->num_sent_feedbacks++;
			c_piggyback_feedback(decomp->compressor, feedback, feedbacksize);

			/* destroy the feedback */
			zfree(feedback);
			break;

		case ROHC_ERROR_NO_CONTEXT:
			/* create a STATIC NACK feedback */
			rohc_debugf(1, "send a STATIC NACK feedback\n");
			ret = f_feedback2(ACKTYPE_STATIC_NACK, O_MODE, 0, &sfeedback);
			if(ret != ROHC_OK)
			{
				rohc_debugf(0, "failed to build the STATIC NACK feedback\n");
				return;
			}
			ret = f_add_option(&sfeedback, OPT_TYPE_SN_NOT_VALID, NULL, 0);
			if(ret != ROHC_OK)
			{
				rohc_debugf(0, "failed to add the SN-NOT-VALID option to the "
				            "STATIC NACK feedback\n");
				return;
			}
			feedback = f_wrap_feedback(&sfeedback, cid, cid_type,
			                           NO_CRC, NULL /* CRC table not required */,
			                           &feedbacksize);
			if(feedback == NULL)
			{
				rohc_debugf(0, "failed to wrap the STATIC NACK feedback\n");
				return;
			}

			/* send the feedback via the compressor associated
			 * with the decompressor */
			//context->num_sent_feedbacks++;
			c_piggyback_feedback(decomp->compressor, feedback, feedbacksize);

			/* destroy the feedback */
			zfree(feedback);
			break;

		case ROHC_ERROR_PACKET_FAILED:
		case ROHC_ERROR_CRC:
			context->num_sent_feedbacks++;
			switch(context->state)
			{
				case NO_CONTEXT:
					/* create a STATIC NACK feedback */
					rohc_debugf(1, "send a STATIC NACK feedback\n");
					ret = f_feedback2(ACKTYPE_STATIC_NACK, context->mode,
					                  context->profile->get_sn(context), &sfeedback);
					if(ret != ROHC_OK)
					{
						rohc_debugf(0, "failed to build the STATIC NACK feedback\n");
						return;
					}
					feedback = f_wrap_feedback(&sfeedback, cid, cid_type,
					                           WITH_CRC, decomp->crc_table_8,
					                           &feedbacksize);
					if(feedback == NULL)
					{
						rohc_debugf(0, "failed to create a STATIC NACK feedback\n");
						return;
					}

					/* send the feedback via the compressor associated
					 * with the decompressor */
					c_piggyback_feedback(decomp->compressor, feedback, feedbacksize);

					/* destroy the feedback */
					zfree(feedback);
					break;

				case STATIC_CONTEXT:
				case FULL_CONTEXT:
					/* create a NACK feedback */
					rohc_debugf(1, "send a NACK feedback\n");
					ret = f_feedback2(ACKTYPE_NACK, context->mode,
					                  context->profile->get_sn(context), &sfeedback);
					if(ret != ROHC_OK)
					{
						rohc_debugf(0, "failed to build the NACK feedback\n");
						return;
					}
					feedback = f_wrap_feedback(&sfeedback, cid, cid_type,
					                           WITH_CRC, decomp->crc_table_8,
					                           &feedbacksize);
					if(feedback == NULL)
					{
						rohc_debugf(0, "failed to create the NACK feedback\n");
						return;
					}

					/* send the feedback via the compressor associated
					 * with the decompressor */
					c_piggyback_feedback(decomp->compressor, feedback, feedbacksize);

					/* change state */
					if(context->state == STATIC_CONTEXT)
					{
						context->state = NO_CONTEXT;
					}
					if(context->state == FULL_CONTEXT)
					{
						context->state = STATIC_CONTEXT;
					}

					/* destroy the feedback */
					zfree(feedback);
					break;

				default:
					rohc_debugf(0, "should not arrive: unknown state value (%d)\n",
					            context->state);
					break;
			}
			break;
	}

skip:
	;
}


/**
 * @brief Send feedback depending on the mode: Unidirectional, Optimistic or Reliable.
 *
 * @param decomp       The ROHC decompressor
 * @param rohc_status  The type of feedback to send: 0 = OK (ack),
 *                     -1 = ContextInvalid (S-nack), -2 = PackageFailed (Nack)
 * @param cid          The Context ID (CID) to which the feedback is related
 * @param addcidUsed   Whether add-CID is used or not
 * @param cid_type     The type of CID used for the feedback
 * @param mode         The mode in which the ROHC decompressor operates:
 *                     U_MODE, O_MODE or R_MODE
 * @param context      The context to which the feedback is related
 */
void d_operation_mode_feedback(struct rohc_decomp *decomp,
                               int rohc_status,
                               const uint16_t cid,
                               int addcidUsed,
                               const rohc_cid_type_t cid_type,
                               int mode,
                               struct d_context *context)
{
	switch(mode)
	{
		case U_MODE:
			/* no feedback needed */
			//break;

		case O_MODE:
			d_optimistic_feedback(decomp, rohc_status, cid, addcidUsed,
			                      cid_type, context);
			break;

		case R_MODE:
			/* TODO: send feedback (not implemented) */
			break;
	}
}


/**
 * @brief Clear all the statistics.
 *
 * @param decomp The ROHC decompressor
 *
 * @ingroup rohc_decomp
 */
void clear_statistics(struct rohc_decomp *decomp)
{
	decomp->stats.received = 0;
	decomp->stats.failed_crc = 0;
	decomp->stats.failed_no_context = 0;
	decomp->stats.failed_decomp = 0;
	decomp->stats.feedbacks = 0;
}


/**
 * @brief Output the decompression statistics of one decompressor to a buffer.
 * The buffer must be large enough to store all the statistics.
 *
 * @param decomp The ROHC decompressor
 * @param indent The level of indentation to add during output
 * @param buffer The buffer where to outputs the statistics
 * @return       The length of data written to the buffer
 *
 * @ingroup rohc_decomp
 */
int rohc_d_statistics(struct rohc_decomp *decomp,
                      unsigned int indent,
                      char *buffer)
{
	struct d_profile *p;
	char *prefix;
	char *save;
	int i;

	/* compute the indent prefix */
	prefix = malloc((indent + 1) * sizeof(char));
	if(prefix == NULL)
	{
		return -1;
	}

	memset(prefix, '\t', indent);
	prefix[indent] = '\0';

	/* add the instance info */
	save = buffer;
	buffer += strlen(buffer);

	buffer += sprintf(buffer, "%s<instance>\n", prefix);

	/* add the profiles part */
	buffer += sprintf(buffer, "%s\t<profiles>\n", prefix);

	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		p = d_profiles[i];

		buffer += sprintf(buffer, "%s\t\t<profile ", prefix);
		buffer += sprintf(buffer, "id=\"%d\" ", p->id);
		buffer += sprintf(buffer, "name=\"%s\" ", p->description);
		buffer += sprintf(buffer, "active=\"yes\" />\n");
	}

	buffer += sprintf(buffer, "%s\t</profiles>\n", prefix);

	/* add the contexts part */
	i = 0;
	while(rohc_d_context(decomp, i, indent + 1, buffer) != -2)
	{
		i++;
	}
	buffer += strlen(buffer);

	buffer += sprintf(buffer, "%s</instance>\n\n", prefix);

	/* clean the indent prefix */
	zfree(prefix);

	return buffer - save;
}


/**
 * @brief Output the statistics of one decompression context to a buffer.
 *
 * The buffer must be large enough to store the statistics of one context.
 *
 * @param decomp The ROHC decompressor
 * @param index  The index of the decompression context in the contexts array
 * @param indent The level of indentation to add during output
 * @param buffer The buffer where to outputs the statistics
 * @return       The length of data written to the buffer
 */
int rohc_d_context(struct rohc_decomp *decomp,
                   int index,
                   unsigned int indent,
                   char *buffer)
{
	struct d_context *c;
	char *prefix;
	char *save;
	int v;

	if(index > decomp->medium.max_cid)
	{
		return -2;
	}

	c = decomp->contexts[index];
	if(!c || !c->profile)
	{
		return -1;
	}

	/* compute the line prefix */
	prefix = malloc((indent + 1) * sizeof(char));
	if(prefix == NULL)
	{
		return -1;
	}

	memset(prefix, '\t', indent);
	prefix[indent] = '\0';

	/* compute context info */
	save = buffer;
	buffer += strlen(buffer);

	buffer += sprintf(buffer, "\n%s<context type=\"decompressor\" cid=\"%d\">\n", prefix, index);
	buffer += sprintf(buffer, "%s\t<state>%s</state>\n", prefix,
	                  rohc_decomp_get_state_descr(c->state));
	buffer += sprintf(buffer, "%s\t<mode>%s</mode>\n", prefix,
	                  rohc_get_mode_descr(c->mode));
	buffer += sprintf(buffer, "%s\t<profile>%s</profile>\n", prefix, c->profile->description);

	/* compression ratio */
	buffer += sprintf(buffer, "%s\t<ratio>\n", prefix);

	if(c->total_uncompressed_size != 0)
	{
		v = (100 * c->total_compressed_size) / c->total_uncompressed_size;
	}
	else
	{
		v = 0;
	}
	buffer += sprintf(buffer, "%s\t\t<all_packets>%d%%</all_packets>\n", prefix, v);

	if(c->header_uncompressed_size != 0)
	{
		v = (100 * c->header_compressed_size) / c->header_uncompressed_size;
	}
	else
	{
		v = 0;
	}
	buffer += sprintf(buffer, "%s\t\t<all_headers>%d%%</all_headers>\n", prefix, v);

	v = c_sum_wlsb(c->total_16_uncompressed);
	if(v != 0)
	{
		v = (100 * c_sum_wlsb(c->total_16_compressed)) / v;
	}
	buffer += sprintf(buffer, "%s\t\t<last_16_packets>%d%%</last_16_packets>\n", prefix, v);

	v = c_sum_wlsb(c->header_16_uncompressed);
	if(v != 0)
	{
		v = (100 * c_sum_wlsb(c->header_16_compressed)) / v;
	}
	buffer += sprintf(buffer, "%s\t\t<last_16_headers>%d%%</last_16_headers>\n", prefix, v);

	buffer += sprintf(buffer, "%s\t</ratio>\n", prefix);

	/* compression mean */
	buffer += sprintf(buffer, "%s\t<mean>\n", prefix);

	v = c->total_compressed_size / c->num_recv_packets;
	buffer += sprintf(buffer, "%s\t\t<all_packets>%d</all_packets>\n", prefix, v);

	v = c->header_compressed_size / c->num_recv_packets;
	buffer += sprintf(buffer, "%s\t\t<all_headers>%d</all_headers>\n", prefix, v);

	v = c_mean_wlsb(c->total_16_compressed);
	buffer += sprintf(buffer, "%s\t\t<last_16_packets>%d</last_16_packets>\n", prefix, v);

	v = c_mean_wlsb(c->header_16_compressed);
	buffer += sprintf(buffer, "%s\t\t<last_16_headers>%d</last_16_headers>\n", prefix, v);

	buffer += sprintf(buffer, "%s\t</mean>\n", prefix);

	/* times */
	buffer += sprintf(buffer, "%s\t<activation_time>%u</activation_time>\n",
	                  prefix, (get_milliseconds() - c->first_used) / 1000 );
	buffer += sprintf(buffer, "%s\t<idle_time>%u</idle_time>\n",
	                  prefix, (get_milliseconds() - c->latest_used) / 1000);

	/* packets */
	buffer += sprintf(buffer, "%s\t<packets recv_total=\"%d\" ", prefix, c->num_recv_packets);
	buffer += sprintf(buffer, "recv_ir=\"%d\" ", c->num_recv_ir);
	buffer += sprintf(buffer, "recv_irdyn=\"%d\" ", c->num_recv_ir_dyn);
	buffer += sprintf(buffer, "sent_feedback=\"%d\" />\n", c->num_sent_feedbacks);

	/* failures/repairs */
	buffer += sprintf(buffer, "%s\t<decomp>\n", prefix);
	buffer += sprintf(buffer, "%s\t\t<failures>%d</failures>\n", prefix, c->num_decomp_failures);
	buffer += sprintf(buffer, "%s\t\t<repairs>%d</repairs>\n", prefix, c->num_decomp_repairs);
	buffer += sprintf(buffer, "%s\t</decomp>\n", prefix);

	buffer += sprintf(buffer, "%s</context>\n", prefix);

	free(prefix);
	return buffer - save;
}


/**
 * @brief Give a description for the given ROHC decompression context state
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
const char * rohc_decomp_get_state_descr(const rohc_d_state state)
{
	switch(state)
	{
		case NO_CONTEXT:
			return "NC";
		case STATIC_CONTEXT:
			return "SC";
		case FULL_CONTEXT:
			return "FC";
		default:
			return "no description";
	}
}


/**
 * @brief Create a feedback ACK packet telling the compressor to change state.
 *
 * @param decomp  The ROHC decompressor
 * @param context The decompression context
 *
 * @ingroup rohc_decomp
 */
void d_change_mode_feedback(struct rohc_decomp *decomp,
                            struct d_context *context)
{
	struct d_feedback sfeedback;
	int cid, feedbacksize;
	unsigned char *feedback;

	/* check associated compressor availability */
	if(decomp->compressor == NULL)
	{
		rohc_debugf(1, "no associated compressor, do not sent feedback\n");
		goto skip;
	}

	/* check context validity */
	for(cid = 0; cid <= decomp->medium.max_cid; cid++)
	{
		if(context == decomp->contexts[cid])
		{
			break;
		}
	}
	if(cid > decomp->medium.max_cid)
	{
		rohc_debugf(0, "failed to find CID for decompression context %p, "
		            "shall not happen\n", context);
		assert(0);
		return;
	}

	/* create an ACK feedback */
	f_feedback2(ACKTYPE_ACK, context->mode, context->profile->get_sn(context),
	            &sfeedback);
	feedback = f_wrap_feedback(&sfeedback, cid, decomp->medium.cid_type,
	                           WITH_CRC, decomp->crc_table_8,
	                           &feedbacksize);

	if(feedback == NULL)
	{
		rohc_debugf(0, "failed to create an ACK feedback\n");
		return;
	}

	/* deliver the feedback via the compressor associated
	 * with the decompressor */
	c_piggyback_feedback(decomp->compressor, feedback, feedbacksize);

	/* destroy the feedback */
	zfree(feedback);

skip:
	;
}


/**
 * @brief Update feedback interval by the user.
 *
 * @param decomp          The ROHC decompressor
 * @param feedback_maxval The feedback interval given by user
 *
 * @ingroup rohc_decomp
 */
void user_interactions(struct rohc_decomp *decomp, int feedback_maxval)
{
	decomp->maxval = feedback_maxval * 100;
}


/**
 * @brief Set the type of CID to use for the given decompressor
 *
 * @warning Changing the CID type while library is used may lead to
 *          destruction of decompression contexts
 *
 * @param decomp   The decompressor for which to set CID type
 * @param cid_type The new CID type among \ref ROHC_SMALL_CID or
 *                                 \ref ROHC_LARGE_CID
 * @return         true if the CID type was successfully set, false otherwise
 *
 * @ingroup rohc_decomp
 */

bool rohc_decomp_set_cid_type(struct rohc_decomp *const decomp,
                              const rohc_cid_type_t cid_type)
{
	rohc_cid_type_t old_cid_type;

	/* decompressor must be valid */
	if(decomp == NULL)
	{
		rohc_debugf(0, "decompressor is not valid\n");
		goto error;
	}

	/* new CID type value must be ROHC_SMALL_CID or ROHC_LARGE_CID */
	if(cid_type != ROHC_SMALL_CID && cid_type != ROHC_LARGE_CID)
	{
		rohc_debugf(0, "unexpected CID type: must be ROHC_SMALL_CID or "
		            "ROHC_LARGE_CID\n");
		goto error;
	}

	/* set the new CID type (make a backup to be able to revert) */
	if(cid_type != decomp->medium.cid_type)
	{
		old_cid_type = decomp->medium.cid_type;
		decomp->medium.cid_type = cid_type;

		/* reduce MAX_CID if required */
		if(!rohc_decomp_set_max_cid(decomp, decomp->medium.max_cid))
		{
			rohc_debugf(0, "failed to reduce MAX_CID after changing CID type\n");
			goto revert_cid_type;
		}

		rohc_debugf(1, "CID type is now set to %d\n", decomp->medium.cid_type);
	}

	return true;

revert_cid_type:
	decomp->medium.cid_type = old_cid_type;
error:
	return false;
}


/**
 * @brief Set the MAX_CID allowed for the given decompressor
 *
 * @warning Changing the MAX_CID value while library is used may lead to
 *          destruction of decompression contexts
 *
 * @param decomp   The decompressor for which to set MAX_CID
 * @param max_cid  The new MAX_CID value:
 *                  - in range [0, \ref ROHC_SMALL_CID_MAX] if CID type is
 *                    \ref ROHC_SMALL_CID
 *                  - in range [0, \ref ROHC_LARGE_CID_MAX] if CID type is
 *                    \ref ROHC_LARGE_CID
 * @return         true if the MAX_CID was successfully set, false otherwise
 *
 * @ingroup rohc_decomp
 */
bool rohc_decomp_set_max_cid(struct rohc_decomp *const decomp,
                             const size_t max_cid)
{
	int max_possible_cid;

	/* decompressor must be valid */
	if(decomp == NULL)
	{
		rohc_debugf(0, "decompressor is not valid\n");
		goto error;
	}

	/* what is the maximum possible MAX_CID value wrt CID type? */
	if(decomp->medium.cid_type == ROHC_SMALL_CID)
	{
		max_possible_cid = ROHC_SMALL_CID_MAX;
	}
	else
	{
		max_possible_cid = ROHC_LARGE_CID_MAX;
	}

	/* new MAX_CID value must not be in range [0, max_possible_cid] */
	if(max_cid > max_possible_cid)
	{
		rohc_debugf(0, "unexpected MAX_CID value: must be in range [0, %d]\n",
		            max_possible_cid);
		goto error;
	}

	/* set the new MAX_CID value (make a backup to be able to revert) */
	if(max_cid != decomp->medium.max_cid)
	{
		/* resize the array of decompression contexts */
		if(!rohc_decomp_create_contexts(decomp, max_cid))
		{
			rohc_debugf(0, "failed to re-create decompression contexts after "
			            "changing MAX_CID\n");
			goto error;
		}

		/* warn about destroyed contexts */
		if(max_cid < decomp->medium.max_cid)
		{
			rohc_debugf(1, "%u decompression contexts are about to be destroyed "
			            "due to MAX_CID change\n",
			            (unsigned int) (decomp->medium.max_cid - max_cid));
		}

		decomp->medium.max_cid = max_cid;
		rohc_debugf(1, "MAX_CID is now set to %d\n", decomp->medium.max_cid);
	}

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
 * @param id  The profile ID to search for
 * @return    The matching ROHC profile
 */
static struct d_profile * find_profile(int id)
{
	int i = 0;

	while(i < D_NUM_PROFILES && d_profiles[i]->id != id)
	{
		i++;
	}

	if(i >= D_NUM_PROFILES)
	{
		rohc_debugf(0, "no profile found for decompression\n");
		return NULL;
	}

	return d_profiles[i];
}


/**
 * @brief Decode the CID of a packet
 *
 * @param decomp  The ROHC decompressor
 * @param packet  The ROHC packet to extract CID from
 * @param len     The size of the ROHC packet
 * @param ddata   IN/OUT: decompression-related data (e.g. the context)
 * @return        ROHC_OK in case of success, ROHC_ERROR in case of failure
 */
static int rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                  unsigned char *packet,
                                  unsigned int len,
                                  struct d_decode_data *ddata)
{
	/* is feedback data is large enough to read add-CID or first byte
	   of large CID ? */
	if(len < 1)
	{
		rohc_debugf(0, "feedback data too short for add-CID or large CID\n");
		goto error;
	}

	if(decomp->medium.cid_type == ROHC_SMALL_CID)
	{
		/* small CID */
		ddata->large_cid_size = 0;

		/* if add-CID is present, extract the CID value */
		if(d_is_add_cid(packet))
		{
			ddata->addcidUsed = 1;
			ddata->cid = d_decode_add_cid(packet);
			rohc_debugf(2, "add-CID present (0x%x) contains CID = %d\n",
			            packet[0], ddata->cid);
		}
		else
		{
			/* no add-CID, CID defaults to 0 */
			ddata->addcidUsed = 0;
			ddata->cid = 0;
			rohc_debugf(2, "no add-CID found, CID defaults to 0\n");
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
			rohc_debugf(0, "failed to decode SDVL-encoded large CID field\n");
			goto error;
		}
		ddata->cid = large_cid;
		rohc_debugf(2, "%u-byte large CID = %d (0x%02x)\n",
		            ddata->large_cid_size, ddata->cid, ddata->cid);
	}
	else
	{
		rohc_debugf(0, "unexpected CID type (%d), should not happen\n",
		            decomp->medium.cid_type);
		assert(0);
		goto error;
	}

	return ROHC_OK;

error:
	return ROHC_ERROR;
}


/**
 * @brief Decode zero or more feedback packets if present
 *
 * @param decomp       The ROHC decompressor
 * @param packet       The ROHC packet to decompress
 * @param size         The size of the ROHC packet
 * @param parsed_size  OUT: The size (in bytes) of the padding and feedback
 *                          parsed in case of success, undefined otherwise
 * @return             ROHC_OK in case of success, ROHC_ERROR in case of failure
 */
static int d_decode_feedback_first(struct rohc_decomp *decomp,
                                   unsigned char *packet,
                                   unsigned int size,
                                   unsigned int *parsed_size)
{
	/* nothing parsed for the moment */
	*parsed_size = 0;

	/* remove all padded bytes */
	while(size > 0 && d_is_padding(packet))
	{
		packet++;
		size--;
		(*parsed_size)++;
	}
	rohc_debugf(2, "skip %u byte(s) of padding\n", *parsed_size);

	/* parse as much feedback data as possible */
	while(size > 0 && d_is_feedback(packet))
	{
		unsigned int feedback_size;
		int ret;

		/* decode one feedback packet */
		ret = d_decode_feedback(decomp, packet, size, &feedback_size);
		if(ret != ROHC_OK)
		{
			rohc_debugf(0, "failed to decode feedback in packet\n");
			goto error;
		}
		packet += feedback_size;
		size -= feedback_size;
		(*parsed_size) += feedback_size;
	}

	return ROHC_OK;

error:
	return ROHC_ERROR;
}


/**
 * @brief Decode the feedback packet and deliver it to the associated compressor
 *
 * @param decomp         The ROHC decompressor
 * @param packet         The ROHC packet starting with feedback info
 * @param len            The length of the ROHC packet
 * @param feedback_size  OUT: The feedback size (including the feedback header)
 *                            in case of success, undefined otherwise
 * @return               ROHC_OK in case of success, ROHC_ERROR in case of failure
 */
static int d_decode_feedback(struct rohc_decomp *decomp,
                             unsigned char *packet,
                             unsigned int len,
                             unsigned int *feedback_size)
{
	unsigned int header_size;
	unsigned int data_size;

	/* feedback info is at least 2 byte with the header */
	if(len < 2)
	{
		rohc_debugf(0, "packet too short to contain feedback\n");
		goto error;
	}

	/* extract the size of the feedback */
	data_size = d_feedback_size(packet);
	if(data_size > len)
	{
		rohc_debugf(0, "packet too short to contain one %u-byte feedback "
		            "(feedback header not included)\n", data_size);
		goto error;
	}

	/* extract the size of the feedback header */
	header_size = d_feedback_headersize(packet);
	if((header_size + data_size) > len)
	{
		rohc_debugf(0, "packet too short to contain one %u-byte feedback "
		            "(feedback header included)\n", header_size + data_size);
		goto error;
	}

	rohc_debugf(1, "feedback present (header = %u bytes, data = %u bytes)\n",
	            header_size, data_size);

	/* deliver the feedback data to the associated compressor */
	c_deliver_feedback(decomp->compressor, packet + header_size, data_size);

	/* return the total size to caller */
	*feedback_size = header_size + data_size;

	return ROHC_OK;

error:
	return ROHC_ERROR;
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
                                        const size_t max_cid)
{
	struct d_context **new_contexts;

	assert(decomp != NULL);
	assert(max_cid <= ROHC_LARGE_CID_MAX);

	/* allocate memory for the new context array */
	new_contexts = calloc(max_cid + 1, sizeof(struct d_context *));
	if(new_contexts == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the contexts\n");
		return false;
	}

	/* move as many existing contexts as possible if needed */
	if(decomp->contexts != NULL)
	{
		memcpy(new_contexts, decomp->contexts,
		       rohc_min(decomp->medium.max_cid, max_cid) + 1);
		zfree(decomp->contexts);
	}
	decomp->contexts = new_contexts;

	rohc_debugf(1, "room for %zd decompression contexts created\n",
	            (size_t) (max_cid + 1));

	return true;
}

