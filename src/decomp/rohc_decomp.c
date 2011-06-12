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
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 */

/**
 * @defgroup rohc_decomp ROHC decompression API
 */

#include "rohc_decomp.h"
#include "rohc_traces.h"
#include "rohc_time.h"
#include "rohc_debug.h"
#include "feedback.h"
#include "wlsb.h"
#include "decode.h"


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
 * Private function prototypes:
 */

struct d_profile * find_profile(int id);

static int d_decode_feedback_first(struct rohc_decomp *decomp,
                                   unsigned char *packet,
                                   unsigned int size,
                                   unsigned int *parsed_size);

static int d_decode_feedback(struct rohc_decomp *decomp,
                             unsigned char *packet,
                             unsigned int len,
                             unsigned int *feedback_size);

static int rohc_decomp_decode_cid(struct rohc_decomp *decomp,
                                  unsigned char *packet,
                                  unsigned int len,
                                  struct d_decode_data *ddata);



/**
 * @brief Increases the context array size in sizes of 2^x (max 16384).
 *
 * @param decomp       The ROHC decompressor
 * @param highest_cid  Highest CID to adapt context array size with
 */
void context_array_increase(struct rohc_decomp *decomp, int highest_cid)
{
	struct d_context **new_contexts;
	int calcsize, i;
	
	/* calculate the new size of the context array */
	for(i = 4; i < 15; i++)
	{
		calcsize = 1 << i;
		if(highest_cid < calcsize)
			break;
	}

	/* check the new array size:
	 *  - error if new size is smaller than the current one
	 *  - ignore if sizes are equal */
	if(calcsize < decomp->num_contexts)
	{
		rohc_debugf(0, "new array size is smaller than current one\n");
		return;
	}
	else if(calcsize == decomp->num_contexts)
		return;

	/* allocate memory for the context array */
	new_contexts = (struct d_context**) calloc(calcsize, sizeof(struct d_context*));
	if(new_contexts == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the contexts\n");
		return;
	}

	/* reset all context pointers */
	bzero(new_contexts, calcsize * sizeof(struct d_context*));

	/* fill in the new array with the existing contexts */
	memcpy(new_contexts, decomp->contexts,
	       decomp->num_contexts * sizeof(struct d_context*));

	/* replace the existing array with the new one */
	decomp->num_contexts = calcsize;
	zfree(decomp->contexts);
	decomp->contexts = new_contexts;
}


/**
 * @brief Decreases the context array size in sizes of 2^x (min 16).
 *
 * @param decomp The ROHC decompressor
 */
void context_array_decrease(struct rohc_decomp *decomp)
{
	struct d_context **new_contexts;
	int highest_cid = 0;
	int calcsize;
	int i;

	/* find the highest CID (from the end of the array and backwards) */
	highest_cid = decomp->num_contexts - 1;
	while(highest_cid >= 0 && decomp->contexts[highest_cid] == NULL)
		highest_cid--;

	/* calculate the new size of the context array */
	for(i = 4; i < 15; i++)
	{
		calcsize = 1 << i;
		if(highest_cid < calcsize)
			break;
	}

	/* allocate memory for the context array */
	new_contexts = (struct d_context **) calloc(calcsize, sizeof(struct d_context*));
	if(new_contexts == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the contexts\n");
		return;
	}

	/* reset all context pointers */
	bzero(new_contexts, calcsize * sizeof(struct d_context*));
	
	/* fill in the new array with the existing contexts */
	memcpy(new_contexts, decomp->contexts, calcsize * sizeof(struct d_context*));

	/* replace the existing array with the new one */
	decomp->num_contexts = calcsize;
	zfree(decomp->contexts);
	decomp->contexts = new_contexts;
}


/**
 * @brief Find one decompression context thanks to its CID.
 *
 * @param decomp The ROHC decompressor
 * @param cid    The CID of the context to find out
 * @return       The context if found, NULL otherwise
 */
struct d_context * find_context(struct rohc_decomp *decomp, int cid)
{
	/* check the CID value: CID must not be equal or larger than the context
	 * array size */
	if(cid >= decomp->num_contexts)
		return NULL;

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
	struct d_context * context;

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
	context->total_16_uncompressed = c_create_wlsb(32, 16, 0);
	if(context->total_16_uncompressed == NULL)
	{
		rohc_debugf(0, "cannot create the total_16_uncompressed W-LSB window\n");
		goto destroy_profile_data;
	}

	context->total_16_compressed = c_create_wlsb(32, 16, 0);
	if(context->total_16_compressed == NULL)
	{
		rohc_debugf(0, "cannot create the total_16_compressed W-LSB window\n");
		goto destroy_window_tu;
	}

	context->header_16_uncompressed = c_create_wlsb(32, 16, 0);
	if(context->header_16_uncompressed == NULL)
	{
		rohc_debugf(0, "cannot create the header_16_uncompressed W-LSB window\n");
		goto destroy_window_tc;
	}

	context->header_16_compressed = c_create_wlsb(32, 16, 0);
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
	struct medium medium = { ROHC_SMALL_CID, 15 };
	struct rohc_decomp * decomp;

	/* allocate memory for the decompressor */
	decomp = (struct rohc_decomp *) malloc(sizeof(struct rohc_decomp));
	if(decomp == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the decompressor\n");
		goto error;
	}

	/* allocate memory for the decompressor medium and initialize it */
	decomp->medium = (struct medium *) malloc(sizeof(struct medium));
	if(decomp->medium == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the decompressor medium\n");
		goto destroy_decomp;
	}
	memcpy(decomp->medium, &medium, sizeof(struct medium));

	/* associate the compressor and the decompressor */
	decomp->compressor = compressor;

	/* initialize the array of decompression contexts to its minimal value */
	decomp->num_contexts = 0;
	decomp->contexts = NULL;
	context_array_increase(decomp, 0);
	decomp->last_context = NULL;

	decomp->maxval = 300;
	decomp->errval = 100;
	decomp->okval = 12;
	decomp->curval = 0;

	clear_statistics(decomp);

	return decomp;

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

	if(decomp != NULL)
	{
		/* destroy all the contexts owned by the decompressor */
		if(decomp->contexts != NULL)
		{
			for(i = 0; i < decomp->num_contexts; i++)
			{
				if(decomp->contexts[i] != NULL)
					context_free(decomp->contexts[i]);
			}
			zfree(decomp->contexts);
		}

		/* destroy the decompressor medium */
		if(decomp->medium != NULL)
			zfree(decomp->medium);

		/* destroy the decompressor itself */
		zfree(decomp);
	}
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
	struct d_decode_data ddata = { -1, 0, 0, 0, NULL };

	decomp->statistics.packets_received++;
	rohc_debugf(1, "decompress the packet #%u\n",
	            decomp->statistics.packets_received);
	
	ret = d_decode_header(decomp, ibuf, isize, obuf, osize, &ddata);
	if(ddata.active == NULL &&
	   (ret == ROHC_ERROR_PACKET_FAILED ||
	    ret == ROHC_ERROR ||
	    ret == ROHC_ERROR_CRC))
		ret = ROHC_ERROR_NO_CONTEXT;

	if(ddata.active != NULL)
	{
		ddata.active->num_recv_packets++;
		rohc_debugf(2, "state in decompressor = %d\n", ddata.active->state);
	}

	if(ret >= 0)
	{
		if(!ddata.active)
		{
			rohc_debugf(1, "ddata.active == null when ret >=0 !\n");
		}
		else
		{
			struct d_context *c = ddata.active;
			c->total_uncompressed_size += ret;
			c->total_compressed_size += isize;

			c_add_wlsb(c->total_16_uncompressed, 0, ret);
			c_add_wlsb(c->total_16_compressed, 0, isize);
		}
	}
	else if(ddata.active)
	{
		ddata.active->num_decomp_failures++;
	}

	switch(ret)
	{
		case ROHC_ERROR_PACKET_FAILED:
		case ROHC_ERROR:
			decomp->statistics.packets_failed_decompression++;
			ddata.active->curval += decomp->errval;
			if(ddata.active->curval >= decomp->maxval)
			{
				ddata.active->curval = 0;
				d_operation_mode_feedback(decomp, ROHC_ERROR_PACKET_FAILED,
				                          ddata.cid, ddata.addcidUsed,
				                          ddata.largecidUsed, ddata.active->mode,
				                          ddata.active);
			}
			break;

		case ROHC_ERROR_NO_CONTEXT:
			decomp->statistics.packets_failed_no_context++;
			decomp->curval += decomp->errval;
			if(decomp->curval >= decomp->maxval)
			{
				decomp->curval = 0;
				d_operation_mode_feedback(decomp, ROHC_ERROR_NO_CONTEXT, ddata.cid,
				                          ddata.addcidUsed, ddata.largecidUsed,
				                          O_MODE, NULL);
			}
			break;

		case ROHC_FEEDBACK_ONLY:
			decomp->statistics.packets_feedback++;
			break;

		case ROHC_ERROR_CRC:
			decomp->statistics.packets_failed_crc++;
			ddata.active->curval += decomp->errval;
			rohc_debugf(2, "feedback curr %d\n", ddata.active->curval);
			rohc_debugf(2, "feedback max %d\n", decomp->maxval);
			if(ddata.active->curval >= decomp->maxval)
			{
				ddata.active->curval = 0;
				d_operation_mode_feedback(decomp, ROHC_ERROR_CRC, ddata.cid,
				                          ddata.addcidUsed, ddata.largecidUsed,
				                          ddata.active->mode, ddata.active);
			}
			break;

		default:	/* ROHC_OK_NO_DATA, ROHC_OK */
			decomp->curval -= decomp->okval; /* framework (S-NACK) */
			ddata.active->curval -= decomp->okval; /* context (NACK) */
			rohc_debugf(2, "feedback curr %d\n", ddata.active->curval);
			if(decomp->curval < 0)
				decomp->curval = 0;

			if(ddata.active->curval < 0)
				ddata.active->curval = 0;

			rohc_debugf(2, "feedback curr %d\n", ddata.active->curval);
			if(decomp->compressor != NULL && ddata.active->mode == U_MODE)
			{
				/* switch active context to O-mode */
				ddata.active->mode = O_MODE;
				d_operation_mode_feedback(decomp, ROHC_OK, ddata.cid, ddata.addcidUsed,
				                          ddata.largecidUsed, ddata.active->mode,
				                          ddata.active);
			}
			break;
	}

	return ret;
}


/**
 * @brief Decompress both large and small CID packets.
 *
 * @param decomp The ROHC decompressor
 * @param ibuf   The ROHC packet to decompress
 * @param isize  The size of the ROHC packet
 * @param obuf   The buffer where to store the decompressed packet
 * @param osize  The size of the buffer for the decompressed packet
 * @param large  Whether the packet use large CID or not
 * @return       The size of the decompressed packet
 */
int rohc_decompress_both(struct rohc_decomp * decomp,
                         unsigned char *ibuf, int isize,
                         unsigned char *obuf, int osize,
                         int large)
{
	decomp->medium->cid_type = large ? ROHC_LARGE_CID : ROHC_SMALL_CID;

	return rohc_decompress(decomp, ibuf, isize, obuf, osize);
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
	struct d_profile * profile;
	unsigned char * walk = ibuf;
	unsigned int feedback_size;
	int status;

	if(isize < 2)
		return ROHC_ERROR_NO_CONTEXT;

	/* decode feedback if present */
	status = d_decode_feedback_first(decomp, walk, isize, &feedback_size);
	if(status != ROHC_OK)
	{
		rohc_debugf(0, "failed to decode feedback at the beginning "
		            "of the packet\n");
		return status;
	}
	walk += feedback_size;
	isize -= feedback_size;

	/* decode small or large CID */
	status = rohc_decomp_decode_cid(decomp, walk, isize, ddata);
	if(status != ROHC_OK)
	{
		rohc_debugf(0, "failed to decode small or large CID in packet\n");
		return status;
	}

	/* skip add-CID if present */
	if(ddata->addcidUsed)
	{
		walk++;
		isize--;
	}

	/* is the ROHC packet an IR packet? */
	if(d_is_ir(walk))
	{
		uint8_t profile_id;

		rohc_debugf(1, "ROHC packet is an IR packet\n");

		/* find the profile specified in the ROHC packet */
		profile_id = walk[1 + ddata->large_cid_size];
		profile = find_profile(profile_id);
		if(profile == NULL)
		{
			rohc_debugf(0, "failed to find profile identified by 0x%04x\n",
			            profile_id);
			return ROHC_ERROR_NO_CONTEXT;
		}
		rohc_debugf(1, "profile 0x%04x found in IR packet\n", profile_id);

		/* do we need more space in the array of contexts? */
		if(ddata->cid >= decomp->num_contexts)
		{
			rohc_debugf(2, "CID in ROHC packet (%d) is greater than the current "
			            "number of contexts (%d), so enlarge the context array\n",
			            ddata->cid, decomp->num_contexts);
			context_array_increase(decomp, ddata->cid);
		}

		if(decomp->contexts[ddata->cid] && decomp->contexts[ddata->cid]->profile == profile)
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

		/* check the CRC of the IR packet */
		if(!rohc_ir_packet_crc_ok(ddata->active, walk, isize,
		                          ddata->large_cid_size, ddata->addcidUsed, profile))
		{
			rohc_debugf(0, "IR packet has incorrect CRC, abort all changes\n");
			if(casenew)
				context_free(ddata->active);
			else
				decomp->contexts[ddata->cid] = ddata->active;							
			return ROHC_ERROR_CRC;
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
			context_free(ddata->active);
		else
			decomp->contexts[ddata->cid] = ddata->active;

		return size;
	}
	else /* the ROHC packet is not an IR packet */
	{
		int second_byte;

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
			if(d_is_irdyn(walk))
			{
				rohc_debugf(1, "ROHC packet is an IR-DYN packet\n");
				ddata->active->num_recv_ir_dyn++;

				/* find the profile specified in the ROHC packet */
				profile = find_profile(walk[ddata->large_cid_size + 1]);

				/* if IR-DYN changes profile, make the decompressor
				 * transit to the NO_CONTEXT state */
				if(profile != ddata->active->profile)
				{
					decomp->curval = decomp->maxval;
					rohc_debugf(2, "IR-DYN changed profile, sending S-NACK\n");
					return ROHC_ERROR_NO_CONTEXT;
				}

				/* check the CRC of the IR-DYN packet */
				if(!rohc_ir_dyn_packet_crc_ok(walk, isize,
				                              ddata->large_cid_size,
				                              ddata->addcidUsed,
				                              profile, ddata->active))
				{
					rohc_debugf(0, "IR-DYN packet has incorrect CRC\n");
					return ROHC_ERROR_CRC;
				}
			}

			/* determine the offset of the second byte */
			second_byte = 1 + ddata->large_cid_size;
			rohc_debugf(2, "the second byte in the packet is at offset %d\n",
			            second_byte);

			/* decode the IR-DYN or UO* packet thanks to the
			 * profile-specific routines */
			return ddata->active->profile->decode(decomp, ddata->active, walk,
			                                      isize, second_byte, obuf);
		}

	} /* end of 'the ROHC packet is not an IR packet' */

	return ROHC_ERROR_NO_CONTEXT;
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

	if(decomp->medium->cid_type == ROHC_SMALL_CID)
	{
		/* small CID */
		ddata->large_cid_size = 0;
		ddata->largecidUsed = 0;

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
	else if(decomp->medium->cid_type == ROHC_LARGE_CID)
	{
		int ret;

		/* large CID */
		ddata->addcidUsed = 0;
		ddata->largecidUsed = 1;

		/* skip the first byte of packet located just before the large CID */
		packet++;
		len--;

		/* get the length of the SDVL-encoded large CID **/
		ret = d_sdvalue_size(packet);
		if(ret < 0)
		{
			rohc_debugf(0, "malformed large CID SDVL-encoded field\n");
			goto error;
		}
		ddata->large_cid_size = ret;

		/* only 1-byte and 2-byte SDVL fields are allowed for large CID */
		if(ddata->large_cid_size != 1 && ddata->large_cid_size != 2)
		{
			rohc_debugf(0, "bad large CID SDVL-encoded field length (%u bytes)\n",
			            ddata->large_cid_size);
			goto error;
		}

		/* is feedback data large enough ? */
		if(len < ddata->large_cid_size)
		{
			rohc_debugf(0, "feedback data too small (%u bytes) for %u-byte "
			            "SDVL-encoded large CID field\n", len,
			            ddata->large_cid_size);
			goto error;
		}

		/* decode SDVL-encoded large CID */
		ddata->cid = d_sdvalue_decode(packet);
		if(ddata->cid == -1)
		{
			rohc_debugf(0, "bad large CID SDVL-encoded field\n");
			goto error;
		}

		rohc_debugf(2, "%u-byte large CID = %d (0x%02x)\n",
		           ddata->large_cid_size, ddata->cid, ddata->cid);
	}
	else
	{
		rohc_debugf(0, "unexpected CID type (%d), should not append\n",
		            decomp->medium->cid_type);
		goto error;
	}

	return ROHC_OK;

error:
	return ROHC_ERROR;
}


/**
 * @brief Find the ROHC profile with the given profile ID.
 *
 * @param id  The profile ID to search for
 * @return    The matching ROHC profile
 */
struct d_profile * find_profile(int id)
{
	int i = 0;
	
	while(i < D_NUM_PROFILES && d_profiles[i]->id != id)
		i++;
	
	if(i >= D_NUM_PROFILES)
	{
		rohc_debugf(0, "no profile found for decompression\n");
		return NULL;
	}

	return d_profiles[i];
}


/**
 * @brief Check the CRC of one IR packet.
 *
 * @param context    The decompression context
 * @param walk       The ROHC IR packet
 * @param plen       The length of the ROHC packet
 * @param largecid   The size of the large CID field
 * @param addcidUsed Whether add-CID is used or not
 * @param profile    The profile associated with the ROHC packet
 * @return           Whether the CRC is ok or not
 */
int rohc_ir_packet_crc_ok(struct d_context *context,
                          unsigned char *walk,
                          unsigned int plen,
                          const int largecid,
                          const int addcidUsed,
                          const struct d_profile *profile)
{
	int realcrc, crc;
	int ir_size;

	/* extract the CRC transmitted in the IR packet */
	if(largecid + 2 >= plen)
	{
		rohc_debugf(0, "ROHC packet too small, cannot read the CRC (len = %d)\n",
		            plen);
		goto bad;
	}
	realcrc = walk[largecid + 2];

	/* detect the size of the IR header */
	ir_size = profile->detect_ir_size(context, walk, plen, largecid);
	if(ir_size == 0)
	{
		rohc_debugf(0, "cannot detect the IR size with profile %s (0x%04x)\n",
		            profile->description, profile->id);
		goto bad;
	}
	rohc_debugf(3, "size of IR packet header : %d \n", ir_size);

	/* compute the CRC of the IR packet */
	walk[largecid + 2] = 0;
	crc = crc_calculate(CRC_TYPE_8, walk - addcidUsed,
	                    ir_size + largecid + addcidUsed, CRC_INIT_8);
	walk[largecid + 2] = realcrc;

	/* compare the transmitted CRC and the computed one */
	if(crc != realcrc)
	{
		rohc_debugf(0, "CRC failed (real = 0x%x, calc = 0x%x, profile_id = "
		            "%d, largecid = %d, addcidUsed = %d, ir_size = %d)\n",
		            realcrc, crc, profile->id, largecid, addcidUsed, ir_size);
		goto bad;
	}
	
	rohc_debugf(2, "CRC OK (crc = 0x%x, profile_id = %d, largecid = %d, "
	            "addcidUsed = %d, ir_size = %d)\n", crc, profile->id,
	            largecid, addcidUsed, ir_size);

	return 1;

bad:
	return 0;
}


/**
 * @brief Check the CRC of one IR-DYN packet.
 *
 * @param walk       The ROHC packet
 * @param plen       The length of the ROHC packet
 * @param largecid   The large CID value
 * @param addcidUsed Whether add-CID is used or not
 * @param profile    The profile associated with the ROHC packet
 * @param context    The decompression context associated with the ROHC packet
 * @return           Whether the CRC is ok or not
 */
int rohc_ir_dyn_packet_crc_ok(unsigned char *walk,
                              unsigned int plen,
                              const int largecid,
                              const int addcidUsed,
                              const struct d_profile *profile,
                              struct d_context *context)
{
	int realcrc, crc;
	int irdyn_size;

	/* extract the CRC transmitted in the IR-DYN packet */
	if(largecid + 2 >= plen)
	{
		rohc_debugf(0, "ROHC packet too small, cannot read the CRC (len = %d)\n",
		            plen);
		goto bad;
	}
	realcrc = walk[largecid + 2];
	
	/* detect the size of the IR-DYN header */
	irdyn_size = profile->detect_ir_dyn_size(context, walk, plen, largecid);
	if(irdyn_size == 0)
	{
		rohc_debugf(0, "cannot detect the IR-DYN size\n");
		goto bad;
	}

	/* compute the CRC of the IR-DYN packet */
	walk[largecid + 2] = 0;
	crc = crc_calculate(CRC_TYPE_8, walk - addcidUsed,
	                    irdyn_size + largecid + addcidUsed, CRC_INIT_8);
	walk[largecid + 2] = realcrc;

	/* compare the transmitted CRC and the computed one */
	if(crc != realcrc)
	{
		rohc_debugf(0, "CRC failed (real = 0x%x, calc = 0x%x, largecid = %d, "
		            "addcidUsed = %d, ir_dyn_size = %d)\n",
		            realcrc, crc, largecid, addcidUsed, irdyn_size);
		goto bad;
	}

	rohc_debugf(2, "CRC OK (crc = 0x%x, largecid = %d, addcidUsed = %d, "
	            "ir_dyn_size = %d)\n", crc, largecid, addcidUsed, irdyn_size);

	return 1;

bad:
	return 0;
}


/**
 * @brief Send feedback in Optimistic Mode.
 *
 * @param decomp       The ROHC decompressor
 * @param rohc_status  The type of feedback to send: 0 = OK (ack),
 *                     -1 = ContextInvalid (S-nack), -2 = PackageFailed (Nack)
 * @param cid          The Context ID (CID) to which the feedback is related
 * @param addcidUsed   Whether add-CID is used or not
 * @param largecidUsed Whether large CIDs are used or not
 * @param context      The context to which the feedback is related
 */
void d_optimistic_feedback(struct rohc_decomp *decomp,
                           int rohc_status, int cid,
                           int addcidUsed, int largecidUsed,
                           struct d_context *context)
{
	struct d_feedback sfeedback;
	unsigned char *feedback;
	int feedbacksize;
	int ret;

	/* check associated compressor availability */
	if(decomp->compressor == NULL)
	{
		rohc_debugf(1, "no associated compressor, do not sent feedback\n");

		/* only change state if needed */
		if(rohc_status == ROHC_ERROR_PACKET_FAILED ||
		   rohc_status == ROHC_ERROR_CRC)
		{
			if(context->state == STATIC_CONTEXT)
				context->state = NO_CONTEXT;
			else if(context->state == FULL_CONTEXT)
				context->state = STATIC_CONTEXT;
		}
		
		goto skip;
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
			feedback = f_wrap_feedback(&sfeedback, cid, largecidUsed, WITH_CRC, &feedbacksize);
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
			feedback = f_wrap_feedback(&sfeedback, cid, largecidUsed, NO_CRC,
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
					feedback = f_wrap_feedback(&sfeedback, cid, largecidUsed, WITH_CRC,
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
					feedback = f_wrap_feedback(&sfeedback, cid, largecidUsed, WITH_CRC,
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
						context->state = NO_CONTEXT;
					if(context->state == FULL_CONTEXT)
						context->state = STATIC_CONTEXT;

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
 * @param largecidUsed Whether large CIDs are used or not
 * @param mode         The mode in which the ROHC decompressor operates:
 *                     U_MODE, O_MODE or R_MODE
 * @param context      The context to which the feedback is related
 */
void d_operation_mode_feedback(struct rohc_decomp *decomp,
                               int rohc_status, int cid,
                               int addcidUsed, int largecidUsed,
                               int mode, struct d_context *context)
{
	switch(mode)
	{
		case U_MODE:
			/* no feedback needed */
			//break;

		case O_MODE:
			d_optimistic_feedback(decomp, rohc_status, cid, addcidUsed,
			                      largecidUsed, context);
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
	decomp->statistics.packets_received = 0;
	decomp->statistics.packets_failed_crc = 0;
	decomp->statistics.packets_failed_no_context = 0;
	decomp->statistics.packets_failed_decompression = 0;
	decomp->statistics.packets_feedback = 0;
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
	prefix = calloc(indent + 1, sizeof(char));
	if(prefix == NULL)
		return -1;

	memset(prefix, '\t', indent);
	prefix[indent] = '\0';

	/* add the instance info */
	save = buffer;
	buffer += strlen(buffer);

	sprintf(buffer, "%s<instance>\n", prefix);
	buffer += strlen(buffer);

	/* add the profiles part */
	sprintf(buffer, "%s\t<profiles>\n", prefix);
	buffer += strlen(buffer);

	for(i = 0; i < D_NUM_PROFILES; i++)
	{
		p = d_profiles[i];

		sprintf(buffer, "%s\t\t<profile ", prefix);
		buffer += strlen(buffer);
		sprintf(buffer, "id=\"%d\" ", p->id);
		buffer += strlen(buffer);
		sprintf(buffer, "name=\"%s\" ", p->description);
		buffer += strlen(buffer);
		sprintf(buffer, "active=\"yes\" />\n");
		buffer += strlen(buffer);
	}

	sprintf(buffer, "%s\t</profiles>\n", prefix);
	buffer += strlen(buffer);

	/* add the contexts part */
	i = 0;
	while(rohc_d_context(decomp, i, indent + 1, buffer) != -2)
		i++;
	buffer += strlen(buffer);

	sprintf(buffer, "%s</instance>\n\n", prefix);
	buffer += strlen(buffer);

	/* clean the indent prefix */
	zfree(prefix);

	return strlen(save);
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
	char *modes[4] = { "error", "U-mode", "O-mode", "R-mode" };
	char *states[4] = { "error", "NC", "SC", "FC" };
	struct d_context *c;
	char *prefix;
	char *save;
	int v;

	if (index >= decomp->num_contexts)
		return -2;

	c = decomp->contexts[index];
	if(!c || !c->profile)
		return -1;

	/* compute the line prefix */
	prefix = calloc(indent + 1, sizeof(char));
	if(prefix == NULL)
		return -1;

	memset(prefix, '\t', indent);
	prefix[indent] = '\0';

	/* compute context info */
	save = buffer;
	buffer += strlen(buffer);

	sprintf(buffer, "\n%s<context type=\"decompressor\" cid=\"%d\">\n", prefix, index);
	buffer += strlen(buffer);
	sprintf(buffer, "%s\t<state>%s</state>\n",
	        prefix, (c->state < 0 || c->state >= sizeof(states)) ? states[0] : states[c->state]);
	buffer += strlen(buffer);
	sprintf(buffer, "%s\t<mode>%s</mode>\n",
	        prefix, (c->mode < 0 || c->mode >= sizeof(modes)) ? modes[0] : modes[c->mode]);
	buffer += strlen(buffer);
	sprintf(buffer, "%s\t<profile>%s</profile>\n", prefix, c->profile->description);
	buffer += strlen(buffer);

	/* compression ratio */
	sprintf(buffer, "%s\t<ratio>\n", prefix);
	buffer += strlen(buffer);

	if (c->total_uncompressed_size != 0)
		v = (100*c->total_compressed_size) / c->total_uncompressed_size;
	else
		v = 0;
	sprintf(buffer, "%s\t\t<all_packets>%d%%</all_packets>\n", prefix, v);
	buffer += strlen(buffer);

	if (c->header_uncompressed_size != 0)
		v = (100*c->header_compressed_size) / c->header_uncompressed_size;
	else
		v = 0;
	sprintf(buffer, "%s\t\t<all_headers>%d%%</all_headers>\n", prefix, v);
	buffer += strlen(buffer);

	v = c_sum_wlsb(c->total_16_uncompressed);
	if (v != 0)
		v = (100 * c_sum_wlsb(c->total_16_compressed)) / v;
	sprintf(buffer, "%s\t\t<last_16_packets>%d%%</last_16_packets>\n", prefix, v);
	buffer += strlen(buffer);

	v = c_sum_wlsb(c->header_16_uncompressed);
	if (v != 0)
		v = (100 * c_sum_wlsb(c->header_16_compressed)) / v;
	sprintf(buffer, "%s\t\t<last_16_headers>%d%%</last_16_headers>\n", prefix, v);
	buffer += strlen(buffer);

	sprintf(buffer, "%s\t</ratio>\n", prefix);
	buffer += strlen(buffer);

	/* compression mean */
	sprintf(buffer, "%s\t<mean>\n", prefix);
	buffer += strlen(buffer);

	v = c->total_compressed_size/c->num_recv_packets;
	sprintf(buffer, "%s\t\t<all_packets>%d</all_packets>\n", prefix, v);
	buffer += strlen(buffer);

	v = c->header_compressed_size/c->num_recv_packets;
	sprintf(buffer, "%s\t\t<all_headers>%d</all_headers>\n", prefix, v);
	buffer += strlen(buffer);

	v = c_mean_wlsb(c->total_16_compressed);
	sprintf(buffer, "%s\t\t<last_16_packets>%d</last_16_packets>\n", prefix, v);
	buffer += strlen(buffer);

	v = c_mean_wlsb(c->header_16_compressed);
	sprintf(buffer, "%s\t\t<last_16_headers>%d</last_16_headers>\n", prefix, v);
	buffer += strlen(buffer);

	sprintf(buffer, "%s\t</mean>\n", prefix);
	buffer += strlen(buffer);

	/* times */
	sprintf(buffer, "%s\t<activation_time>%u</activation_time>\n",
	        prefix, (get_milliseconds() - c->first_used) / 1000 );
	buffer += strlen(buffer);
	sprintf(buffer, "%s\t<idle_time>%u</idle_time>\n",
	        prefix, (get_milliseconds() - c->latest_used) / 1000);
	buffer += strlen(buffer);

	/* packets */
	sprintf(buffer, "%s\t<packets recv_total=\"%d\" ", prefix, c->num_recv_packets);
	buffer += strlen(buffer);
	sprintf(buffer, "recv_ir=\"%d\" ", c->num_recv_ir);
	buffer += strlen(buffer);
	sprintf(buffer, "recv_irdyn=\"%d\" ", c->num_recv_ir_dyn);
	buffer += strlen(buffer);
	sprintf(buffer, "sent_feedback=\"%d\" />\n", c->num_sent_feedbacks);
	buffer += strlen(buffer);

	/* failures/repairs */
	sprintf(buffer, "%s\t<decomp>\n", prefix);
	buffer += strlen(buffer);
	sprintf(buffer, "%s\t\t<failures>%d</failures>\n", prefix, c->num_decomp_failures);
	buffer += strlen(buffer);
	sprintf(buffer, "%s\t\t<repairs>%d</repairs>\n", prefix, c->num_decomp_repairs);
	buffer += strlen(buffer);
	sprintf(buffer, "%s\t</decomp>\n", prefix);
	buffer += strlen(buffer);

	sprintf(buffer, "%s</context>\n", prefix);
	buffer += strlen(buffer);

	free(prefix);
	return strlen(save);
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
	for(cid = 0; cid < decomp->num_contexts; cid++)
	{
		if(context == decomp->contexts[cid])
			break;
	}
	if(cid >= decomp->num_contexts)
		return;

	/* create an ACK feedback */
	f_feedback2(ACKTYPE_ACK, context->mode, context->profile->get_sn(context),
	            &sfeedback);
	feedback = f_wrap_feedback(&sfeedback, cid,
	                           (decomp->medium->cid_type == ROHC_LARGE_CID ? 1 : 0),
	                           WITH_CRC, &feedbacksize);

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

