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
 * @file rohc_comp.c
 * @brief ROHC compression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 */

/**
 * @defgroup rohc_comp ROHC compression API
 */

#include "rohc_comp.h"
#include "rohc_comp_internals.h"
#include "rohc_traces.h"
#include "rohc_time.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "sdvl.h"
#include "decode.h"
#include "ip.h"
#include "crc.h"
#include "protocols/udp.h"
#include "protocols/ip_numbers.h"

#include "config.h" /* for PACKAGE_(NAME|URL|VERSION) */

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>


extern struct c_profile c_rtp_profile,
                        c_udp_profile,
                        c_udp_lite_profile,
                        c_esp_profile,
                        c_ip_profile,
                        c_uncompressed_profile;

/**
 * @brief The compression parts of the ROHC profiles.
 */
struct c_profile *c_profiles[C_NUM_PROFILES] =
{
	&c_rtp_profile,
	&c_udp_profile,
	&c_udp_lite_profile,
	&c_esp_profile,
	&c_ip_profile,
	&c_uncompressed_profile,
};


/*
 * Prototypes of private functions related to ROHC compression profiles
 */

static const struct c_profile * c_get_profile_from_id(const struct rohc_comp *comp,
                                                      const int profile_id);

static const struct c_profile * c_get_profile_from_packet(const struct rohc_comp *comp,
                                                          const struct ip_packet *outer_ip,
                                                          const struct ip_packet *inner_ip,
                                                          const int protocol);

static int c_is_in_list(struct c_profile *profile, int port);


/*
 * Prototypes of private functions related to ROHC compression contexts
 */

static int c_create_contexts(struct rohc_comp *const comp);
static int c_alloc_contexts(struct rohc_comp *const comp, int num);
static void c_destroy_contexts(struct rohc_comp *const comp);

static struct c_context * c_create_context(struct rohc_comp *comp,
                                           const struct c_profile *profile,
                                           const struct ip_packet *ip);
static struct c_context * c_find_context(const struct rohc_comp *comp,
                                         const struct c_profile *profile,
                                         const struct ip_packet *ip);
static struct c_context * c_get_context(struct rohc_comp *comp, int cid);


/*
 * Prototypes of private functions related to ROHC feedback
 */

static void rohc_feedback_destroy(struct rohc_comp *const comp);
static int rohc_feedback_get(struct rohc_comp *const comp,
                             unsigned char *const buffer,
                             const unsigned int max);
static bool rohc_feedback_remove_locked(struct rohc_comp *const comp);
static bool rohc_feedback_unlock(struct rohc_comp *const comp);


/*
 * Prototypes of miscellaneous private functions
 */
static int rohc_comp_get_random_default(const struct rohc_comp *const comp,
                                        void *const user_context)
	__attribute__((nonnull(1)));



/*
 * Definitions of public functions
 */


/**
 * @brief Create one ROHC compressor
 *
 * @param max_cid     The maximal CID value the compressor should use for contexts
 * @param jam_use     not used anymore, must be 0
 * @param adapt_size  not used anymore, ignored
 * @param encap_size  not used anymore, ignored
 * @return            The newly-created compressor if successful,
 *                    NULL otherwise
 *
 * @ingroup rohc_comp
 */
struct rohc_comp * rohc_alloc_compressor(int max_cid,
                                         int jam_use,
                                         int adapt_size,
                                         int encap_size)
{
	struct rohc_comp *comp;
	bool is_fine;
	int i;

	rohc_debugf(1, "creating compressor\n");

	if(jam_use != 0)
	{
		rohc_debugf(0, "the jamming algorithm was removed, please set "
		            "jam_use to 0\n");
		goto error;
	}

	comp = malloc(sizeof(struct rohc_comp));
	if(comp == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the compressor\n");
		goto error;
	}
	memset(comp, 0, sizeof(struct rohc_comp));

	comp->enabled = 1;
	comp->medium.max_cid = max_cid;
	comp->medium.cid_type = ROHC_SMALL_CID;
	comp->mrru = 0;

	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		comp->profiles[i] = 0;
	}

	comp->num_packets = 0;
	comp->total_compressed_size = 0;
	comp->total_uncompressed_size = 0;
	comp->last_context = NULL;

	/* set the default W-LSB window width */
	is_fine = rohc_comp_set_wlsb_window_width(comp, C_WINDOW_WIDTH);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

	/* set the default timeouts for periodic refreshes of contexts */
	is_fine = rohc_comp_set_periodic_refreshes(comp,
	                                           CHANGE_TO_IR_COUNT,
	                                           CHANGE_TO_FO_COUNT);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

	/* set default callback for random numbers */
	comp->random_cb = rohc_comp_get_random_default;
	comp->random_cb_ctxt = NULL;

	/* init the tables for fast CRC computation */
	is_fine = rohc_crc_init_table(comp->crc_table_2, ROHC_CRC_TYPE_2);
	if(is_fine != true)
	{
		goto destroy_comp;
	}
	is_fine = rohc_crc_init_table(comp->crc_table_3, ROHC_CRC_TYPE_3);
	if(is_fine != true)
	{
		goto destroy_comp;
	}
	is_fine = rohc_crc_init_table(comp->crc_table_6, ROHC_CRC_TYPE_6);
	if(is_fine != true)
	{
		goto destroy_comp;
	}
	is_fine = rohc_crc_init_table(comp->crc_table_7, ROHC_CRC_TYPE_7);
	if(is_fine != true)
	{
		goto destroy_comp;
	}
	is_fine = rohc_crc_init_table(comp->crc_table_8, ROHC_CRC_TYPE_8);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

	/* init the ring of feedbacks */
	for(i = 0; i < FEEDBACK_RING_SIZE; i++)
	{
		comp->feedbacks[i].data = NULL;
		comp->feedbacks[i].length = 0;
		comp->feedbacks[i].is_locked = false;
	}
	comp->feedbacks_first = 0;
	comp->feedbacks_first_unlocked = 0;
	comp->feedbacks_next = 0;

	if(!c_create_contexts(comp))
	{
		goto destroy_comp;
	}

	return comp;

destroy_comp:
	zfree(comp);
error:
	return NULL;
}


/**
 * @brief Destroy one ROHC compressor.
 *
 * @param comp The compressor to destroy
 *
 * @ingroup rohc_comp
 */
void rohc_free_compressor(struct rohc_comp *comp)
{
	if(comp != NULL)
	{
		/* free memory used by contexts */
		rohc_debugf(2, "free contexts\n");
		c_destroy_contexts(comp);

		/* destroy unsent piggybacked feedback */
		rohc_debugf(2, "free feedback buffer\n");
		rohc_feedback_destroy(comp);

		/* free the compressor */
		zfree(comp);
	}
}


/**
 * @brief Set the user-defined callback for random numbers
 *
 * If no callback is defined, an internal one that always returns 0 will be
 * defined for compatibility reasons.
 *
 * @param comp          The ROHC compressor to set the random callback for
 * @param callback      The random callback to set
 * @param user_context  Private data that will be given to the callback, may
 *                      be used as a context by user
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_random_cb(struct rohc_comp *const comp,
                             rohc_comp_random_cb_t callback,
                             void *const user_context)
{
	if(comp == NULL || callback == NULL)
	{
		goto error;
	}

	comp->random_cb = callback;
	comp->random_cb_ctxt = user_context;

	return true;

error:
	return false;
}


/**
 * @brief The default callback for random numbers
 *
 * The default callback for random numbers always returns 0 to keep
 * compatibility with previous releases. That could be changed for the 2.0.0
 * release.
 *
 * @param comp          The ROHC compressor
 * @param user_context  Should always be NULL
 * @return              Always 0
 */
static int rohc_comp_get_random_default(const struct rohc_comp *const comp,
                                        void *const user_context)
{
	assert(comp != NULL);
	assert(user_context == NULL);

	rohc_debugf(0, "please define a callback for random numbers\n");

	return 0;
}


/**
 * @brief Compress a ROHC packet.
 *
 * @param comp   The ROHC compressor
 * @param ibuf   The uncompressed packet to compress
 * @param isize  The size of the uncompressed packet
 * @param obuf   The buffer where to store the ROHC packet
 * @param osize  The size of the buffer for the ROHC packet
 * @return       The size of the ROHC packet in case of success,
 *               0 in case of error
 *
 * @ingroup rohc_comp
 */
int rohc_compress(struct rohc_comp *comp, unsigned char *ibuf, int isize,
                  unsigned char *obuf, int osize)
{
	struct ip_packet ip;
	struct ip_packet ip2;
	int proto;
	const struct ip_packet *outer_ip;
	const struct ip_packet *inner_ip;
	const struct c_profile *p;
	struct c_context *c;
	int feedback_size, payload_size, payload_offset;
	rohc_packet_t packet_type;
	int size, esize;
	const unsigned char *ip_raw_data;

	/* check compressor validity */
	if(comp == NULL)
	{
		rohc_debugf(0, "compressor not valid\n");
		goto error;
	}

	/* print uncompressed bytes */
	rohc_dump_packet("uncompressed data, max 100 bytes",
	                 ibuf, rohc_min(isize, 100));

	/* create the IP packet from raw data */
	if(!ip_create(&ip, ibuf, isize))
	{
		rohc_debugf(0, "cannot create the outer IP header\n");
		goto error;
	}
	outer_ip = &ip;
	rohc_debugf(3, "size of uncompressed packet = %d bytes\n", isize);

	/* get the transport protocol in the IP packet (skip the second IP header
	 * if present) */
	proto = ip_get_protocol(outer_ip);
	if(proto == ROHC_IPPROTO_IPIP || proto == ROHC_IPPROTO_IPV6)
	{
		/* create the second IP header */
		if(!ip_get_inner_packet(outer_ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto error;
		}

		/* there are two IP headers, the inner IP header is the second one */
		inner_ip = &ip2;

		/* get the transport protocol */
		proto = ip_get_protocol(inner_ip);
	}
	else
	{
		/* there is only one IP header, there is no inner IP header */
		inner_ip = NULL;
	}

	/* find the best profile for the packet */
	rohc_debugf(2, "try to find the best profile for packet with "
	            "transport protocol %d\n", proto);
	p = c_get_profile_from_packet(comp, outer_ip, inner_ip, proto);
	if(p == NULL)
	{
		rohc_debugf(0, "no profile found to compress packet\n");
		goto error;
	}
	rohc_debugf(1, "using profile '%s' (0x%04x)\n", p->description, p->id);

	/* get the context using help from the profiles */
	c = c_find_context(comp, p, outer_ip);
	if(c == NULL)
	{
		/* context not found, create a new one */
		c = c_create_context(comp, p, outer_ip);
		if(c == NULL)
		{
			rohc_debugf(0, "failed to create a new context\n");
			goto error;
		}
	}
	else if(c == (struct c_context*) -1)
	{
		/* the profile detected anomalities in IP packet (such as fragments)
		 * that made it not compressible -> switch to uncompressed profile */

		rohc_debugf(0, "error while finding context, using uncompressed profile\n");

		p = c_get_profile_from_id(comp, ROHC_PROFILE_UNCOMPRESSED);
		if(p == NULL)
		{
			rohc_debugf(0, "uncompressed profile not found, giving up\n");
			goto error;
		}

		/* find the context or create a new one */
		c = c_find_context(comp, p, outer_ip);
		if(c == NULL)
		{
			c = c_create_context(comp, p, outer_ip);
			if(c == NULL)
			{
				rohc_debugf(0, "failed to create an uncompressed context\n");
				goto error;
			}
		}
		else if(c == (struct c_context*)-1)
		{
			rohc_debugf(0, "error while finding context in uncompressed profile, "
			            "giving up\n");
			goto error;
		}
	}

	c->latest_used = get_milliseconds();

	/* create the ROHC packet: */
	size = 0;

	/* 1. add feedback */
	do
	{
		feedback_size = rohc_feedback_get(comp, obuf, osize - size);
		if(feedback_size > 0)
		{
			obuf += feedback_size;
			size += feedback_size;
		}
	}
	while(feedback_size > 0);

	/* 2. use profile to compress packet */
	rohc_debugf(1, "compress the packet #%d\n", comp->num_packets + 1);
	esize = p->encode(c, outer_ip, isize, obuf, osize - size,
	                  &packet_type, &payload_offset);
	if(esize < 0)
	{
		/* error while compressing, use uncompressed */
		rohc_debugf(0, "error while compressing with the profile, "
		            "using uncompressed profile\n");

		/* free context if it was just created */
		if(c->num_sent_packets <= 1)
		{
			c->profile->destroy(c);
			c->used = 0;
			comp->num_contexts_used--;
		}

		/* get uncompressed profile */
		p = c_get_profile_from_id(comp, ROHC_PROFILE_UNCOMPRESSED);
		if(p == NULL)
		{
			rohc_debugf(0, "uncompressed profile not found, giving up\n");
			goto error_unlock_feedbacks;
		}

		/* find the context or create a new one */
		c = c_find_context(comp, p, outer_ip);
		if(c == NULL)
		{
			c = c_create_context(comp, p, outer_ip);
			if(c == NULL)
			{
				rohc_debugf(0, "failed to create an uncompressed context\n");
				goto error_unlock_feedbacks;
			}
		}
		else if(c == (struct c_context*)-1)
		{
			rohc_debugf(0, "error while finding context in uncompressed profile, "
			            "giving up\n");
			goto error_unlock_feedbacks;
		}

		esize = p->encode(c, outer_ip, isize, obuf, osize - size,
		                  &packet_type, &payload_offset);
		if(esize < 0)
		{
			rohc_debugf(0, "error while compressing with uncompressed profile, "
			            "giving up\n");
			goto error_free_new_context;
		}
	}

	size += esize;
	obuf += esize;

	payload_size = ip_get_totlen(outer_ip) - payload_offset;

	/* is packet too large? */
	if(size + payload_size > osize)
	{
		/* TODO: should use uncompressed profile */
		rohc_debugf(0, "ROHC packet too large (input size = %d, maximum output "
		            "size = %d, required output size = %d + %d = %d)\n",
		            isize, osize, size, payload_size, size + payload_size);
		goto error_free_new_context;
	}

	/* copy payload to rohc packet */
	ip_raw_data = ip_get_raw_data(outer_ip);
	memcpy(obuf, ip_raw_data + payload_offset, payload_size);
	obuf += payload_size;
	size += payload_size;

	/* remove locked feedbacks since compression is successful */
	if(rohc_feedback_remove_locked(comp) != true)
	{
		rohc_debugf(0, "failed to remove locked feedbacks\n");
		goto error_free_new_context;
	}

	rohc_debugf(2, "ROHC size = %d (feedback = %d, header = %d, payload = %d), "
	            "output buffer size = %d\n", size, feedback_size, esize,
	            payload_size, osize);

	/* update some statistics:
	 *  - compressor statistics
	 *  - context statistics (global + last packet + last 16 packets) */
	comp->num_packets++;
	comp->total_uncompressed_size += isize;
	comp->total_compressed_size += size;
	comp->last_context = c;

	c->packet_type = packet_type;

	c->total_uncompressed_size += isize;
	c->total_compressed_size += size;
	c->header_uncompressed_size += payload_offset;
	c->header_compressed_size += esize;
	c->num_sent_packets++;

	c->total_last_uncompressed_size = isize;
	c->total_last_compressed_size = size;
	c->header_last_uncompressed_size = payload_offset;
	c->header_last_compressed_size = esize;

	c_add_wlsb(c->total_16_uncompressed, 0, isize);
	c_add_wlsb(c->total_16_compressed, 0, size);
	c_add_wlsb(c->header_16_uncompressed, 0, payload_offset);
	c_add_wlsb(c->header_16_compressed, 0, esize);

	/* compression is successfully, return the size of the ROHC packet */
	return size;

error_free_new_context:
	/* free context if it was just created */
	if(c->num_sent_packets <= 1)
	{
		c->profile->destroy(c);
		c->used = 0;
		comp->num_contexts_used--;
	}
error_unlock_feedbacks:
	if(rohc_feedback_unlock(comp) != true)
	{
		rohc_debugf(0, "failed to unlock feedbacks\n");
	}
error:
	return 0;
}


/**
 * @brief Set the window width for the W-LSB algorithm
 *
 * W-LSB window width is set to \ref C_WINDOW_WIDTH by default.
 *
 * @warning The value can not be modified after library initialization
 *
 * @param comp   The ROHC compressor
 * @param width  The width of the W-LSB sliding window
 * @return       true in case of success, false in case of failure
 */
bool rohc_comp_set_wlsb_window_width(struct rohc_comp *const comp,
                                     const size_t width)
{
	/* we need a valid compressor and a positive non-zero window width */
	if(comp == NULL)
	{
		return false;
	}
	if(width <= 0)
	{
		rohc_debugf(0, "failed to set width of W-LSB sliding window to %zd\n",
		            width);
		return false;
	}

	/* refuse to set a value if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_debugf(0, "unable to modify the W-LSB window width after "
		            "initialization\n");
		return false;
	}

	comp->wlsb_window_width = width;

	rohc_debugf(2, "width of W-LSB sliding window set to %zd\n", width);

	return true;
}


/**
 * @brief Set the timeout values for IR and FO periodic refreshes
 *
 * The IR timeout shall be greater than the FO timeout. Both timeouts are
 * expressed in number of compressed packets.
 *
 * IR timeout is set to \ref CHANGE_TO_IR_COUNT by default.
 * FO timeout is set to \ref CHANGE_TO_FO_COUNT by default.
 *
 * @warning The values can not be modified after library initialization
 *
 * @param comp        The ROHC compressor
 * @param ir_timeout  The number of packets to compress before going back
 *                    to IR state to force a context refresh
 * @param fo_timeout  The number of packets to compress before going back
 *                    to FO state to force a context refresh
 * @return            true in case of success, false in case of failure
 */
bool rohc_comp_set_periodic_refreshes(struct rohc_comp *const comp,
                                      const size_t ir_timeout,
                                      const size_t fo_timeout)
{
	/* we need a valid compressor, positive non-zero timeouts,
	 * and IR timeout > FO timeout */
	if(comp == NULL)
	{
		return false;
	}
	if(ir_timeout <= 0 || fo_timeout <= 0 || ir_timeout <= fo_timeout)
	{
		rohc_debugf(0, "invalid timeouts for context periodic refreshes "
		            "(IR timeout = %zd, FO timeout = %zd)\n",
		            ir_timeout, fo_timeout);
		return false;
	}

	/* refuse to set values if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_debugf(0, "unable to modify the timeouts for periodic refreshes "
		            "after initialization\n");
		return false;
	}

	comp->periodic_refreshes_ir_timeout = ir_timeout;
	comp->periodic_refreshes_fo_timeout = fo_timeout;

	rohc_debugf(2, "IR timeout for context periodic refreshes set to %zd\n",
	            ir_timeout);
	rohc_debugf(2, "FO timeout for context periodic refreshes set to %zd\n",
	            fo_timeout);

	return true;
}


/**
 * @brief Activate a profile for a compressor
 *
 * @param comp    The ROHC compressor
 * @param profile The ID of the profile to activate
 *
 * @ingroup rohc_comp
 */
void rohc_activate_profile(struct rohc_comp *comp, int profile)
{
	int i;

	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		if(c_profiles[i]->id == profile)
		{
			/* mark the profile as activated */
			comp->profiles[i] = 1;
			return;
		}
	}

	rohc_debugf(0, "unknown ROHC profile (ID = %d)\n", profile);
}


/**
 * @brief Whether the compressor uses small CID or not
 *
 * @param comp The ROHC compressor
 * @return     Whether the compressor uses small CID or not
 *
 * @ingroup rohc_comp
 */
int rohc_c_using_small_cid(struct rohc_comp *comp)
{
	return (comp->medium.cid_type == ROHC_SMALL_CID);
}


/**
 * @brief Set the maximal header size. The maximal header size is ignored
 *        for the moment.
 *
 * @param comp   The ROHC compressor
 * @param header The maximal header size
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_header(struct rohc_comp *comp, int header)
{
	comp->max_header_size = header;
}


/**
 * @brief Set the Maximum Reconstructed Reception Unit (MRRU). The MRRU is
 *        ignored for the moment.
 *
 * @param comp  The ROHC compressor
 * @param value The new MRRU value
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_mrru(struct rohc_comp *comp, int value)
{
	comp->mrru = value;
}


/**
 * @brief Set the maximal CID value the compressor should use
 *
 * @param comp  The ROHC compressor
 * @param value The new maximal CID value
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_max_cid(struct rohc_comp *comp, int value)
{
	/* large CID */
	if(comp->medium.cid_type == ROHC_LARGE_CID)
	{
		if(value > 0 && value <= ROHC_LARGE_CID_MAX)
		{
			comp->medium.max_cid = value;
		}
	}
	else /* small CID */
	{
		if(value > 0 && value <= ROHC_SMALL_CID_MAX)
		{
			comp->medium.max_cid = value;
		}
	}
}


/**
 * @brief Tell the compressor to use large CIDs
 *
 * @param comp      The ROHC compressor
 * @param large_cid Whether to use large CIDs or not
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_large_cid(struct rohc_comp *comp, int large_cid)
{
	if(large_cid)
	{
		comp->medium.cid_type = ROHC_LARGE_CID;
	}
	else
	{
		comp->medium.cid_type = ROHC_SMALL_CID;

		/* reduce the MAX_CID parameter if needed */
		if(comp->medium.max_cid > ROHC_SMALL_CID_MAX)
		{
			comp->medium.max_cid = ROHC_SMALL_CID_MAX;
		}
	}
}


/**
 * @brief Enable the ROHC compressor
 *
 * @param comp   The ROHC compressor
 * @param enable Whether to enable the compressor or not
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_enable(struct rohc_comp *comp, int enable)
{
	comp->enabled = enable;
}


/**
 * @brief Whether the ROHC compressor is enabled or not
 *
 * @param comp  The ROHC compressor
 * @return      Whether the compressor is enabled or not
 *
 * @ingroup rohc_comp
 */
int rohc_c_is_enabled(struct rohc_comp *comp)
{
	return comp->enabled;
}


/**
 * @brief Get information about available compression profiles
 *
 * This function outputs XML.
 *
 * @param buffer The buffer where to store profile information
 * @return       The length of the data stored in the buffer
 *
 * @ingroup rohc_comp
 */
int rohc_c_info(char *buffer)
{
	char *save;
	int i;

	save = buffer;
	buffer += strlen(buffer);

	buffer += sprintf(buffer, "<profiles>\n");

	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		buffer += sprintf(buffer, "\t<profile id=\"%d\" ", c_profiles[i]->id);
		buffer += sprintf(buffer, "name=\"%s\" ", c_profiles[i]->description);
		buffer += sprintf(buffer, "/>\n");
	}

	buffer += sprintf(buffer, "</profiles>\n");

	return buffer - save;
}


/**
 * @brief Get information about a ROHC compressor
 *
 * This function outputs XML.
 *
 * @param comp   The ROHC compressor
 * @param indent The indent level to beautify the XML output
 * @param buffer The buffer where to store the information
 * @return       The length of the data stored in the buffer if successful,
 *               -1 if an error occurs
 *
 * @ingroup rohc_comp
 */
int rohc_c_statistics(struct rohc_comp *comp, unsigned int indent, char *buffer)
{
	struct c_profile *p;
	char *prefix;
	char *save;
	int i,v;

	/* compute the indent prefix */
	prefix = malloc((indent + 1) * sizeof(char));
	if(prefix == NULL)
	{
		return -1;
	}

	memset(prefix, '\t', indent);
	prefix[indent] = '\0';

	/* compute instance info */
	save = buffer;
	buffer += strlen(buffer);

	buffer += sprintf(buffer, "%s<instance>\n", prefix);
	buffer += sprintf(buffer, "%s\t<creator>%s</creator>\n", prefix,
	        PACKAGE_NAME " (" PACKAGE_URL ")");
	buffer += sprintf(buffer, "%s\t<version>%s</version>\n", prefix, PACKAGE_VERSION);
	buffer += sprintf(buffer, "%s\t<status>%s</status>\n", prefix, comp->enabled ? "enabled" : "disabled");
	buffer += sprintf(buffer, "%s\t<flows>%d</flows>\n", prefix, comp->num_contexts_used);
	buffer += sprintf(buffer, "%s\t<packets>%d</packets>\n", prefix, comp->num_packets);

	if(comp->total_uncompressed_size != 0)
	{
		v = (100 * comp->total_compressed_size) / comp->total_uncompressed_size;
	}
	else
	{
		v = 0;
	}
	buffer += sprintf(buffer, "%s\t<compression_ratio>%d%%</compression_ratio>\n", prefix, v);
	buffer += sprintf(buffer, "%s\t<max_cid>%d</max_cid>\n", prefix, comp->medium.max_cid);
	buffer += sprintf(buffer, "%s\t<mrru>%d</mrru>\n", prefix, comp->mrru);
	buffer += sprintf(buffer, "%s\t<large_cid>%s</large_cid>\n", prefix,
	                  comp->medium.cid_type == ROHC_LARGE_CID ? "yes" : "no");
	buffer += sprintf(buffer, "%s\t<connection_type>%d</connection_type>\n", prefix, 3);
	buffer += sprintf(buffer, "%s\t<feedback_freq>%d</feedback_freq>\n\n", prefix, 7); // comp-> ??

	/* profiles part */
	buffer += sprintf(buffer, "%s\t<profiles>\n", prefix);

	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		p = c_profiles[i];

		buffer += sprintf(buffer, "%s\t\t<profile id=\"%d\" ", prefix, p->id);
		buffer += sprintf(buffer, "name=\"%s\" ", p->description);
		buffer += sprintf(buffer, "active=\"%s\" ", comp->profiles[i] ? "yes" : "no");
		buffer += sprintf(buffer, "/>\n");
	}

	buffer += sprintf(buffer, "%s\t</profiles>\n", prefix);

	/* contexts part */
	i = 0;
	while(rohc_c_context(comp, i, indent + 1, buffer) != -2)
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
 * @brief Get information about a compression context
 *
 * This function outputs XML.
 *
 * @param comp   The ROHC compressor
 * @param cid    The CID of the compressor context to output information about
 * @param indent The indent level to beautify the XML output
 * @param buffer The buffer where to store the information
 * @return       The length of the data stored in the buffer if successful,
 *               -2 if the given CID is too large,
 *               -1 if the given CID is unused or an error occurs
 */
int rohc_c_context(struct rohc_comp *comp, int cid, unsigned int indent, char *buffer)
{
	struct c_context *c;
	char *prefix;
	char *save;
	int v;

	if(cid >= comp->num_contexts)
	{
		return -2;
	}

	c = &comp->contexts[cid];
	if(!c->used)
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

	buffer += sprintf(buffer, "\n%s<context type=\"compressor\" cid=\"%d\">\n", prefix, c->cid);
	buffer += sprintf(buffer, "%s\t<cid_state>%s</cid_state>\n", prefix, c->used ? "USED" : "UNUSED");
	buffer += sprintf(buffer, "%s\t<state>%s</state>\n", prefix,
	                  rohc_comp_get_state_descr(c->state));
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

	if(c->num_sent_packets != 0)
	{
		v = c->total_compressed_size / c->num_sent_packets;
	}
	else
	{
		v = 0;
	}
	buffer += sprintf(buffer, "%s\t\t<all_packets>%d</all_packets>\n", prefix, v);

	if(c->num_sent_packets != 0)
	{
		v = c->header_compressed_size / c->num_sent_packets;
	}
	else
	{
		v = 0;
	}
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
	buffer += sprintf(buffer, "%s\t<packets sent_total=\"%d\" ", prefix, c->num_sent_packets);
	buffer += sprintf(buffer, "sent_ir=\"%d\" ", c->num_sent_ir);
	buffer += sprintf(buffer, "sent_irdyn=\"%d\" ", c->num_sent_ir_dyn);
	buffer += sprintf(buffer, "recv_feedback=\"%d\" />\n", c->num_recv_feedbacks);

	buffer += sprintf(buffer, "%s</context>\n", prefix);

	free(prefix);
	return buffer - save;
}


/**
 * @brief Add a feedback packet to the next outgoing ROHC packet (piggybacking)
 *
 * @param comp     The ROHC compressor
 * @param feedback The feedback data
 * @param size     The length of the feedback packet
 */
void c_piggyback_feedback(struct rohc_comp *comp,
                          unsigned char *feedback,
                          int size)
{
	/* ignore feedback if no valid compressor is provided */
	if(comp == NULL)
	{
		rohc_debugf(0, "no compressor associated with the decompressor, "
		            "cannot deliver feedback\n");
		return;
	}

	rohc_debugf(2, "try to add %d byte(s) of feedback to the next outgoing "
	            "ROHC packet\n", size);

	assert(comp->feedbacks_next >= 0);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_first >= 0);
	assert(comp->feedbacks_first < FEEDBACK_RING_SIZE);

	/* If first and next feedbacks are equals, the ring is either empty or full.
	 * If the first feedback is 0-byte length, then the ring is empty. */
	if(comp->feedbacks_next == comp->feedbacks_first &&
	   comp->feedbacks[comp->feedbacks_first].length != 0)
	{
		rohc_debugf(0, "no place in buffer for feedback data\n");
		return;
	}

	/* allocate memory for new feedback data */
	comp->feedbacks[comp->feedbacks_next].data = malloc(size);
	if(comp->feedbacks[comp->feedbacks_next].data == NULL)
	{
		rohc_debugf(0, "no memory for feedback data\n");
		return;
	}

	/* record new feedback data in the ring */
	memcpy(comp->feedbacks[comp->feedbacks_next].data, feedback, size);
	comp->feedbacks[comp->feedbacks_next].length = size;

	/* use the next ring location next time */
	comp->feedbacks_next = (comp->feedbacks_next + 1) % FEEDBACK_RING_SIZE;

	rohc_debugf(2, "%d byte(s) of feedback added to the next outgoing "
	            "ROHC packet\n", size);
}


/**
 * @brief Callback called by a decompressor to deliver a feedback packet to the
 *        compressor
 *
 * When feedback is received by the decompressor, this function is called and
 * delivers the feedback to the right profile/context of the compressor.
 *
 * @param comp   The ROHC compressor
 * @param packet The feedback data
 * @param size   The length of the feedback packet
 */
void c_deliver_feedback(struct rohc_comp *comp, unsigned char *packet, int size)
{
	struct c_context *c;
	struct c_feedback feedback;
	unsigned char *p = packet;

	if(comp == NULL)
	{
		rohc_debugf(0, "no compressor associated with the decompressor, "
		            "cannot deliver feedback\n");
		goto quit;
	}

	rohc_debugf(2, "deliver %d byte(s) of feedback to the right context\n",
	            size);

	feedback.size = size;

	/* decode CID */
	if(comp->medium.cid_type == ROHC_LARGE_CID)
	{
		size_t large_cid_size;
		size_t large_cid_bits_nr;
		uint32_t large_cid;

		/* decode SDVL-encoded large CID field */
		large_cid_size = sdvl_decode(p, size, &large_cid, &large_cid_bits_nr);
		if(large_cid_size != 1 && large_cid_size != 2)
		{
			rohc_debugf(0, "failed to decode SDVL-encoded large CID field\n");
			goto quit;
		}
		feedback.cid = large_cid;
		p += large_cid_size;
	}
	else
	{
		/* decode small CID */
		if(d_is_add_cid(p))
		{
			feedback.cid = d_decode_add_cid(p);
			p++;
		}
		else
		{
			feedback.cid = 0;
		}
	}

	feedback.specific_size = size - (p - packet);
	rohc_debugf(2, "feedback size = %d\n", feedback.specific_size);

	if(feedback.specific_size == 1)
	{
		feedback.type = 1; /* FEEDBACK-1 */
	}
	else
	{
		feedback.type = 2; /* FEEDBACK-2 */
		feedback.acktype = p[0] >> 6;
	}

	feedback.specific_offset = p - packet;
	feedback.data = malloc(feedback.size);
	if(feedback.data == NULL)
	{
		rohc_debugf(0, "no memory for feedback data\n");
		goto quit;
	}

	memcpy(feedback.data, packet, feedback.size);

	/* find context */
	c = c_get_context(comp, feedback.cid);
	if(c == NULL)
	{
		/* context was not found */
		rohc_debugf(0, "context not found (CID = %d)\n", feedback.cid);
		goto clean;
	}

	c->num_recv_feedbacks++;

	/* deliver feedback to profile with the context */
	c->profile->feedback(c, &feedback);

clean:
	zfree(feedback.data);
quit:
	;
}


/**
 * @brief Send as much feedback data as possible
 *
 * @param comp   The ROHC compressor
 * @param obuf   The buffer where to store the feedback-only packet
 * @param osize  The size of the buffer for the feedback-only packet
 * @return       The size of the feedback-only packet,
 *               0 if there is no feedback data to send
 *
 * @ingroup rohc_comp
 */
int rohc_feedback_flush(struct rohc_comp *comp,
                        unsigned char *obuf,
                        int osize)
{
	unsigned int size;
	int feedback_size;

	/* check compressor validity */
	if(comp == NULL)
	{
		rohc_debugf(0, "compressor not valid\n");
		return 0;
	}

	/* build the feedback-only packet */
	size = 0;
	do
	{
		feedback_size = rohc_feedback_get(comp, obuf, osize - size);
		if(feedback_size > 0)
		{
			obuf += feedback_size;
			size += feedback_size;
		}
	}
	while(feedback_size > 0);

	return size;
}


/**
 * @brief Get some information about the last compressed packet
 *
 * @param comp  The ROHC compressor to get information from
 * @param info  IN/OUT: the structure where information will be stored
 * @return      ROHC_OK in case of success, ROHC_ERROR otherwise
 *
 * @ingroup rohc_comp
 */
int rohc_comp_get_last_packet_info(const struct rohc_comp *const comp,
                                   rohc_comp_last_packet_info_t *const info)
{
	if(comp == NULL)
	{
		rohc_debugf(0, "compressor is not valid\n");
		return ROHC_ERROR;
	}

	if(comp->last_context == NULL)
	{
		rohc_debugf(0, "last context found in compressor is not valid\n");
		return ROHC_ERROR;
	}

	if(info == NULL)
	{
		rohc_debugf(0, "structure for last packet information is not valid\n");
		return ROHC_ERROR;
	}

	info->context_mode = comp->last_context->mode;
	info->context_state = comp->last_context->state;
	info->packet_type = comp->last_context->packet_type;
	info->total_last_uncomp_size = comp->last_context->total_last_uncompressed_size;
	info->header_last_uncomp_size = comp->last_context->header_last_uncompressed_size;
	info->total_last_comp_size = comp->last_context->total_last_compressed_size;
	info->header_last_comp_size = comp->last_context->header_last_compressed_size;

	return ROHC_OK;
}


/**
 * @brief Give a description for the given ROHC compression context state
 *
 * The descriptions are not part of the API. They may change between
 * releases without any warning. Do NOT use them for other means that
 * providing to users a textual description of compression context states
 * used by the library. If unsure, ask on the mailing list.
 *
 * @param state  The compression context state to get a description for
 * @return       A string that describes the given compression context state
 *
 * @ingroup rohc_comp
 */
const char * rohc_comp_get_state_descr(const rohc_c_state state)
{
	switch(state)
	{
		case IR:
			return "IR";
		case FO:
			return "FO";
		case SO:
			return "SO";
		default:
			return "no description";
	}
}


/*
 * Definitions of private functions
 */


/**
 * @brief Find out a ROHC profile given a profile ID
 *
 * @param comp       The ROHC compressor
 * @param profile_id The ID of the ROHC profile to find out
 * @return           The ROHC profile if found, NULL otherwise
 */
static const struct c_profile * c_get_profile_from_id(const struct rohc_comp *comp,
                                                      const int profile_id)
{
	int i;

	/* test all compression profiles */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		/* if the profile IDs match and the profile is enabled */
		if(c_profiles[i]->id == profile_id && comp->profiles[i] == 1)
		{
			return c_profiles[i];
		}
	}

	return NULL;
}


/**
 * @brief Check whether an UDP port is associated with a given profile or not
 *
 * @param profile  The ROHC profile
 * @param port     The UDP port
 * @return         1 if UDP port is associated with profile,
 *                 0 otherwise
 */
static int c_is_in_list(struct c_profile *profile, int port)
{
	int match = 0;
	int i;

	i = 0;
	while(profile->ports[i] != 0 && !match)
	{
		match = (port == profile->ports[i]);
		i++;
	}

	return match;
}


/**
 * @brief Find out a ROHC profile given an IP protocol ID
 *
 * @param comp      The ROHC compressor
 * @param outer_ip  The outer IP header of the network packet that will help
 *                  choosing the best profile
 * @param inner_ip  \li The inner IP header of the network packet that will
 *                      help choosing the best profile if any
 *                  \li NULL if there is no inner IP header in the packet
 * @param protocol  The transport protocol of the network packet
 * @return          The ROHC profile if found, NULL otherwise
 */
static const struct c_profile * c_get_profile_from_packet(const struct rohc_comp *comp,
                                                          const struct ip_packet *outer_ip,
                                                          const struct ip_packet *inner_ip,
                                                          const int protocol)
{
	int i;

	/* test all compression profiles */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		/* skip profile if the profile is not enabled */
		if(!comp->profiles[i])
		{
			rohc_debugf(3, "skip disabled profile '%s' (0x%04x)\n",
			            c_profiles[i]->description, c_profiles[i]->id);
			continue;
		}

		/* for all profiles except the uncompressed profile, skip the profile:
		    - if the outer IP header of the packet is not IPv4 nor IPv6,
		    - if the outer IP header of the packet is an IPv4 fragment,
		    - if the inner IP header of the packet is not IPv4 nor IPv6,
		    - if the inner IP header of the packet is an IPv4 fragment. */
		if(c_profiles[i]->id != ROHC_PROFILE_UNCOMPRESSED)
		{
			/* check outer IP header */
			if(outer_ip->version != IPV4 && outer_ip->version != IPV6)
			{
				rohc_debugf(3, "skip profile '%s' (0x%04x) because it only support "
				            "IPv4 or IPv6\n", c_profiles[i]->description,
				            c_profiles[i]->id);
				continue;
			}

			if(ip_is_fragment(outer_ip))
			{
				rohc_debugf(3, "skip profile '%s' (0x%04x) because it does not "
				            "support IPv4 fragments\n", c_profiles[i]->description,
				            c_profiles[i]->id);
				continue;
			}

			/* check inner IP header if present */
			if(inner_ip != NULL)
			{
				if(inner_ip->version != IPV4 && inner_ip->version != IPV6)
				{
					rohc_debugf(3, "skip profile '%s' (0x%04x) because it only support "
					            "IPv4 or IPv6\n", c_profiles[i]->description,
					            c_profiles[i]->id);
					continue;
				}

				if(ip_is_fragment(inner_ip))
				{
					rohc_debugf(3, "skip profile '%s' (0x%04x) because it does not "
					            "support IPv4 fragments\n", c_profiles[i]->description,
					            c_profiles[i]->id);
					continue;
				}
			}
		}

		/* skip profile if the profile handles a specific transport protocol and
		   this protocol does not match the transport protocol of the packet */
		if(c_profiles[i]->protocol != 0 && c_profiles[i]->protocol != protocol)
		{
			rohc_debugf(3, "skip profile '%s' (0x%04x) because transport protocol "
			            "does not match\n", c_profiles[i]->description,
			            c_profiles[i]->id);
			continue;
		}

		/* skip profile if it uses UDP as transport protocol and the UDP ports
		   are not reserved for the profile */
		if(c_profiles[i]->protocol == ROHC_IPPROTO_UDP &&
		   c_profiles[i]->ports != NULL &&
		   c_profiles[i]->ports[0] != 0)
		{
			struct udphdr *udp;
			int port;

			/* retrieve the UDP header after the last IP header */
			if(inner_ip == NULL)
			{
				udp = (struct udphdr *) ip_get_next_layer(outer_ip);
			}
			else
			{
				udp = (struct udphdr *) ip_get_next_layer(inner_ip);
			}

			/* retrieve the destination port in the UDP header */
			port = ntohs(udp->dest);
			rohc_debugf(3, "UDP port = 0x%x (%u)\n", port, port);

			/* check if UDP port is reserved by the ROHC profile */
			if(!c_is_in_list(c_profiles[i], port))
			{
				rohc_debugf(3, "skip profile '%s' (0x%04x) because UDP destination port "
				            "is not reserved for profile\n", c_profiles[i]->description,
				            c_profiles[i]->id);
				continue;
			}
		}

		/* the packet is compatible with the profile, let's go with it ! */
		return c_profiles[i];
	}

	return NULL;
}


/**
 * @brief Allocate memory for the array of compression contexts
 *
 * @param comp The ROHC compressor
 * @param size The size of the context array (maximum: comp->medium.max_cid + 1)
 * @return     1 if the creation is successful, 0 otherwise
 */
static int c_alloc_contexts(struct rohc_comp *const comp, int size)
{
	/* the array size must not be greater than comp->medium.max_cid,
	 * it would be a waste of memory */
	if(size > comp->medium.max_cid + 1)
	{
		size = comp->medium.max_cid + 1;
	}

	/* The current context array is too small, replace it with a larger one */
	if(comp->num_contexts < size)
	{
		struct c_context *new_contexts;
		int i;

		rohc_debugf(2, "enlarge the context array from %d to %d elements "
		            "(MAX_CID = %d)\n", comp->num_contexts, size,
		            comp->medium.max_cid);

		new_contexts = calloc(size, sizeof(struct c_context));
		if(new_contexts == NULL)
		{
			rohc_debugf(0, "cannot allocate memory for contexts\n");
			return 0;
		}

		/* move already-created contexts from the current array to the new one if any
		 * and then destroy the current context array */
		if(comp->num_contexts > 0 && comp->contexts != NULL)
		{
			memcpy(new_contexts, comp->contexts, comp->num_contexts * sizeof(struct c_context));
			zfree(comp->contexts);
		}

		/* initialize the other contexts in the context array */
		for(i = comp->num_contexts; i < size; i++)
		{
			/* create windows with 16 entries */
			new_contexts[i].total_16_uncompressed =
				c_create_wlsb(32, 16, ROHC_LSB_SHIFT_STATS);
			new_contexts[i].total_16_compressed =
				c_create_wlsb(32, 16, ROHC_LSB_SHIFT_STATS);
			new_contexts[i].header_16_uncompressed =
				c_create_wlsb(32, 16, ROHC_LSB_SHIFT_STATS);
			new_contexts[i].header_16_compressed =
				c_create_wlsb(32, 16, ROHC_LSB_SHIFT_STATS);
		}

		comp->contexts = new_contexts;
		comp->num_contexts = size;
	}

	return 1;
}


/**
 * @brief Create a compression context
 *
 * @param comp    The ROHC compressor
 * @param profile The profile to associate the context with
 * @param ip      The IP packet to initialize the context
 * @return        The compression context if successful, NULL otherwise
 */
static struct c_context * c_create_context(struct rohc_comp *comp,
                                           const struct c_profile *profile,
                                           const struct ip_packet *ip)
{
	struct c_context *c;
	int index, i;
	unsigned int oldest;

	index = 0;

	/* first case:
	 *      all the contexts in the array are used
	 *  AND the array fails to be enlarged (size was not increased)
	 *  => recycle the oldest context to make room
	 *
	 * second case:
	 *     at least one context in the array is not used
	 *  OR the array is successfully enlarged (size was increased)
	 *  => pick the first unused context
	 */
	if(comp->num_contexts_used >= comp->num_contexts &&
	   (!c_alloc_contexts(comp, comp->num_contexts * 2) ||
	    comp->num_contexts_used >= comp->num_contexts))
	{
		/* all the contexts in the array were used and the enlargement failed,
		 * recycle the oldest context to make room */

		/* find the oldest context */
		index = 0;
		oldest = 0xffffffff;
		for(i = 0; i < comp->num_contexts; i++)
		{
			if(comp->contexts[i].latest_used < oldest)
			{
				oldest = comp->contexts[i].latest_used;
				index = i;
			}
		}

		/* destroy the oldest context before replacing it with a new one */
		rohc_debugf(2, "recycle oldest context (CID = %d)\n", index);
		comp->contexts[index].profile->destroy(&comp->contexts[index]);
		comp->contexts[index].used = 0;
		comp->num_contexts_used--;
	}
	else
	{
		/* there was at least one unused context in the array
		 * OR the array of contexts was successfully enlarged,
		 * pick the first unused context in the context array */

		/* find the first unused context */
		for(i = 0; i < comp->num_contexts; i++)
		{
			if(comp->contexts[i].used == 0)
			{
				index = i;
				break;
			}
		}

		rohc_debugf(2, "take the first unused context (CID = %d)\n", index);
	}

	/* initialize the previously found context */
	c = &comp->contexts[index];

	c->total_uncompressed_size = 0;
	c->total_compressed_size = 0;
	c->header_uncompressed_size = 0;
	c->header_compressed_size = 0;

	c->total_last_uncompressed_size = 0;
	c->total_last_compressed_size = 0;
	c->header_last_uncompressed_size = 0;
	c->header_last_compressed_size = 0;

	c->num_sent_packets = 0;
	c->num_sent_ir = 0;
	c->num_sent_ir_dyn = 0;
	c->num_recv_feedbacks = 0;

	c->cid = index;
	c->profile = profile;

	c->mode = U_MODE;
	c->state = IR;

	c->compressor = comp;

	/* create profile-specific context */
	if(!profile->create(c, ip))
	{
		return NULL;
	}

	/* if creation is successful, mark the context as used */
	c->used = 1;
	c->first_used = get_milliseconds();
	c->latest_used = get_milliseconds();
	comp->num_contexts_used++;

	rohc_debugf(1, "context (CID = %d) created (num_used = %d)\n",
	            c->cid, comp->num_contexts_used);

	return c;
}


/**
 * @brief Find a compression context given a profile and an IP packet
 *
 * @param comp    The ROHC compressor
 * @param profile The profile the context must be associated with
 * @param ip      The IP packet that must be accepted by the context
 * @return        The compression context if found,
 *                NULL if not found,
 *                -1 if an error occurs
 */
static struct c_context * c_find_context(const struct rohc_comp *comp,
                                         const struct c_profile *profile,
                                         const struct ip_packet *ip)
{
	struct c_context *c = NULL;
	int i;
	int ret;

	for(i = 0; i < comp->num_contexts; i++)
	{
		c = &comp->contexts[i];

		if(c && c->used && c->profile->id == profile->id)
		{
			ret = c->profile->check_context(c, ip);
			if(ret == -1)
			{
				c = (struct c_context*) -1;
				break;
			}
			else if(ret)
			{
				rohc_debugf(1, "using context CID = %d\n", c->cid);
				break;
			}
		}
	}

	if(c == NULL || i == comp->num_contexts)
	{
		rohc_debugf(2, "no context was found\n");
		c = NULL;
	}

	return c;
}


/**
 * @brief Find out a context given its CID
 *
 * @param comp The ROHC compressor
 * @param cid  The CID of the context to find
 * @return     The context with the given CID if found, NULL otherwise
 */
static struct c_context * c_get_context(struct rohc_comp *comp, int cid)
{
	/* the CID must not be larger than the context array */
	if(cid >= comp->num_contexts)
	{
		goto not_found;
	}

	/* the context with the given CID must be in use */
	if(comp->contexts[cid].used == 0)
	{
		goto not_found;
	}

	return &comp->contexts[cid];

not_found:
	return NULL;
}


/**
 * @brief Create the array of compression contexts
 *
 * @param comp The ROHC compressor
 * @return     1 if the creation is successful, 0 otherwise
 */
static int c_create_contexts(struct rohc_comp *const comp)
{
	comp->contexts = NULL;
	comp->num_contexts = 0;
	comp->num_contexts_used = 0;

	return c_alloc_contexts(comp, 4); /* start with 4 contexts at the beginning */
}


/**
 * @brief Destroy all the compression contexts in the context array
 *
 * The profile-specific contexts are also destroyed.
 *
 * @param comp The ROHC compressor
 */
static void c_destroy_contexts(struct rohc_comp *const comp)
{
	int i;

	if(comp->num_contexts > 0)
	{
		for(i = 0; i < comp->num_contexts; i++)
		{
			if(comp->contexts[i].used && comp->contexts[i].profile != 0)
			{
				comp->contexts[i].profile->destroy(&comp->contexts[i]);
			}

			c_destroy_wlsb(comp->contexts[i].total_16_uncompressed);
			c_destroy_wlsb(comp->contexts[i].total_16_compressed);
			c_destroy_wlsb(comp->contexts[i].header_16_uncompressed);
			c_destroy_wlsb(comp->contexts[i].header_16_compressed);

			comp->contexts[i].used = 0;
			comp->num_contexts_used--;
		}

		zfree(comp->contexts);
	}
}


/**
 * @brief Retrieve one feedback packet and store it in the given buffer
 *
 * The feedback packet is not removed from the context, it is locked. It will
 * be removed only in case of success when \ref rohc_feedback_remove_locked
 * is called. It will be unlocked but not removed in case of failure when
 * \ref rohc_feedback_unlock is called. Doing these actions in two times is
 * required not to lose feedback data if compression fails.
 *
 * @param comp   The ROHC compressor
 * @param buffer The buffer to store the feedback packet
 * @param max    The size of the buffer
 * @return       The length of the feedback packet if any,
 *               0 if no feedback is available,
 *               -1 if the feedback is too large for the given buffer
 */
static int rohc_feedback_get(struct rohc_comp *const comp,
                             unsigned char *const buffer,
                             const unsigned int max)
{
	int i;
	size_t feedback_length;
	int index = 0;

	assert(comp->feedbacks_first_unlocked >= 0);
	assert(comp->feedbacks_first_unlocked < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_next >= 0);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);

	/* are there some feedback data to send with the next outgoing packet? */
	if(comp->feedbacks_first_unlocked != comp->feedbacks_next)
	{
		feedback_length = comp->feedbacks[comp->feedbacks_first_unlocked].length;

		/* check that there is enough space in the output buffer for the
		 * feedback data */
		if(feedback_length + 1 + (feedback_length < 8 ? 0 : 1) > max)
		{
			rohc_debugf(1, "no more place in the buffer for feedback\n");
			goto full;
		}

		/* the feedback length may be encoded either in the last 3 bits of the
		 * first byte or in the 2nd byte */
		if(feedback_length < 8)
		{
			/* length is small, use only 3 bits to code it */
			rohc_debugf(3, "use 1-byte form factor for feedback length\n");
			buffer[index] = 0xf0 | feedback_length;
			index++;
		}
		else
		{
			/* size is large, use 8 bits to code it */
			rohc_debugf(3, "use 2-byte form factor for feedback length\n");
			buffer[index] = 0xf0;
			index++;
			buffer[index] = feedback_length;
			index++;
		}

		/* copy feedback data in the buffer */
		memcpy(buffer + index,
		       comp->feedbacks[comp->feedbacks_first_unlocked].data,
		       feedback_length);

		comp->feedbacks_first_unlocked =
			(comp->feedbacks_first_unlocked + 1) % FEEDBACK_RING_SIZE;
	}
	else
	{
		feedback_length = 0;
	}

	rohc_debugf(2, "add %zd byte(s) of feedback data", feedback_length);
	if(feedback_length > 0)
	{
		rohc_debugf_(3, ": ");
		for(i = 0; i < feedback_length; i++)
		{
			rohc_debugf_(3, "0x%02x ", buffer[index + i]);
		}
	}
	rohc_debugf_(2, "\n");

	/* return the length of the feedback header/data,
	 * or zero if no feedback */
	return index + feedback_length;

full:
	return -1;
}


/**
 * @brief Remove all feedbacks locked during the packet build
 *
 * This function does remove the locked feedbacks. See function
 * \ref rohc_feedback_unlock instead if you want not to remove them.
 *
 * @param comp  The ROHC compressor
 * @return      true if action succeeded, false in case of error
 */
static bool rohc_feedback_remove_locked(struct rohc_comp *const comp)
{
	assert(comp != NULL);
	assert(comp->feedbacks_first >= 0);
	assert(comp->feedbacks_first < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_first_unlocked >= 0);
	assert(comp->feedbacks_first_unlocked < FEEDBACK_RING_SIZE);

	while(comp->feedbacks_first != comp->feedbacks_first_unlocked)
	{
		/* destroy the feedback and unlock the ring location */
		assert(comp->feedbacks[comp->feedbacks_first].data != NULL);
		assert(comp->feedbacks[comp->feedbacks_first].length > 0);
		zfree(comp->feedbacks[comp->feedbacks_first].data);
		comp->feedbacks[comp->feedbacks_first].length = 0;
		comp->feedbacks[comp->feedbacks_first].is_locked = false;
		comp->feedbacks_first = (comp->feedbacks_first + 1) % FEEDBACK_RING_SIZE;
	}

	assert(comp->feedbacks_first == comp->feedbacks_first_unlocked);

	return true;
}


/**
 * @brief Unlock all feedbacks locked during the packet build
 *
 * This function does not remove the locked feedbacks. See function
 * \ref rohc_feedback_remove_locked instead if you want to remove them.
 *
 * @param comp  The ROHC compressor
 * @return      true if action succeeded, false in case of error
 */
static bool rohc_feedback_unlock(struct rohc_comp *const comp)
{
	assert(comp != NULL);
	assert(comp->feedbacks_first >= 0);
	assert(comp->feedbacks_first < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_first_unlocked >= 0);
	assert(comp->feedbacks_first_unlocked < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_next >= 0);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);

	/* unlock all the ring locations between first unlocked one and first one */
	while(comp->feedbacks_first_unlocked != comp->feedbacks_first)
	{
		/* unlock the ring location if it is valid */
		if(comp->feedbacks_first_unlocked != comp->feedbacks_next)
		{
			assert(comp->feedbacks[comp->feedbacks_first_unlocked].is_locked == true);
			comp->feedbacks[comp->feedbacks_first_unlocked].is_locked = false;
		}
		comp->feedbacks_first_unlocked =
			(comp->feedbacks_first_unlocked - 1) % FEEDBACK_RING_SIZE;
	}

	assert(comp->feedbacks_first_unlocked == comp->feedbacks_first);

	return true;
}


/**
 * @brief Destroy memory allocated for the feedback packets
 *
 * @param comp  The ROHC compressor
 */
static void rohc_feedback_destroy(struct rohc_comp *const comp)
{
	int i;

	for(i = 0; i < FEEDBACK_RING_SIZE; i++)
	{
		if(comp->feedbacks[i].length > 0)
		{
			assert(comp->feedbacks[i].data != NULL);
			zfree(comp->feedbacks[i].data);
			comp->feedbacks[i].length = 0;
			comp->feedbacks[i].is_locked = false;
		}
	}

	comp->feedbacks_first = 0;
	comp->feedbacks_first_unlocked = 0;
	comp->feedbacks_next = 0;
}

