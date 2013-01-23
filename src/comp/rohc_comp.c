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
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 */

/**
 * @defgroup rohc_comp ROHC compression API
 */

#include "rohc_comp.h"
#include "rohc_comp_internals.h"
#include "rohc_traces.h"
#include "rohc_traces_internal.h"
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
#include <stdio.h> /* for printf(3) */
#include <stdarg.h>


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


/*
 * Prototypes of miscellaneous private functions
 */

static void rohc_comp_print_trace_default(const rohc_trace_level_t level,
                                          const rohc_trace_entity_t entity,
                                          const int profile,
                                          const char *const format,
                                          ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));

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

	if(jam_use != 0)
	{
		/* the jamming algorithm was removed, please set jam_use to 0 */
		goto error;
	}

	comp = malloc(sizeof(struct rohc_comp));
	if(comp == NULL)
	{
		goto error;
	}
	memset(comp, 0, sizeof(struct rohc_comp));

	comp->enabled = 1;
	comp->medium.max_cid = max_cid;
	comp->medium.cid_type = ROHC_SMALL_CID;
	comp->mrru = 0; /* no segmentation by default */

	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		comp->profiles[i] = 0;
	}

	/* reset the list of UDP ports for RTP */
	for(i = 0; i < MAX_RTP_PORTS; i++)
	{
		comp->rtp_ports[i] = 0;
	}

	comp->num_packets = 0;
	comp->total_compressed_size = 0;
	comp->total_uncompressed_size = 0;
	comp->last_context = NULL;

	/* set default callback for traces */
	comp->trace_callback = rohc_comp_print_trace_default;

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

	/* set default UDP ports dedicated to RTP traffic (for compatibility) */
	{
		const size_t default_rtp_ports_nr = 5;
		unsigned int default_rtp_ports[] =
			{ 1234, 36780, 33238, 5020, 5002 };

		/* add default ports to the list of RTP ports */
		for(i = 0; i < default_rtp_ports_nr; i++)
		{
			if(!rohc_comp_add_rtp_port(comp, default_rtp_ports[i]))
			{
				goto destroy_comp;
			}
		}
	}

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
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "free compressor\n");

		/* free memory used by contexts */
		c_destroy_contexts(comp);

		/* destroy unsent piggybacked feedback */
		rohc_feedback_destroy(comp);

		/* free the compressor */
		zfree(comp);
	}
}


/**
 * @brief Set the callback function used to manage traces in compressor
 *
 * @warning The callback can not be modified after library initialization
 *
 * @param comp     The ROHC compressor
 * @param callback \li The callback function used to manage traces
 *                 \li NULL to remove the previous callback
 * @return         true on success, false otherwise
 */
bool rohc_comp_set_traces_cb(struct rohc_comp *const comp,
                             rohc_trace_callback_t callback)
{
	/* check compressor validity */
	if(comp == NULL)
	{
		/* cannot print a trace without a valid compressor */
		goto error;
	}

	/* refuse to set a new trace callback if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "unable to "
		           "modify the trace callback after initialization\n");
		goto error;
	}

	/* replace current trace callback by the new one */
	comp->trace_callback = callback;

	return true;

error:
	return false;
}


/**
 * @brief The default callback for traces
 *
 * The default callback for traces always prints traces on stdout for
 * compatibility with previous releases. That could be changed for the 2.0.0
 * release.
 *
 * @param level    The level of the message
 * @param entity   The entity concerned by the traces
 * @param profile  The number of the profile concerned by the message
 * @param format   The format string for the trace message
 */
static void rohc_comp_print_trace_default(const rohc_trace_level_t level,
                                          const rohc_trace_entity_t entity,
                                          const int profile,
                                          const char *const format,
                                          ...)
{
	va_list args;
	static bool first_time = true;

	/* display a warning with the first message */
	if(first_time)
	{
		printf("please define a callback for compressor traces\n");
		first_time = false;
	}

	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
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

	rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	             "please define a callback for random numbers\n");

	return 0;
}


/**
 * @brief Compress a ROHC packet.
 *
 * @deprecated do not use this function anymore,
 *             use rohc_compress2() instead
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
int rohc_compress(struct rohc_comp *comp,
                  unsigned char *ibuf,
                  int isize,
                  unsigned char *obuf,
                  int osize)
{
	size_t rohc_len;
	int code;

	if(isize <= 0 || osize <= 0)
	{
		goto error;
	}

	/* use the new function to keep API compatibility */
	code = rohc_compress2(comp, ibuf, isize, obuf, osize, &rohc_len);
	if(code != ROHC_OK)
	{
		/* compression failed */
		goto error;
	}

	/* compression succeeded */
	return rohc_len;

error:
	return 0;
}


/**
 * @brief Compress a ROHC packet
 *
 * May return a full ROHC packet, or a segment of a ROHC packet if the output
 * buffer was too small for the ROHC packet or if MRRU was exceeded. Use the
 * rohc_comp_get_segment function to retrieve next ROHC segments.
 *
 * @param comp                 The ROHC compressor
 * @param uncomp_packet        The uncompressed packet to compress
 * @param uncomp_packet_len    The size of the uncompressed packet
 * @param rohc_packet          The buffer where to store the ROHC packet
 * @param rohc_packet_max_len  The maximum length (in bytes) of the buffer
 *                             for the ROHC packet
 * @param rohc_packet_len      OUT: The length (in bytes) of the ROHC packet
 * @return                     \li ROHC_OK if a ROHC packed is returned
 *                             \li ROHC_NEED_SEGMENT if no compressed data is
 *                                 returned and segmentation required
 *                             \li ROHC_ERROR if an error occurred
 *
 * @ingroup rohc_comp
 */
int rohc_compress2(struct rohc_comp *const comp,
                   const unsigned char *const uncomp_packet,
                   const size_t uncomp_packet_len,
                   unsigned char *const rohc_packet,
                   const size_t rohc_packet_max_len,
                   size_t *const rohc_packet_len)
{
	struct ip_packet ip;
	struct ip_packet ip2;
	int proto;
	const struct ip_packet *outer_ip;
	const struct ip_packet *inner_ip;
	const struct c_profile *p;
	struct c_context *c;
	rohc_packet_t packet_type;
	const unsigned char *ip_raw_data;

	/* ROHC feedbacks */
	size_t feedbacks_size;
	int feedback_size;

	/* ROHC header */
	unsigned char *rohc_hdr;
	int rohc_hdr_size;

	/* ROHC payload */
	unsigned char *rohc_payload;
	size_t payload_size;
	int payload_offset;

	int status = ROHC_ERROR; /* error status by default */

	/* check inputs validity */
	if(comp == NULL ||
	   uncomp_packet == NULL ||
	   uncomp_packet_len <= 0 ||
	   rohc_packet == NULL ||
	   rohc_packet_max_len <= 0 ||
	   rohc_packet_len == NULL)
	{
		goto error;
	}

	/* print uncompressed bytes */
	rohc_dump_packet(comp->trace_callback, ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	                 "uncompressed data, max 100 bytes",
	                 uncomp_packet, rohc_min(uncomp_packet_len, 100));

	/* create the IP packet from raw data */
	if(!ip_create(&ip, uncomp_packet, uncomp_packet_len))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "cannot create the outer IP header\n");
		goto error;
	}
	outer_ip = &ip;
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "size of uncompressed packet = %zd bytes\n", uncomp_packet_len);

	/* get the transport protocol in the IP packet (skip the second IP header
	 * if present) */
	proto = ip_get_protocol(outer_ip);
	if(proto == ROHC_IPPROTO_IPIP || proto == ROHC_IPPROTO_IPV6)
	{
		/* create the second IP header */
		if(!ip_get_inner_packet(outer_ip, &ip2))
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "cannot create the outer IP header\n");
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
	ip_raw_data = ip_get_raw_data(outer_ip);

	/* find the best profile for the packet */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "try to find the best profile for packet with transport "
	           "protocol %u\n", proto);
	p = c_get_profile_from_packet(comp, outer_ip, inner_ip, proto);
	if(p == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "no profile found for packet, giving up\n");
		goto error;
	}
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "using profile '%s' (0x%04x)\n", p->description, p->id);

	/* get the context using help from the profiles */
	c = c_find_context(comp, p, outer_ip);
	if(c == NULL)
	{
		/* context not found, create a new one */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no existing context found for packet, create a new one\n");
		c = c_create_context(comp, p, outer_ip);
		if(c == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to create a new context\n");
			goto error;
		}
	}
	else if(c == (struct c_context*) -1)
	{
		/* the profile detected anomalities in IP packet (such as fragments)
		 * that made it not compressible -> switch to uncompressed profile */
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "error while compressing with the profile, "
		             "using uncompressed profile\n");

		p = c_get_profile_from_id(comp, ROHC_PROFILE_UNCOMPRESSED);
		if(p == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "uncompressed profile not found, giving up\n");
			goto error;
		}

		/* find the context or create a new one */
		c = c_find_context(comp, p, outer_ip);
		if(c == NULL)
		{
			c = c_create_context(comp, p, outer_ip);
			if(c == NULL)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				             "failed to create an uncompressed context\n");
				goto error;
			}
		}
		else if(c == (struct c_context*)-1)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "error while finding context in uncompressed profile, "
			             "giving up\n");
			goto error;
		}
	}

	c->latest_used = get_milliseconds();

	/* create the ROHC packet: */
	*rohc_packet_len = 0;

	/* 1. add feedback */
	feedbacks_size = 0;
	do
	{
		feedback_size = rohc_feedback_get(comp, rohc_packet + feedbacks_size,
		                                  rohc_packet_max_len - (*rohc_packet_len));
		if(feedback_size > 0)
		{
			feedbacks_size += feedback_size;
		}
	}
	while(feedback_size > 0 && feedbacks_size <= 500);

	/* the ROHC header starts after the feedbacks */
	rohc_hdr = rohc_packet + feedbacks_size;
	*rohc_packet_len += feedbacks_size;

	/* 2. use profile to compress packet */
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "compress the packet #%d\n", comp->num_packets + 1);
	rohc_hdr_size = p->encode(c, outer_ip, uncomp_packet_len, rohc_hdr,
	                          rohc_packet_max_len - (*rohc_packet_len),
	                          &packet_type, &payload_offset);
	if(rohc_hdr_size < 0)
	{
		/* error while compressing, use uncompressed */
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "error while compressing with the profile, "
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
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "uncompressed profile not found, giving up\n");
			goto error_unlock_feedbacks;
		}

		/* find the context or create a new one */
		c = c_find_context(comp, p, outer_ip);
		if(c == NULL)
		{
			c = c_create_context(comp, p, outer_ip);
			if(c == NULL)
			{
				rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				             "failed to create an uncompressed context\n");
				goto error_unlock_feedbacks;
			}
		}
		else if(c == (struct c_context*)-1)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "uncompressed profile not found, giving up\n");
			goto error_unlock_feedbacks;
		}

		rohc_hdr_size = p->encode(c, outer_ip, uncomp_packet_len, rohc_hdr,
		                          rohc_packet_max_len - (*rohc_packet_len),
		                          &packet_type, &payload_offset);
		if(rohc_hdr_size < 0)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "error while compressing with uncompressed profile, "
			             "giving up\n");
			goto error_free_new_context;
		}
	}

	/* the payload starts after the header */
	rohc_payload = rohc_hdr + rohc_hdr_size;
	*rohc_packet_len += rohc_hdr_size;
	payload_size = ip_get_totlen(outer_ip) - payload_offset;

	/* is packet too large for output buffer? */
	if(((*rohc_packet_len) + payload_size) > rohc_packet_max_len)
	{
		uint32_t rru_crc;

		/* resulting ROHC packet too large, segmentation may be a solution */
		rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		          "%s ROHC packet is too large for the given output buffer, "
		          "try to segment it (input size = %zd, maximum output "
		          "size = %zd, required output size = %zd + %d + %zd = %zd, "
		          "MRRU = %zd)\n", rohc_get_packet_descr(packet_type),
		          uncomp_packet_len, rohc_packet_max_len, feedbacks_size,
		          rohc_hdr_size, payload_size, feedbacks_size + rohc_hdr_size +
		          payload_size, comp->mrru);

		/* in order to be segmented, a ROHC packet shall be <= MRRU
		 * (remember that MRRU includes the CRC length) */
		if(((*rohc_packet_len) + payload_size + CRC_FCS32_LEN) > comp->mrru)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "%s ROHC packet cannot be segmented: too large "
			             "(%zd + %zd + %u = %zd bytes) for MRRU (%zd bytes)\n",
			             rohc_get_packet_descr(packet_type), *rohc_packet_len,
			             payload_size, CRC_FCS32_LEN, (*rohc_packet_len) +
			             payload_size + CRC_FCS32_LEN, comp->mrru);
			goto error_free_new_context;
		}
		rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		          "%s ROHC packet can be segmented (MRRU = %zd)\n",
		          rohc_get_packet_descr(packet_type), comp->mrru);

		/* store the whole ROHC packet in compressor (headers and payload only,
		 * not feedbacks, feedbacks will be transmitted with the first segment
		 * when rohc_comp_get_segment() is called) */
		if(comp->rru_len != 0)
		{
			/* warn users about previous, not yet retrieved RRU */
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "erase the existing %zd-byte RRU that was not "
			             "retrieved yet (call rohc_comp_get_segment() to add "
			             "support for ROHC segments in your application)\n",
			             comp->rru_len);
		}
		comp->rru_len = 0;
		comp->rru_off = 0;
		/* ROHC header */
		memcpy(comp->rru + comp->rru_off, rohc_hdr, rohc_hdr_size);
		comp->rru_len += rohc_hdr_size;
		/* ROHC payload */
		memcpy(comp->rru + comp->rru_off + comp->rru_len,
		       ip_raw_data + payload_offset, payload_size);
		comp->rru_len += payload_size;
		/* compute FCS-32 CRC over header and payload (optional feedbacks and
		   the CRC field itself are excluded) */
		rru_crc = crc_calc_fcs32(comp->rru + comp->rru_off, comp->rru_len,
		                         CRC_INIT_FCS32);
		memcpy(comp->rru + comp->rru_off + comp->rru_len, &rru_crc,
		       CRC_FCS32_LEN);
		comp->rru_len += CRC_FCS32_LEN;
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "RRU 32-bit FCS CRC = 0x%08x\n", ntohl(rru_crc));
		/* computed RRU must be <= MRRU */
		assert(comp->rru_len <= comp->mrru);

		/* release locked feedbacks since there are not used for the moment */
		if(rohc_feedback_unlock(comp) != true)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to remove locked feedbacks\n");
			goto error_free_new_context;
		}

		/* report to users that segmentation is possible */
		status = ROHC_NEED_SEGMENT;
	}
	else
	{
		/* copy full payload after ROHC header */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "copy full %zd-byte payload\n", payload_size);
		memcpy(rohc_payload, ip_raw_data + payload_offset, payload_size);
		rohc_payload += payload_size;
		*rohc_packet_len += payload_size;

		/* remove locked feedbacks since compression is successful */
		if(rohc_feedback_remove_locked(comp) != true)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to remove locked feedbacks\n");
			goto error_free_new_context;
		}

		/* report to user that compression was successful */
		status = ROHC_OK;
	}

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "ROHC size = %zd bytes (feedbacks = %zd, header = %d, "
	          "payload = %zd), output buffer size = %zd\n", *rohc_packet_len,
	          feedbacks_size, rohc_hdr_size, payload_size, rohc_packet_max_len);

	/* update some statistics:
	 *  - compressor statistics
	 *  - context statistics (global + last packet + last 16 packets) */
	comp->num_packets++;
	comp->total_uncompressed_size += uncomp_packet_len;
	comp->total_compressed_size += *rohc_packet_len;
	comp->last_context = c;

	c->packet_type = packet_type;

	c->total_uncompressed_size += uncomp_packet_len;
	c->total_compressed_size += *rohc_packet_len;
	c->header_uncompressed_size += payload_offset;
	c->header_compressed_size += rohc_hdr_size;
	c->num_sent_packets++;

	c->total_last_uncompressed_size = uncomp_packet_len;
	c->total_last_compressed_size = *rohc_packet_len;
	c->header_last_uncompressed_size = payload_offset;
	c->header_last_compressed_size = rohc_hdr_size;

	c_add_wlsb(c->total_16_uncompressed, 0, uncomp_packet_len);
	c_add_wlsb(c->total_16_compressed, 0, *rohc_packet_len);
	c_add_wlsb(c->header_16_uncompressed, 0, payload_offset);
	c_add_wlsb(c->header_16_compressed, 0, rohc_hdr_size);

	/* compression is successful */
	return status;

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
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to unlock feedbacks\n");
	}
error:
	return ROHC_ERROR;
}


/**
 * @brief Get the next ROHC segment if any
 *
 * To get all the segments of one ROHC packet, call this function until
 * ROHC_SEGMENT_LAST is returned.
 *
 * @param comp     The ROHC compressor
 * @param segment  The buffer where to store the ROHC segment
 * @param max_len  The maximum length (in bytes) of the buffer for the
 *                 ROHC segment
 * @param len      OUT: The length (in bytes) of the ROHC segment
 * @return         \li ROHC_NEED_SEGMENT if a ROHC segment is returned
 *                     and more segments are available,
 *                 \li ROHC_OK if a ROHC segment is returned
 *                     and no more ROHC segment is available
 *                 \li ROHC_ERROR if an error occurred
 *
 * @ingroup rohc_comp
 */
int rohc_comp_get_segment(struct rohc_comp *const comp,
                          unsigned char *const segment,
                          const size_t max_len,
                          size_t *const len)
{
	const size_t segment_type_len = 1; /* segment type byte */
	int feedback_size;
	size_t max_data_len;
	int status;

	/* no segment yet */
	*len = 0;

	/* check input parameters */
	if(comp == NULL || segment == NULL || max_len <= 0 || len == NULL)
	{
		goto error;
	}

	/* abort if no RRU is available in the compressor */
	if(comp->rru_len <= 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "no RRU available in given compressor\n");
		goto error;
	}

	/* abort is the given output buffer is too small for RRU */
	if(max_len <= segment_type_len)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "output buffer is too small for RRU, more than %zd bytes "
		             "are required\n", segment_type_len);
		goto error;
	}

	/* add feedbacks if some are available */
	do
	{
		feedback_size = rohc_feedback_get(comp, segment + (*len),
		                                  max_len - (*len));
		if(feedback_size > 0)
		{
			*len += feedback_size;
		}
	}
	while(feedback_size > 0);
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "%zd bytes of feedback(s) added to ROHC packet\n", *len);

	/* how many bytes of ROHC packet can we put in that new segment? */
	max_data_len = rohc_min(max_len - (*len) - segment_type_len,
	                        comp->rru_len);
	assert(max_data_len > 0);
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "copy %zd bytes of the remaining %zd bytes of ROHC packet and "
	           "CRC in the segment\n", max_data_len, comp->rru_len);

	/* set segment type with F bit set only for last segment */
	segment[0] = 0xfe | (max_data_len == comp->rru_len);
	(*len)++;

	/* copy remaining ROHC data (CRC included) */
	memcpy(segment + (*len), comp->rru + comp->rru_off, max_data_len);
	*len += max_data_len;
	comp->rru_off += max_data_len;
	comp->rru_len -= max_data_len;

	/* set status wrt to (non-)final segment */
	if(comp->rru_len == 0)
	{
		/* final segment, no more segment available */
		status = ROHC_OK;
		/* reset context for next RRU */
		comp->rru_off = 0;
	}
	else
	{
		/* non-final segment, more segments to available */
		status = ROHC_NEED_SEGMENT;
	}

	return status;

error:
	return ROHC_ERROR;
}


/**
 * @brief Force the compressor to re-initialize all its contexts
 *
 * Make all contexts restart their initialization with decompressor, ie. they
 * go in the lowest compression state. This function can be used once the
 * ROHC channel is established again after an interruption.
 *
 * @param comp  The ROHC compressor
 * @return      true in case of success, false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_force_contexts_reinit(struct rohc_comp *const comp)
{
	int i;

	if(comp == NULL)
	{
		goto error;
	}

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "force re-initialization for all %d contexts\n",
	          comp->num_contexts_used);

	for(i = 0; i < comp->num_contexts; i++)
	{
		if(comp->contexts[i].used)
		{
			if(!comp->contexts[i].profile->reinit_context(&(comp->contexts[i])))
			{
				rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				             "failed to force re-initialization for CID %d\n", i);
				goto error;
			}
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Set the window width for the W-LSB algorithm
 *
 * W-LSB window width is set to \ref C_WINDOW_WIDTH by default.
 *
 * @warning The value must be a power of 2
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
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "failed to "
		             "set width of W-LSB sliding window to %zd: window width "
		             "must be a non-null positive integer\n", width);
		return false;
	}

	/* window width must be a power of 2 */
	if((width & (width - 1)) != 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "failed to "
		             "set width of W-LSB sliding window to %zd: window width "
		             "must be a power of 2\n", width);
		return false;
	}

	/* refuse to set a value if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "unable to "
		             "modify the W-LSB window width after initialization\n");
		return false;
	}

	comp->wlsb_window_width = width;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "width of W-LSB sliding window set to %zd\n", width);

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
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "invalid "
		             "timeouts for context periodic refreshes (IR timeout = %zd, "
		             "FO timeout = %zd)\n", ir_timeout, fo_timeout);
		return false;
	}

	/* refuse to set values if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unable to modify the timeouts for periodic refreshes "
		             "after initialization\n");
		return false;
	}

	comp->periodic_refreshes_ir_timeout = ir_timeout;
	comp->periodic_refreshes_fo_timeout = fo_timeout;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "IR timeout for "
	          "context periodic refreshes set to %zd\n", ir_timeout);
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "FO timeout for "
	          "context periodic refreshes set to %zd\n", fo_timeout);

	return true;
}


/**
 * @brief Set the RTP detection callback function
 *
 * @param comp        The ROHC compressor
 * @param callback    The callback function used to detect RTP packets
 *                    The callback is deactivated if NULL is given as parameter
 * @param rtp_private A pointer to an external memory area
 *                    provided and used by the callback user
 * @return            true on success, false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_rtp_detection_cb(struct rohc_comp *const comp,
                                    rohc_rtp_detection_callback_t callback,
                                    void *const rtp_private)
{
	/* sanity check on compressor */
	if(comp == NULL)
	{
		return false;
	}

	/* set RTP detection callback */
	comp->rtp_callback = callback;
	comp->rtp_private = rtp_private;

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

	rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	             "unknown ROHC profile (ID = %d)\n", profile);
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
 * @brief Set the Maximum Reconstructed Reception Unit (MRRU).
 *
 * The MRRU value must be in range [0 ; ROHC_MAX_MRRU]. Remember that the
 * MRRU includes the 32-bit CRC that protects it.
 *
 * If set to 0, segmentation is disabled as no segment headers are allowed
 * on the channel. No segment will be generated.
 *
 * @param comp  The ROHC compressor
 * @param value The new MRRU value
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_mrru(struct rohc_comp *comp, int value)
{
	if(value >= 0)
	{
		bool __attribute__((unused)) ret; /* avoid warn_unused_result */
		ret = rohc_comp_set_mrru(comp, value);
	}
}


/**
 * @brief Set the Maximum Reconstructed Reception Unit (MRRU).
 *
 * The MRRU value must be in range [0 ; ROHC_MAX_MRRU]. Remember that the
 * MRRU includes the 32-bit CRC that protects it.
 *
 * If set to 0, segmentation is disabled as no segment headers are allowed
 * on the channel. No segment will be generated.
 *
 * @param comp  The ROHC compressor
 * @param mrru  The new MRRU value
 * @return      true if the MRRU was successfully set, false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_mrru(struct rohc_comp *const comp,
                        const size_t mrru)
{
	/* compressor must be valid */
	if(comp == NULL)
	{
		/* cannot print a trace without a valid compressor */
		goto error;
	}

	/* new MRRU value must be in range [0, ROHC_MAX_MRRU] */
	if(mrru > ROHC_MAX_MRRU)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unexpected MRRU value: must be in range [0, %d]\n",
		             ROHC_MAX_MRRU);
		goto error;
	}

	/* set new MRRU */
	comp->mrru = mrru;
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "MRRU is now set to %zd\n", comp->mrru);

	return true;

error:
	return false;
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
 * @brief Add a port to the list of UDP ports dedicated for RTP traffic
 *
 * @param comp  The ROHC compressor
 * @param port  The UDP port to add in the list
 * @return      true on success, false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_add_rtp_port(struct rohc_comp *const comp,
                            const unsigned int port)
{
	unsigned int idx;

	/* sanity check on compressor */
	if(comp == NULL)
	{
		goto error;
	}

	/* check port validity */
	if(port <= 0 || port > 0xffff)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "invalid port number (%u)\n", port);
		goto error;
	}

	/* explore the table (table is sorted in ascending order)
	   and insert the new port if possible */
	for(idx = 0; idx < MAX_RTP_PORTS; idx++)
	{
		/* if the current entry in table is empty, put the new port in it */
		if(comp->rtp_ports[idx] == 0)
		{
			comp->rtp_ports[idx] = port;
			break;
		}

		/* the port should not already be in the list */
		if(comp->rtp_ports[idx] == port)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "port %u is already in the list\n", port);
			goto error;
		}

		/* if the port is less than the one in table at the current index,
		   insert the port in the table in order to get the port list in
		   increasing order */
		if(port < comp->rtp_ports[idx])
		{
			unsigned int i;

			/* move the ports already in the table by one index
			   to make room for the new port */
			for(i = MAX_RTP_PORTS - 2; i > idx; i--)
			{
				comp->rtp_ports[i] = comp->rtp_ports[i - 1];
			}

			/* insert the new port in table at the current index */
			comp->rtp_ports[idx] = port;

			break;
		}
	}

	/* was the table full? */
	if(idx == MAX_RTP_PORTS)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "can not add a new RTP port, the list is full\n");
		goto error;
	}

	/* everything is fine */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "port %u added to the UDP port list for RTP traffic\n", port);

	return true;

error:
	return false;
}


/**
 * @brief Remove a port from the list of UDP ports dedicated to RTP traffic
 *
 * @param comp  The ROHC compressor
 * @param port  The UDP port to remove
 * @return      true on success, false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_remove_rtp_port(struct rohc_comp *const comp,
                               const unsigned int port)
{
	unsigned int idx;
	bool is_found = false;

	/* sanity check on compressor */
	if(comp == NULL)
	{
		goto error;
	}

	/* check port validity */
	if(port <= 0 || port > 0xffff)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "invalid port number (%u)\n", port);
		goto error;
	}

	if(comp->rtp_ports[0] == 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "can not remove UDP port %u, the list is empty\n", port);
		goto error;
	}

	/* explore the table (table is sorted in ascending order)
	   and remove the port if found */
	for(idx = 0; idx < MAX_RTP_PORTS && !is_found; idx++)
	{
		int i;

		/* if the current entry in table is empty or if the current entry
		   in table is greater than the port to remove, stop search */
		if(comp->rtp_ports[idx] == 0 || comp->rtp_ports[idx] > port)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "port %u is not in the list\n", port);
			goto error;
		}

		/* skip the table entry if the searched port is greater */
		if(port > comp->rtp_ports[idx])
		{
			continue;
		}

		/* the port matches, remove it from the table */
		/* move other entries to erase the current entry */
		for(i = idx; i < (MAX_RTP_PORTS - 1); i++)
		{
			comp->rtp_ports[i] = comp->rtp_ports[i + 1];
		}

		/* be sure to mark the last entry as unused */
		comp->rtp_ports[MAX_RTP_PORTS - 1] = 0;

		/* deactivate all contexts which used this port */
		for(i = 0; i < comp->num_contexts; i++)
		{
			if(comp->contexts[i].used &&
			   comp->contexts[i].profile->use_udp_port(&comp->contexts[i],
			                                           htons(port)))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "destroy context with CID %d because it uses "
				           "UDP port %u that is removed from the list of "
				           "RTP ports\n", i, port);
				comp->contexts[i].profile->destroy(&comp->contexts[i]);
				comp->contexts[i].used = 0;
				comp->num_contexts_used--;
			}
		}

		/* the port was found */
		is_found = true;
	}

	/* all the list was explored, the port is not in the list */
	if(idx == MAX_RTP_PORTS)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "port %u is not in the list\n", port);
		goto error;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "port %u removed from the RTP port list\n", port);

	/* everything is fine */
	return true;

error:
	return false;
}


/**
 * @brief Reset the list of dedicated RTP ports
 *
 * @param comp  The ROHC compressor
 * @return      true on success, false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_reset_rtp_ports(struct rohc_comp *const comp)
{
	unsigned int idx;

	/* sanity check on compressor */
	if(comp == NULL)
	{
		goto error;
	}

	/* set all the table entries to 0 stopping on the first unused entry */
	for(idx = 0; idx < MAX_RTP_PORTS && comp->rtp_ports[idx] != 0; idx++)
	{
		comp->rtp_ports[idx] = 0;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "RTP port list is now reset\n");

	return true;

error:
	return false;
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
	buffer += sprintf(buffer, "%s\t<mrru>%zd</mrru>\n", prefix, comp->mrru);
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
 * @deprecated do not use this function anymore,
 *             use rohc_comp_piggyback_feedback() instead
 *
 * @param comp     The ROHC compressor
 * @param feedback The feedback data
 * @param size     The length of the feedback packet
 */
void c_piggyback_feedback(struct rohc_comp *comp,
                          unsigned char *feedback,
                          int size)
{
	bool __attribute__((unused)) ret; /* avoid warn_unused_result */
	ret = rohc_comp_piggyback_feedback(comp, feedback, size);
}


/**
 * @brief Add a feedback packet to the next outgoing ROHC packet (piggybacking)
 *
 * @param comp     The ROHC compressor
 * @param feedback The feedback data
 * @param size     The length of the feedback packet
 * @return         true in case of success, false otherwise
 */
bool rohc_comp_piggyback_feedback(struct rohc_comp *const comp,
                                  const unsigned char *const feedback,
                                  const size_t size)

{
	/* ignore feedback if no valid compressor nor feedback is provided */
	if(comp == NULL || feedback == NULL || size <= 0)
	{
		goto error;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "try to add %zd "
	           "byte(s) of feedback to the next outgoing ROHC packet\n", size);
	assert(comp->feedbacks_next >= 0);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_first >= 0);
	assert(comp->feedbacks_first < FEEDBACK_RING_SIZE);

	/* If first and next feedbacks are equals, the ring is either empty or full.
	 * If the first feedback is 0-byte length, then the ring is empty. */
	if(comp->feedbacks_next == comp->feedbacks_first &&
	   comp->feedbacks[comp->feedbacks_first].length != 0)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no place in buffer for feedback data\n");
		goto error;
	}

	/* allocate memory for new feedback data */
	comp->feedbacks[comp->feedbacks_next].data = malloc(size);
	if(comp->feedbacks[comp->feedbacks_next].data == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no memory for feedback data\n");
		goto error;
	}

	/* record new feedback data in the ring */
	memcpy(comp->feedbacks[comp->feedbacks_next].data, feedback, size);
	comp->feedbacks[comp->feedbacks_next].length = size;
	comp->feedbacks[comp->feedbacks_next].is_locked = false;

	/* use the next ring location next time */
	comp->feedbacks_next = (comp->feedbacks_next + 1) % FEEDBACK_RING_SIZE;

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "%zd byte(s) of feedback added to the next outgoing "
	           "ROHC packet\n", size);

	return true;

error:
	return false;
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
		/* no compressor associated with decompressor, cannot deliver feedback */
		goto quit;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "deliver %d byte(s) of feedback to the right context\n", size);

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
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to decode SDVL-encoded large CID field\n");
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

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "feedback CID = %d\n", feedback.cid);

	feedback.specific_size = size - (p - packet);
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "feedback size = %d\n", feedback.specific_size);

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
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no memory for feedback data\n");
		goto quit;
	}

	memcpy(feedback.data, packet, feedback.size);

	/* find context */
	c = c_get_context(comp, feedback.cid);
	if(c == NULL)
	{
		/* context was not found */
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "context not found (CID = %d)\n", feedback.cid);
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
		/* no compressor associated with decompressor */
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

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "flush %u bytes of feedback\n", size);

	return size;
}


/**
 * @brief Get some information about the last compressed packet
 *
 * @deprecated do not use this function anymore,
 *             use rohc_comp_get_last_packet_info2() instead
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
		return ROHC_ERROR;
	}

	if(comp->last_context == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "last context found in compressor is not valid\n");
		return ROHC_ERROR;
	}

	if(info == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "structure for last packet information is not valid\n");
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
 * @brief Get some information about the last compressed packet
 *
 * To use the function, call it with a pointer on a pre-allocated
 * 'rohc_comp_last_packet_info2_t' structure with the 'version_major' and
 * 'version_minor' fields set to one of the following supported versions:
 *  - Major 0, minor 0
 *
 * See rohc_comp_last_packet_info2_t for details about fields that
 * are supported in the above versions.
 *
 * @param comp  The ROHC compressor to get information from
 * @param info  IN/OUT: the structure where information will be stored
 * @return      true in case of success, false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_get_last_packet_info2(const struct rohc_comp *const comp,
                                     rohc_comp_last_packet_info2_t *const info)
{
	if(comp == NULL)
	{
		goto error;
	}

	if(comp->last_context == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "last context found in compressor is not valid\n");
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "structure for last packet information is not valid\n");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		info->context_id = comp->last_context->cid;
		info->is_context_init = (comp->last_context->num_sent_packets == 1);
		info->context_mode = comp->last_context->mode;
		info->context_state = comp->last_context->state;
		info->context_used = (comp->last_context->used ? true : false);
		info->profile_id = comp->last_context->profile->id;
		info->packet_type = comp->last_context->packet_type;
		info->total_last_uncomp_size = comp->last_context->total_last_uncompressed_size;
		info->header_last_uncomp_size = comp->last_context->header_last_uncompressed_size;
		info->total_last_comp_size = comp->last_context->total_last_compressed_size;
		info->header_last_comp_size = comp->last_context->header_last_compressed_size;

		/* new fields added by minor versions */
		if(info->version_minor > 0)
		{
			rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported minor version (%u) of the structure for "
			           "last packet information", info->version_minor);
			goto error;
		}
	}
	else
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for last "
		           "packet information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
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
		bool check_profile;

		/* skip profile if the profile is not enabled */
		if(!comp->profiles[i])
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "skip disabled profile '%s' (0x%04x)\n",
			           c_profiles[i]->description, c_profiles[i]->id);
			continue;
		}

		/* does the profile accept the packet? */
		check_profile = c_profiles[i]->check_profile(comp, outer_ip, inner_ip,
		                                             protocol);
		if(!check_profile)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "skip profile '%s' (0x%04x) because it does not "
			           "match packet\n", c_profiles[i]->description,
			           c_profiles[i]->id);
			continue;
		}

		/* the packet is compatible with the profile, let's go with it! */
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

		rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		          "enlarge the context array from %d to %d elements "
		          "(MAX_CID = %d)\n", comp->num_contexts, size,
		          comp->medium.max_cid);

		new_contexts = calloc(size, sizeof(struct c_context));
		if(new_contexts == NULL)
		{
			rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "cannot allocate memory for contexts\n");
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
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "recycle oldest context (CID = %d)\n", index);
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

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "take the first unused context (CID = %d)\n", index);
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

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "context (CID = %d) created (num_used = %d)\n",
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
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "using context CID = %d\n", c->cid);
				break;
			}
		}
	}

	if(c == NULL || i == comp->num_contexts)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no context was found\n");
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

	return &(comp->contexts[cid]);

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
		assert(comp->contexts != NULL);

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

		comp->num_contexts = 0;
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
	size_t feedback_length;
	int index = 0;

	assert(comp->feedbacks_first_unlocked >= 0);
	assert(comp->feedbacks_first_unlocked < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_next >= 0);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);

	/* are there some feedback data to send with the next outgoing packet? */
	if(comp->feedbacks_first == comp->feedbacks_next &&
	   comp->feedbacks[comp->feedbacks_first].length == 0)
	{
		/* ring buffer is empty */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no feedback is available\n");
		feedback_length = 0;
	}
	else if(comp->feedbacks_first_unlocked == comp->feedbacks_next &&
	        comp->feedbacks[comp->feedbacks_first_unlocked].length == 0)
	{
		/* ring buffer is not full, and all feedbacks are locked */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "all available feedbacks are locked\n");
		feedback_length = 0;
	}
	else if(comp->feedbacks_first_unlocked == comp->feedbacks_next &&
	        comp->feedbacks[comp->feedbacks_first_unlocked].is_locked == true)
	{
		/* ring buffer is full, and all feedbacks are locked */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "all available feedbacks are locked\n");
		feedback_length = 0;
	}
	else
	{
		size_t required_length;

		/* some feedbacks are not locked yet */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "some available feedbacks are not locked\n");

		feedback_length = comp->feedbacks[comp->feedbacks_first_unlocked].length;
		required_length = feedback_length + 1 + (feedback_length < 8 ? 0 : 1);

		/* check that there is enough space in the output buffer for the
		 * feedback data */
		if(required_length > max)
		{
			rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			          "no more room in the buffer for feedback: %zd bytes "
			          "required, only %u bytes available\n", required_length,
			          max);
			goto full;
		}

		/* the feedback length may be encoded either in the last 3 bits of the
		 * first byte or in the 2nd byte */
		if(feedback_length < 8)
		{
			/* length is small, use only 3 bits to code it */
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "use 1-byte form factor for feedback length\n");
			buffer[index] = 0xf0 | feedback_length;
			index++;
		}
		else
		{
			/* size is large, use 8 bits to code it */
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "use 2-byte form factor for feedback length\n");
			buffer[index] = 0xf0;
			index++;
			buffer[index] = feedback_length;
			index++;
		}

		/* copy feedback data in the buffer */
		memcpy(buffer + index,
		       comp->feedbacks[comp->feedbacks_first_unlocked].data,
		       feedback_length);

		/* lock the feedback */
		comp->feedbacks[comp->feedbacks_first_unlocked].is_locked = true;

		comp->feedbacks_first_unlocked =
			(comp->feedbacks_first_unlocked + 1) % FEEDBACK_RING_SIZE;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "add %zd byte(s) of feedback data\n", feedback_length);
	if(feedback_length > 0)
	{
		rohc_dump_packet(comp->trace_callback, ROHC_TRACE_COMP,
		                 ROHC_TRACE_DEBUG, "feedback data added",
		                 buffer + index, feedback_length);
	}

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
 *
 * @ingroup rohc_comp
 */
bool rohc_feedback_remove_locked(struct rohc_comp *const comp)
{
	unsigned int removed_nr = 0;

	if(comp == NULL)
	{
		/* bad compressor */
		goto error;
	}

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
		removed_nr++;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "%u locked feedbacks removed\n", removed_nr);

	assert(comp->feedbacks_first == comp->feedbacks_first_unlocked);

	return true;

error:
	return false;
}


/**
 * @brief Unlock all feedbacks locked during the packet build
 *
 * This function does not remove the locked feedbacks. See function
 * \ref rohc_feedback_remove_locked instead if you want to remove them.
 *
 * @param comp  The ROHC compressor
 * @return      true if action succeeded, false in case of error
 *
 * @ingroup rohc_comp
 */
bool rohc_feedback_unlock(struct rohc_comp *const comp)
{
	if(comp == NULL)
	{
		/* bad compressor */
		goto error;
	}

	assert(comp->feedbacks_first >= 0);
	assert(comp->feedbacks_first < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_first_unlocked >= 0);
	assert(comp->feedbacks_first_unlocked < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_next >= 0);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);

	/* unlock all the ring locations between first unlocked one (excluded)
	 * and first one */
	while(comp->feedbacks_first_unlocked != comp->feedbacks_first)
	{
		comp->feedbacks_first_unlocked =
			(comp->feedbacks_first_unlocked - 1) % FEEDBACK_RING_SIZE;

		assert(comp->feedbacks[comp->feedbacks_first_unlocked].is_locked == true);
		comp->feedbacks[comp->feedbacks_first_unlocked].is_locked = false;
	}

	assert(comp->feedbacks_first_unlocked == comp->feedbacks_first);

	return true;

error:
	return false;
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

