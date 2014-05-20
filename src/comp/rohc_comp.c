/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2013 Friedrich
 * Copyright 2009,2010 Thales Communications
 * Copyright 2007,2009,2010,2012,2013,2014 Viveris Technologies
 * Copyright 2012 WBX
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/**
 * @file rohc_comp.c
 * @brief ROHC compression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

/**
 * @defgroup rohc_comp  The ROHC compression API
 *
 * The compression API of the ROHC library allows a program to compress the
 * protocol headers of some uncompressed packets into ROHC packets.
 *
 * The program shall first create a compressor context and configure it. It
 * then may compress as many packets as needed. When done, the ROHC compressor
 * context shall be destroyed.
 */

#include "rohc_comp.h"
#include "rohc_comp_internals.h"
#include "rohc_packets.h"
#include "rohc_traces.h"
#include "rohc_traces_internal.h"
#include "rohc_time_internal.h"
#include "rohc_debug.h"
#include "rohc_utils.h"
#include "sdvl.h"
#include "rohc_add_cid.h"
#include "ip.h"
#include "crc.h"
#include "protocols/udp.h"
#include "protocols/ip_numbers.h"

#include "config.h" /* for PACKAGE_(NAME|URL|VERSION) */

#ifndef __KERNEL__
#	include <string.h>
#endif
#include <stdlib.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif
#include <assert.h>
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
#include <stdio.h> /* for printf(3) */
#endif
#include <stdarg.h>


extern const struct rohc_comp_profile c_rtp_profile,
                                      c_udp_profile,
                                      c_udp_lite_profile,
                                      c_esp_profile,
                                      c_tcp_profile,
                                      c_ip_profile,
                                      c_uncompressed_profile;

/**
 * @brief The compression parts of the ROHC profiles.
 *
 * The order of profiles declaration is important: they are evaluated in that
 * order. The RTP profile shall be declared before the UDP one for example.
 */
static const struct rohc_comp_profile *const
	rohc_comp_profiles[C_NUM_PROFILES] =
{
	&c_rtp_profile,
	&c_udp_profile,  /* must be declared after RTP profile */
	&c_udp_lite_profile,
	&c_esp_profile,
	&c_tcp_profile,
	&c_ip_profile,  /* must be declared after all IP-based profiles */
	&c_uncompressed_profile, /* must be declared last */
};


/*
 * Prototypes of private functions related to ROHC compression profiles
 */

static const struct rohc_comp_profile *
	rohc_get_profile_from_id(const struct rohc_comp *comp,
	                         const rohc_profile_t profile_id)
	__attribute__((warn_unused_result, nonnull(1)));

static const struct rohc_comp_profile *
	c_get_profile_from_packet(const struct rohc_comp *const comp,
	                          const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));


/*
 * Prototypes of private functions related to ROHC compression contexts
 */

static bool c_create_contexts(struct rohc_comp *const comp);
static void c_destroy_contexts(struct rohc_comp *const comp);

static struct rohc_comp_ctxt *
	c_create_context(struct rohc_comp *const comp,
	                 const struct rohc_comp_profile *const profile,
	                 const struct net_pkt *const packet,
	                 const struct rohc_ts arrival_time)
    __attribute__((nonnull(1, 2, 3), warn_unused_result));
static struct rohc_comp_ctxt *
	rohc_comp_find_ctxt(struct rohc_comp *const comp,
	                    const struct net_pkt *const packet,
	                    const int profile_id_hint,
	                    const struct rohc_ts arrival_time)
	__attribute__((nonnull(1, 2), warn_unused_result));
static struct rohc_comp_ctxt *
	c_get_context(struct rohc_comp *const comp, const rohc_cid_t cid)
	__attribute__((nonnull(1), warn_unused_result));


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

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
static void rohc_comp_print_trace_default(const rohc_trace_level_t level,
                                          const rohc_trace_entity_t entity,
                                          const int profile,
                                          const char *const format,
                                          ...)
	__attribute__((format(printf, 4, 5), nonnull(4)));

static void __rohc_c_set_max_cid(struct rohc_comp *comp, int value);

#endif /* !ROHC_ENABLE_DEPRECATED_API */

static int rohc_comp_get_random_default(const struct rohc_comp *const comp,
                                        void *const user_context)
	__attribute__((nonnull(1)));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
static int __rohc_c_context(struct rohc_comp *comp,
                            int cid,
                            unsigned int indent,
                            char *buffer);
#endif /* !ROHC_ENABLE_DEPRECATED_API */


/*
 * Definitions of public functions
 */


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Create one ROHC compressor
 *
 * @deprecated do not use this function anymore, use rohc_comp_new() instead
 *
 * @param max_cid     The maximal CID value the compressor should use for contexts
 * @param jam_use     not used anymore, must be 0
 * @param adapt_size  not used anymore, ignored
 * @param encap_size  not used anymore, ignored
 * @return            The newly-created compressor if successful,
 *                    NULL otherwise
 *
 * @warning Don't forget to free compressor memory with
 *          \ref rohc_free_compressor if \e rohc_alloc_compressor succeeded
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_free_compressor
 * @see rohc_comp_set_traces_cb
 * @see rohc_comp_set_random_cb
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_enable_profile
 * @see rohc_comp_disable_profiles
 * @see rohc_comp_disable_profile
 * @see rohc_comp_set_wlsb_window_width
 * @see rohc_comp_set_periodic_refreshes
 * @see rohc_comp_set_rtp_detection_cb
 * @see rohc_comp_reset_rtp_ports
 * @see rohc_comp_add_rtp_port
 * @see rohc_comp_remove_rtp_port
 */
struct rohc_comp * rohc_alloc_compressor(int max_cid,
                                         int jam_use,
                                         int adapt_size,
                                         int encap_size)
{
	if(jam_use != 0 || adapt_size != 0 || encap_size != 0)
	{
		/* the jamming algorithm was removed, please set jam_use, adapt_size,
		 * and encap_size to 0 */
		goto error;
	}

	return rohc_comp_new(ROHC_SMALL_CID, max_cid);

error:
	return NULL;
}


/**
 * @brief Destroy one ROHC compressor.
 *
 * Destroy a ROHC compressor that was successfully created with
 * \ref rohc_alloc_compressor
 *
 * @deprecated do not use this function anymore, use rohc_comp_free() instead
 *
 * @param comp The compressor to destroy
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_alloc_compressor
 */
void rohc_free_compressor(struct rohc_comp *comp)
{
	rohc_comp_free(comp);
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Create a new ROHC compressor
 *
 * Create a new ROHC compressor with the given type of CIDs and MAX_CID.
 *
 * @param cid_type  The type of Context IDs (CID) that the ROHC compressor
 *                  shall operate with.
 *                  Accepted values are:
 *                    \li \ref ROHC_SMALL_CID for small CIDs
 *                    \li \ref ROHC_LARGE_CID for large CIDs
 * @param max_cid   The maximum value that the ROHC compressor should use for
 *                  context IDs (CID). As CIDs starts with value 0, the number
 *                  of contexts is \e max_cid + 1. \n
 *                  Accepted values are:
 *                    \li [0, \ref ROHC_SMALL_CID_MAX] if \e cid_type is
 *                        \ref ROHC_SMALL_CID
 *                    \li [0, \ref ROHC_LARGE_CID_MAX] if \e cid_type is
 *                        \ref ROHC_LARGE_CID
 * @return          The created compressor if successful,
 *                  NULL if creation failed
 *
 * @warning Don't forget to free compressor memory with \ref rohc_comp_free
 *          if \e rohc_comp_new succeeded
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_comp_free
 * @see rohc_compress4
 * @see rohc_comp_set_traces_cb
 * @see rohc_comp_set_random_cb
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_enable_profile
 * @see rohc_comp_disable_profiles
 * @see rohc_comp_disable_profile
 * @see rohc_comp_set_mrru
 * @see rohc_comp_set_wlsb_window_width
 * @see rohc_comp_set_periodic_refreshes
 * @see rohc_comp_set_rtp_detection_cb
 * @see rohc_comp_reset_rtp_ports
 * @see rohc_comp_add_rtp_port
 * @see rohc_comp_remove_rtp_port
 */
struct rohc_comp * rohc_comp_new(const rohc_cid_type_t cid_type,
                                 const rohc_cid_t max_cid)
{
	const size_t wlsb_width = 4; /* default window width for W-LSB encoding */
	struct rohc_comp *comp;
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

	/* allocate memory for the ROHC compressor */
	comp = malloc(sizeof(struct rohc_comp));
	if(comp == NULL)
	{
		goto error;
	}
	memset(comp, 0, sizeof(struct rohc_comp));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	comp->enabled = 1;
#endif
	comp->medium.cid_type = cid_type;
	comp->medium.max_cid = max_cid;
	comp->mrru = 0; /* no segmentation by default */

	/* all compression profiles are disabled by default */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		comp->enabled_profiles[i] = false;
	}

	/* reset the list of UDP ports for RTP */
	for(i = 0; i < MAX_RTP_PORTS; i++)
	{
		comp->rtp_ports[i] = 0;
	}

	/* reset statistics */
	comp->num_packets = 0;
	comp->total_compressed_size = 0;
	comp->total_uncompressed_size = 0;
	comp->last_context = NULL;

	/* set the default W-LSB window width */
	is_fine = rohc_comp_set_wlsb_window_width(comp, wlsb_width);
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

	/* set the default number of uncompressed transmissions for list
	 * compression */
	is_fine = rohc_comp_set_list_trans_nr(comp, ROHC_LIST_DEFAULT_L);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

	/* set default callback for random numbers */
	is_fine = rohc_comp_set_random_cb(comp, rohc_comp_get_random_default, NULL);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
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
#endif /* !ROHC_ENABLE_DEPRECATED_API */

	/* init the tables for fast CRC computation */
	is_fine = rohc_crc_init_table(comp->crc_table_3, ROHC_CRC_TYPE_3);
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

	/* create the MAX_CID + 1 contexts */
	if(!c_create_contexts(comp))
	{
		goto destroy_comp;
	}

	/* set default callback for traces */
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	/* keep same behaviour as previous 1.x.y versions: traces on by default */
	is_fine = rohc_comp_set_traces_cb(comp, rohc_comp_print_trace_default);
	if(is_fine != true)
	{
		goto destroy_comp;
	}
#endif

	return comp;

destroy_comp:
	zfree(comp);
error:
	return NULL;
}


/**
 * @brief Destroy the given ROHC compressor
 *
 * Destroy a ROHC compressor that was successfully created with
 * \ref rohc_comp_new
 *
 * @param comp  The ROHC compressor to destroy
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_comp_new
 */
void rohc_comp_free(struct rohc_comp *const comp)
{
	if(comp != NULL)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "free ROHC compressor");

		/* free memory used by contexts */
		c_destroy_contexts(comp);

		/* destroy unsent piggybacked feedback */
		rohc_feedback_destroy(comp);

		/* free the compressor */
		free(comp);
	}
}


/**
 * @brief Set the callback function used to manage traces in compressor
 *
 * Set the user-defined callback function used to manage traces in the
 * compressor.
 *
 * The function will be called by the ROHC library every time it wants to
 * print something related to compression, from errors to debug. User may
 * thus decide what traces are interesting (filter on \e level, source
 * \e entity, or \e profile) and what to do with them (print on console,
 * storage in file, syslog...).
 *
 * @warning The callback can not be modified after library initialization
 *
 * @param comp     The ROHC compressor
 * @param callback Two possible cases:
 *                   \li The callback function used to manage traces
 *                   \li NULL to remove the previous callback
 * @return         true on success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet rtp_detection.c define compression traces callback
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet rtp_detection.c set compression traces callback
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
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
		           "modify the trace callback after initialization");
		goto error;
	}

	/* replace current trace callback by the new one */
	comp->trace_callback = callback;

	return true;

error:
	return false;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

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
 * @param ...      The arguments related to the format string
 */
static void rohc_comp_print_trace_default(const rohc_trace_level_t level __attribute__((unused)),
                                          const rohc_trace_entity_t entity __attribute__((unused)),
                                          const int profile __attribute__((unused)),
                                          const char *const format,
                                          ...)
{
#ifndef __KERNEL__ /* TODO */
	va_list args;
#ifndef __KERNEL__
	static bool first_time = true;

	/* display a warning with the first message */
	if(first_time)
	{
		printf("please define a callback for compressor traces\n");
		first_time = false;
	}
#endif

	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
#endif
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Set the user-defined callback for random numbers
 *
 * Set the user-defined callback for random numbers. The callback is called
 * by the ROHC library every time a new random number is required. It
 * currently happens only to initiate the Sequence Number (SN) of new IP-only,
 * IP/UDP, or IP/UDP-Lite streams to a random value as defined by RFC 3095.
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
 *
 * \par Example:
 * \snippet rtp_detection.c define random callback 2
 * \code
        ...
\endcode
 * \snippet rtp_detection.c define random callback 1
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet rtp_detection.c set random callback
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_comp_random_cb_t
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
	             "please define a callback for random numbers");

	return 0;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Compress the given uncompressed packet into a ROHC packet
 *
 * @deprecated do not use this function anymore,
 *             use rohc_compress4() instead
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
	const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	const struct rohc_buf uncomp_packet =
		rohc_buf_init_full(ibuf, isize, arrival_time);
	struct rohc_buf rohc_packet = rohc_buf_init_empty(obuf, osize);
	int code;

	if(ibuf == NULL || isize <= 0 || obuf == NULL || osize <= 0)
	{
		goto error;
	}

	/* use the new function to keep API compatibility */
	code = rohc_compress4(comp, uncomp_packet, &rohc_packet);
	if(code != ROHC_OK)
	{
		/* compression failed */
		goto error;
	}

	/* compression succeeded */
	return rohc_packet.len;

error:
	return 0;
}


/**
 * @brief Compress the given uncompressed packet into a ROHC packet
 *
 * May return a full ROHC packet, or a segment of a ROHC packet if the output
 * buffer was too small for the ROHC packet or if MRRU was exceeded. Use the
 * rohc_comp_get_segment function to retrieve next ROHC segments.
 *
 * @deprecated do not use this function anymore,
 *             use rohc_compress4() instead
 *
 * @param comp                 The ROHC compressor
 * @param uncomp_packet        The uncompressed packet to compress
 * @param uncomp_packet_len    The size of the uncompressed packet
 * @param rohc_packet          The buffer where to store the ROHC packet
 * @param rohc_packet_max_len  The maximum length (in bytes) of the buffer
 *                             for the ROHC packet
 * @param[out] rohc_packet_len The length (in bytes) of the ROHC packet
 * @return                     \li \e ROHC_OK if a ROHC packet is returned
 *                             \li \e ROHC_NEED_SEGMENT if no compressed data
 *                                 is returned and segmentation required
 *                             \li \e ROHC_ERROR if an error occurred
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
	struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
	const struct rohc_buf __uncomp_packet =
		rohc_buf_init_full((uint8_t *) uncomp_packet, uncomp_packet_len,
		                   arrival_time);
	struct rohc_buf __rohc_packet =
		rohc_buf_init_empty(rohc_packet, rohc_packet_max_len);
	int code;

	if(rohc_packet_len == NULL)
	{
		return ROHC_ERROR;
	}

	code = rohc_compress4(comp, __uncomp_packet, &__rohc_packet);
	if(code == ROHC_OK)
	{
		*rohc_packet_len = __rohc_packet.len;
	}

	return code;
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Compress the given uncompressed packet into a ROHC packet
 *
 * Compress the given uncompressed packet into a ROHC packet. The compression
 * may succeed into two different ways:
 *   \li return \ref ROHC_OK and a full ROHC packet,
 *   \li return \ref ROHC_NEED_SEGMENT and no ROHC data if ROHC segmentation
 *       is required.
 *
 * The ROHC compressor has to use ROHC segmentation if the output buffer
 * rohc_packet was too small for the compressed ROHC packet and if the
 * Maximum Reconstructed Reception Unit (MRRU) configured with the function
 * \ref rohc_comp_set_mrru was not exceeded. If ROHC segmentation is used, one
 * may use the \ref rohc_comp_get_segment function to retrieve all the ROHC
 * segments one by one.
 *
 * @param comp                  The ROHC compressor
 * @param arrival_time          The time at which packet was received
 *                              (0 if unknown, or to disable time-related
 *                               features in the ROHC protocol)
 * @param uncomp_packet         The uncompressed packet to compress
 * @param uncomp_packet_len     The size of the uncompressed packet
 * @param rohc_packet           The buffer where to store the ROHC packet
 * @param rohc_packet_max_len   The maximum length (in bytes) of the buffer
 *                              for the ROHC packet
 * @param[out] rohc_packet_len  The length (in bytes) of the ROHC packet
 * @return                      Possible return values:
 *                              \li \ref ROHC_OK if a ROHC packet is returned
 *                              \li \ref ROHC_NEED_SEGMENT if no ROHC data is
 *                                  returned and ROHC segments can be
 *                                  retrieved with \ref rohc_comp_get_segment
 *                              \li \ref ROHC_ERROR if an error occurred
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
	const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
\endcode
 * \code
	unsigned char ip_packet[BUFFER_SIZE];   // the buffer that will contain
	                                        // the IPv4 packet to compress
	size_t ip_packet_len;                   // the length (in bytes) of the
	                                        // IPv4 packet
	unsigned char rohc_packet[BUFFER_SIZE]; // the buffer that will contain
	                                        // the resulting ROHC packet
	size_t rohc_packet_len;                 // the length (in bytes) of the
	                                        // resulting ROHC packet
	...
\endcode
 * \code
	ret = rohc_compress3(compressor, arrival_time, ip_packet, ip_packet_len,
	                     rohc_packet, BUFFER_SIZE, &rohc_packet_len);
\endcode
 * \snippet simple_rohc_program.c compress IP packet #2
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #3
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #4
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #5
 * \code
	...
\endcode
 *
 * @see rohc_comp_set_mrru
 * @see rohc_comp_get_segment
 */
int rohc_compress3(struct rohc_comp *const comp,
                   const struct rohc_ts arrival_time,
                   const unsigned char *const uncomp_packet,
                   const size_t uncomp_packet_len,
                   unsigned char *const rohc_packet,
                   const size_t rohc_packet_max_len,
                   size_t *const rohc_packet_len)
{
	const struct rohc_buf __uncomp_packet =
		rohc_buf_init_full((uint8_t *) uncomp_packet, uncomp_packet_len,
		                   arrival_time);
	struct rohc_buf __rohc_packet =
		rohc_buf_init_empty(rohc_packet, rohc_packet_max_len);
	int code;

	if(rohc_packet_len == NULL)
	{
		return ROHC_ERROR;
	}

	code = rohc_compress4(comp, __uncomp_packet, &__rohc_packet);
	if(code == ROHC_OK)
	{
		*rohc_packet_len = __rohc_packet.len;
	}

	return code;
}


/**
 * @brief Compress the given uncompressed packet into a ROHC packet
 *
 * Compress the given uncompressed packet into a ROHC packet. The compression
 * may succeed into two different ways:
 *   \li return \ref ROHC_OK and a full ROHC packet,
 *   \li return \ref ROHC_NEED_SEGMENT and no ROHC data if ROHC segmentation
 *       is required.
 *
 * \par ROHC segmentation:
 * The ROHC compressor has to use ROHC segmentation if the output buffer
 * rohc_packet was too small for the compressed ROHC packet and if the
 * Maximum Reconstructed Reception Unit (MRRU) configured with the function
 * \ref rohc_comp_set_mrru was not exceeded. If ROHC segmentation is used, one
 * may use the \ref rohc_comp_get_segment function to retrieve all the ROHC
 * segments one by one.
 *
 * \par Time-related features in the ROHC protocol:
 * Set the \e uncomp_packet.time parameter to 0 if arrival time of the
 * uncompressed packet is unknown or to disable the time-related features in
 * the ROHC protocol.
 *
 * @param comp              The ROHC compressor
 * @param uncomp_packet     The uncompressed packet to compress
 * @param[out] rohc_packet  The resulting compressed ROHC packet
 * @return                  Possible return values:
 *                          \li \ref ROHC_OK if a ROHC packet is returned
 *                          \li \ref ROHC_NEED_SEGMENT if no ROHC data is
 *                              returned and ROHC segments can be retrieved
 *                              with successive calls to
 *                              \ref rohc_comp_get_segment
 *                          \li \ref ROHC_ERROR if an error occurred
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \snippet simple_rohc_program.c define IP and ROHC packets
 * \code
	...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #1
 * \snippet simple_rohc_program.c compress IP packet #2
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #3
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #4
 * \code
		...
\endcode
 * \snippet simple_rohc_program.c compress IP packet #5
 * \code
	...
\endcode
 *
 * @see rohc_comp_set_mrru
 * @see rohc_comp_get_segment
 */
int rohc_compress4(struct rohc_comp *const comp,
                   const struct rohc_buf uncomp_packet,
                   struct rohc_buf *const rohc_packet)
{
	struct net_pkt ip_pkt;
	struct rohc_comp_ctxt *c;
	rohc_packet_t packet_type;
	size_t feedbacks_size;
	int feedback_size;
	int rohc_hdr_size;
	size_t payload_size;
	size_t payload_offset;

	int status = ROHC_ERROR; /* error status by default */

	/* check inputs validity */
	if(comp == NULL ||
	   rohc_buf_is_malformed(uncomp_packet) ||
	   rohc_buf_is_empty(uncomp_packet) ||
	   rohc_packet == NULL ||
	   rohc_buf_is_malformed(*rohc_packet) ||
	   !rohc_buf_is_empty(*rohc_packet))
	{
		goto error;
	}

#if ROHC_EXTRA_DEBUG == 1
	/* print uncompressed bytes */
	rohc_dump_packet(comp->trace_callback, ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	                 "uncompressed data, max 100 bytes", uncomp_packet);
#endif

	/* parse the uncompressed packet */
	if(!net_pkt_parse(&ip_pkt, uncomp_packet, comp->trace_callback,
	                  ROHC_TRACE_COMP))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to parse uncompressed packet");
		goto error;
	}

	/* find the best context for the packet */
	c = rohc_comp_find_ctxt(comp, &ip_pkt, -1, uncomp_packet.time);
	if(c == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to find a matching context or to create a new "
		             "context");
		goto error;
	}

	/* create the ROHC packet: */
	rohc_packet->len = 0;

	/* 1. add feedback */
	feedbacks_size = 0;
	do
	{
		feedback_size =
			rohc_feedback_get(comp, rohc_buf_data_at(*rohc_packet, feedbacks_size),
			                  rohc_buf_avail_len(*rohc_packet));
		if(feedback_size > 0)
		{
			feedbacks_size += feedback_size;
		}
	}
	while(feedback_size > 0 && feedbacks_size <= 500);
	rohc_packet->len += feedbacks_size;

	/* the ROHC header starts after the feedbacks, skip them */
	rohc_buf_shift(rohc_packet, feedbacks_size);

	/* 2. use profile to compress packet */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "compress the packet #%d", comp->num_packets + 1);
	rohc_hdr_size =
		c->profile->encode(c, &ip_pkt, rohc_buf_data(*rohc_packet),
		                   rohc_buf_avail_len(*rohc_packet),
		                   &packet_type, &payload_offset);
	if(rohc_hdr_size < 0)
	{
		/* error while compressing, use the Uncompressed profile */
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "error while compressing with the profile, using "
		             "uncompressed profile");

		/* free context if it was just created */
		if(c->num_sent_packets <= 1)
		{
			c->profile->destroy(c);
			c->used = 0;
			assert(comp->num_contexts_used > 0);
			comp->num_contexts_used--;
		}

		/* find the best context for the Uncompressed profile */
		c = rohc_comp_find_ctxt(comp, &ip_pkt, ROHC_PROFILE_UNCOMPRESSED,
		                        uncomp_packet.time);
		if(c == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to find a matching Uncompressed context or to "
			             "create a new Uncompressed context");
			goto error_unlock_feedbacks;
		}

		/* use the Uncompressed profile to compress the packet */
		rohc_hdr_size =
			c->profile->encode(c, &ip_pkt, rohc_buf_data(*rohc_packet),
			                   rohc_buf_avail_len(*rohc_packet),
			                   &packet_type, &payload_offset);
		if(rohc_hdr_size < 0)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "error while compressing with uncompressed profile, "
			             "giving up");
			goto error_free_new_context;
		}
	}
	rohc_packet->len += rohc_hdr_size;

	/* the payload starts after the header, skip it */
	rohc_buf_shift(rohc_packet, rohc_hdr_size);
	payload_size = ip_pkt.len - payload_offset;

	/* is packet too large for output buffer? */
	if(payload_size > rohc_buf_avail_len(*rohc_packet))
	{
		const size_t max_rohc_buf_len =
			rohc_buf_avail_len(*rohc_packet) + feedbacks_size + rohc_hdr_size;
		uint32_t rru_crc;

		/* resulting ROHC packet too large, segmentation may be a solution */
		rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		          "%s ROHC packet is too large for the given output buffer, "
		          "try to segment it (input size = %zd, maximum output "
		          "size = %zd, required output size = %zd + %d + %zd = %zd, "
		          "MRRU = %zd)", rohc_get_packet_descr(packet_type),
		          uncomp_packet.len, max_rohc_buf_len, feedbacks_size,
		          rohc_hdr_size, payload_size, feedbacks_size +
		          rohc_hdr_size + payload_size, comp->mrru);

		/* in order to be segmented, a ROHC packet shall be <= MRRU
		 * (remember that MRRU includes the CRC length) */
		if((payload_size + CRC_FCS32_LEN) > comp->mrru)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "%s ROHC packet cannot be segmented: too large (%zu + "
			             "%d + %zu + %u = %zu bytes) for MRRU (%zu bytes)",
			             rohc_get_packet_descr(packet_type), feedbacks_size,
			             rohc_hdr_size, payload_size, CRC_FCS32_LEN,
			             feedbacks_size + rohc_hdr_size + payload_size +
			             CRC_FCS32_LEN, comp->mrru);
			goto error_free_new_context;
		}
		rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		          "%s ROHC packet can be segmented (MRRU = %zd)",
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
			             "support for ROHC segments in your application)",
			             comp->rru_len);
		}
		comp->rru_len = 0;
		comp->rru_off = 0;
		/* ROHC header */
		rohc_buf_shift(rohc_packet, -rohc_hdr_size);
		memcpy(comp->rru + comp->rru_off, rohc_buf_data(*rohc_packet),
		       rohc_hdr_size);
		comp->rru_len += rohc_hdr_size;
		rohc_buf_shift(rohc_packet, rohc_hdr_size);
		/* ROHC payload */
		memcpy(comp->rru + comp->rru_off + comp->rru_len,
		       rohc_buf_data_at(uncomp_packet, payload_offset), payload_size);
		comp->rru_len += payload_size;
		/* compute FCS-32 CRC over header and payload (optional feedbacks and
		   the CRC field itself are excluded) */
		rru_crc = crc_calc_fcs32(comp->rru + comp->rru_off, comp->rru_len,
		                         CRC_INIT_FCS32);
		memcpy(comp->rru + comp->rru_off + comp->rru_len, &rru_crc,
		       CRC_FCS32_LEN);
		comp->rru_len += CRC_FCS32_LEN;
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "RRU 32-bit FCS CRC = 0x%08x", rohc_ntoh32(rru_crc));
		/* computed RRU must be <= MRRU */
		assert(comp->rru_len <= comp->mrru);

		/* release locked feedbacks since there are not used for the moment */
		if(rohc_feedback_unlock(comp) != true)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to remove locked feedbacks");
			goto error_free_new_context;
		}

		/* report to users that segmentation is possible */
		status = ROHC_NEED_SEGMENT;
	}
	else
	{
		/* copy full payload after ROHC header */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "copy full %zd-byte payload", payload_size);
		memcpy(rohc_buf_data(*rohc_packet),
		       rohc_buf_data_at(uncomp_packet, payload_offset), payload_size);
		rohc_packet->len += payload_size;

		/* remove locked feedbacks since compression is successful */
		if(rohc_feedback_remove_locked(comp) != true)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to remove locked feedbacks");
			goto error_free_new_context;
		}

		/* report to user that compression was successful */
		status = ROHC_OK;
	}

	/* shift back the ROHC header and feedback data */
	rohc_buf_shift(rohc_packet, -rohc_hdr_size);
	rohc_buf_shift(rohc_packet, -feedbacks_size);
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "ROHC size = %zd bytes (feedback = %zd, header = %d, "
	           "payload = %zu), output buffer size = %zu", rohc_packet->len,
	           feedbacks_size, rohc_hdr_size, payload_size,
	           rohc_buf_avail_len(*rohc_packet));

	/* update some statistics:
	 *  - compressor statistics
	 *  - context statistics (global + last packet + last 16 packets) */
	comp->num_packets++;
	comp->total_uncompressed_size += uncomp_packet.len;
	comp->total_compressed_size += rohc_packet->len;
	comp->last_context = c;

	c->packet_type = packet_type;

	c->total_uncompressed_size += uncomp_packet.len;
	c->total_compressed_size += rohc_packet->len;
	c->header_uncompressed_size += payload_offset;
	c->header_compressed_size += rohc_hdr_size;
	c->num_sent_packets++;

	c->total_last_uncompressed_size = uncomp_packet.len;
	c->total_last_compressed_size = rohc_packet->len;
	c->header_last_uncompressed_size = payload_offset;
	c->header_last_compressed_size = rohc_hdr_size;

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	rohc_stats_add(&c->total_16_uncompressed, uncomp_packet.len);
	rohc_stats_add(&c->total_16_compressed, rohc_packet->len);
	rohc_stats_add(&c->header_16_uncompressed, payload_offset);
	rohc_stats_add(&c->header_16_compressed, rohc_hdr_size);
#endif

	/* compression is successful */
	return status;

error_free_new_context:
	/* free context if it was just created */
	if(c->num_sent_packets <= 1)
	{
		c->profile->destroy(c);
		c->used = 0;
		assert(comp->num_contexts_used > 0);
		comp->num_contexts_used--;
	}
error_unlock_feedbacks:
	if(rohc_feedback_unlock(comp) != true)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to unlock feedbacks");
	}
error:
	return ROHC_ERROR;
}


/**
 * @brief Get the next ROHC segment if any
 *
 * Get the next ROHC segment if any.
 *
 * To get all the segments of one ROHC packet, call this function until
 * \ref ROHC_OK or \ref ROHC_ERROR is returned.
 *
 * @param comp      The ROHC compressor
 * @param segment   The buffer where to store the ROHC segment
 * @param max_len   The maximum length (in bytes) of the buffer for the
 *                  ROHC segment
 * @param[out] len  The length (in bytes) of the ROHC segment
 * @return          Possible return values:
 *                  \li \ref ROHC_NEED_SEGMENT if a ROHC segment is returned
 *                      and more segments are available,
 *                  \li \ref ROHC_OK if a ROHC segment is returned
 *                      and no more ROHC segment is available
 *                  \li \ref ROHC_ERROR if an error occurred
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet test_segment.c define ROHC compressor
 * \code
        ...
        // compress the IP packet with a small ROHC buffer
\endcode
 * \snippet test_segment.c segment ROHC packet #1
 * \snippet test_segment.c segment ROHC packet #2
 * \code
                        ...
                        // decompress the ROHC segment here, the function
                        // rohc_decompress4 shall return
                        // ROHC_NON_FINAL_SEGMENT
                        ...
\endcode
 * \snippet test_segment.c segment ROHC packet #3
 * \code
                // decompress the final ROHC segment here, the function
                // rohc_decompress4 shall return ROHC_OK
\endcode
 * \snippet test_segment.c segment ROHC packet #4
 * \code
                // handle compression error here
                ...
\endcode
 *
 * @see rohc_comp_get_mrru
 * @see rohc_comp_set_mrru
 * @see rohc_compress4
 */
int rohc_comp_get_segment(struct rohc_comp *const comp,
                          unsigned char *const segment,
                          const size_t max_len,
                          size_t *const len)
{
	struct rohc_buf __segment = rohc_buf_init_empty(segment, max_len);
	int ret;

	/* check input parameters
	 * (other parameters checked in rohc_comp_get_segment2) */
	if(len == NULL)
	{
		goto error;
	}

	/* no segment yet */
	*len = 0;

	/* use function from new API */
	ret = rohc_comp_get_segment2(comp, &__segment);
	if(ret == ROHC_NEED_SEGMENT || ret == ROHC_OK)
	{
		*len = __segment.len;
	}

	return ret;

error:
	return ROHC_ERROR;
}


/**
 * @brief Get the next ROHC segment if any
 *
 * Get the next ROHC segment if any.
 *
 * To get all the segments of one ROHC packet, call this function until
 * \ref ROHC_OK or \ref ROHC_ERROR is returned.
 *
 * @param comp          The ROHC compressor
 * @param[out] segment  The buffer where to store the ROHC segment
 * @return              Possible return values:
 *                       \li \ref ROHC_NEED_SEGMENT if a ROHC segment is
 *                           returned and more segments are available,
 *                       \li \ref ROHC_OK if a ROHC segment is returned
 *                           and no more ROHC segment is available
 *                       \li \ref ROHC_ERROR if an error occurred
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet test_segment.c define ROHC compressor
 * \code
        ...
        // compress the IP packet with a small ROHC buffer
\endcode
 * \snippet test_segment.c segment ROHC packet #1
 * \snippet test_segment.c segment ROHC packet #2
 * \code
                        ...
                        // decompress the ROHC segment here, the function
                        // rohc_decompress4 shall return
                        // ROHC_NON_FINAL_SEGMENT
                        ...
\endcode
 * \snippet test_segment.c segment ROHC packet #3
 * \code
                // decompress the final ROHC segment here, the function
                // rohc_decompress4 shall return ROHC_OK
\endcode
 * \snippet test_segment.c segment ROHC packet #4
 * \code
                // handle compression error here
                ...
\endcode
 *
 * @see rohc_comp_get_mrru
 * @see rohc_comp_set_mrru
 * @see rohc_compress4
 */
int rohc_comp_get_segment2(struct rohc_comp *const comp,
                           struct rohc_buf *const segment)

{
	const size_t segment_type_len = 1; /* segment type byte */
	size_t feedbacks_size;
	int feedback_size;
	size_t max_data_len;
	int status;

	/* check input parameters */
	if(comp == NULL)
	{
		goto error;
	}
	if(segment == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given segment cannot be NULL");
		goto error;
	}
	if(rohc_buf_is_malformed(*segment))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given segment is malformed");
		goto error;
	}
	if(!rohc_buf_is_empty(*segment))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given segment is not empty");
		goto error;
	}

	/* no segment yet */
	segment->len = 0;

	/* abort if no RRU is available in the compressor */
	if(comp->rru_len <= 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "no RRU available in given compressor");
		goto error;
	}

	/* abort is the given output buffer is too small for RRU */
	if(rohc_buf_avail_len(*segment) <= segment_type_len)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "output buffer is too small for RRU, more than %zd bytes "
		             "are required", segment_type_len);
		goto error;
	}

	/* add feedbacks if some are available */
	feedbacks_size = 0;
	do
	{
		feedback_size = rohc_feedback_get(comp, rohc_buf_data(*segment),
		                                  rohc_buf_avail_len(*segment));
		if(feedback_size > 0)
		{
			segment->len += feedback_size;
			rohc_buf_shift(segment, feedback_size);
			feedbacks_size += feedback_size;
		}
	}
	while(feedback_size > 0);
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "%zu bytes of feedback added to ROHC packet", feedbacks_size);

	/* how many bytes of ROHC packet can we put in that new segment? */
	max_data_len = rohc_min(rohc_buf_avail_len(*segment) - segment_type_len,
	                        comp->rru_len);
	assert(max_data_len > 0);
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "copy %zd bytes of the remaining %zd bytes of ROHC packet and "
	           "CRC in the segment", max_data_len, comp->rru_len);

	/* set segment type with F bit set only for last segment */
	rohc_buf_byte_at(*segment, 0) = 0xfe | (max_data_len == comp->rru_len);
	segment->len++;
	rohc_buf_shift(segment, 1);

	/* copy remaining ROHC data (CRC included) */
	memcpy(rohc_buf_data(*segment), comp->rru + comp->rru_off, max_data_len);
	segment->len += max_data_len;
	rohc_buf_shift(segment, max_data_len);
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

	/* shift backward the RRU data, header and the feedback data */
	rohc_buf_shift(segment, -(max_data_len + 1 + feedbacks_size));

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
	rohc_cid_t i;

	if(comp == NULL)
	{
		goto error;
	}

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "force re-initialization for all %zu contexts",
	          comp->num_contexts_used);

	for(i = 0; i <= comp->medium.max_cid; i++)
	{
		if(comp->contexts[i].used)
		{
			if(!comp->contexts[i].profile->reinit_context(&(comp->contexts[i])))
			{
				rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				             "failed to force re-initialization for CID %zu", i);
				goto error;
			}
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Set the window width for the W-LSB encoding scheme
 *
 * Set the window width for the Window-based Least Significant Bits (W-LSB)
 * encoding. See section 4.5.2 of RFC 3095 for more details about the encoding
 * scheme.
 *
 * The width of the W-LSB window is set to 4 by default.
 *
 * @warning The value must be a power of 2
 *
 * @warning The value can not be modified after library initialization
 *
 * @param comp   The ROHC compressor
 * @param width  The width of the W-LSB sliding window
 * @return       true in case of success, false in case of failure
 *
 * @ingroup rohc_comp
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
		             "must be a non-null positive integer", width);
		return false;
	}

	/* window width must be a power of 2 */
	if((width & (width - 1)) != 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "failed to "
		             "set width of W-LSB sliding window to %zd: window width "
		             "must be a power of 2", width);
		return false;
	}

	/* refuse to set a value if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "unable to "
		             "modify the W-LSB window width after initialization");
		return false;
	}

	comp->wlsb_window_width = width;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "width of W-LSB sliding window set to %zd", width);

	return true;
}


/**
 * @brief Set the timeout values for IR and FO periodic refreshes
 *
 * Set the timeout values for IR and FO periodic refreshes. The IR timeout
 * shall be greater than the FO timeout. Both timeouts are expressed in
 * number of compressed packets.
 *
 * The IR timeout is set to \ref CHANGE_TO_IR_COUNT by default.
 * The FO timeout is set to \ref CHANGE_TO_FO_COUNT by default.
 *
 * @warning The values can not be modified after library initialization
 *
 * @param comp        The ROHC compressor
 * @param ir_timeout  The number of packets to compress before going back
 *                    to IR state to force a context refresh
 * @param fo_timeout  The number of packets to compress before going back
 *                    to FO state to force a context refresh
 * @return            true in case of success, false in case of failure
 *
 * @ingroup rohc_comp
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
		             "FO timeout = %zd)", ir_timeout, fo_timeout);
		return false;
	}

	/* refuse to set values if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unable to modify the timeouts for periodic refreshes "
		             "after initialization");
		return false;
	}

	comp->periodic_refreshes_ir_timeout = ir_timeout;
	comp->periodic_refreshes_fo_timeout = fo_timeout;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "IR timeout for "
	          "context periodic refreshes set to %zd", ir_timeout);
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "FO timeout for "
	          "context periodic refreshes set to %zd", fo_timeout);

	return true;
}


/**
 * @brief Set the number of uncompressed transmissions for list compression
 *
 * Set the number of transmissions required for list compression. This matches
 * the L parameter described in RFC 3095 and 4815. The compressor sends the
 * list items uncompressed L times before compressing them. The compressor
 * also sends the list structure L times before compressing it out.
 *
 * The L parameter is set to \ref ROHC_LIST_DEFAULT_L by default.
 *
 * @warning The value can not be modified after library initialization
 *
 * @param comp           The ROHC compressor
 * @param list_trans_nr  The number of times the list items or the list itself
 *                       are sent uncompressed before being sent compressed
 * @return               true if the new value is accepted,
 *                       false if the value is rejected
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_list_trans_nr(struct rohc_comp *const comp,
                                 const size_t list_trans_nr)
{
	/* we need a valid compressor and a positive non-zero value for L */
	if(comp == NULL)
	{
		return false;
	}
	if(list_trans_nr <= 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "invalid "
		             "value for uncompressed transmissions of list compression "
		             "(%zu)", list_trans_nr);
		return false;
	}

	/* refuse to set values if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unable to modify the value for uncompressed transmissions"
		             " of list compression after initialization");
		return false;
	}

	comp->list_trans_nr = list_trans_nr;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "uncompressed "
	          "transmissions of list compression set to %zu", list_trans_nr);

	return true;
}


/**
 * @brief Set the RTP detection callback function
 *
 * Set or replace the callback function that the ROHC library will call to
 * detect RTP streams among other UDP streams.
 *
 * The function is called once per UDP packet to compress, with the IP and
 * UDP headers and the UDP payload. If the callback function returns true, the
 * RTP profile is used for compression, otherwise the IP/UDP profile is used
 * instead.
 *
 * Special value NULL may be used to disable the detection of RTP streams with
 * the callback method. The detection will then be based on a list of UDP
 * ports dedicated for RTP streams.
 *
 * @param comp        The ROHC compressor
 * @param callback    The callback function used to detect RTP packets
 *                    The callback is deactivated if NULL is given as parameter
 * @param rtp_private A pointer to an external memory area
 *                    provided and used by the callback user
 * @return            true on success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet rtp_detection.c define RTP detection callback
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet rtp_detection.c set RTP detection callback
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_rtp_detection_callback_t
 * @see rohc_comp_add_rtp_port
 * @see rohc_comp_remove_rtp_port
 * @see rohc_comp_reset_rtp_ports
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
 * @brief Is the given compression profile enabled for a compressor?
 *
 * Is the given compression profile enabled or disabled for a compressor?
 *
 * @param comp     The ROHC compressor
 * @param profile  The profile to ask status for
 * @return         Possible return values:
 *                  \li true if the profile exists and is enabled,
 *                  \li false if the compressor is not valid, the profile
 *                      does not exist, or the profile is disabled
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_enable_profile
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_disable_profile
 * @see rohc_comp_disable_profiles
 */
bool rohc_comp_profile_enabled(const struct rohc_comp *const comp,
                               const rohc_profile_t profile)
{
	size_t i;

	if(comp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		if(rohc_comp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == C_NUM_PROFILES)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC compression profile (ID = %d)", profile);
		goto error;
	}

	/* return profile status */
	return comp->enabled_profiles[i];

error:
	return false;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Activate a profile for a compressor
 *
 * @deprecated do not use this function anymore, use
 *             rohc_comp_enable_profile() instead
 *
 * @param comp    The ROHC compressor
 * @param profile The ID of the profile to activate
 *
 * @ingroup rohc_comp
 */
void rohc_activate_profile(struct rohc_comp *comp, int profile)
{
	size_t i;

	if(comp == NULL)
	{
		goto error;
	}

	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		if(((int) rohc_comp_profiles[i]->id) == profile)
		{
			/* mark the profile as activated */
			comp->enabled_profiles[i] = true;
			return;
		}
	}

	rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	             "unknown ROHC compression profile (ID = %d)", profile);

error:
	return;
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Enable a compression profile for a compressor
 *
 * Enable a compression profiles for a compressor.
 *
 * The ROHC compressor does not use the compression profiles that are not
 * enabled. Thus not enabling a profile might affect compression performances.
 * Compression will fail if no profile at all is enabled.
 *
 * If the profile is already enabled, nothing is performed and success is
 * reported.
 *
 * @param comp     The ROHC compressor
 * @param profile  The profile to enable
 * @return         true if the profile exists,
 *                 false if the profile does not exist
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c enable ROHC compression profile
 * \code
        ...
\endcode
 *
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_disable_profile
 * @see rohc_comp_disable_profiles
 */
bool rohc_comp_enable_profile(struct rohc_comp *const comp,
                              const rohc_profile_t profile)
{
	size_t i;

	if(comp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		if(rohc_comp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == C_NUM_PROFILES)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC compression profile (ID = %d)", profile);
		goto error;
	}

	/* mark the profile as enabled */
	comp->enabled_profiles[i] = true;
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "ROHC compression profile (ID = %d) enabled", profile);

	return true;

error:
	return false;
}


/**
 * @brief Disable a compression profile for a compressor
 *
 * Disable a compression profile for a compressor.
 *
 * The ROHC compressor does not use the compression profiles that were
 * disabled. Thus disabling a profile might affect compression performances.
 * Compression will fail if no profile at all is enabled.
 *
 * If the profile is already disabled, nothing is performed and success is
 * reported.
 *
 * @param comp     The ROHC compressor
 * @param profile  The profile to disable
 * @return         true if the profile exists,
 *                 false if the profile does not exist
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_enable_profile
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_disable_profiles
 */
bool rohc_comp_disable_profile(struct rohc_comp *const comp,
                               const rohc_profile_t profile)
{
	size_t i;

	if(comp == NULL)
	{
		goto error;
	}

	/* search the profile location */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		if(rohc_comp_profiles[i]->id == profile)
		{
			/* found */
			break;
		}
	}

	if(i == C_NUM_PROFILES)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "unknown ROHC compression profile (ID = %d)", profile);
		goto error;
	}

	/* mark the profile as disabled */
	comp->enabled_profiles[i] = false;
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "ROHC compression profile (ID = %d) disabled", profile);

	return true;

error:
	return false;
}


/**
 * @brief Enable several compression profiles for a compressor
 *
 * Enable several compression profiles for a compressor. The list of profiles
 * to enable shall stop with -1.
 *
 * The ROHC compressor does not use the compression profiles that are not
 * enabled. Thus not enabling a profile might affect compression performances.
 * Compression will fail if no profile at all is enabled.
 *
 * If one or more of the profiles are already enabled, nothing is performed
 * and success is reported.
 *
 * @param comp  The ROHC compressor
 * @param ...   The sequence of compression profiles to enable, the sequence
 *              shall be terminated by -1
 * @return      true if all of the profiles exist,
 *              false if at least one of the profiles does not exist
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c enable ROHC compression profiles
 * \code
        ...
\endcode
 *
 * @see rohc_comp_enable_profile
 * @see rohc_comp_disable_profile
 * @see rohc_comp_disable_profiles
 */
bool rohc_comp_enable_profiles(struct rohc_comp *const comp,
                               ...)
{
	va_list profiles;
	int profile_id;
	size_t err_nr = 0;
	bool is_ok;

	if(comp == NULL)
	{
		goto error;
	}

	va_start(profiles, comp);

	while((profile_id = va_arg(profiles, int)) >= 0)
	{
		is_ok = rohc_comp_enable_profile(comp, profile_id);
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
 * @brief Disable several compression profiles for a compressor
 *
 * Disable several compression profiles for a compressor. The list of profiles
 * to disable shall stop with -1.
 *
 * The ROHC compressor does not use the compression profiles that were
 * disabled. Thus disabling a profile might affect compression performances.
 * Compression will fail if no profile at all is enabled.
 *
 * If one or more of the profiles are already disabled, nothing is performed
 * and success is reported.
 *
 * @param comp  The ROHC compressor
 * @param ...   The sequence of compression profiles to disable, the sequence
 *              shall be terminated by -1
 * @return      true if all of the profiles exist,
 *              false if at least one of the profiles does not exist
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_enable_profile
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_disable_profile
 */
bool rohc_comp_disable_profiles(struct rohc_comp *const comp,
                                ...)
{
	va_list profiles;
	int profile_id;
	size_t err_nr = 0;
	bool is_ok;

	if(comp == NULL)
	{
		goto error;
	}

	va_start(profiles, comp);

	while((profile_id = va_arg(profiles, int)) >= 0)
	{
		is_ok = rohc_comp_disable_profile(comp, profile_id);
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


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Whether the compressor uses small CID or not
 *
 * @deprecated please do not use this function anymore,
 *             use rohc_comp_get_cid_type() instead
 *
 * @param comp The ROHC compressor
 * @return     Whether the compressor uses small CID or not
 *
 * @ingroup rohc_comp
 */
int rohc_c_using_small_cid(struct rohc_comp *comp)
{
	return (comp != NULL && comp->medium.cid_type == ROHC_SMALL_CID);
}


/**
 * @brief Set the maximal header size. The maximal header size is ignored
 *        for the moment.
 *
 * @deprecated do not use this function anymore,
 *             simply remove it from your code
 *
 * @param comp   The ROHC compressor
 * @param header The maximal header size
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_header(struct rohc_comp *comp __attribute__((unused)),
                       int header __attribute__((unused)))
{
	/* nothing to do */
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
 * @deprecated do not use this function anymore, use rohc_comp_set_mrru()
 *             instead
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

#endif /* !ROHC_ENABLE_DEPRECATED_API */


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
 * on the channel. No segment will be generated.
 *
 * If segmentation is enabled and used by the compressor, the function
 * \ref rohc_comp_get_segment can be used to retrieve ROHC segments.
 *
 * @param comp  The ROHC compressor
 * @param mrru  The new MRRU value (in bytes)
 * @return      true if the MRRU was successfully set, false otherwise
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet test_segment.c define ROHC compressor
 * \code
        size_t mrru = 500;
        ...
\endcode
 * \snippet test_segment.c set compressor MRRU
 * \code
        ...
\endcode
 *
 * @see rohc_comp_get_mrru
 * @see rohc_comp_get_segment
 * @see rohc_decomp_set_mrru
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
		             "unexpected MRRU value: must be in range [0, %d]",
		             ROHC_MAX_MRRU);
		goto error;
	}

	/* set new MRRU */
	comp->mrru = mrru;
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "MRRU is now set to %zd", comp->mrru);

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
 * \ref rohc_comp_get_segment can be used to retrieve ROHC segments.
 *
 * @param comp       The ROHC compressor
 * @param[out] mrru  The current MRRU value (in bytes)
 * @return           true if MRRU was successfully retrieved, false otherwise
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet test_segment.c define ROHC compressor
 * \code
        size_t mrru;
        ...
\endcode
 * \snippet test_non_regression.c get compressor MRRU
 * \code
        printf("the current MMRU at compressor is %zu bytes\n", mrru);
        ...
\endcode
 *
 * @see rohc_comp_set_mrru
 * @see rohc_comp_get_segment
 * @see rohc_decomp_set_mrru
 * @see rohc_decomp_get_mrru
 */
bool rohc_comp_get_mrru(const struct rohc_comp *const comp,
                        size_t *const mrru)
{
	if(comp == NULL || mrru == NULL)
	{
		goto error;
	}

	*mrru = comp->mrru;
	return true;

error:
	return false;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Set the maximal CID value the compressor should use
 *
 * @deprecated please do not use this function anymore, use the parameter
 *             max_cid of rohc_comp_new() instead
 *
 * @param comp  The ROHC compressor
 * @param value The new maximal CID value
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_max_cid(struct rohc_comp *comp, int value)
{
	__rohc_c_set_max_cid(comp, value);
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Get the maximal CID value the compressor uses
 *
 * Get the maximal CID value the compressor uses, ie. the \e MAX_CID parameter
 * defined in RFC 3095.
 *
 * @param comp          The ROHC compressor
 * @param[out] max_cid  The current maximal CID value
 * @return              true if MAX_CID was successfully retrieved,
 *                      false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_get_max_cid(const struct rohc_comp *const comp,
                           size_t *const max_cid)
{
	if(comp == NULL || max_cid == NULL)
	{
		goto error;
	}

	*max_cid = comp->medium.max_cid;
	return true;

error:
	return false;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Tell the compressor to use large CIDs
 *
 * @deprecated please do not use this function anymore, use the parameter
 *             cid_type of rohc_comp_new() instead
 *
 * @param comp      The ROHC compressor
 * @param large_cid Whether to use large CIDs or not
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_large_cid(struct rohc_comp *comp, int large_cid)
{
	if(comp == NULL)
	{
		return;
	}
	if(large_cid != 0 && large_cid != 1)
	{
		return;
	}

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
			__rohc_c_set_max_cid(comp, ROHC_SMALL_CID_MAX);
		}
	}
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Get the CID type that the compressor uses
 *
 * Get the CID type that the compressor currently uses.
 *
 * @param comp           The ROHC compressor
 * @param[out] cid_type  The current CID type among \ref ROHC_SMALL_CID and
 *                       \ref ROHC_LARGE_CID
 * @return               true if the CID type was successfully retrieved,
 *                       false otherwise
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_get_cid_type(const struct rohc_comp *const comp,
                            rohc_cid_type_t *const cid_type)
{
	if(comp == NULL || cid_type == NULL)
	{
		goto error;
	}

	*cid_type = comp->medium.cid_type;
	return true;

error:
	return false;
}


/**
 * @brief Add a port to the list of UDP ports dedicated for RTP traffic
 *
 * If no function callback was defined for the detection of RTP streams, the
 * detection is based on a list of UDP ports dedicated for RTP streams.
 *
 * This function allows to update the list by adding the given UDP port to the
 * list of UDP ports dedicated for RTP traffic.
 *
 * @param comp  The ROHC compressor
 * @param port  The UDP port to add in the list
 * @return      true on success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet rtp_detection.c reset RTP ports
 * \snippet rtp_detection.c add RTP port
 * \snippet rtp_detection.c remove RTP port
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_comp_remove_rtp_port
 * @see rohc_comp_reset_rtp_ports
 * @see rohc_comp_set_rtp_detection_cb
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
		             "invalid port number (%u)", port);
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
			             "port %u is already in the list", port);
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
		             "can not add a new RTP port, the list is full");
		goto error;
	}

	/* everything is fine */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "port %u added to the UDP port list for RTP traffic", port);

	return true;

error:
	return false;
}


/**
 * @brief Remove a port from the list of UDP ports dedicated to RTP traffic
 *
 * If no function callback was defined for the detection of RTP streams, the
 * detection is based on a list of UDP ports dedicated for RTP streams.
 *
 * This function allows to update the list by removing the given UDP port to
 * the list of UDP ports dedicated for RTP traffic.
 *
 * @param comp  The ROHC compressor
 * @param port  The UDP port to remove
 * @return      true on success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet rtp_detection.c reset RTP ports
 * \snippet rtp_detection.c add RTP port
 * \snippet rtp_detection.c remove RTP port
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_comp_add_rtp_port
 * @see rohc_comp_reset_rtp_ports
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
		             "invalid port number (%u)", port);
		goto error;
	}

	if(comp->rtp_ports[0] == 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "can not remove UDP port %u, the list is empty", port);
		goto error;
	}

	/* explore the table (table is sorted in ascending order)
	   and remove the port if found */
	for(idx = 0; idx < MAX_RTP_PORTS && !is_found; idx++)
	{
		rohc_cid_t i;

		/* if the current entry in table is empty or if the current entry
		   in table is greater than the port to remove, stop search */
		if(comp->rtp_ports[idx] == 0 || comp->rtp_ports[idx] > port)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "port %u is not in the list", port);
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
		for(i = 0; i <= comp->medium.max_cid; i++)
		{
			if(comp->contexts[i].used &&
			   comp->contexts[i].profile->use_udp_port(&comp->contexts[i],
			                                           rohc_hton16(port)))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "destroy context with CID %zu because it uses "
				           "UDP port %u that is removed from the list of "
				           "RTP ports", i, port);
				comp->contexts[i].profile->destroy(&comp->contexts[i]);
				comp->contexts[i].used = 0;
				assert(comp->num_contexts_used > 0);
				comp->num_contexts_used--;
			}
		}

		/* the port was found */
		is_found = true;
	}

	/* all the list was explored, the port is not in the list */
	if(idx == MAX_RTP_PORTS && !is_found)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "port %u is not in the list", port);
		goto error;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "port %u removed from the RTP port list", port);

	/* everything is fine */
	return true;

error:
	return false;
}


/**
 * @brief Reset the list of dedicated RTP ports
 *
 * If no function callback was defined for the detection of RTP streams, the
 * detection is based on a list of UDP ports dedicated for RTP streams.
 *
 * This function allows to update the list by emptying the list of UDP ports
 * dedicated for RTP traffic.
 *
 * @param comp  The ROHC compressor
 * @return      true on success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * \par Example:
 * \snippet simple_rohc_program.c define ROHC compressor
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c create ROHC compressor
 * \code
        ...
\endcode
 * \snippet rtp_detection.c reset RTP ports
 * \snippet rtp_detection.c add RTP port
 * \snippet rtp_detection.c remove RTP port
 * \code
        ...
\endcode
 * \snippet simple_rohc_program.c destroy ROHC compressor
 *
 * @see rohc_comp_add_rtp_port
 * @see rohc_comp_remove_rtp_port
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
	           "RTP port list is now reset");

	return true;

error:
	return false;
}


/**
 * @brief Enable/disable features for ROHC compressor
 *
 * Enable/disable features for ROHC compressor. Features control whether
 * mechanisms defined as optional by RFCs are enabled or not.
 *
 * Available features are listed by \ref rohc_comp_features_t. They may be
 * combined by XOR'ing them together.
 *
 * @warning Changing the feature set while library is used is not supported
 *
 * @param comp      The ROHC compressor
 * @param features  The feature set to enable/disable
 * @return          true if the feature set was successfully enabled/disabled,
 *                  false if a problem occurred
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_features_t
 */
bool rohc_comp_set_features(struct rohc_comp *const comp,
                            const rohc_comp_features_t features)
{
	const rohc_comp_features_t all_features =
		ROHC_COMP_FEATURE_COMPAT_1_6_x |
		ROHC_COMP_FEATURE_NO_IP_CHECKSUMS;

	/* compressor must be valid */
	if(comp == NULL)
	{
		/* cannot print a trace without a valid compressor */
		goto error;
	}

	/* reject unsupported features */
	if((features & all_features) != features)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "feature set 0x%x is not supported (supported features "
		             "set is 0x%x)", features, all_features);
		goto error;
	}

	/* record new feature set */
	comp->features = features;

	return true;

error:
	return false;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Enable the ROHC compressor
 *
 * Enable the ROHC compressor.
 *
 * @deprecated do not use this function anymore,
 *             the ROHC compressor shall be considered always enabled now
 *
 * @param comp   The ROHC compressor
 * @param enable 1 to enable the compressor, 0 to disable it
 *
 * @ingroup rohc_comp
 */
void rohc_c_set_enable(struct rohc_comp *comp, int enable)
{
	if(comp == NULL)
	{
		return;
	}
	if(enable != 0 && enable != 1)
	{
		return;
	}
	comp->enabled = enable;
}


/**
 * @brief Whether the ROHC compressor is enabled or not
 *
 * Return whether the ROHC compressor is enabled or not.
 *
 * @deprecated do not use this function anymore,
 *             the ROHC compressor shall be considered always enabled now
 *
 * @param comp  The ROHC compressor
 * @return      1 if the compressor is enabled, 0 if not
 *
 * @ingroup rohc_comp
 */
int rohc_c_is_enabled(struct rohc_comp *comp)
{
	return (comp != NULL && comp->enabled);
}


/**
 * @brief Get information about available compression profiles
 *
 * This function outputs XML.
 *
 * @deprecated do not use this function anymore,
 *             use rohc_comp_get_general_info() instead
 *
 * @param buffer The buffer where to store profile information
 * @return       The length of the data stored in the buffer
 *
 * @ingroup rohc_comp
 */
int rohc_c_info(char *buffer)
{
	char *save;
	size_t i;

	save = buffer;
	buffer += strlen(buffer);

	buffer += sprintf(buffer, "<profiles>\n");

	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		buffer += sprintf(buffer, "\t<profile id=\"%d\" ",
		                  rohc_comp_profiles[i]->id);
		buffer += sprintf(buffer, "name=\"%s\" ",
		                  rohc_get_profile_descr(rohc_comp_profiles[i]->id));
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
 * @deprecated do not use this function anymore,
 *             use rohc_comp_get_general_info() instead
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
	char *prefix;
	char *save;
	size_t i;
	int v;

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
	buffer += sprintf(buffer, "%s\t<flows>%zu</flows>\n", prefix, comp->num_contexts_used);
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
	buffer += sprintf(buffer, "%s\t<max_cid>%zu</max_cid>\n", prefix, comp->medium.max_cid);
	buffer += sprintf(buffer, "%s\t<mrru>%zd</mrru>\n", prefix, comp->mrru);
	buffer += sprintf(buffer, "%s\t<large_cid>%s</large_cid>\n", prefix,
	                  comp->medium.cid_type == ROHC_LARGE_CID ? "yes" : "no");
	buffer += sprintf(buffer, "%s\t<connection_type>%d</connection_type>\n", prefix, 3);
	buffer += sprintf(buffer, "%s\t<feedback_freq>%d</feedback_freq>\n\n", prefix, 7); // comp-> ??

	/* profiles part */
	buffer += sprintf(buffer, "%s\t<profiles>\n", prefix);

	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		const struct rohc_comp_profile *const p = rohc_comp_profiles[i];

		buffer += sprintf(buffer, "%s\t\t<profile id=\"%d\" ", prefix, p->id);
		buffer += sprintf(buffer, "name=\"%s\" ",
		                  rohc_get_profile_descr(p->id));
		buffer += sprintf(buffer, "active=\"%s\" ",
		                  comp->enabled_profiles[i] ? "yes" : "no");
		buffer += sprintf(buffer, "/>\n");
	}

	buffer += sprintf(buffer, "%s\t</profiles>\n", prefix);

	/* contexts part */
	i = 0;
	while(__rohc_c_context(comp, i, indent + 1, buffer) != -2)
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
 * @deprecated do not use this function anymore,
 *             use rohc_comp_get_general_info() instead
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
	/* for compatibility reasons */
	return __rohc_c_context(comp, cid, indent, buffer);
}


/**
 * @brief Get information about a compression context
 *
 * This function outputs XML.
 *
 * Internal implementation of rohc_c_context() for compatibility reasons.
 *
 * @param comp   The ROHC compressor
 * @param cid    The CID of the compressor context to output information about
 * @param indent The indent level to beautify the XML output
 * @param buffer The buffer where to store the information
 * @return       The length of the data stored in the buffer if successful,
 *               -2 if the given CID is too large,
 *               -1 if the given CID is unused or an error occurs
 */
static int __rohc_c_context(struct rohc_comp *comp,
                            int cid,
                            unsigned int indent,
                            char *buffer)
{
	struct rohc_comp_ctxt *c;
	char *prefix;
	char *save;
	int v;

	if(cid < 0)
	{
		return -1;
	}

	if(cid > ((int) comp->medium.max_cid))
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

	buffer += sprintf(buffer, "\n%s<context type=\"compressor\" cid=\"%zu\">\n", prefix, c->cid);
	buffer += sprintf(buffer, "%s\t<cid_state>%s</cid_state>\n", prefix, c->used ? "USED" : "UNUSED");
	buffer += sprintf(buffer, "%s\t<state>%s</state>\n", prefix,
	                  rohc_comp_get_state_descr(c->state));
	buffer += sprintf(buffer, "%s\t<mode>%s</mode>\n", prefix,
	                  rohc_get_mode_descr(c->mode));
	buffer += sprintf(buffer, "%s\t<profile>%s</profile>\n", prefix,
	                  rohc_get_profile_descr(c->profile->id));

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

	v = rohc_stats_sum(&c->total_16_uncompressed);
	if(v != 0)
	{
		v = (100 * rohc_stats_sum(&c->total_16_compressed)) / v;
	}
	buffer += sprintf(buffer, "%s\t\t<last_16_packets>%d%%</last_16_packets>\n", prefix, v);

	v = rohc_stats_sum(&c->header_16_uncompressed);
	if(v != 0)
	{
		v = (100 * rohc_stats_sum(&c->header_16_compressed)) / v;
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

	v = rohc_stats_mean(&c->total_16_compressed);
	buffer += sprintf(buffer, "%s\t\t<last_16_packets>%d</last_16_packets>\n", prefix, v);

	v = rohc_stats_mean(&c->header_16_compressed);
	buffer += sprintf(buffer, "%s\t\t<last_16_headers>%d</last_16_headers>\n", prefix, v);

	buffer += sprintf(buffer, "%s\t</mean>\n", prefix);

	/* times */
	buffer += sprintf(buffer, "%s\t<activation_time>%lu</activation_time>\n",
	                  prefix, (unsigned long) (rohc_get_seconds() - c->first_used));
	buffer += sprintf(buffer, "%s\t<idle_time>%lu</idle_time>\n",
	                  prefix, (unsigned long) (rohc_get_seconds() - c->latest_used));

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
 *
 * @ingroup rohc_comp
 */
void c_piggyback_feedback(struct rohc_comp *comp,
                          unsigned char *feedback,
                          int size)
{
	bool __attribute__((unused)) ret; /* avoid warn_unused_result */
	ret = rohc_comp_piggyback_feedback(comp, feedback, size);
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Add a feedback packet to the next outgoing ROHC packet (piggybacking)
 *
 * @param comp     The ROHC compressor
 * @param feedback The feedback data
 * @param size     The length of the feedback packet
 * @return         true in case of success, false otherwise
 *
 * @ingroup rohc_comp
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
	           "byte(s) of feedback to the next outgoing ROHC packet", size);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_first < FEEDBACK_RING_SIZE);

	/* If first and next feedbacks are equals, the ring is either empty or full.
	 * If the first feedback is 0-byte length, then the ring is empty. */
	if(comp->feedbacks_next == comp->feedbacks_first &&
	   comp->feedbacks[comp->feedbacks_first].length != 0)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no place in buffer for feedback data");
		goto error;
	}

	/* allocate memory for new feedback data */
	comp->feedbacks[comp->feedbacks_next].data = malloc(size);
	if(comp->feedbacks[comp->feedbacks_next].data == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no memory for feedback data");
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
	           "ROHC packet", size);

	return true;

error:
	return false;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

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
 *
 * @ingroup rohc_comp
 */
void c_deliver_feedback(struct rohc_comp *comp,
                        unsigned char *packet,
                        int size)
{
	const bool is_ok __attribute__((unused)) =
		rohc_comp_deliver_feedback(comp, packet, size);
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Deliver a feedback packet to the compressor
 *
 * When feedback is received by the decompressor, this function is called and
 * delivers the feedback to the right profile/context of the compressor.
 *
 * @param comp   The ROHC compressor
 * @param packet The feedback data
 * @param size   The length of the feedback packet
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_deliver_feedback(struct rohc_comp *const comp,
                                const uint8_t *const packet,
                                const size_t size)

{
	struct rohc_comp_ctxt *c;
	struct c_feedback feedback;
	const uint8_t *p;
	bool is_success = false;

	/* sanity check */
	if(packet == NULL || size <= 0)
	{
		goto error;
	}
	p = packet;

	/* if decompressor is not associated with a compressor, we cannot deliver
	 * feedback */
	if(comp == NULL)
	{
		goto ignore;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "deliver %zu byte(s) of feedback to the right context", size);

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
			             "failed to decode SDVL-encoded large CID field");
			goto error;
		}
		feedback.cid = large_cid;
		p += large_cid_size;
	}
	else
	{
		/* decode small CID if present */
		if(rohc_add_cid_is_present(p))
		{
			feedback.cid = rohc_add_cid_decode(p);
			p++;
		}
		else
		{
			feedback.cid = 0;
		}
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "feedback CID = %zu", feedback.cid);

	feedback.specific_size = size - (p - packet);
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "feedback size = %d", feedback.specific_size);

	if(feedback.specific_size == 1)
	{
		feedback.type = 1; /* FEEDBACK-1 */
	}
	else
	{
		feedback.type = 2; /* FEEDBACK-2 */
		feedback.acktype = (p[0] >> 6) & 0x3;
	}

	feedback.specific_offset = p - packet;
	feedback.data = malloc(feedback.size);
	if(feedback.data == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no memory for feedback data");
		goto error;
	}
	memcpy(feedback.data, packet, feedback.size);

	/* find context */
	c = c_get_context(comp, feedback.cid);
	if(c == NULL)
	{
		/* context was not found */
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "context not found (CID = %zu)", feedback.cid);
		goto clean;
	}

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	c->num_recv_feedbacks++;
#endif

	/* deliver feedback to profile with the context */
	if(!c->profile->feedback(c, &feedback))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to handle FEEDBACK-%d data", feedback.type);
	}
	else
	{
		/* everything went fine */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "FEEDBACK-%d data successfully handled", feedback.type);
		is_success = true;
	}

clean:
	zfree(feedback.data);
error:
	return is_success;

ignore:
	return true;
}


/**
 * @brief Send as much feedback data as possible
 *
 * Flush unsent feedback data as much as possible. Flushing stops either
 * because there is no more unsent feedback data in compressor, or either
 * because the given buffer is too small.
 *
 * The \e rohc_feedback_flush function starts a transaction. The feedback data
 * are not removed from the compressor's context when the function is called
 * (they are only locked). There are two ways to close the transaction:
 *  \li A call to the function \ref rohc_feedback_remove_locked to tell the
 *      ROHC compressor that feedback bytes were successfully sent. The
 *      feedback data will be removed from the compressor's context.
 *  \li A call to the function \ref rohc_feedback_unlock to tell the ROHC
 *      compressor that feedback bytes failed to be sent successfully (eg. a
 *      temporary network problem). The feedback data will be unlocked but not
 *      removed from the compressor's context. This way, the compressor will
 *      try to send them again.
 *
 * The \ref rohc_feedback_avail_bytes function might be useful to flush only
 * when a given amount of unsent feedback data is reached. It might be useful
 * to correctly size the buffer given to \e rohc_feedback_flush.
 *
 * @param comp       The ROHC compressor
 * @param[out] obuf  The buffer where to store the feedback-only packet
 * @param osize      The size of the buffer for the feedback-only packet
 * @return           The size of the feedback-only packet,
 *                   0 if there is no feedback data to send
 *
 * @ingroup rohc_comp
 *
 * @see rohc_feedback_remove_locked
 * @see rohc_feedback_unlock
 * @see rohc_feedback_avail_bytes
 */
int rohc_feedback_flush(struct rohc_comp *comp,
                        unsigned char *obuf,
                        int osize)
{
	unsigned int size;
	int feedback_size;

	/* check input validity */
	if(comp == NULL || obuf == NULL || osize <= 0)
	{
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
	           "flush %u bytes of feedback", size);

	return size;
}


/**
 * @brief How many bytes of unsent feedback data are available at compressor?
 *
 * How many bytes of unsent feedback data are available at compressor? It
 * might be useful to know how many feedback data is waiting to be sent before
 * flushing them with the \ref rohc_feedback_flush function.
 *
 * @param comp  The ROHC compressor
 * @return      The number of bytes of unsent feedback data,
 *              0 if no unsent feedback data is available
 *
 * @ingroup rohc_comp
 *
 * @see rohc_feedback_flush
 */
size_t rohc_feedback_avail_bytes(const struct rohc_comp *const comp)
{
	size_t feedback_length;
	size_t i;

	/* check input validity */
	if(comp == NULL)
	{
		goto error;
	}

	feedback_length = 0;
	for(i = 0; i < FEEDBACK_RING_SIZE; i++)
	{
		/* take only defined, unlocked feedbacks into account */
		if(comp->feedbacks[i].length > 0 && !comp->feedbacks[i].is_locked)
		{
			/* retrieve the length of the feedback data */
			feedback_length += comp->feedbacks[i].length;

			/* how many additional bytes are required to encode length? */
			if(comp->feedbacks[i].length < 8)
			{
				feedback_length++;
			}
			else
			{
				feedback_length += 2;
			}
		}
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "there are %zu byte(s) of available unsent feedback data",
	           feedback_length);

	return feedback_length;

error:
	return 0;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Get some information about the last compressed packet
 *
 * @deprecated do not use this function anymore,
 *             use rohc_comp_get_last_packet_info2() instead
 *
 * @param comp          The ROHC compressor to get information from
 * @param[in,out] info  the structure where information will be stored
 * @return              Possible return values:
 *                      \li \ref ROHC_OK in case of success,
 *                      \li \ref ROHC_ERROR otherwise
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
		           "last context found in compressor is not valid");
		return ROHC_ERROR;
	}

	if(info == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "structure for last packet information is not valid");
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

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Get some information about the last compressed packet
 *
 * Get some information about the last compressed packet.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_comp_last_packet_info2_t structure with the \e version_major and
 * \e version_minor fields set to one of the following supported versions:
 *  - Major 0, minor 0
 *
 * See the \ref rohc_comp_last_packet_info2_t structure for details about
 * fields that are supported in the above versions.
 *
 * @param comp          The ROHC compressor to get information from
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_last_packet_info2_t
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
		           "last context found in compressor is not valid");
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "structure for last packet information is not valid");
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
 * @brief Get some general information about the compressor
 *
 * Get some general information about the compressor.
 *
 * To use the function, call it with a pointer on a pre-allocated
 * \ref rohc_comp_general_info_t structure with the \e version_major and
 * \e version_minor fields set to one of the following supported versions:
 *  - Major 0, minor 0
 *
 * See the \ref rohc_comp_general_info_t structure for details about fields
 * that are supported in the above versions.
 *
 * @param comp          The ROHC compressor to get information from
 * @param[in,out] info  The structure where information will be stored
 * @return              true in case of success, false otherwise
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_general_info_t
 */
bool rohc_comp_get_general_info(const struct rohc_comp *const comp,
                                rohc_comp_general_info_t *const info)
{
	if(comp == NULL)
	{
		goto error;
	}

	if(info == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "structure for general information is not valid");
		goto error;
	}

	/* check compatibility version */
	if(info->version_major == 0)
	{
		/* base fields for major version 0 */
		info->contexts_nr = comp->num_contexts_used;
		info->packets_nr = comp->num_packets;
		info->uncomp_bytes_nr = comp->total_uncompressed_size;
		info->comp_bytes_nr = comp->total_compressed_size;

		/* new fields added by minor versions */
		if(info->version_minor > 0)
		{
			rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported minor version (%u) of the structure for "
			           "general information", info->version_minor);
			goto error;
		}
	}
	else
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unsupported major version (%u) of the structure for "
		           "general information", info->version_major);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Give a description for the given ROHC compression context state
 *
 * Give a description for the given ROHC compression context state.
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
const char * rohc_comp_get_state_descr(const rohc_comp_state_t state)
{
	switch(state)
	{
		case ROHC_COMP_STATE_IR:
			return "IR";
		case ROHC_COMP_STATE_FO:
			return "FO";
		case ROHC_COMP_STATE_SO:
			return "SO";
		default:
			assert(0);
#ifdef __KERNEL__
			return "no description";
#endif
	}
}


/**
 * @brief Remove all feedbacks locked during the packet build
 *
 * Remove all feedbacks locked during the packet build from the compressor's
 * context. A call to function \e rohc_feedback_remove_locked closes the
 * transaction started by the function \ref rohc_feedback_flush. It frees
 * the compressor's internal memory related to feedback data once the feedback
 * data was sent for sure.
 *
 * If the feedback data failed to be sent correctly (eg. temporary network
 * problem), then the feedback data shall not be removed but only unlocked
 * with the \ref rohc_feedback_unlock function. This way, feedback data could
 * be sent again later.
 *
 * @param comp  The ROHC compressor
 * @return      true if action succeeded, false in case of error
 *
 * @ingroup rohc_comp
 *
 * @see rohc_feedback_unlock
 * @see rohc_feedback_flush
 */
bool rohc_feedback_remove_locked(struct rohc_comp *const comp)
{
	unsigned int removed_nr = 0;

	if(comp == NULL)
	{
		/* bad compressor */
		goto error;
	}

	assert(comp->feedbacks_first < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_first_unlocked < FEEDBACK_RING_SIZE);

	while(comp->feedbacks[comp->feedbacks_first].is_locked)
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
	           "%u locked feedbacks removed", removed_nr);

	assert(comp->feedbacks_first == comp->feedbacks_first_unlocked);

	return true;

error:
	return false;
}


/**
 * @brief Unlock all feedbacks locked during the packet build
 *
 * Unlock all feedbacks locked during the packet build, but do not remove them
 * from the compressor's context. A call to function \e rohc_feedback_unlock
 * closes the transaction started by the function \ref rohc_feedback_flush. It
 * allows the compressor to send the unlocked feedback bytes again after the
 * the program failed to send them correctly (eg. temporary network problem).
 *
 * If the feedback data was sent successfully, then the feedback data shall
 * not be unlocked, but removed with the \ref rohc_feedback_remove_locked
 * function. This way, feedback data will not be sent again later.
 *
 * @param comp  The ROHC compressor
 * @return      true if action succeeded, false in case of error
 *
 * @ingroup rohc_comp
 *
 * @see rohc_feedback_remove_locked
 * @see rohc_feedback_flush
 */
bool rohc_feedback_unlock(struct rohc_comp *const comp)
{
	size_t i;

	if(comp == NULL)
	{
		/* bad compressor */
		goto error;
	}

	assert(comp->feedbacks_first < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_first_unlocked < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);

	/* unlock all the ring locations between first unlocked one (excluded)
	 * and first one */
	i = comp->feedbacks_first;
	while(comp->feedbacks[i].is_locked)
	{
		comp->feedbacks[i].is_locked = false;
		i = (i + 1) % FEEDBACK_RING_SIZE;
	}
	comp->feedbacks_first_unlocked = comp->feedbacks_first;

	return true;

error:
	return false;
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
static const struct rohc_comp_profile *
	rohc_get_profile_from_id(const struct rohc_comp *comp,
	                         const rohc_profile_t profile_id)
{
	size_t i;

	/* test all compression profiles */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		/* if the profile IDs match and the profile is enabled */
		if(rohc_comp_profiles[i]->id == profile_id && comp->enabled_profiles[i])
		{
			return rohc_comp_profiles[i];
		}
	}

	return NULL;
}


/**
 * @brief Find out a ROHC profile given an IP protocol ID
 *
 * @param comp    The ROHC compressor
 * @param packet  The packet to find a compression profile for
 * @return        The ROHC profile if found, NULL otherwise
 */
static const struct rohc_comp_profile *
	c_get_profile_from_packet(const struct rohc_comp *const comp,
	                          const struct net_pkt *const packet)
{
	size_t i;

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "try to find the best profile for packet with transport "
	           "protocol %u", packet->transport->proto);

	/* test all compression profiles */
	for(i = 0; i < C_NUM_PROFILES; i++)
	{
		bool check_profile;

		/* skip profile if the profile is not enabled */
		if(!comp->enabled_profiles[i])
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "skip disabled profile '%s' (0x%04x)",
			           rohc_get_profile_descr(rohc_comp_profiles[i]->id),
			           rohc_comp_profiles[i]->id);
			continue;
		}

		/* does the profile accept the packet? */
		check_profile = rohc_comp_profiles[i]->check_profile(comp, packet);
		if(!check_profile)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "skip profile '%s' (0x%04x) because it does not match "
			           "packet",rohc_get_profile_descr(rohc_comp_profiles[i]->id),
			           rohc_comp_profiles[i]->id);
			continue;
		}

		/* the packet is compatible with the profile, let's go with it! */
		return rohc_comp_profiles[i];
	}

	return NULL;
}


/**
 * @brief Create a compression context
 *
 * @param comp          The ROHC compressor
 * @param profile       The profile to associate the context with
 * @param packet        The packet to create a compression context for
 * @param arrival_time  The time at which packet was received (0 if unknown,
 *                      or to disable time-related features in ROHC protocol)
 * @return              The compression context if successful, NULL otherwise
 */
static struct rohc_comp_ctxt *
	c_create_context(struct rohc_comp *const comp,
	                 const struct rohc_comp_profile *const profile,
	                 const struct net_pkt *const packet,
	                 const struct rohc_ts arrival_time)
{
	struct rohc_comp_ctxt *c;
	rohc_cid_t cid_to_use;

	assert(comp != NULL);
	assert(profile != NULL);
	assert(packet != NULL);

	cid_to_use = 0;

	/* if all the contexts in the array are used:
	 *   => recycle the oldest context to make room
	 * if at least one context in the array is not used:
	 *   => pick the first unused context
	 */
	if(comp->num_contexts_used > comp->medium.max_cid)
	{
		/* all the contexts in the array were used, recycle the oldest context
		 * to make some room */

		uint64_t oldest;
		rohc_cid_t i;

		/* find the oldest context */
		oldest = 0xffffffff;
		for(i = 0; i <= comp->medium.max_cid; i++)
		{
			if(comp->contexts[i].latest_used < oldest)
			{
				oldest = comp->contexts[i].latest_used;
				cid_to_use = i;
			}
		}

		/* destroy the oldest context before replacing it with a new one */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "recycle oldest context (CID = %zu)", cid_to_use);
		comp->contexts[cid_to_use].profile->destroy(&comp->contexts[cid_to_use]);
		comp->contexts[cid_to_use].key = 0; /* reset context key */
		comp->contexts[cid_to_use].used = 0;
		assert(comp->num_contexts_used > 0);
		comp->num_contexts_used--;
	}
	else
	{
		/* there was at least one unused context in the array, pick the first
		 * unused context in the context array */

		rohc_cid_t i;

		/* find the first unused context */
		for(i = 0; i <= comp->medium.max_cid; i++)
		{
			if(comp->contexts[i].used == 0)
			{
				cid_to_use = i;
				break;
			}
		}

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "take the first unused context (CID = %zu)", cid_to_use);
	}

	/* initialize the previously found context */
	c = &comp->contexts[cid_to_use];

	c->total_uncompressed_size = 0;
	c->total_compressed_size = 0;
	c->header_uncompressed_size = 0;
	c->header_compressed_size = 0;

	c->total_last_uncompressed_size = 0;
	c->total_last_compressed_size = 0;
	c->header_last_uncompressed_size = 0;
	c->header_last_compressed_size = 0;

	c->num_sent_packets = 0;
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	c->num_sent_ir = 0;
	c->num_sent_ir_dyn = 0;
	c->num_recv_feedbacks = 0;
#endif

	c->cid = cid_to_use;
	c->profile = profile;
	c->key = packet->key;

	c->mode = ROHC_U_MODE;
	c->state = ROHC_COMP_STATE_IR;

	c->compressor = comp;

	/* create profile-specific context */
	if(!profile->create(c, packet))
	{
		return NULL;
	}

	/* if creation is successful, mark the context as used */
	c->used = 1;
	c->first_used = arrival_time.sec;
	c->latest_used = arrival_time.sec;
	assert(comp->num_contexts_used <= comp->medium.max_cid);
	comp->num_contexts_used++;

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "context (CID = %zu) created (num_used = %zu)",
	           c->cid, comp->num_contexts_used);
	return c;
}


/**
 * @brief Find a compression context given an IP packet
 *
 * @param comp             The ROHC compressor
 * @param packet           The packet to find a compression context for
 * @param profile_id_hint  If positive, indicate the profile to use
 * @param arrival_time     The time at which packet was received
 *                         (0 if unknown, or to disable time-related features
 *                          in the ROHC protocol)
 * @return                 The context if found or successfully created,
 *                         NULL if not found
 */
static struct rohc_comp_ctxt *
	rohc_comp_find_ctxt(struct rohc_comp *const comp,
	                    const struct net_pkt *const packet,
	                    const int profile_id_hint,
	                    const struct rohc_ts arrival_time)
{
	const struct rohc_comp_profile *profile;
	struct rohc_comp_ctxt *context;
	size_t num_used_ctxt_seen = 0;
	rohc_cid_t i;

	/* use the suggested profile if any, otherwise find the best profile for
	 * the packet */
	if(profile_id_hint < 0)
	{
		profile = c_get_profile_from_packet(comp, packet);
	}
	else
	{
		profile = rohc_get_profile_from_id(comp, profile_id_hint);
	}
	if(profile == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "no profile found for packet, giving up");
		goto not_found;
	}
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "using profile '%s' (0x%04x)",
	           rohc_get_profile_descr(profile->id), profile->id);

	/* get the context using help from the profile we just found */
	for(i = 0; i <= comp->medium.max_cid; i++)
	{
		context = &comp->contexts[i];

		/* don't even look at unused contexts */
		if(!context->used)
		{
			continue;
		}
		num_used_ctxt_seen++;

		/* don't look at contexts with the wrong profile */
		if(context->profile->id != profile->id)
		{
			continue;
		}

		/* don't look at contexts with the wrong key */
		if(packet->key != context->key)
		{
			continue;
		}

		/* ask the profile whether the packet matches the context */
		if(context->profile->check_context(context, packet))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "using context CID = %zu", context->cid);
			break;
		}

		/* if all used contexts were checked, no need go search further */
		if(num_used_ctxt_seen >= comp->num_contexts_used)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "no context was found");
			context = NULL;
			break;
		}
	}
	if(context == NULL || i > comp->medium.max_cid)
	{
		/* context not found, create a new one */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no existing context found for packet, create a new one");
		context = c_create_context(comp, profile, packet, arrival_time);
		if(context == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to create a new context");
			goto not_found;
		}
	}
	else
	{
		/* matching context found, update use timestamp */
		context->latest_used = arrival_time.sec;
	}

	return context;

not_found:
	return NULL;
}


/**
 * @brief Find out a context given its CID
 *
 * @param comp The ROHC compressor
 * @param cid  The CID of the context to find
 * @return     The context with the given CID if found, NULL otherwise
 */
static struct rohc_comp_ctxt *
	c_get_context(struct rohc_comp *const comp, const rohc_cid_t cid)
{
	/* the CID must not be larger than the context array */
	if(cid > comp->medium.max_cid)
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
 * @return     true if the creation is successful, false otherwise
 */
static bool c_create_contexts(struct rohc_comp *const comp)
{
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	rohc_cid_t i;
#endif

	assert(comp != NULL);
	assert(comp->contexts == NULL);

	comp->num_contexts_used = 0;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "create enough room for %zu contexts (MAX_CID = %zu)",
	          comp->medium.max_cid + 1, comp->medium.max_cid);

	comp->contexts = calloc(comp->medium.max_cid + 1,
	                        sizeof(struct rohc_comp_ctxt));
	if(comp->contexts == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "cannot allocate memory for contexts");
		goto error;
	}

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	/* initialize all the contexts */
	for(i = 0; i <= comp->medium.max_cid; i++)
	{
		/* create contexts for statistics */
		memset(&comp->contexts[i].total_16_uncompressed, 0,
		       sizeof(struct rohc_stats));
		memset(&comp->contexts[i].total_16_compressed, 0,
		       sizeof(struct rohc_stats));
		memset(&comp->contexts[i].header_16_uncompressed, 0,
		       sizeof(struct rohc_stats));
		memset(&comp->contexts[i].header_16_compressed, 0,
		       sizeof(struct rohc_stats));
	}
#endif

	return true;

error:
	return false;
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
	rohc_cid_t i;

	assert(comp != NULL);
	assert(comp->contexts != NULL);

	for(i = 0; i <= comp->medium.max_cid; i++)
	{
		if(comp->contexts[i].used && comp->contexts[i].profile != NULL)
		{
			comp->contexts[i].profile->destroy(&comp->contexts[i]);
		}

		if(comp->contexts[i].used)
		{
			comp->contexts[i].used = 0;
			assert(comp->num_contexts_used > 0);
			comp->num_contexts_used--;
		}
	}
	assert(comp->num_contexts_used == 0);

	free(comp->contexts);
	comp->contexts = NULL;
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
	size_t pos = 0;

	assert(comp->feedbacks_first_unlocked < FEEDBACK_RING_SIZE);
	assert(comp->feedbacks_next < FEEDBACK_RING_SIZE);

	/* are there some feedback data to send with the next outgoing packet? */
	if(comp->feedbacks_first == comp->feedbacks_next &&
	   comp->feedbacks[comp->feedbacks_first].length == 0)
	{
		/* ring buffer is empty */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no feedback is available");
		feedback_length = 0;
	}
	else if(comp->feedbacks_first_unlocked == comp->feedbacks_next &&
	        comp->feedbacks[comp->feedbacks_first_unlocked].length == 0)
	{
		/* ring buffer is not full, and all feedbacks are locked */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "all available feedbacks are locked");
		feedback_length = 0;
	}
	else if(comp->feedbacks_first_unlocked == comp->feedbacks_next &&
	        comp->feedbacks[comp->feedbacks_first_unlocked].is_locked == true)
	{
		/* ring buffer is full, and all feedbacks are locked */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "all available feedbacks are locked");
		feedback_length = 0;
	}
	else
	{
		size_t required_length;

		/* some feedbacks are not locked yet */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "some available feedbacks are not locked");

		feedback_length = comp->feedbacks[comp->feedbacks_first_unlocked].length;
		required_length = feedback_length + 1 + (feedback_length < 8 ? 0 : 1);

		/* check that there is enough space in the output buffer for the
		 * feedback data */
		if(required_length > max)
		{
			rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			          "no more room in the buffer for feedback: %zd bytes "
			          "required, only %u bytes available", required_length,
			          max);
			goto full;
		}

		/* the feedback length may be encoded either in the last 3 bits of the
		 * first byte or in the 2nd byte */
		if(feedback_length < 8)
		{
			/* length is small, use only 3 bits to code it */
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "use 1-byte form factor for feedback length");
			buffer[pos] = 0xf0 | feedback_length;
			pos++;
		}
		else
		{
			/* size is large, use 8 bits to code it */
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "use 2-byte form factor for feedback length");
			buffer[pos] = 0xf0;
			pos++;
			buffer[pos] = feedback_length;
			pos++;
		}

		/* copy feedback data in the buffer */
		memcpy(buffer + pos,
		       comp->feedbacks[comp->feedbacks_first_unlocked].data,
		       feedback_length);

		/* lock the feedback */
		comp->feedbacks[comp->feedbacks_first_unlocked].is_locked = true;

		comp->feedbacks_first_unlocked =
			(comp->feedbacks_first_unlocked + 1) % FEEDBACK_RING_SIZE;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "add %zd byte(s) of feedback data", feedback_length);

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(comp->trace_callback, ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "feedback data added", buffer + pos, feedback_length);
#endif

	/* return the length of the feedback header/data, or zero if no feedback */
	return (pos + feedback_length);

full:
	return -1;
}


/**
 * @brief Destroy memory allocated for the feedback packets
 *
 * @param comp  The ROHC compressor
 */
static void rohc_feedback_destroy(struct rohc_comp *const comp)
{
	size_t i;

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


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Set the maximal CID value the compressor should use
 *
 * @param comp  The ROHC compressor
 * @param value The new maximal CID value
 */
static void __rohc_c_set_max_cid(struct rohc_comp *comp, int value)
{
	if(comp == NULL)
	{
		goto error;
	}

	/* check validity of the new MAX_CID */
	if(comp->medium.cid_type == ROHC_LARGE_CID)
	{
		/* large CID */
		if(value < 0 || value > ROHC_LARGE_CID_MAX)
		{
			goto error;
		}
	}
	else /* small CID */
	{
		if(value < 0 || value > ROHC_SMALL_CID_MAX)
		{
			goto error;
		}
	}

	if(((size_t) value) != comp->medium.max_cid)
	{
		/* free memory used by contexts */
		c_destroy_contexts(comp);

		/* change MAX_CID */
		comp->medium.max_cid = value;

		/* create the MAX_CID contexts */
		if(!c_create_contexts(comp))
		{
			goto error;
		}
	}

error:
	return;
}

#endif /* !ROHC_ENABLE_DEPRECATED_API */

