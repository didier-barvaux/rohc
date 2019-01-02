/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2013 Friedrich
 * Copyright 2009,2010 Thales Communications
 * Copyright 2007,2009,2010,2012,2013,2014,2017,2018 Viveris Technologies
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
#include "rohc_bit_ops.h"
#include "ip.h"
#include "crc.h"
#include "protocols/ip.h"
#include "schemes/ipv6_exts.h"
#include "protocols/udp.h"
#include "protocols/ip_numbers.h"
#include "c_tcp_opts_list.h"
#include "feedback_parse.h"
#include "hashtable.h"
#include "hashtable_cr.h"

#include "config.h" /* for PACKAGE_(NAME|URL|VERSION) */

#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>


/** The affinity between packet and context */
typedef enum
{
	ROHC_AFFINITY_NONE = 0,
	ROHC_AFFINITY_LOW  = 1,
	ROHC_AFFINITY_MED  = 2,
	ROHC_AFFINITY_HIGH = 3,
} rohc_ctxt_affinity_t;


/* ROHCv1 profiles */
extern const struct rohc_comp_profile c_rtp_profile;
extern const struct rohc_comp_profile c_udp_profile;
extern const struct rohc_comp_profile c_esp_profile;
extern const struct rohc_comp_profile c_tcp_profile;
extern const struct rohc_comp_profile c_ip_profile;
extern const struct rohc_comp_profile c_uncompressed_profile;

/* ROHCv2 profiles */
extern const struct rohc_comp_profile rohc_comp_rfc5225_ip_profile;
extern const struct rohc_comp_profile rohc_comp_rfc5225_ip_udp_profile;
extern const struct rohc_comp_profile rohc_comp_rfc5225_ip_esp_profile;
extern const struct rohc_comp_profile rohc_comp_rfc5225_ip_udp_rtp_profile;

/** The ROHC compression profiles */
static const struct rohc_comp_profile *const
	rohc_comp_profiles[ROHC_PROFILE_ID_MAJOR_MAX + 1][ROHC_PROFILE_ID_MINOR_MAX + 1] =
{
	[0] = {
		[0] = &c_uncompressed_profile,
		[1] = &c_rtp_profile,
		[2] = &c_udp_profile,
		[3] = &c_esp_profile,
		[4] = &c_ip_profile,
		[5] = NULL,
		[6] = &c_tcp_profile,
		[7] = NULL,
		[8] = NULL,
	},
	[1] = {
		[0] = NULL,
		[1] = &rohc_comp_rfc5225_ip_udp_rtp_profile,
		[2] = &rohc_comp_rfc5225_ip_udp_profile,
		[3] = &rohc_comp_rfc5225_ip_esp_profile,
		[4] = &rohc_comp_rfc5225_ip_profile,
		[5] = NULL,
		[6] = NULL,
		[7] = NULL,
		[8] = NULL,
	},
};



/*
 * Prototypes of private functions related to ROHC compression profiles
 */

static rohc_profile_t rohc_comp_get_profile(const struct rohc_comp *const comp,
                                            const struct rohc_buf *const packet,
                                            struct rohc_fingerprint *const fingerprint,
                                            struct rohc_pkt_hdrs *const pkt_hdrs)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static bool rohc_comp_are_ip_hdrs_supported(const struct rohc_comp *const comp,
                                            const uint8_t *const packet,
                                            const size_t packet_len,
                                            struct rohc_fingerprint *const fingerprint,
                                            struct rohc_pkt_hdrs *const pkt_hdrs,
                                            size_t *const all_ip_hdrs_len,
                                            size_t *const all_ipv6_exts_len)
	__attribute__((nonnull(1, 2, 4, 5, 6, 7), warn_unused_result));

static rohc_profile_t rohc_comp_get_profile_l4(const struct rohc_comp *const comp,
                                               const struct rohc_buf *const packet,
                                               const rohc_profile_t l3_profile,
                                               const size_t all_ipv6_exts_len,
                                               const uint8_t l4_proto,
                                               const uint8_t *const l4_data,
                                               const size_t l4_len,
                                               struct rohc_fingerprint *const fingerprint,
                                               struct rohc_pkt_hdrs *const pkt_hdrs)
	__attribute__((nonnull(1, 2, 6, 8, 9), warn_unused_result));

static bool rohc_comp_is_tcp_hdr_supported(const struct rohc_comp *const comp,
                                           const uint8_t *const packet,
                                           const size_t packet_len,
                                           struct rohc_pkt_hdrs *const pkt_hdrs,
                                           size_t *const tcp_hdr_full_len)
	__attribute__((nonnull(1, 2, 4, 5), warn_unused_result));

static bool rohc_comp_is_rtp_hdr_supported(const struct rohc_comp *const comp,
                                           const uint8_t *const packet,
                                           const size_t packet_len,
                                           struct rohc_pkt_hdrs *const pkt_hdrs)
	__attribute__((nonnull(1, 2, 4), warn_unused_result));

static bool rohc_comp_profile_enabled_nocheck(const struct rohc_comp *const comp,
                                              const rohc_profile_t profile)
	__attribute__((warn_unused_result, nonnull(1)));


/*
 * Prototypes of private functions related to ROHC compression contexts
 */

static bool c_create_contexts(struct rohc_comp *const comp)
	__attribute__((warn_unused_result, nonnull(1)));
static void c_destroy_contexts(struct rohc_comp *const comp)
	__attribute__((nonnull(1)));

static struct rohc_comp_ctxt *
	c_create_context(struct rohc_comp *const comp,
	                 const struct rohc_comp_profile *const profile,
	                 const struct rohc_fingerprint *const fingerprint,
	                 const struct rohc_pkt_hdrs *const pkt_hdrs,
	                 const struct rohc_ts pkt_time)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));
static struct rohc_comp_ctxt *
	rohc_comp_find_ctxt(struct rohc_comp *const comp,
	                    const struct rohc_comp_profile *const profile,
	                    const struct rohc_buf *const packet,
	                    const struct rohc_fingerprint *const pkt_fingerprint,
	                    const struct rohc_pkt_hdrs *const pkt_hdrs)
	__attribute__((nonnull(1, 2, 3, 4, 5), warn_unused_result));
static struct rohc_comp_ctxt *
	c_get_context(struct rohc_comp *const comp, const rohc_cid_t cid)
	__attribute__((nonnull(1), warn_unused_result));

static rohc_ctxt_affinity_t
	rohc_comp_get_ctxt_affinity(const struct rohc_comp_ctxt *const ctxt,
	                            const struct rohc_fingerprint *const pkt_fingerprint,
	                            const struct rohc_pkt_hdrs *const pkt_hdrs)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));


/*
 * Prototypes of private functions related to context state
 */

static void rohc_comp_decide_state(struct rohc_comp_ctxt *const context,
                                   struct rohc_ts pkt_time)
	__attribute__((nonnull(1)));

static void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context,
                                               const struct rohc_ts pkt_time)
	__attribute__((nonnull(1)));


/*
 * Prototypes of private functions related to ROHC feedback
 */

static bool __rohc_comp_deliver_feedback(struct rohc_comp *const comp,
                                         const uint8_t *const packet,
                                         const size_t size)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool rohc_comp_feedback_parse_cid(const struct rohc_comp *const comp,
                                         const uint8_t *const feedback,
                                         const size_t feedback_len,
                                         rohc_cid_t *const cid,
                                         size_t *const cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static bool rohc_comp_feedback_parse_opt_sn(const struct rohc_comp_ctxt *const context,
                                            const uint8_t *const feedback_data,
                                            const size_t feedback_data_len,
                                            uint32_t *const sn_bits,
                                            size_t *const sn_bits_nr)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

static bool rohc_comp_feedback_check_opts(const struct rohc_comp_ctxt *const context,
                                          const size_t opts_present[ROHC_FEEDBACK_OPT_MAX])
	__attribute__((warn_unused_result, nonnull(1, 2)));


/*
 * Definitions of public functions
 */


/**
 * @brief Create a new ROHC compressor
 *
 * Create a new ROHC compressor with the given type of CIDs and MAX_CID.
 *
 * The user-defined callback for random numbers is called by the ROHC library
 * every time a new random number is required. It currently happens only to
 * initiate the Sequence Number (SN) of new IP-only, IP/UDP, or IP/UDP-Lite
 * streams to a random value as defined by RFC 3095.
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
 * @param rand_cb   The random callback to set
 * @param rand_priv Private data that will be given to the callback, may be
 *                  used as a context by user
 * @return          The created compressor if successful,
 *                  NULL if creation failed
 *
 * @warning Don't forget to free compressor memory with \ref rohc_comp_free
 *          if \e rohc_comp_new2 succeeded
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
 * @see rohc_comp_set_traces_cb2
 * @see rohc_comp_enable_profiles
 * @see rohc_comp_enable_profile
 * @see rohc_comp_disable_profiles
 * @see rohc_comp_disable_profile
 * @see rohc_comp_set_mrru
 * @see rohc_comp_set_optimistic_approach
 * @see rohc_comp_set_periodic_refreshes
 * @see rohc_comp_set_rtp_detection_cb
 */
struct rohc_comp * rohc_comp_new2(const rohc_cid_type_t cid_type,
                                  const rohc_cid_t max_cid,
                                  const rohc_comp_random_cb_t rand_cb,
                                  void *const rand_priv)
{
	const size_t oa_repetitions_nr = ROHC_OA_REPEAT_DEFAULT;
	const size_t reorder_ratio = ROHC_REORDERING_NONE; /* default reordering ratio */
	struct rohc_comp *comp;
	uint8_t profile_major;
	bool is_fine;

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
	if(rand_cb == NULL)
	{
		return NULL;
	}

	/* allocate memory for the ROHC compressor */
	comp = calloc(1, sizeof(struct rohc_comp));
	if(comp == NULL)
	{
		goto error;
	}

	comp->medium.cid_type = cid_type;
	comp->medium.max_cid = max_cid;
	comp->mrru = 0; /* no segmentation by default */
	comp->rru = NULL; /* no segmentation by default */
	comp->random_cb = rand_cb;
	comp->random_cb_ctxt = rand_priv;

	/* all compression profiles are disabled by default */
	for(profile_major = 0; profile_major <= ROHC_PROFILE_ID_MAJOR_MAX; profile_major++)
	{
		uint8_t profile_minor;

		for(profile_minor = 0; profile_minor <= ROHC_PROFILE_ID_MINOR_MAX; profile_minor++)
		{
			comp->enabled_profiles[profile_major][profile_minor] = false;
		}
	}

	/* reset statistics */
	comp->num_packets = 0;
	comp->total_compressed_size = 0;
	comp->total_uncompressed_size = 0;
	comp->last_context = NULL;

	/* set the default number of repetitions for Optimistic Approach */
	is_fine = rohc_comp_set_optimistic_approach(comp, oa_repetitions_nr);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

	/* set the default reordering ratio for W-LSB MSN in ROHCv2 profiles */
	is_fine = rohc_comp_set_reorder_ratio(comp, reorder_ratio);
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
	is_fine = rohc_comp_set_periodic_refreshes_time(comp,
	                                                CHANGE_TO_IR_TIME,
	                                                CHANGE_TO_FO_TIME);
	if(is_fine != true)
	{
		goto destroy_comp;
	}

	/* create the MAX_CID + 1 contexts */
	if(!c_create_contexts(comp))
	{
		goto destroy_comp;
	}
	{
		const unsigned int max_ctxts = max_cid + 1;
		const size_t items_nr = 1 << (32 - __builtin_clz(max_ctxts - 1));
		const size_t hashtable_size = items_nr << 5;
		size_t i;

		/* create hash table for finding contexts by their fingerprint */
		for(i = 0; i < sizeof(comp->contexts_by_fingerprint.key); i++)
		{
			comp->contexts_by_fingerprint.key[i] =
				comp->random_cb(comp, comp->random_cb_ctxt) & 0xff;
		}
		if(!hashtable_new(&comp->contexts_by_fingerprint,
		                  sizeof(struct rohc_fingerprint), hashtable_size))
		{
			goto destroy_contexts;
		}

		/* create hash table for finding Context Replication (CR) contexts
		 * by their base fingerprint */
		for(i = 0; i < sizeof(comp->contexts_cr.key); i++)
		{
			comp->contexts_cr.key[i] =
				comp->random_cb(comp, comp->random_cb_ctxt) & 0xff;
		}
		if(!hashtable_cr_new(&comp->contexts_cr,
		                     sizeof(struct rohc_fingerprint_base),
		                     sizeof(struct rohc_fingerprint), hashtable_size))
		{
			goto free_hashtable;
		}
	}

	return comp;

free_hashtable:
	hashtable_free(&comp->contexts_by_fingerprint);
destroy_contexts:
	c_destroy_contexts(comp);
destroy_comp:
	zfree(comp);
error:
	return NULL;
}


/**
 * @brief Destroy the given ROHC compressor
 *
 * Destroy a ROHC compressor that was successfully created with
 * \ref rohc_comp_new2
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
 * @see rohc_comp_new2
 */
void rohc_comp_free(struct rohc_comp *const comp)
{
	if(comp != NULL)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "free ROHC compressor");

		/* free memory used by contexts */
		hashtable_cr_free(&comp->contexts_cr);
		hashtable_free(&comp->contexts_by_fingerprint);
		c_destroy_contexts(comp);

		/* free RRU buffer */
		if(comp->rru != NULL)
		{
			zfree(comp->rru);
		}

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
 * @param comp       The ROHC compressor
 * @param callback   Two possible cases:
 *                     \li The callback function used to manage traces
 *                     \li NULL to remove the previous callback
 * @param priv_ctxt  An optional private context, may be NULL
 * @return           true on success, false otherwise
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
bool rohc_comp_set_traces_cb2(struct rohc_comp *const comp,
                              rohc_trace_callback2_t callback,
                              void *const priv_ctxt)
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
	comp->trace_callback_priv = priv_ctxt;

	return true;

error:
	return false;
}


/**
 * @brief Get the best compression profile for the given network packet
 *
 * @param comp              The ROHC compressor to compress the packet with
 * @param packet            The packet to search the best compression profile for
 * @param[out] fingerprint  The computed fingerprint of the packet to later help
 *                          finding the best compression context
 * @param[out] pkt_hdrs     The information collected about the packet headers,
 *                          may be used later during the detection of changes
 *                          with the compression context, thus avoiding another
 *                          packet parsing
 * @return                  The ID of the best compression profile to compress
 *                          the packet
 */
static rohc_profile_t rohc_comp_get_profile(const struct rohc_comp *const comp,
                                            const struct rohc_buf *const packet,
                                            struct rohc_fingerprint *const fingerprint,
                                            struct rohc_pkt_hdrs *const pkt_hdrs)
{
	const uint8_t *remain_data = rohc_buf_data(*packet);
	size_t remain_len = packet->len;
	size_t all_ip_hdrs_len = 0;
	size_t all_ipv6_exts_len = 0;
	uint8_t next_proto;
	rohc_profile_t profile = ROHC_PROFILE_MAX;

	/* reset the fingerprint */
	memset(fingerprint, 0, sizeof(struct rohc_fingerprint));

	/* remember the beginning of all headers */
	pkt_hdrs->all_hdrs = remain_data;

	/* only the ROHCv1 Uncompressed profile can support network packets larger
	 * than 65535 bytes, but the library implementation does not support it */
	if(packet->len > UINT16_MAX)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unsupported packet larger than 65535 bytes");
		goto unsupported_net_pkt;
	}

	/* ROHCv1 Uncompressed profile is possible if it is enabled */
	if(rohc_comp_profile_enabled_nocheck(comp, ROHCv1_PROFILE_UNCOMPRESSED))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "ROHCv1 Uncompressed profile is possible");
		profile = ROHCv1_PROFILE_UNCOMPRESSED;
		pkt_hdrs->all_hdrs_len = packet->len - remain_len;
		pkt_hdrs->payload_len = remain_len;
		pkt_hdrs->payload = remain_data;
	}

	/* check that the IP headers are supported by the ROHC profiles */
	if(!rohc_comp_are_ip_hdrs_supported(comp, remain_data, remain_len,
	                                    fingerprint, pkt_hdrs,
	                                    &all_ip_hdrs_len, &all_ipv6_exts_len))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unsupported IP headers");
		goto unsupported_ip_hdr;
	}
	next_proto = pkt_hdrs->innermost_ip_hdr->next_proto;
	remain_data += all_ip_hdrs_len;
	remain_len -= all_ip_hdrs_len;

	/* ROHCv1/v2 IP-only profiles are possible if they are enabled */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "IP packet detected");
	if(rohc_comp_profile_enabled_nocheck(comp, ROHCv1_PROFILE_IP))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "ROHCv1 IP-Only profile is possible");
		profile = ROHCv1_PROFILE_IP;
		pkt_hdrs->all_hdrs_len = packet->len - remain_len;
		pkt_hdrs->payload_len = remain_len;
		pkt_hdrs->payload = remain_data;
	}
	else if(all_ipv6_exts_len == 0 && /* TODO: ROHCv2: add IPv6 ext hdrs support */
	        rohc_comp_profile_enabled_nocheck(comp, ROHCv2_PROFILE_IP))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "ROHCv2 IP-Only profile is possible");
		profile = ROHCv2_PROFILE_IP;
		pkt_hdrs->all_hdrs_len = packet->len - remain_len;
		pkt_hdrs->payload_len = remain_len;
		pkt_hdrs->payload = remain_data;
	}

	/* profiles cannot handle the packet if it bypasses internal limit
	 * of IP headers, except the IP-only profiles that got support for
	 * Static Chain Termination (see RFC 3843, §3.1) */
	if(rohc_is_tunneling(next_proto))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "too many IP headers (%u headers max) for non-IP profiles",
		           ROHC_MAX_IP_HDRS);
		goto too_many_ip_hdrs;
	}

	/* determine the best profile for the layer-4 header */
	profile = rohc_comp_get_profile_l4(comp, packet,
	                                   profile, all_ipv6_exts_len, next_proto,
	                                   remain_data, remain_len,
	                                   fingerprint, pkt_hdrs);

too_many_ip_hdrs:
unsupported_ip_hdr:
unsupported_net_pkt:
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "profile '%s' (0x%04x) will be used to compress the packet",
	           rohc_get_profile_descr(profile), profile);
	return profile;
}


/**
 * @brief Get the best compression profile for the given network packet
 *
 * @param comp              The ROHC compressor to compress the packet with
 * @param packet            The packet to search the best compression profile for
 * @param l3_profile        The best ROHC profile identified for layer-3 headers
 * @param all_ipv6_exts_len The length of the IPv6 extension headers
 * @param l4_proto          The IP protocol type of the layer-4 header
 * @param l4_data           The layer-4 header to search the best profile for
 * @param l4_len            The length of the layer-4 header
 * @param[out] fingerprint  The computed fingerprint of the packet to later help
 *                          finding the best compression context
 * @param[out] pkt_hdrs     The information collected about the packet headers,
 *                          may be used later during the detection of changes
 *                          with the compression context, thus avoiding another
 *                          packet parsing
 * @return                  The ID of the best compression profile to compress
 *                          the packet
 */
static rohc_profile_t rohc_comp_get_profile_l4(const struct rohc_comp *const comp,
                                               const struct rohc_buf *const packet,
                                               const rohc_profile_t l3_profile,
                                               const size_t all_ipv6_exts_len,
                                               const uint8_t l4_proto,
                                               const uint8_t *const l4_data,
                                               const size_t l4_len,
                                               struct rohc_fingerprint *const fingerprint,
                                               struct rohc_pkt_hdrs *const pkt_hdrs)
{
	rohc_profile_t profile = l3_profile;
	const uint8_t *remain_data = l4_data;
	size_t remain_len = l4_len;

	/* check that the transport protocol is supported */
	if(l4_proto == ROHC_IPPROTO_TCP)
	{
		const struct tcphdr *tcp_header;
		size_t tcp_hdr_full_len;

		/* check that the TCP header is supported by the ROHC profiles */
		if(!rohc_comp_is_tcp_hdr_supported(comp, remain_data, remain_len,
		                                   pkt_hdrs, &tcp_hdr_full_len))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported TCP header");
			goto unsupported_tcp_hdr;
		}
		tcp_header = (const struct tcphdr *) remain_data;
		remain_data += tcp_hdr_full_len;
		remain_len -= tcp_hdr_full_len;

		/* ROHCv1 IP/TCP profiles is possible if it is enabled */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "IP/TCP packet detected");
		if(rohc_comp_profile_enabled_nocheck(comp, ROHCv1_PROFILE_IP_TCP))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "ROHCv1 IP/TCP profile is possible");
			profile = ROHCv1_PROFILE_IP_TCP;
			pkt_hdrs->tcp = tcp_header;
			pkt_hdrs->all_hdrs_len = packet->len - remain_len;
			pkt_hdrs->payload_len = remain_len;
			pkt_hdrs->payload = remain_data;
			fingerprint->base.profile_id = profile;
			fingerprint->src_port = rohc_ntoh16(tcp_header->src_port);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tsource port = %u", fingerprint->src_port);
			fingerprint->dst_port = rohc_ntoh16(tcp_header->dst_port);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tdestination port = %u", fingerprint->dst_port);
		}
	}
	else if(l4_proto == ROHC_IPPROTO_UDP)
	{
		const struct udphdr *udp_header;
		const struct rtphdr *rtp;
		size_t udp_len;

		/* innermost IP payload shall be large enough for UDP header */
		if(remain_len < sizeof(struct udphdr))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "innermost IP payload too small for UDP header");
			goto unsupported_udp_hdr;
		}

		/* retrieve the UDP header and the UDP payload */
		udp_header = (const struct udphdr *) remain_data;
		udp_len = remain_len;
		remain_data += sizeof(struct udphdr);
		remain_len -= sizeof(struct udphdr);

		/* the UDP length field shall be correct in order to be inferred */
		if(udp_len != rohc_ntoh16(udp_header->len))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "UDP header is not supported: UDP length is %u while it "
			           "shall be %zu", rohc_ntoh16(udp_header->len), udp_len);
			goto unsupported_udp_hdr;
		}
		pkt_hdrs->udp = udp_header;

		/* ROHCv1/v2 IP/UDP profiles are possible if they are enabled */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "IP/UDP packet detected");
		if(pkt_hdrs->ip_hdrs_nr <= ROHC_MAX_IP_HDRS_RFC3095 &&
		   rohc_comp_profile_enabled_nocheck(comp, ROHCv1_PROFILE_IP_UDP))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "ROHCv1 IP/UDP profile is possible");
			profile = ROHCv1_PROFILE_IP_UDP;
			pkt_hdrs->all_hdrs_len = packet->len - remain_len;
			pkt_hdrs->payload_len = remain_len;
			pkt_hdrs->payload = remain_data;
			fingerprint->base.profile_id = profile;
			fingerprint->src_port = rohc_ntoh16(udp_header->source);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tsource port = %u", fingerprint->src_port);
			fingerprint->dst_port = rohc_ntoh16(udp_header->dest);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tdestination port = %u", fingerprint->dst_port);
		}
		else if(all_ipv6_exts_len == 0 && /* TODO: ROHCv2: add IPv6 ext hdrs support */
		        rohc_comp_profile_enabled_nocheck(comp, ROHCv2_PROFILE_IP_UDP))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "ROHCv2 IP/UDP profile is possible");
			profile = ROHCv2_PROFILE_IP_UDP;
			pkt_hdrs->all_hdrs_len = packet->len - remain_len;
			pkt_hdrs->payload_len = remain_len;
			pkt_hdrs->payload = remain_data;
			fingerprint->base.profile_id = profile;
			fingerprint->src_port = rohc_ntoh16(udp_header->source);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tsource port = %u", fingerprint->src_port);
			fingerprint->dst_port = rohc_ntoh16(udp_header->dest);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tdestination port = %u", fingerprint->dst_port);
		}

		/* check if the IP/UDP packet is a RTP packet */
		if(!rohc_comp_is_rtp_hdr_supported(comp, remain_data, remain_len, pkt_hdrs))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported RTP header");
			goto unsupported_rtp_hdr;
		}
		rtp = (const struct rtphdr *) remain_data;
		pkt_hdrs->rtp = rtp;
		remain_data += sizeof(struct rtphdr);
		remain_len -= sizeof(struct rtphdr);

		/* ROHCv1/v2 IP/UDP/RTP profiles are possible if they are enabled */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "IP/UDP/RTP packet detected by the RTP callback");
		if(pkt_hdrs->ip_hdrs_nr <= ROHC_MAX_IP_HDRS_RFC3095 &&
		   rohc_comp_profile_enabled_nocheck(comp, ROHCv1_PROFILE_IP_UDP_RTP))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "ROHCv1 IP/UDP/RTP profile is possible");
			profile = ROHCv1_PROFILE_IP_UDP_RTP;
			pkt_hdrs->all_hdrs_len = packet->len - remain_len;
			pkt_hdrs->payload_len = remain_len;
			pkt_hdrs->payload = remain_data;
			fingerprint->base.profile_id = profile;
			fingerprint->src_port = rohc_ntoh16(udp_header->source);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tsource port = %u", fingerprint->src_port);
			fingerprint->dst_port = rohc_ntoh16(udp_header->dest);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tdestination port = %u", fingerprint->dst_port);
			fingerprint->rtp_ssrc = rohc_ntoh32(rtp->ssrc);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tSSRC = 0x%08x", fingerprint->rtp_ssrc);
		}
		else if(all_ipv6_exts_len == 0 && /* TODO: ROHCv2: add IPv6 ext hdrs support */
		        rtp->version == 2 && /* ROHCv2 only supports RTP version 2 */
		        rohc_comp_profile_enabled_nocheck(comp, ROHCv2_PROFILE_IP_UDP_RTP))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "ROHCv2 IP/UDP/RTP profile is possible");
			profile = ROHCv2_PROFILE_IP_UDP_RTP;
			pkt_hdrs->all_hdrs_len = packet->len - remain_len;
			pkt_hdrs->payload_len = remain_len;
			pkt_hdrs->payload = remain_data;
			fingerprint->base.profile_id = profile;
			fingerprint->src_port = rohc_ntoh16(udp_header->source);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tsource port = %u", fingerprint->src_port);
			fingerprint->dst_port = rohc_ntoh16(udp_header->dest);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tdestination port = %u", fingerprint->dst_port);
			fingerprint->rtp_ssrc = rohc_ntoh32(rtp->ssrc);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tSSRC = 0x%08x", fingerprint->rtp_ssrc);
		}
	}
	else if(l4_proto == ROHC_IPPROTO_ESP)
	{
		const struct esphdr *esp;

		/* innermost IP payload shall be large enough for ESP header */
		if(remain_len < sizeof(struct esphdr))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "innermost IP payload too small for ESP header");
			goto unsupported_esp_hdr;
		}
		esp = (const struct esphdr *) remain_data;
		pkt_hdrs->esp = esp;
		remain_data += sizeof(struct esphdr);
		remain_len -= sizeof(struct esphdr);

		/* ROHCv1/v2 IP/ESP profiles are possible if they are enabled */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "IP/ESP packet detected");
		if(pkt_hdrs->ip_hdrs_nr <= ROHC_MAX_IP_HDRS_RFC3095 &&
		   rohc_comp_profile_enabled_nocheck(comp, ROHCv1_PROFILE_IP_ESP))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "ROHCv1 IP/ESP profile is possible");
			profile = ROHCv1_PROFILE_IP_ESP;
			pkt_hdrs->all_hdrs_len = packet->len - remain_len;
			pkt_hdrs->payload_len = remain_len;
			pkt_hdrs->payload = remain_data;
			fingerprint->base.profile_id = profile;
			fingerprint->esp_spi = rohc_ntoh32(esp->spi);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tSPI = 0x%08x", fingerprint->esp_spi);
		}
		else if(all_ipv6_exts_len == 0 && /* TODO: ROHCv2: add IPv6 ext hdrs support */
		        rohc_comp_profile_enabled_nocheck(comp, ROHCv2_PROFILE_IP_ESP))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "ROHCv2 IP/ESP profile is possible");
			profile = ROHCv2_PROFILE_IP_ESP;
			pkt_hdrs->all_hdrs_len = packet->len - remain_len;
			pkt_hdrs->payload_len = remain_len;
			pkt_hdrs->payload = remain_data;
			fingerprint->base.profile_id = profile;
			fingerprint->esp_spi = rohc_ntoh32(esp->spi);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tSPI = 0x%08x", fingerprint->esp_spi);
		}
	}

unsupported_rtp_hdr:
unsupported_esp_hdr:
unsupported_udp_hdr:
unsupported_tcp_hdr:
	return profile;
}


/**
 * @brief Are the given IP headers supported?
 *
 * @param comp                    The ROHC compressor to compress the packet with
 * @param packet                  The packet to search the best compression profile
 *                                for
 * @param packet_len              The length (in bytes) of the uncompressed packet
 * @param[out] fingerprint        The fingerprint computed on the packet to later
 *                                help finding the best compression context
 * @param[out] pkt_hdrs           The information collected about the packet
 *                                headers, may be used later during the detection
 *                                of changes with the compression context, thus
 *                                avoiding another packet parsing
 * @param[out] all_ip_hdrs_len    The length (in bytes) of the parsed IP headers
 * @param[out] all_ipv6_exts_len  The length (in bytes) of the parsed IP extension
 *                                headers
 * @return                        The ID of the best compression profile to compress
 *                                the packet
 */
static bool rohc_comp_are_ip_hdrs_supported(const struct rohc_comp *const comp,
                                            const uint8_t *const packet,
                                            const size_t packet_len,
                                            struct rohc_fingerprint *const fingerprint,
                                            struct rohc_pkt_hdrs *const pkt_hdrs,
                                            size_t *const all_ip_hdrs_len,
                                            size_t *const all_ipv6_exts_len)
{
	const uint8_t *remain_data = packet;
	size_t remain_len = packet_len;
	bool are_ip_hdrs_supported = false;
	size_t ip_hdrs_nr;
	uint8_t next_proto;

	/* check that the the versions of IP headers are 4 or 6 and that IP headers
	 * are not IP fragments */
	ip_hdrs_nr = 0;
	do
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;

		/* check minimal length for IP version */
		if(remain_len < sizeof(struct ip_hdr))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "failed to determine the version of IP header #%zu",
			           ip_hdrs_nr + 1);
			goto unsupported_ip_hdr;
		}

		pkt_hdrs->ip_hdrs[ip_hdrs_nr].tot_len = remain_len;
		pkt_hdrs->ip_hdrs[ip_hdrs_nr].version = ip->version;

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;
			const size_t ipv4_min_words_nr = sizeof(struct ipv4_hdr) / sizeof(uint32_t);

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "found IPv4");
			if(remain_len < sizeof(struct ipv4_hdr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "uncompressed packet too short for IP header #%zu",
				           ip_hdrs_nr + 1);
				goto unsupported_ip_hdr;
			}

			/* IPv4 options are not supported by the TCP profile */
			if(ipv4->ihl != ipv4_min_words_nr)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported: IP options are not "
				           "accepted", ip_hdrs_nr + 1);
				goto unsupported_ip_hdr;
			}

			/* IPv4 total length shall be correct */
			if(rohc_ntoh16(ipv4->tot_len) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported: total length is %u "
				           "while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv4->tot_len), remain_len);
				goto unsupported_ip_hdr;
			}

			/* check if the IPv4 header is a fragment */
			if(ipv4_is_fragment(ipv4))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported: header is fragmented",
				           ip_hdrs_nr + 1);
				goto unsupported_ip_hdr;
			}

			/* the IPv4 header checksum shall be correct in order to be inferred */
			if((comp->features & ROHC_COMP_FEATURE_NO_IP_CHECKSUMS) == 0 &&
			   ip_fast_csum(remain_data, ipv4_min_words_nr) != 0)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported: checksum is not correct",
				           ip_hdrs_nr + 1);
				goto unsupported_ip_hdr;
			}

			next_proto = ipv4->protocol;
			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);

			pkt_hdrs->ip_hdrs[ip_hdrs_nr].ipv4 = ipv4;
			pkt_hdrs->ip_hdrs[ip_hdrs_nr].tos_tc = ipv4->tos;
			pkt_hdrs->ip_hdrs[ip_hdrs_nr].ttl_hl = ipv4->ttl;
			pkt_hdrs->ip_hdrs[ip_hdrs_nr].exts_nr = 0;
			fingerprint->base.ip_hdrs[ip_hdrs_nr].saddr.u32[0] = ipv4->saddr;
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tsource address = " IPV4_ADDR_FORMAT,
			           IPV4_ADDR_RAW(fingerprint->base.ip_hdrs[ip_hdrs_nr].saddr.u8));
			fingerprint->base.ip_hdrs[ip_hdrs_nr].daddr.u32[0] = ipv4->daddr;
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tdestination address = " IPV4_ADDR_FORMAT,
			           IPV4_ADDR_RAW(fingerprint->base.ip_hdrs[ip_hdrs_nr].daddr.u8));
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "found IPv6");
			if(remain_len < sizeof(struct ipv6_hdr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "uncompressed packet too short for IP header #%zu",
				           ip_hdrs_nr + 1);
				goto unsupported_ip_hdr;
			}
			next_proto = ipv6->nh;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* payload length shall be correct */
			if(rohc_ntoh16(ipv6->plen) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported: payload length is %u "
				           "while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv6->plen), remain_len);
				goto unsupported_ip_hdr;
			}

			/* reject packets with malformed IPv6 extension headers or IPv6
			 * extension headers that are not compatible with the TCP profile */
			if(!rohc_comp_ipv6_exts_are_acceptable(comp, &next_proto,
			                                       remain_data, remain_len,
			                                       pkt_hdrs->ip_hdrs + ip_hdrs_nr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported: malformed or incompatible "
				           "IPv6 extension headers detected", ip_hdrs_nr + 1);
				goto unsupported_ip_hdr;
			}
			(*all_ipv6_exts_len) += pkt_hdrs->ip_hdrs[ip_hdrs_nr].exts_len;
			remain_data += pkt_hdrs->ip_hdrs[ip_hdrs_nr].exts_len;
			remain_len -= pkt_hdrs->ip_hdrs[ip_hdrs_nr].exts_len;

			pkt_hdrs->ip_hdrs[ip_hdrs_nr].ipv6 = ipv6;
			pkt_hdrs->ip_hdrs[ip_hdrs_nr].tos_tc = ipv6_get_tc(ipv6);
			pkt_hdrs->ip_hdrs[ip_hdrs_nr].ttl_hl = ipv6->hl;
			memcpy(&fingerprint->base.ip_hdrs[ip_hdrs_nr].saddr.u8, &ipv6->saddr,
			       sizeof(struct ipv6_addr));
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tsource address = " IPV6_ADDR_FORMAT,
			           IPV6_ADDR_RAW(fingerprint->base.ip_hdrs[ip_hdrs_nr].saddr.u8));
			memcpy(&fingerprint->base.ip_hdrs[ip_hdrs_nr].daddr.u8, &ipv6->daddr,
			       sizeof(struct ipv6_addr));
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tdestination address = " IPV6_ADDR_FORMAT,
			           IPV6_ADDR_RAW(fingerprint->base.ip_hdrs[ip_hdrs_nr].daddr.u8));
			fingerprint->base.ip_hdrs[ip_hdrs_nr].flow_label = ipv6_get_flow_label(ipv6);
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "\tflow label = 0x%x",
			           fingerprint->base.ip_hdrs[ip_hdrs_nr].flow_label);
		}
		else
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported version %u for header #%zu",
			           ip->version, ip_hdrs_nr + 1);
			goto unsupported_ip_hdr;
		}

		fingerprint->base.ip_hdrs[ip_hdrs_nr].version = ip->version;
		fingerprint->base.ip_hdrs[ip_hdrs_nr].next_proto = next_proto;
		pkt_hdrs->ip_hdrs[ip_hdrs_nr].next_proto = next_proto;
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "\tnext protocol = %u", next_proto);
		fingerprint->base.ip_hdrs_nr++;
		ip_hdrs_nr++;
	}
	while(rohc_is_tunneling(next_proto) && ip_hdrs_nr < ROHC_MAX_IP_HDRS);

	/* remember the number of IP headers and the innermost IP header */
	assert(ip_hdrs_nr > 0);
	pkt_hdrs->ip_hdrs_nr = ip_hdrs_nr;
	pkt_hdrs->innermost_ip_hdr = &(pkt_hdrs->ip_hdrs[ip_hdrs_nr - 1]);

	/* IP headers are supported */
	(*all_ip_hdrs_len) = packet_len - remain_len;
	are_ip_hdrs_supported = true;

unsupported_ip_hdr:
	return are_ip_hdrs_supported;
}


/**
 * @brief Is the given TCP header supported?
 *
 * @param comp                   The ROHC compressor to compress the packet with
 * @param packet                 The TCP packet to search the best compression
 *                               profile for
 * @param packet_len             The length (in bytes) of the uncompressed packet
 * @param[out] pkt_hdrs          The information collected about the packet
 *                               headers, may be used later during the detection
 *                               of changes with the compression context, thus
 *                               avoiding another packet parsing
 * @param[out] tcp_hdr_full_len  The length of the TCP header including options
 * @return                       The ID of the best compression profile to
 *                               compress the packet
 */
static bool rohc_comp_is_tcp_hdr_supported(const struct rohc_comp *const comp,
                                           const uint8_t *const packet,
                                           const size_t packet_len,
                                           struct rohc_pkt_hdrs *const pkt_hdrs,
                                           size_t *const tcp_hdr_full_len)
{
	const uint8_t *remain_data = packet;
	size_t remain_len = packet_len;
	const struct tcphdr *tcp_header;
	bool is_tcp_hdr_supported = false;

	/* innermost IP payload shall be large enough for TCP header */
	if(remain_len < sizeof(struct tcphdr))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "innermost IP payload too small for minimal TCP header");
		goto unsupported_tcp_hdr;
	}

	/* retrieve the TCP header */
	tcp_header = (const struct tcphdr *) remain_data;
	if(tcp_header->data_offset < 5)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "TCP data offset too small for minimal TCP header");
		goto unsupported_tcp_hdr;
	}

	/* is packet large enough for the full TCP header with options? */
	*tcp_hdr_full_len = tcp_header->data_offset * sizeof(uint32_t);
	if(remain_len < (*tcp_hdr_full_len))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "TCP data too small for full TCP header with options");
		goto unsupported_tcp_hdr;
	}

	/* reject packets with malformed TCP options or TCP options that are not
	 * compatible with the TCP profile */
	if(!rohc_comp_tcp_are_options_acceptable(comp, tcp_header->options,
	                                         tcp_header->data_offset, pkt_hdrs))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "malformed or incompatible TCP options detected");
		goto unsupported_tcp_hdr;
	}

	/* TCP header is supported */
	is_tcp_hdr_supported = true;

unsupported_tcp_hdr:
	return is_tcp_hdr_supported;
}


/**
 * @brief Is the given RTP header supported?
 *
 * @param comp              The ROHC compressor to compress the packet with
 * @param packet            The uncompressed packet to search the best compression
 *                          profile for
 * @param packet_len        The length (in bytes) of the uncompressed packet
 * @param[out] pkt_hdrs     The information collected about the packet headers,
 *                          may be used later during the detection of changes
 *                          with the compression context, thus avoiding another
 *                          packet parsing
 * @return                  The ID of the best compression profile to compress
 *                          the packet
 */
static bool rohc_comp_is_rtp_hdr_supported(const struct rohc_comp *const comp,
                                           const uint8_t *const packet,
                                           const size_t packet_len,
                                           struct rohc_pkt_hdrs *const pkt_hdrs)
{
	const uint8_t *remain_data = packet;
	size_t remain_len = packet_len;
	const uint8_t *udp_payload;
	unsigned int udp_payload_size;
	const struct rtphdr *rtp;
	bool is_rtp = false;

	if(comp->rtp_callback == NULL)
	{
		goto unsupported_rtp_hdr;
	}

	/* UDP payload shall be large enough for RTP header  */
	if(remain_len < sizeof(struct rtphdr))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "UDP header is not large enough for RTP header");
		goto unsupported_rtp_hdr;
	}
	udp_payload = (uint8_t *) remain_data;
	udp_payload_size = remain_len;
	rtp = (const struct rtphdr *) udp_payload;

	/* RTP packets with one or more CSRC items cannot be compressed by the
	 * RTP profile for the moment */
	if(rtp->cc != 0)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "RTP header is not supported: compression of CSRC items is "
		           "not supported yet by RTP profile");
		goto unsupported_rtp_hdr;
	}

	/* check if the IP/UDP packet is a RTP packet with the user callback
	   dedicated to RTP stream detection: if the RTP callback returns true,
	   consider that the packet matches the RTP profile */
	is_rtp = comp->rtp_callback((const uint8_t *) pkt_hdrs->innermost_ip_hdr->ip,
	                            (const uint8_t *) pkt_hdrs->udp,
	                            udp_payload, udp_payload_size,
	                            comp->rtp_private);
	if(is_rtp)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "user said the IP/UDP packet is one IP/UDP/RTP packet");
	}

unsupported_rtp_hdr:
	return is_rtp;
}


/**
 * @brief Compress the given uncompressed packet into a ROHC packet
 *
 * Compress the given uncompressed packet into a ROHC packet. The compression
 * may succeed into two different ways:
 *   \li return \ref ROHC_STATUS_OK and a full ROHC packet,
 *   \li return \ref ROHC_STATUS_SEGMENT and no ROHC data if ROHC segmentation
 *       is required.
 *
 * Notes:
 *   \li ROHC segmentation:
 *       The ROHC compressor has to use ROHC segmentation if the output buffer
 *       rohc_packet was too small for the compressed ROHC packet and if the
 *       Maximum Reconstructed Reception Unit (MRRU) configured with the
 *       function \ref rohc_comp_set_mrru was not exceeded. If ROHC segmentation
 *       is used, one may use the \ref rohc_comp_get_segment2 function to
 *       retrieve all the ROHC segments one by one.
 *   \li Time-related features in the ROHC protocol:
 *       Set the \e uncomp_packet.time parameter to 0 if arrival time of the
 *       uncompressed packet is unknown or to disable the time-related features
 *       in the ROHC protocol.
 *
 * @param comp              The ROHC compressor
 * @param uncomp_packet     The uncompressed packet to compress
 * @param[out] rohc_packet  The resulting compressed ROHC packet
 * @return                  Possible return values:
 *                          \li \ref ROHC_STATUS_OK if a ROHC packet is
 *                              returned
 *                          \li \ref ROHC_STATUS_SEGMENT if no ROHC data is
 *                              returned and ROHC segments can be retrieved
 *                              with successive calls to
 *                              \ref rohc_comp_get_segment2
 *                          \li \ref ROHC_STATUS_OUTPUT_TOO_SMALL if the
 *                              output buffer is too small for the compressed
 *                              packet
 *                          \li \ref ROHC_STATUS_ERROR if an error occurred
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
 * @see rohc_comp_get_segment2
 */
rohc_status_t rohc_compress4(struct rohc_comp *const comp,
                             const struct rohc_buf uncomp_packet,
                             struct rohc_buf *const rohc_packet)
{
	struct rohc_comp_ctxt *c;
	rohc_packet_t packet_type;
	int rohc_hdr_size;

	const struct rohc_comp_profile *profile;
	rohc_profile_t profile_id;

	struct rohc_fingerprint fingerprint;
	struct rohc_pkt_hdrs pkt_hdrs;

	rohc_status_t status = ROHC_STATUS_ERROR; /* error status by default */

	/* check inputs validity */
	if(comp == NULL)
	{
		goto error;
	}
	if(rohc_buf_is_malformed(uncomp_packet))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is malformed");
		goto error;
	}
	if(rohc_buf_is_empty(uncomp_packet))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given uncomp_packet is empty");
		goto error;
	}
	if(rohc_packet == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is NULL");
		goto error;
	}
	if(rohc_buf_is_malformed(*rohc_packet))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is malformed");
		goto error;
	}
	if(!rohc_buf_is_empty(*rohc_packet))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_packet is not empty");
		goto error;
	}

	/* print uncompressed bytes */
	if((comp->features & ROHC_COMP_FEATURE_DUMP_PACKETS) != 0)
	{
		rohc_dump_packet(comp->trace_callback, comp->trace_callback_priv,
		                 ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
		                 "uncompressed data, max 100 bytes", uncomp_packet);
	}

	/* what ROHC profile fits the uncompressed packet best? */
	profile_id = rohc_comp_get_profile(comp, &uncomp_packet, &fingerprint, &pkt_hdrs);
	if(profile_id == ROHC_PROFILE_MAX)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to find a matching profile among the enabled profiles "
		             "for the uncompressed packet");
		goto error;
	}

	/* find the profile identified by the given profile ID */
	{
		const uint8_t profile_major = (profile_id >> 8) & 0xff;
		const uint8_t profile_minor = profile_id & 0xff;
		profile = rohc_comp_profiles[profile_major][profile_minor];
		if(profile == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "profile '%s' (0x%04x) is not implemented yet",
			             rohc_get_profile_descr(profile_id), profile_id);
			goto error;
		}
	}

	/* find the best profile context for the packet */
	c = rohc_comp_find_ctxt(comp, profile, &uncomp_packet, &fingerprint, &pkt_hdrs);
	if(c == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to find a matching context or to create a new "
		             "context");
		goto error;
	}

	/* decide the next state to go */
	rohc_comp_decide_state(c, uncomp_packet.time);

	/* create the ROHC packet: */
	rohc_packet->len = 0;

	/* use profile to compress packet */
	rohc_comp_debug(c, "compress the packet #%d", comp->num_packets + 1);
	rohc_hdr_size =
		c->profile->encode(c, &pkt_hdrs, rohc_buf_data(*rohc_packet),
		                   rohc_buf_avail_len(*rohc_packet),
		                   &packet_type);
	if(rohc_hdr_size < 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "error while compressing with profile '%s' (0x%04x)",
		             rohc_get_profile_descr(profile_id), profile_id);
		goto error_free_new_context;
	}
	rohc_packet->len += rohc_hdr_size;

	if(profile_id == ROHCv1_PROFILE_UNCOMPRESSED &&
	   packet_type == ROHC_PACKET_NORMAL)
	{
		pkt_hdrs.all_hdrs_len++;
		pkt_hdrs.payload_len--;
	}

	/* increment the number of packets that were emitted in the current
	 * compression state */
	if(c->state_oa_repeat_nr < comp->oa_repetitions_nr)
	{
		c->state_oa_repeat_nr++;
		rohc_comp_debug(c, "last change was transmitted %u/%u times",
		                c->state_oa_repeat_nr, comp->oa_repetitions_nr);
	}

	/* the payload starts after the header, skip it */
	rohc_buf_pull(rohc_packet, rohc_hdr_size);

	/* is packet too large for output buffer? */
	if(pkt_hdrs.payload_len > rohc_buf_avail_len(*rohc_packet))
	{
		const size_t max_rohc_buf_len =
			rohc_buf_avail_len(*rohc_packet) + rohc_hdr_size;
		uint32_t rru_crc;

		/* resulting ROHC packet too large, segmentation may be a solution */
		rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		          "%s ROHC packet is too large for the given output buffer, "
		          "try to segment it (input size = %zd, maximum output "
		          "size = %zd, required output size = %d + %u = %u, "
		          "MRRU = %zd)", rohc_get_packet_descr(packet_type),
		          uncomp_packet.len, max_rohc_buf_len, rohc_hdr_size,
		          pkt_hdrs.payload_len, rohc_hdr_size + pkt_hdrs.payload_len,
		          comp->mrru);

		/* in order to be segmented, a ROHC packet shall be <= MRRU
		 * (remember that MRRU includes the CRC length) */
		if((pkt_hdrs.payload_len + CRC_FCS32_LEN) > comp->mrru)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "%s ROHC packet cannot be segmented: too large (%d + "
			             "%u + %u = %u bytes) for MRRU (%zu bytes)",
			             rohc_get_packet_descr(packet_type), rohc_hdr_size,
			             pkt_hdrs.payload_len, CRC_FCS32_LEN, rohc_hdr_size +
			             pkt_hdrs.payload_len + CRC_FCS32_LEN, comp->mrru);
			goto error_free_new_context;
		}
		rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		          "%s ROHC packet can be segmented (MRRU = %zd)",
		          rohc_get_packet_descr(packet_type), comp->mrru);

		/* store the whole ROHC packet in compressor (headers and payload only,
		 * not feedbacks, feedbacks will be transmitted with the first segment
		 * when rohc_comp_get_segment2() is called) */
		if(comp->rru_len != 0)
		{
			/* warn users about previous, not yet retrieved RRU */
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "erase the existing %zd-byte RRU that was not "
			             "retrieved yet (call rohc_comp_get_segment2() to add "
			             "support for ROHC segments in your application)",
			             comp->rru_len);
		}
		comp->rru_len = 0;
		comp->rru_off = 0;
		/* ROHC header */
		rohc_buf_push(rohc_packet, rohc_hdr_size);
		memcpy(comp->rru + comp->rru_off, rohc_buf_data(*rohc_packet),
		       rohc_hdr_size);
		comp->rru_len += rohc_hdr_size;
		/* ROHC payload */
		memcpy(comp->rru + comp->rru_off + comp->rru_len,
		       rohc_buf_data_at(uncomp_packet, pkt_hdrs.all_hdrs_len),
		       pkt_hdrs.payload_len);
		comp->rru_len += pkt_hdrs.payload_len;
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

		/* reset the length of the ROHC packet: it shall be 0 for users */
		rohc_packet->len = 0;

		/* report to users that segmentation is possible */
		status = ROHC_STATUS_SEGMENT;
	}
	else
	{
		/* copy full payload after ROHC header */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "copy full %u-byte payload", pkt_hdrs.payload_len);
		rohc_buf_append(rohc_packet,
		                rohc_buf_data_at(uncomp_packet, pkt_hdrs.all_hdrs_len),
		                pkt_hdrs.payload_len);

		/* unhide the ROHC header */
		rohc_buf_push(rohc_packet, rohc_hdr_size);
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "ROHC size = %zd bytes (header = %d, payload = %u), output "
		           "buffer size = %zu", rohc_packet->len, rohc_hdr_size,
		           pkt_hdrs.payload_len, rohc_buf_avail_len(*rohc_packet));

		/* report to user that compression was successful */
		status = ROHC_STATUS_OK;
	}

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
	c->header_uncompressed_size += pkt_hdrs.all_hdrs_len;
	c->header_compressed_size += rohc_hdr_size;
	c->num_sent_packets++;

	c->total_last_uncompressed_size = uncomp_packet.len;
	c->total_last_compressed_size = rohc_packet->len;
	c->header_last_uncompressed_size = pkt_hdrs.all_hdrs_len;
	c->header_last_compressed_size = rohc_hdr_size;

	/* compression is successful */
	return status;

error_free_new_context:
	/* free context if it was just created */
	if(c->num_sent_packets <= 1)
	{
		if(c->profile->id == ROHCv1_PROFILE_UNCOMPRESSED)
		{
			comp->uncompressed_ctxt = NULL;
		}
		else
		{
			hashtable_del(&comp->contexts_by_fingerprint, &c->fingerprint);
			/* TODO: replace TCP by CR capacity */
			if(c->profile->id == ROHCv1_PROFILE_IP_TCP)
			{
				hashtable_cr_del(&comp->contexts_cr, &c->fingerprint);
			}
		}
		c->profile->destroy(c);
		c->used = 0;
		assert(comp->num_contexts_used > 0);
		comp->num_contexts_used--;
	}
error:
	return ROHC_STATUS_ERROR;
}


/**
 * @brief Pad the given ROHC compressed packet
 *
 * Add as many padding bytes as required to get a ROHC packet of the given length.
 *
 * @param comp              The ROHC compressor
 * @param[in,out] rohc_pkt  The compressed ROHC packet to pad up to \e min_pkt_len
 * @param min_pkt_len       The minimum length of the ROHC packet
 * @return                  Possible return values:
 *                          \li \ref ROHC_STATUS_OK if a padded ROHC packet is
 *                              returned
 *                          \li \ref ROHC_STATUS_OUTPUT_TOO_SMALL if the
 *                              buffer is too small for the padded ROHC packet
 *                          \li \ref ROHC_STATUS_ERROR if an error occurred
 *
 * @ingroup rohc_comp
 *
 * @see rohc_compress4
 */
rohc_status_t rohc_comp_pad(struct rohc_comp *const comp,
                            struct rohc_buf *const rohc_pkt,
                            const size_t min_pkt_len)
{
	rohc_status_t status = ROHC_STATUS_ERROR; /* error status by default */
	const uint8_t padding_byte = ROHC_PADDING_BYTE;
	size_t padding_bytes_nr = 0;
	size_t i;

	/* check inputs validity */
	if(comp == NULL)
	{
		goto error;
	}
	if(rohc_pkt == NULL)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_pkt is NULL");
		goto error;
	}
	if(rohc_buf_is_malformed(*rohc_pkt))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_pkt is malformed");
		goto error;
	}
	if(rohc_buf_is_empty(*rohc_pkt))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "given rohc_pkt is empty");
		goto error;
	}

	/* if ROHC packet is already smaller than the minimum length, prepend
	 * some padding bytes before the ROHC packet up to the minimum length */
	if(rohc_pkt->len >= min_pkt_len)
	{
		padding_bytes_nr = 0;
	}
	else
	{
		padding_bytes_nr = min_pkt_len - rohc_pkt->len;
	}

	/* ROHC packet cannot be padded if buffer has not enough room before packet */
	if(rohc_pkt->offset < padding_bytes_nr)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "%zu-byte ROHC packet cannot be padded up to %zu bytes with "
		             "%zu bytes: only %zu bytes available in buffer before ROHC "
		             "data", rohc_pkt->len, min_pkt_len, padding_bytes_nr,
		             rohc_pkt->offset);
		status = ROHC_STATUS_OUTPUT_TOO_SMALL;
		goto error;
	}

	/* add required padding bytes */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "pad %zu-byte ROHC packet up to %zu bytes with %zu bytes",
	           rohc_pkt->len, min_pkt_len, padding_bytes_nr);
	for(i = 0; i < padding_bytes_nr; i++)
	{
		rohc_buf_prepend(rohc_pkt, &padding_byte, 1);
	}
	assert(rohc_pkt->len >= min_pkt_len);

	/* everything went fine */
	status = ROHC_STATUS_OK;

error:
	return status;
}


/**
 * @brief Get the next ROHC segment if any
 *
 * Get the next ROHC segment if any.
 *
 * To get all the segments of one ROHC packet, call this function until
 * \ref ROHC_STATUS_OK or \ref ROHC_STATUS_ERROR is returned.
 *
 * @param comp          The ROHC compressor
 * @param[out] segment  The buffer where to store the ROHC segment
 * @return              Possible return values:
 *                       \li \ref ROHC_STATUS_SEGMENT if a ROHC segment is
 *                           returned and more segments are available,
 *                       \li \ref ROHC_STATUS_OK if a ROHC segment is returned
 *                           and no more ROHC segment is available
 *                       \li \ref ROHC_STATUS_ERROR if an error occurred
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
                        // rohc_decompress3 shall return ROHC_STATUS_OK
                        // and no decompressed packet
                        ...
\endcode
 * \snippet test_segment.c segment ROHC packet #3
 * \code
                // decompress the final ROHC segment here, the function
                // rohc_decompress4 shall return ROHC_STATUS_OK
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
rohc_status_t rohc_comp_get_segment2(struct rohc_comp *const comp,
                                     struct rohc_buf *const segment)

{
	const size_t segment_type_len = 1; /* segment type byte */
	size_t max_data_len;
	rohc_status_t status;

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
	if(comp->rru_len == 0)
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
	rohc_buf_pull(segment, 1);

	/* copy remaining ROHC data (CRC included) */
	rohc_buf_append(segment, comp->rru + comp->rru_off, max_data_len);
	rohc_buf_pull(segment, max_data_len);
	comp->rru_off += max_data_len;
	comp->rru_len -= max_data_len;

	/* set status wrt to (non-)final segment */
	if(comp->rru_len == 0)
	{
		/* final segment, no more segment available */
		status = ROHC_STATUS_OK;
		/* reset context for next RRU */
		comp->rru_off = 0;
	}
	else
	{
		/* non-final segment, more segments to available */
		status = ROHC_STATUS_SEGMENT;
	}

	/* shift backward the RRU data, header and the feedback data */
	rohc_buf_push(segment, max_data_len + 1);

	return status;

error:
	return ROHC_STATUS_ERROR;
}


/**
 * @brief Force the compressor to re-initialize all its contexts
 *
 * Make all contexts restart their initialization with decompressor, ie. they
 * go in the lowest compression state. This function can be used once the
 * ROHC channel is established again after an interruption.
 *
 * The function implements the CONTEXT_REINITIALIZATION signal described by
 * RFC 3095 at §6.3.1 as:
 * \verbatim
   CONTEXT_REINITIALIZATION -- signal
   This parameter triggers a reinitialization of the entire context at
   the decompressor, both the static and the dynamic part.  The
   compressor MUST, when CONTEXT_REINITIALIZATION is triggered, back off
   to the IR state and fully reinitialize the context by sending IR
   packets with both the static and dynamic chains covering the entire
   uncompressed headers until it is reasonably confident that the
   decompressor contexts are reinitialized.  The context
   reinitialization MUST be done for all contexts at the compressor.
   This parameter may for instance be used to do context relocation at,
   e.g., a cellular handover that results in a change of compression
   point in the radio access network.
\endverbatim
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
	          "force re-initialization for all %u contexts",
	          comp->num_contexts_used);

	for(i = 0; i <= comp->medium.max_cid; i++)
	{
		if(comp->contexts[i].used)
		{
			if(!rohc_comp_reinit_context(&(comp->contexts[i])))
			{
				rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				             "failed to force re-initialization for CID %u", i);
				goto error;
			}
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Set the number of repetitions required to gain transmission confidence
 *
 * The Optimistic Approach is defined by RFC 3095 §5.3.1.1.1 as follow:
 *
 *   Transition to a higher compression state in Unidirectional mode is
 *   carried out according to the optimistic approach principle.  This
 *   means that the compressor transits to a higher compression state when
 *   it is fairly confident that the decompressor has received enough
 *   information to correctly decompress packets sent according to the
 *   higher compression state.
 *
 *   When the compressor is in the IR state, it will stay there until it
 *   assumes that the decompressor has correctly received the static
 *   context information.  For transition from the FO to the SO state, the
 *   compressor should be confident that the decompressor has all
 *   parameters needed to decompress according to a fixed pattern.
 *
 *   The compressor normally obtains its confidence about decompressor
 *   status by sending several packets with the same information according
 *   to the lower compression state.  If the decompressor receives any of
 *   these packets, it will be in sync with the compressor.  The number of
 *   consecutive packets to send for confidence is not defined in this
 *   document.
 *
 * This function allows the library users to set the number of repetitions
 * required by the ROHC compressor to gain confidence that the ROHC
 * decompressor got the transmitted information.
 *
 * It controls:
 *  - the number of IR packets transmitted in a row at context initialization,
 *  - the number of context-updating packets transmitted in case of stream change,
 *  - the number of transmissions of TS stride, list structures or list items
 *    before they are considered as known,
 *  - the width of the W-LSB window.
 *
 * The number of repetitions may be chosen as follow:
 *  a/ define the largest loss burst that you want to be robust to,
 *  b/ increment that number by one, so that at least one packet per burst
 *     is received by the decompressor.
 *
 * @warning The value can not be modified after library initialization
 *
 * @param comp            The ROHC compressor to configure
 * @param repetitions_nr  The number of repetitions (4 by default)
 * @return                true in case of success, false in case of failure
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_optimistic_approach(struct rohc_comp *const comp,
                                       const size_t repetitions_nr)
{
	/* we need a valid compressor */
	if(comp == NULL)
	{
		return false;
	}

	/* the window width shall be in both ranges ]0;ROHC_WLSB_WIDTH_MAX]
	 * and ]0;UINT8_MAX] */
	if(repetitions_nr == 0 ||
	   repetitions_nr > ROHC_WLSB_WIDTH_MAX ||
	   repetitions_nr > UINT8_MAX)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "failed to "
		             "set the number of Optimistic Approach repetitions to %zu: "
		             "value must be in range ]0;%u]",
		             repetitions_nr, rohc_min(ROHC_WLSB_WIDTH_MAX, UINT8_MAX));
		return false;
	}

	/* refuse to set a value if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "unable to "
		             "modify the number of Optimistic Approach repetitions "
		             "after initialization");
		return false;
	}

	comp->oa_repetitions_nr = repetitions_nr;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "number of Optimistic Approach repetitions set to %u",
	          comp->oa_repetitions_nr);

	return true;
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
 * @warning The value can not be modified after library initialization
 *
 * @param comp   The ROHC compressor
 * @param width  The width of the W-LSB sliding window
 * @return       true in case of success, false in case of failure
 *
 * @ingroup rohc_comp
 *
 * @deprecated please use rohc_comp_set_optimistic_approach() instead
 */
bool rohc_comp_set_wlsb_window_width(struct rohc_comp *const comp,
                                     const size_t width)
{
	/* fallback on the new function */
	return rohc_comp_set_optimistic_approach(comp, width);
}


/**
 * @brief Set the reordering ratio for the W-LSB encoding scheme
 *
 * The control field reorder_ratio specifies how much reordering is
 * handled by the W-LSB encoding of the MSN in ROHCv2 profiles.
 *
 * The reordering ration is set to ROHC_REORDERING_NONE by default.
 *
 * @param comp           The ROHC compressor
 * @param reorder_ratio  The reordering ratio
 * @return               true in case of success,
 *                       false in case of failure
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_reorder_ratio(struct rohc_comp *const comp,
                                 const rohc_reordering_offset_t reorder_ratio)
{
	/* we need a valid compressor */
	if(comp == NULL)
	{
		return false;
	}

	/* Check value of reorder ratio */
	if(reorder_ratio != ROHC_REORDERING_NONE &&
	   reorder_ratio != ROHC_REORDERING_QUARTER &&
	   reorder_ratio != ROHC_REORDERING_HALF &&
	   reorder_ratio != ROHC_REORDERING_THREEQUARTERS)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "failed to "
		             "set reorder ratio to %u: reorder ratio must be in range "
		             "[%u;%u]", reorder_ratio, ROHC_REORDERING_NONE,
		             ROHC_REORDERING_THREEQUARTERS);
		return false;
	}

	/* refuse to set a value if compressor is in use */
	if(comp->num_packets > 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "unable to "
		             "modify reorder ratio after initialization");
		return false;
	}

	comp->reorder_ratio = reorder_ratio;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "Reorder ratio set to %u", reorder_ratio);

	return true;
}


/**
 * @brief Set the timeouts in packets for IR and FO periodic refreshes
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
	if(ir_timeout == 0 || fo_timeout == 0 || ir_timeout <= fo_timeout)
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

	comp->periodic_refreshes_ir_timeout_pkts = ir_timeout;
	comp->periodic_refreshes_fo_timeout_pkts = fo_timeout;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "IR timeout for "
	          "context periodic refreshes set to %zd", ir_timeout);
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "FO timeout for "
	          "context periodic refreshes set to %zd", fo_timeout);

	return true;
}


/**
 * @brief Set the timeouts in ms for IR and FO periodic refreshes
 *
 * Set the timeout values for IR and FO periodic refreshes. The IR timeout
 * shall be greater than the FO timeout. Both timeouts are expressed in
 * milliseconds.
 *
 * The IR timeout is set to \ref CHANGE_TO_IR_TIME by default.
 * The FO timeout is set to \ref CHANGE_TO_FO_TIME by default.
 *
 * @warning The values can not be modified after library initialization
 *
 * @param comp        The ROHC compressor
 * @param ir_timeout  The delay (in ms) before going back to IR state
 *                    to force a context refresh
 * @param fo_timeout  The delay (in ms) before going back to FO state
 *                    to force a context refresh
 * @return            true in case of success, false in case of failure
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_set_periodic_refreshes_time(struct rohc_comp *const comp,
                                           const uint64_t ir_timeout,
                                           const uint64_t fo_timeout)
{
	/* we need a valid compressor, positive non-zero timeouts,
	 * and IR timeout > FO timeout */
	if(comp == NULL)
	{
		return false;
	}
	if(ir_timeout == 0 || fo_timeout == 0 || ir_timeout <= fo_timeout)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "invalid timeouts for context periodic refreshes "
		             "(IR timeout = %" PRIu64 " ms, FO timeout = %" PRIu64 " ms)",
		             ir_timeout, fo_timeout);
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

	comp->periodic_refreshes_ir_timeout_time = ir_timeout;
	comp->periodic_refreshes_fo_timeout_time = fo_timeout;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "IR timeout for "
	          "context periodic refreshes set to %" PRIu64 " ms", ir_timeout);
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "FO timeout for "
	          "context periodic refreshes set to %" PRIu64 " ms", fo_timeout);

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
 * The L parameter is set to \ref ROHC_OA_REPEAT_DEFAULT by default.
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
 *
 * @deprecated please use rohc_comp_set_optimistic_approach() instead
 */
bool rohc_comp_set_list_trans_nr(struct rohc_comp *const comp,
                                 const size_t list_trans_nr)
{
	/* fallback on the new function */
	return rohc_comp_set_optimistic_approach(comp, list_trans_nr);
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
 * @param comp     The ROHC compressor, shall be valid
 * @param profile  The profile to ask status for
 * @return         Possible return values:
 *                  \li true if the profile exists and is enabled,
 *                  \li false if the profile does not exist,
 *                  \li false if the profile is disabled
 *
 * @see rohc_comp_profile_enabled
 */
static bool rohc_comp_profile_enabled_nocheck(const struct rohc_comp *const comp,
                                              const rohc_profile_t profile)
{
	const uint8_t profile_major = (profile >> 8) & 0xff;
	const uint8_t profile_minor = profile & 0xff;
	return comp->enabled_profiles[profile_major][profile_minor];
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
	const uint8_t profile_major = (profile >> 8) & 0xff;
	const uint8_t profile_minor = profile & 0xff;
	bool is_profile_enabled;

	if(comp == NULL ||
	   profile_major > ROHC_PROFILE_ID_MAJOR_MAX ||
	   profile_minor > ROHC_PROFILE_ID_MINOR_MAX)
	{
		is_profile_enabled = false;
	}
	else
	{
		is_profile_enabled = comp->enabled_profiles[profile_major][profile_minor];
	}

	return is_profile_enabled;
}


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
 * The ROHCv1 and ROHCv2 profiles are incompatible. The same profile cannot
 * be enabled in both versions 1 and 2.
 *
 * @param comp     The ROHC compressor
 * @param profile  The profile to enable
 * @return         true if the profile exists,
 *                 false if the profile does not exist or a similar profile is already enabled
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
	const uint8_t profile_major = (profile >> 8) & 0xff;
	const uint8_t profile_minor = profile & 0xff;

	if(comp == NULL)
	{
		goto error;
	}
	if(profile_major > ROHC_PROFILE_ID_MAJOR_MAX ||
	   profile_minor > ROHC_PROFILE_ID_MINOR_MAX ||
	   rohc_comp_profiles[profile_major][profile_minor] == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unsupported ROHC compression profile ID 0x%04x", profile);
		goto error;
	}

	/* the same profile cannot be enabled in both ROHCv1 and ROHCv2 versions:
	 * check if the corresponding profile in the other ROHC version is already
	 * enabled or not */
	if(rohc_comp_profile_enabled_nocheck(comp, rohc_profile_get_other_version(profile)))
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "failed to enable ROHC compression profile 0x%04x: "
		           "incompatible profile 0x%04x is already enabled",
		           profile, rohc_profile_get_other_version(profile));
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
	if(rohc_profile_is_rohcv2(profile) && comp->mrru > 0)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "failed to enable ROHC compression profile 0x%04x: ROHC "
		           "segmentation is not compatible with ROHCv2 profiles", profile);
		goto error;
	}

	/* mark the profile as enabled */
	comp->enabled_profiles[profile_major][profile_minor] = true;
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "ROHC compression profile (ID = 0x%04x) enabled", profile);

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
	const uint8_t profile_major = (profile >> 8) & 0xff;
	const uint8_t profile_minor = profile & 0xff;

	if(comp == NULL)
	{
		goto error;
	}
	if(profile_major > ROHC_PROFILE_ID_MAJOR_MAX ||
	   profile_minor > ROHC_PROFILE_ID_MINOR_MAX ||
	   rohc_comp_profiles[profile_major][profile_minor] == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unsupported ROHC compression profile ID 0x%04x", profile);
		goto error;
	}

	/* mark the profile as disabled */
	comp->enabled_profiles[profile_major][profile_minor] = false;
	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "ROHC compression profile (ID = 0x%04x) disabled", profile);

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
 * According to RF5225 §6.1, ROHC segmentation cannot be enabled if any
 * ROHCv2 profile is also enabled.
 *
 * If segmentation is enabled and used by the compressor, the function
 * \ref rohc_comp_get_segment2 can be used to retrieve ROHC segments.
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
 * @see rohc_comp_get_segment2
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
		uint8_t profile_major;

		for(profile_major = 0; profile_major <= ROHC_PROFILE_ID_MAJOR_MAX; profile_major++)
		{
			uint8_t profile_minor;

			for(profile_minor = 0; profile_minor <= ROHC_PROFILE_ID_MINOR_MAX; profile_minor++)
			{
				const uint16_t profile_id = (profile_major << 8) | profile_minor;

				if(rohc_comp_profile_enabled_nocheck(comp, profile_id) &&
				   rohc_profile_is_rohcv2(profile_id))
				{
					rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					             "failed to set MRRU to %zu bytes: segmentation is not "
					             "compatible with ROHCv2 profile 0x%04x that is enabled",
					             mrru, profile_id);
					goto error;
				}
			}
		}
	}

	/* set new MRRU */
	if(mrru == 0)
	{
		comp->rru = NULL;
	}
	else
	{
		uint8_t *const new_rru_buf = malloc(mrru);
		if(new_rru_buf == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to set MRRU: failed to allocate %zu bytes "
			             "of memory for MRRU buffer", mrru);
			goto error;
		}
		if(comp->rru != NULL)
		{
			zfree(comp->rru);
		}
		comp->rru = new_rru_buf;
	}
	comp->mrru = mrru;
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "MRRU is now set to %zu", comp->mrru);

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
 * \ref rohc_comp_get_segment2 can be used to retrieve ROHC segments.
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
 * @see rohc_comp_get_segment2
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
		ROHC_COMP_FEATURE_NO_IP_CHECKSUMS |
		ROHC_COMP_FEATURE_DUMP_PACKETS |
		ROHC_COMP_FEATURE_TIME_BASED_REFRESHES;

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


/**
 * @brief Deliver a feedback packet to the compressor
 *
 * When feedback is received by the decompressor, this function is called and
 * delivers the feedback to the right profile/context of the compressor.
 *
 * @param comp   The ROHC compressor
 * @param packet The feedback data
 * @param size   The length of the feedback packet
 * @return       true if the feedback was successfully taken into account,
 *               false if the feedback could not be taken into account
 */
static bool __rohc_comp_deliver_feedback(struct rohc_comp *const comp,
                                         const uint8_t *const packet,
                                         const size_t size)
{
	struct rohc_comp_ctxt *context;
	const uint8_t *remain_data = packet;
	size_t remain_len = size;
	enum rohc_feedback_type feedback_type;
	rohc_cid_t cid;
	size_t cid_len;

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "deliver %zu byte(s) of feedback to the right context", size);

	/* extract the CID from feedback */
	if(!rohc_comp_feedback_parse_cid(comp, remain_data, remain_len, &cid, &cid_len))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to deliver feedback: failed to extract CID from "
		             "feedback");
		goto error;
	}
	remain_data += cid_len;
	remain_len -= cid_len;

	/* find context */
	context = c_get_context(comp, cid);
	if(context == NULL)
	{
		/* context was not found */
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to deliver feedback: context with CID %u not found",
		             cid);
		goto error;
	}
	assert(context->cid == cid);
	assert(context->used == 1);

	/* FEEDBACK-1 or FEEDBACK-2 ? */
	if(remain_len == 0)
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to deliver feedback: empty feedback data");
		goto error;
	}
	else if(remain_len == 1)
	{
		feedback_type = ROHC_FEEDBACK_1;
	}
	else
	{
		feedback_type = ROHC_FEEDBACK_2;
	}

	/* deliver feedback to profile with the context */
	if(!context->profile->feedback(context, feedback_type, packet, size,
	                               remain_data, remain_len))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to deliver feedback: failed to handle FEEDBACK-%d",
		             feedback_type);
		goto error;
	}

	/* everything went fine */
	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "FEEDBACK-%d data successfully handled", feedback_type);

	return true;

error:
	return false;
}


/**
 * @brief Deliver a feedback packet to the compressor
 *
 * When feedback data is received by a decompressor, this function may be
 * called to deliver the feedback data to the corresponding profile/context
 * on the same-side associated compressor.
 *
 * @param comp      The ROHC compressor
 * @param feedback  The feedback data
 * @return          true if the feedback was successfully taken into account,
 *                  false if the feedback could not be taken into account
 *
 * @ingroup rohc_comp
 */
bool rohc_comp_deliver_feedback2(struct rohc_comp *const comp,
                                 const struct rohc_buf feedback)
{
	struct rohc_buf remain_data = feedback;
	size_t feedbacks_nr = 0;
	size_t nr_failures = 0;

	/* sanity checks */
	if(comp == NULL)
	{
		goto error;
	}
	if(rohc_buf_is_malformed(remain_data))
	{
		rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		             "failed to deliver feedback: feedback is malformed");
		goto error;
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "deliver %zu byte(s) of feedback to the right context",
	           remain_data.len);

	/* there is nothing for compressor if feedback contains no byte at all */
	if(rohc_buf_is_empty(remain_data))
	{
		goto ignore;
	}

	/* parse as much feedback data as possible */
	while(remain_data.len > 0 &&
	      rohc_packet_is_feedback(rohc_buf_byte(remain_data)))
	{
		size_t feedback_hdr_len;
		size_t feedback_data_len;
		size_t feedback_len;

		feedbacks_nr++;

		if(!rohc_feedback_get_size(remain_data, &feedback_hdr_len,
		                           &feedback_data_len))
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to parse a feedback item");
			goto error;
		}
		feedback_len = feedback_hdr_len + feedback_data_len;
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "feedback found (header = %zu bytes, data = %zu bytes)",
		           feedback_hdr_len, feedback_data_len);

		/* reject feedback item if it doesn't fit in the available data */
		if(feedback_len > remain_data.len)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "the %zu-byte feedback is too large for the %zu-byte "
			             "remaining ROHC data", feedback_len, remain_data.len);
			goto error;
		}

		/* skip the feedback header */
		rohc_buf_pull(&remain_data, feedback_hdr_len);

		/* deliver the feedback data to the compressor */
		if(!__rohc_comp_deliver_feedback(comp, rohc_buf_data(remain_data),
		                                 feedback_data_len))
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to deliver feedback item #%zu", feedbacks_nr);
			nr_failures++;
		}

		/* skip the feedback data */
		rohc_buf_pull(&remain_data, feedback_data_len);
	}

	return (nr_failures == 0);

ignore:
	return true;

error:
	return false;
}


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
		case ROHC_COMP_STATE_CR:
			return "CR";
		case ROHC_COMP_STATE_UNKNOWN:
		default:
			return "no description";
	}
}


/*
 * Definitions of private functions
 */


/**
 * @brief Create a compression context
 *
 * @param comp         The ROHC compressor
 * @param profile      The profile to associate the context with
 * @param fingerprint  The packet/context fingerprint
 * @param pkt_hdrs     The information collected about packet headers
 * @param pkt_time     The arrival time of the packet
 * @return             The compression context if successful, NULL otherwise
 */
static struct rohc_comp_ctxt *
	c_create_context(struct rohc_comp *const comp,
	                 const struct rohc_comp_profile *const profile,
	                 const struct rohc_fingerprint *const fingerprint,
	                 const struct rohc_pkt_hdrs *const pkt_hdrs,
	                 const struct rohc_ts pkt_time)
{
	const struct rohc_comp_ctxt *base_ctxt = NULL;
	struct rohc_comp_ctxt *c;
	rohc_cid_t cid_to_use;

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
		c = &comp->contexts[cid_to_use];

		/* destroy the oldest context before replacing it with a new one */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "recycle oldest context (CID %u with profile 0x%04x)",
		           cid_to_use, c->profile->id);
		if(c->profile->id == ROHCv1_PROFILE_UNCOMPRESSED)
		{
			comp->uncompressed_ctxt = NULL;
		}
		else
		{
			hashtable_del(&comp->contexts_by_fingerprint, &c->fingerprint);
			/* TODO: replace TCP by CR capacity */
			if(c->profile->id == ROHCv1_PROFILE_IP_TCP)
			{
				hashtable_cr_del(&comp->contexts_cr, &c->fingerprint);
			}
		}
		c->profile->destroy(&comp->contexts[cid_to_use]);
		c->used = 0;
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
		c = &comp->contexts[cid_to_use];

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "take the first unused context (CID %u)", cid_to_use);
	}

	/* search for a possible base context if Context Replication is possible */
	/* TODO: replace TCP by CR capacity */
	if(profile->id == ROHCv1_PROFILE_IP_TCP)
	{
		size_t best_ctxt_affinity = ROHC_AFFINITY_NONE;
		struct rohc_comp_ctxt *candidate;

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "search a base context for Context Replication");

		/* search for a base context that we may clone the new context from */
		for(candidate = hashtable_cr_get_first(&comp->contexts_cr, fingerprint);
		    candidate != NULL;
		    candidate = hashtable_cr_get_next(&comp->contexts_cr, fingerprint,
		                                      candidate))
		{
			/* context partially matches the fingerprint of the packet */
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "CR: context CID %u shares enough with packet for base context",
			           candidate->cid);

			/* check if context may be used as a base context */
			if(!profile->is_cr_possible(candidate, pkt_hdrs))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "CR: context CID %u cannot be used as base context: "
				           "IR-CR packet cannot transmit some differences",
				           candidate->cid);
			}
			else
			{
				/* context can be used base context for Context Replication (CR),
				 * compute how much it shares with packet */
				rohc_ctxt_affinity_t ctxt_affinity = ROHC_AFFINITY_LOW;
				if(candidate->fingerprint.src_port == fingerprint->src_port)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "CR: context CID %u uses same source port %u",
					           candidate->cid, fingerprint->src_port);
					ctxt_affinity++;
				}
				if(candidate->fingerprint.dst_port == fingerprint->dst_port)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "CR: context CID %u uses same destination port %u",
					           candidate->cid, fingerprint->dst_port);
					ctxt_affinity++;
				}
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "CR: context CID %u scores %u as base context",
				           candidate->cid, ctxt_affinity);
				assert(ctxt_affinity != ROHC_AFFINITY_HIGH);
				if(ctxt_affinity > best_ctxt_affinity)
				{
					base_ctxt = candidate;
					best_ctxt_affinity = ctxt_affinity;
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "CR: context CID %u is the best base context found yet",
					           candidate->cid);
					if(ctxt_affinity == ROHC_AFFINITY_MED)
					{
						rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
						           "CR: maximum affinity reached, stop search");
						break;
					}
				}
			}
		}

		if(base_ctxt != NULL)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "CR: context CID %u is the best base context found",
			           base_ctxt->cid);
		}
		else
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "CR: no context may be used as base context");
		}
	}

	/* context replication? */
	if(base_ctxt != NULL)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "create context with CID %u as a replication of context "
		           "with CID %u", cid_to_use, base_ctxt->cid);

		/* copy the base context, then reset some parts of it */
		memcpy(c, base_ctxt, sizeof(struct rohc_comp_ctxt));
		c->do_ctxt_replication = true;
		c->cr_base_cid = base_ctxt->cid;
		c->state = ROHC_COMP_STATE_CR;
	}
	else
	{
		c->do_ctxt_replication = false;
		c->state = ROHC_COMP_STATE_IR;
	}

	memcpy(&c->fingerprint, fingerprint, sizeof(struct rohc_fingerprint));

	c->state_oa_repeat_nr = 0;
	c->go_back_fo_count = 0;
	c->go_back_fo_time = pkt_time;
	c->go_back_ir_count = 0;
	c->go_back_ir_time = pkt_time;

	c->total_uncompressed_size = 0;
	c->total_compressed_size = 0;
	c->header_uncompressed_size = 0;
	c->header_compressed_size = 0;

	c->total_last_uncompressed_size = 0;
	c->total_last_compressed_size = 0;
	c->header_last_uncompressed_size = 0;
	c->header_last_compressed_size = 0;

	c->num_sent_packets = 0;

	c->cid = cid_to_use;
	c->profile = profile;

	c->mode = ROHC_U_MODE;

	c->compressor = comp;

	/* create profile-specific context */
	if(c->do_ctxt_replication)
	{
		if(!profile->clone(c, base_ctxt))
		{
			return NULL;
		}
	}
	else
	{
		if(!profile->create(c, pkt_hdrs))
		{
			return NULL;
		}
	}

	/* if creation is successful, mark the context as used */
	c->used = 1;
	c->latest_used = pkt_time.sec;
	assert(comp->num_contexts_used <= comp->medium.max_cid);
	comp->num_contexts_used++;

	/* insert the context in the hash table of contexts to efficiently find it
	 * again through its fingerprint */
	if(profile->id == ROHCv1_PROFILE_UNCOMPRESSED)
	{
		comp->uncompressed_ctxt = c;
	}
	else
	{
		hashtable_add(&comp->contexts_by_fingerprint, &(c->fingerprint), c);
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "context (CID %u) created at %" PRIu64 " seconds (num_used = %u)",
	           c->cid, c->latest_used, comp->num_contexts_used);
	return c;
}


/**
 * @brief Compute the affinity between the given packet and context
 *
 * @param ctxt             The context to compute the affinity with
 * @param pkt_fingerprint  The fingerprint of the packet to compute the affinity with
 * @param pkt_hdrs         The information collected about packet headers
 * @return                 The affinity between the packet and context
 */
static rohc_ctxt_affinity_t
	rohc_comp_get_ctxt_affinity(const struct rohc_comp_ctxt *const ctxt,
	                            const struct rohc_fingerprint *const pkt_fingerprint,
	                            const struct rohc_pkt_hdrs *const pkt_hdrs)
{
	size_t affinity;

	/* TODO: replace TCP by CR capacity */
	assert(pkt_fingerprint->base.profile_id == ROHCv1_PROFILE_IP_TCP);

	if(ctxt->profile->id != pkt_fingerprint->base.profile_id)
	{
		affinity = ROHC_AFFINITY_NONE;
	}
	else if(memcmp(&ctxt->fingerprint.base, &pkt_fingerprint->base,
	               sizeof(struct rohc_fingerprint_base)) == 0)
	{
		/* the TCP context partially matches, it might be used as a base for Context
		 * Replication (CR) */
		if(ctxt->profile->is_cr_possible(ctxt, pkt_hdrs))
		{
			/* context can be used base context for Context Replication (CR),
			 * compute how much it shares with packet */
			affinity = ROHC_AFFINITY_LOW;
			if(ctxt->fingerprint.src_port == pkt_fingerprint->src_port)
			{
				affinity++;
			}
			if(ctxt->fingerprint.dst_port == pkt_fingerprint->dst_port)
			{
				affinity++;
			}
		}
		else
		{
			affinity = ROHC_AFFINITY_NONE;
		}
	}
	else
	{
		affinity = ROHC_AFFINITY_NONE;
	}

	return affinity;
}


/**
 * @brief Find a compression context given an IP packet
 *
 * @param comp             The ROHC compressor
 * @param profile          The profile to use
 * @param packet           The packet to find a compression context for
 * @param pkt_fingerprint  The packet fingerprint
 * @param pkt_hdrs         The information collected about packet headers
 * @return                 The context if found or successfully created,
 *                         NULL if not found
 */
static struct rohc_comp_ctxt *
	rohc_comp_find_ctxt(struct rohc_comp *const comp,
	                    const struct rohc_comp_profile *const profile,
	                    const struct rohc_buf *const packet,
	                    const struct rohc_fingerprint *const pkt_fingerprint,
	                    const struct rohc_pkt_hdrs *const pkt_hdrs)
{
	struct rohc_comp_ctxt *context;

	/* get the context matching the packet */
	if(profile->id == ROHCv1_PROFILE_UNCOMPRESSED)
	{
		/* there is already one context with the Uncompressed profile, and
		 * there is no need for several contexts, let's re-use that one */
		context = comp->uncompressed_ctxt;
	}
	else /* non-Uncompressed profiles */
	{
		/* search for an existing context matching the packet fingerprint */
		context = hashtable_get(&comp->contexts_by_fingerprint, pkt_fingerprint);

		/* hmmm, looks like we could re-use that context ; if Context Replication
		 * is in action, check that the base context didn't change too much */
		if(context != NULL &&
		   profile->id == ROHCv1_PROFILE_IP_TCP && /* TODO: replace TCP by CR capacity */
		   context->do_ctxt_replication &&
		   context->state == ROHC_COMP_STATE_CR &&
		   context->state_oa_repeat_nr < comp->oa_repetitions_nr)
		{
			/* Context Replication is in action, so check whether the base context
			 * changed too much to be re-used or not */
			const struct rohc_comp_ctxt *const base_ctxt =
				&(comp->contexts[context->cr_base_cid]);
			rohc_ctxt_affinity_t base_ctxt_affinity;

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "Context Replication in action (%u/%u packets sent): check "
			           "for CID %u whether base context with CID %u changed too much",
			           context->state_oa_repeat_nr, comp->oa_repetitions_nr,
			           context->cid, base_ctxt->cid);

			/* there are two ways the base context may have changed:
			 *   - the base context now matches exactly the replicated context
			 *   - the base context does not share enough with the replicated context */
			base_ctxt_affinity =
				rohc_comp_get_ctxt_affinity(base_ctxt, pkt_fingerprint, pkt_hdrs);
			if(base_ctxt_affinity != ROHC_AFFINITY_NONE)
			{
				/* no large change, we may continue the Context Replication */
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "re-using context CID %u as a replication of context "
				           "CID %u", context->cid, base_ctxt->cid);
			}
			else
			{
				/* too much change, we need to interrupt the Context Replication */
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "cannot re-use context CID %u as replication of context "
				           "CID %u, the base context changed too much", context->cid,
				           base_ctxt->cid);

				/* destroy that half-opened context */
				hashtable_del(&comp->contexts_by_fingerprint, &context->fingerprint);
				hashtable_cr_del(&comp->contexts_cr, &context->fingerprint);
				profile->destroy(context);
				context->used = 0;
				assert(comp->num_contexts_used > 0);
				comp->num_contexts_used--;

				/* no context found */
				context = NULL;
			}
		}
	}

	if(context != NULL)
	{
		/* matching context found, update use timestamp */
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "re-using context CID %u", context->cid);
		context->latest_used = packet->time.sec;
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "context (CID %u) used at %" PRIu64 " seconds",
		           context->cid, context->latest_used);
	}
	else /* context not found, create a new one */
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "no existing context found for packet, create it");

		/* create the new context from packet (and from the base context if
		 * Context Replication is possible) */
		context = c_create_context(comp, profile, pkt_fingerprint, pkt_hdrs, packet->time);
		if(context == NULL)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to create a new context");
		}
	}

	return context;
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
	assert(comp->contexts == NULL);

	comp->num_contexts_used = 0;

	rohc_info(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	          "create enough room for %u contexts (MAX_CID = %u)",
	          comp->medium.max_cid + 1, comp->medium.max_cid);

	comp->contexts = calloc(comp->medium.max_cid + 1,
	                        sizeof(struct rohc_comp_ctxt));
	if(comp->contexts == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "cannot allocate memory for contexts");
		goto error;
	}

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
 * @brief Change the mode of the context.
 *
 * @param context  The compression context
 * @param new_mode The new mode the context must enter in
 */
void rohc_comp_change_mode(struct rohc_comp_ctxt *const context,
                           const rohc_mode_t new_mode)
{
	if(context->mode != new_mode)
	{
		/* TODO: R-mode is not yet supported */
		if(new_mode == ROHC_R_MODE)
		{
			rohc_comp_warn(context, "ignore change to R-mode because R-mode is "
			               "not supported yet");
			return;
		}
		/* TODO: downward transition to U-mode is not yet supported */
		if(new_mode == ROHC_U_MODE)
		{
			rohc_comp_warn(context, "ignore change to U-mode because such a "
			               "transition is not supported yet");
			return;
		}

		/* change mode and go back to IR state */
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %u: change from mode %d to mode %d",
		          context->cid, context->mode, new_mode);
		context->mode = new_mode;

		/* the context can be used as a base context for Context Replication
		 * if it is fully established with the remote decompressor: fully
		 * established means that the static part of the context was explicitly
		 * acknowledged by the decompressor through one ACK protected by a CRC
		 */
		if(context->profile->id == ROHCv1_PROFILE_IP_TCP) /* TODO: replace TCP by CR capacity */
		{
			if(context->mode > ROHC_U_MODE &&
			   (context->state == ROHC_COMP_STATE_FO ||
			    context->state == ROHC_COMP_STATE_SO))
			{
				rohc_comp_debug(context, "CR: context CID %u is considered as "
				                "established", context->cid);
				hashtable_cr_add(&context->compressor->contexts_cr,
				                 &context->fingerprint, context);
			}
			else
			{
				rohc_comp_debug(context, "CR: context CID %u is not considered as "
				                "established", context->cid);
				hashtable_cr_del(&context->compressor->contexts_cr,
				                 &context->fingerprint);
			}
		}
	}
}


/**
 * @brief Change the state of the context.
 *
 * @param context   The compression context
 * @param new_state The new state the context must enter in
 */
void rohc_comp_change_state(struct rohc_comp_ctxt *const context,
                            const rohc_comp_state_t new_state)
{
	if(new_state != context->state)
	{
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %u: change from state %d to state %d",
		          context->cid, context->state, new_state);

		/* reset counters */
		context->state_oa_repeat_nr = 0;

		/* change state */
		context->state = new_state;

		/* the context can be used as a base context for Context Replication
		 * if it is fully established with the remote decompressor: fully
		 * established means that the static part of the context was explicitly
		 * acknowledged by the decompressor through one ACK protected by a CRC
		 */
		if(context->profile->id == ROHCv1_PROFILE_IP_TCP) /* TODO: replace TCP by CR capacity */
		{
			if(context->mode > ROHC_U_MODE &&
			   (context->state == ROHC_COMP_STATE_FO ||
			    context->state == ROHC_COMP_STATE_SO))
			{
				rohc_comp_debug(context, "CR: context CID %u is considered as "
				                "established", context->cid);
				hashtable_cr_add(&context->compressor->contexts_cr,
				                 &context->fingerprint, context);
			}
			else
			{
				rohc_comp_debug(context, "CR: context CID %u is not considered as "
				                "established", context->cid);
				hashtable_cr_del(&context->compressor->contexts_cr,
				                 &context->fingerprint);
			}
		}
	}
}


/**
 * @brief Decide the state that should be used for the next packet
 *
 * The three states are:\n
 *  - Initialization and Refresh (IR),\n
 *  - First Order (FO),\n
 *  - Second Order (SO).
 *
 * @param context   The compression context
 * @param pkt_time  The time of packet arrival
 */
static void rohc_comp_decide_state(struct rohc_comp_ctxt *const context,
                                   struct rohc_ts pkt_time)
{
	const uint8_t oa_repetitions_nr = context->compressor->oa_repetitions_nr;
	const rohc_comp_state_t curr_state = context->state;
	rohc_comp_state_t next_state;

	assert(curr_state != ROHC_COMP_STATE_UNKNOWN);

	if(curr_state == ROHC_COMP_STATE_SO)
	{
		/* do not change state */
		rohc_comp_debug(context, "stay in SO state");
		next_state = ROHC_COMP_STATE_SO;
		/* TODO: handle NACK and STATIC-NACK */
	}
	else if(context->state_oa_repeat_nr < oa_repetitions_nr)
	{
		rohc_comp_debug(context, "not enough packets transmitted in current state "
		                "for the moment (%u/%u), so stay in current state",
		                context->state_oa_repeat_nr, oa_repetitions_nr);
		next_state = curr_state;
	}
	else
	{
		rohc_comp_debug(context, "enough packets transmitted in current state "
		                "(%u/%u), go to upper state", context->state_oa_repeat_nr,
		                oa_repetitions_nr);
		next_state = ROHC_COMP_STATE_SO;
	}

	rohc_comp_change_state(context, next_state);

	/* periodic context refreshes (RFC6846, §5.2.1.2) */
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context, pkt_time);
	}
}


/**
 * @brief Periodically change the context state after a certain number
 *        of packets.
 *
 * @param context   The compression context
 * @param pkt_time  The time of packet arrival
 */
static void rohc_comp_periodic_down_transition(struct rohc_comp_ctxt *const context,
                                               const struct rohc_ts pkt_time)
{
	rohc_comp_state_t next_state;

	rohc_debug(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	           "CID %u: timeouts for periodic refreshes: FO = %zu / %zu, "
	           "IR = %zu / %zu", context->cid, context->go_back_fo_count,
	           context->compressor->periodic_refreshes_fo_timeout_pkts,
	           context->go_back_ir_count,
	           context->compressor->periodic_refreshes_ir_timeout_pkts);

	if(context->go_back_ir_count >=
	   context->compressor->periodic_refreshes_ir_timeout_pkts)
	{
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %u: periodic change to IR state", context->cid);
		context->go_back_ir_count = 0;
		next_state = ROHC_COMP_STATE_IR;
	}
	else if((context->compressor->features & ROHC_COMP_FEATURE_TIME_BASED_REFRESHES) != 0 &&
	        rohc_time_interval(context->go_back_ir_time, pkt_time) >=
	        context->compressor->periodic_refreshes_ir_timeout_time * 1000U)
	{
		const uint64_t interval_since_ir_refresh =
			rohc_time_interval(context->go_back_ir_time, pkt_time);
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %u: force IR refresh since %" PRIu64 " us elapsed since "
		          "last IR packet", context->cid, interval_since_ir_refresh);
		context->go_back_ir_count = 0;
		next_state = ROHC_COMP_STATE_IR;
	}
	else if(context->go_back_fo_count >=
	        context->compressor->periodic_refreshes_fo_timeout_pkts)
	{
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %u: periodic change to FO state", context->cid);
		context->go_back_fo_count = 0;
		next_state = ROHC_COMP_STATE_FO;
	}
	else if((context->compressor->features & ROHC_COMP_FEATURE_TIME_BASED_REFRESHES) != 0 &&
	        rohc_time_interval(context->go_back_fo_time, pkt_time) >=
	        context->compressor->periodic_refreshes_fo_timeout_time * 1000U)
	{
		const uint64_t interval_since_fo_refresh =
			rohc_time_interval(context->go_back_fo_time, pkt_time);
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "CID %u: force FO refresh since %" PRIu64 " us elapsed since "
		          "last FO packet", context->cid, interval_since_fo_refresh);
		context->go_back_fo_count = 0;
		next_state = ROHC_COMP_STATE_FO;
	}
	else
	{
		next_state = context->state;
	}

	rohc_comp_change_state(context, next_state);

	if(context->state == ROHC_COMP_STATE_SO)
	{
		context->go_back_ir_count++;
		context->go_back_fo_count++;
	}
	else if(context->state == ROHC_COMP_STATE_FO)
	{
		context->go_back_ir_count++;
		context->go_back_fo_time = pkt_time;
	}
	else /* ROHC_COMP_STATE_IR */
	{
		context->go_back_fo_time = pkt_time;
		context->go_back_ir_time = pkt_time;
	}
}


/**
 * @brief Re-initialize the given context
 *
 * Make the context restart its initialization with decompressor, ie. it goes
 * in the lowest compression state.
 *
 * @param context  The compression context to re-initialize
 * @return         true in case of success, false otherwise
 */
bool rohc_comp_reinit_context(struct rohc_comp_ctxt *const context)
{
	/* go back to U-mode and IR state */
	rohc_comp_change_mode(context, ROHC_U_MODE);
	rohc_comp_change_state(context, ROHC_COMP_STATE_IR);

	return true;
}


/**
 * @brief Parse ROHC feedback CID
 *
 * @param comp          The ROHC compressor
 * @param feedback      The ROHC feedback data to parse
 * @param feedback_len  The length of the ROHC feedback data
 * @param[out] cid      The CID of the ROHC feedback
 * @param[out] cid_len  The length of the CID of the ROHC feedback
 * @return              true if feedback CID was successfully parsed,
 *                      false if feedback CID is malformed
 */
static bool rohc_comp_feedback_parse_cid(const struct rohc_comp *const comp,
                                         const uint8_t *const feedback,
                                         const size_t feedback_len,
                                         rohc_cid_t *const cid,
                                         size_t *const cid_len)
{
	/* decode CID */
	if(comp->medium.cid_type == ROHC_LARGE_CID)
	{
		size_t large_cid_size;
		size_t large_cid_bits_nr;
		uint32_t large_cid;

		/* decode SDVL-encoded large CID field */
		large_cid_size = sdvl_decode(feedback, feedback_len, &large_cid,
		                             &large_cid_bits_nr);
		if(large_cid_size != 1 && large_cid_size != 2)
		{
			rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			             "failed to parse feedback: failed to decode SDVL-encoded "
			             "large CID field");
			goto error;
		}
		*cid = large_cid;
		*cid_len = large_cid_size;
	}
	else if(feedback_len == 1)
	{
		/* no Add-CID if feedback is only 1 byte long */
		*cid_len = 0;
		*cid = 0;
	}
	else
	{
		/* decode small CID if present */
		*cid = rohc_add_cid_decode(feedback, feedback_len);
		if((*cid) == UINT8_MAX)
		{
			*cid_len = 0;
			*cid = 0;
		}
		else
		{
			*cid_len = 1;
		}
	}

	rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
	           "feedback CID %u", *cid);

	return true;

error:
	return false;
}


/**
 * @brief Parse FEEDBACK-2 options
 *
 * @param context            The ROHC decompression context
 * @param packet             The whole feedback packet with CID bits
 * @param packet_len         The length of the whole feedback packet with CID bits
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @param[out] opts_present  Whether options are present or not
 * @param[out] sn_bits       in: the SN bits collected in base header
 *                           out: the SN bits collected in base header and options
 * @param[out] sn_bits_nr    in: the number of SN bits collected in base header
 *                           out: the number of SN bits collected in base header
 *                                and options
 * @param crc_type           Whether the CRC is present in base header or in option
 * @param crc_in_packet      The CRC of the feedback packet
 * @param crc_pos_from_end   The position of the CRC byte from the end of the
 *                           feedback packet
 * @return                   true if feedback options were successfully parsed,
 *                           false if feedback options were malformed or CRC is wrong
 */
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
{
	const uint8_t *remain_data = feedback_data;
	size_t remain_len = feedback_data_len;

	/* parse options */
	while(remain_len > 0)
	{
		const uint8_t opt_type = (remain_data[0] >> 4) & 0x0f;
		const uint8_t opt_len = (remain_data[0] & 0x0f) + 1;
		const char *const opt_name = rohc_feedback_opt_charac[opt_type].name;
		const size_t opt_unknown = rohc_feedback_opt_charac[opt_type].unknown;
		const size_t opt_supported = rohc_feedback_opt_charac[opt_type].supported;
		const size_t opt_exp_len = rohc_feedback_opt_charac[opt_type].expected_len;

		rohc_comp_debug(context, "FEEDBACK-2: %s option (%u) found",
		                opt_name, opt_type);

		/* check min length */
		if(remain_len < opt_len)
		{
			rohc_comp_warn(context, "malformed FEEDBACK-2: packet too short for "
			               "%u-byte option %u, only %zu bytes remaning", opt_len,
			               opt_type, remain_len);
			goto error;
		}

		if(opt_unknown)
		{
			/* unknown options must be ignored (see RFC3095, §5.7.6.10) */
			rohc_comp_warn(context, "FEEDBACK-2: %s option (%d) is not unknown, "
			               "ignore it", opt_name, opt_type);
		}
		else if(!opt_supported)
		{
			/* unknown options must be ignored (see RFC3095, §5.7.6.10) */
			rohc_comp_warn(context, "FEEDBACK-2: %s option (%d) is not supported "
			               "yet, ignore it", opt_name, opt_type);
		}
		else if(opt_len != opt_exp_len) /* check real length against the expected one */
		{
			rohc_comp_warn(context, "malformed FEEDBACK-2: malformed %s option "
			               "(%u) %u bytes advertised while %zu bytes expected",
			               opt_name, opt_type, opt_len, opt_exp_len);
			goto error;
		}
		else if(opt_type == ROHC_FEEDBACK_OPT_CRC)
		{
			if(opts_present[opt_type] == 0)
			{
				/* first CRC option */
				crc_in_packet = remain_data[1];
			}
			else if(crc_in_packet != remain_data[1])
			{
				/* multiple CRC options are allowed, but they must be identical
				 * (see RFC4815, §8.6) */
				rohc_comp_warn(context, "malformed FEEDBACK-2: duplicate CRC option "
				               "#%zu specifies a CRC value 0x%02x instead of CRC "
				               "0x%02x specified in the first CRC option",
				               opts_present[opt_type], remain_data[1], crc_in_packet);
				goto error;
			}
			crc_pos_from_end = remain_len - 1; /* TODO: handle multiple CRC options */
		}
		else if(opt_type == ROHC_FEEDBACK_OPT_SN)
		{
			if(!rohc_comp_feedback_parse_opt_sn(context, remain_data, remain_len,
			                                    sn_bits, sn_bits_nr))
			{
				rohc_comp_warn(context, "malformed FEEDBACK-2: malformed SN option");
				goto error;
			}
		}

		/* one more occurrence of the option */
		opts_present[opt_type]++;

		/* skip option */
		remain_data += opt_len;
		remain_len -= opt_len;
	}

	/* sanity checks:
	 *  - some profiles do not support all options
	 *  - some options cannot be specified multiple times
	 *  - some options cannot be specified without CRC */
	if(!rohc_comp_feedback_check_opts(context, opts_present))
	{
		rohc_comp_warn(context, "malformed FEEDBACK-2: malformed or unexpected options");
		goto error;
	}

	/* check CRC if present in feedback */
	if(opts_present[ROHC_FEEDBACK_OPT_CRC] > 0 ||
	   crc_type == ROHC_FEEDBACK_WITH_CRC_BASE)
	{
		const size_t zeroed_crc_len = 1;
		const uint8_t zeroed_crc = 0x00;
		uint8_t crc_computed;

		/* compute the CRC of the feedback packet (skip CRC byte) */
		crc_computed = crc_calculate(ROHC_CRC_TYPE_8, packet,
		                             packet_len - crc_pos_from_end, CRC_INIT_8);
		crc_computed = crc_calculate(ROHC_CRC_TYPE_8, &zeroed_crc, zeroed_crc_len,
		                             crc_computed);
		crc_computed = crc_calculate(ROHC_CRC_TYPE_8, packet + packet_len -
		                             crc_pos_from_end + 1, crc_pos_from_end - 1,
		                             crc_computed);

		/* ignore feedback in case of bad CRC */
		if(crc_in_packet != crc_computed)
		{
			rohc_comp_warn(context, "CRC check failed: CRC computed on %zu bytes "
			               "(0x%02x) does not match packet CRC (0x%02x)",
			               packet_len, crc_computed, crc_in_packet);
			goto error;
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Parse the FEEDBACK-2 SN option
 *
 * @param context            The ROHC decompression context
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @param[out] sn_bits       in: the SN bits collected in base header
 *                           out: the SN bits collected in base header and options
 * @param[out] sn_bits_nr    in: the number of SN bits collected in base header
 *                           out: the number of SN bits collected in base header
 *                                and options
 * @return                   true if feedback options were successfully parsed,
 *                           false if feedback options were malformed or CRC is wrong
 */
static bool rohc_comp_feedback_parse_opt_sn(const struct rohc_comp_ctxt *const context,
                                            const uint8_t *const feedback_data,
                                            const size_t feedback_data_len,
                                            uint32_t *const sn_bits,
                                            size_t *const sn_bits_nr)
{
	const uint8_t *remain_data = feedback_data;

	/* min length already checked in caller function */
	assert(feedback_data_len >= 2);

	if(context->profile->id == ROHC_PROFILE_TCP)
	{
		if(((*sn_bits) & 0xffffc000) != 0)
		{
			rohc_comp_warn(context, "malformed FEEDBACK-2: more than 16 bits "
			               "used for SN of the TCP profile");
#ifndef ROHC_RFC_STRICT_DECOMPRESSOR
			rohc_comp_warn(context, "malformed FEEDBACK-2: truncate the MSB "
			               "of the unexpected SN value");
			(*sn_bits) &= 0x00003fff;
#else
			goto error;
#endif
		}
		(*sn_bits) = ((*sn_bits) << 2) + ((remain_data[1] >> 6) & 0x03);
		(*sn_bits_nr) += 2;
	}
	else if(context->profile->id == ROHC_PROFILE_ESP)
	{
		if(((*sn_bits) & 0xff000000) != 0)
		{
			rohc_comp_warn(context, "malformed FEEDBACK-2: more than 32 bits "
			               "used for SN of the ESP profile");
#ifndef ROHC_RFC_STRICT_DECOMPRESSOR
			rohc_comp_warn(context, "malformed FEEDBACK-2: truncate the MSB "
			               "of the unexpected SN value");
			(*sn_bits) &= 0x00ffffff;
#else
			goto error;
#endif
		}
		(*sn_bits) = ((*sn_bits) << 8) + (remain_data[1] & 0xff);
		(*sn_bits_nr) += 8;
	}
	else /* non-TCP and non-ESP profiles */
	{
		if(((*sn_bits) & 0xffffff00) != 0)
		{
			rohc_comp_warn(context, "malformed FEEDBACK-2: more than 16 bits "
			               "used for SN of the non-ESP profile");
#ifndef ROHC_RFC_STRICT_DECOMPRESSOR
			rohc_comp_warn(context, "malformed FEEDBACK-2: truncate the MSB "
			               "of the unexpected SN value");
			(*sn_bits) &= 0x000000ff;
#else
			goto error;
#endif
		}
		(*sn_bits) = ((*sn_bits) << 8) + (remain_data[1] & 0xff);
		(*sn_bits_nr) += 8;
	}

	return true;

#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
error:
	return false;
#endif
}


/**
 * @brief Check FEEDBACK-2 options
 *
 * sanity checks:
 *  - some profiles do not support all options
 *  - some options cannot be specified multiple times
 *  - some options cannot be specified without CRC
 *
 * @param context       The ROHC decompression context
 * @param opts_present  Whether options are present or not
 * @return              true if feedback options are valid,
 *                      false if feedback options are not valid
 */
static bool rohc_comp_feedback_check_opts(const struct rohc_comp_ctxt *const context,
                                          const size_t opts_present[ROHC_FEEDBACK_OPT_MAX])
{
	uint8_t opt_type;
	assert(context->profile->id < ROHC_PROFILE_MAX);

	for(opt_type = 0; opt_type < ROHC_FEEDBACK_OPT_MAX; opt_type++)
	{
		if(opts_present[opt_type] > 0 &&
		   !rohc_feedback_opt_charac[opt_type].unknown &&
		   rohc_feedback_opt_charac[opt_type].supported)
		{
			const size_t max_occurs =
				rohc_feedback_opt_charac[opt_type].max_occurs[context->profile->id];

			/* is the option supported by the current compression profile? */
			if(max_occurs == 0)
			{
				rohc_comp_warn(context, "malformed FEEDBACK-2: %s option (%u) is "
				               "not defined for the compression profile '%s' (%d)",
				               rohc_feedback_opt_charac[opt_type].name, opt_type,
				               rohc_get_profile_descr(context->profile->id),
				               context->profile->id);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
				goto error;
#endif
			}
			/* warn about multiple options */
			else if(opts_present[opt_type] > max_occurs)
			{
				rohc_comp_warn(context, "malformed FEEDBACK-2: %s option (%u) is "
				               "specified %zu times while compression profile '%s' "
				               "(%d) allows only %zu times",
				               rohc_feedback_opt_charac[opt_type].name, opt_type,
				               opts_present[opt_type],
				               rohc_get_profile_descr(context->profile->id),
				               context->profile->id, max_occurs);
				goto error;
			}

			/* some options cannot be specified without CRC */
			if(opts_present[ROHC_FEEDBACK_OPT_CRC] == 0)
			{
				switch(rohc_feedback_opt_charac[opt_type].crc_req)
				{
					case ROHC_FEEDBACK_OPT_CRC_REQUIRED:
						rohc_comp_warn(context, "malformed FEEDBACK-2: %s option (%u) "
						               "must be specified along with a CRC option",
						               rohc_feedback_opt_charac[opt_type].name, opt_type);
						goto error;
					case ROHC_FEEDBACK_OPT_CRC_SUGGESTED:
						rohc_comp_warn(context, "malformed FEEDBACK-2: %s option (%u) "
						               "should be specified along with a CRC option",
						               rohc_feedback_opt_charac[opt_type].name, opt_type);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
						goto error;
#else
						break;
#endif
					case ROHC_FEEDBACK_OPT_CRC_NOT_REQUIRED:
						break;
					default:
						assert(0);
						goto error;
				}
			}
		}
	}

	return true;

error:
	return false;
}

