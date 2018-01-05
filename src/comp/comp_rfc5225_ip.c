/*
 * Copyright 2018 Viveris Technologies
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
 * @file   comp_rfc5225_ip.c
 * @brief  ROHC compression context for the ROHCv2 IP-only profile
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "rohc_comp_internals.h"
#include "rohc_traces.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "protocols/ip_numbers.h"
#include "protocols/ip.h"
#include "schemes/cid.h"
#include "schemes/ipv6_exts.h"
#include "schemes/ip_ctxt.h"
#include "crc.h"

#include <assert.h>


/** Define the ROHCv2 IP-only part of the profile compression context */
struct rohc_comp_rfc5225_ip_ctxt
{
	uint16_t msn;  /**< The Master Sequence Number (MSN) */

	ip_context_t ip_contexts[ROHC_MAX_IP_HDRS];
	size_t ip_contexts_nr;
};


/*
 * Prototypes of private functions
 */

/* create/destroy context */
static bool rohc_comp_rfc5225_ip_create(struct rohc_comp_ctxt *const context,
                                        const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static void rohc_comp_rfc5225_ip_destroy(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));
static bool rohc_comp_rfc5225_ip_check_profile(const struct rohc_comp *const comp,
                                               const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

/* check whether a packet belongs to a context */
static bool rohc_comp_rfc5225_ip_check_context(const struct rohc_comp_ctxt *const context,
                                               const struct net_pkt *const packet,
                                               size_t *const cr_score)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* encode ROHCv2 IP-only packets */
static int rohc_comp_rfc5225_ip_encode(struct rohc_comp_ctxt *const context,
                                       const struct net_pkt *const uncomp_pkt,
                                       uint8_t *const rohc_pkt,
                                       const size_t rohc_pkt_max_len,
                                       rohc_packet_t *const packet_type,
                                       size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));
static int rohc_comp_rfc5225_ip_code_packet(struct rohc_comp_ctxt *const context,
                                            const struct net_pkt *const uncomp_pkt,
                                            uint8_t *const rohc_pkt,
                                            const size_t rohc_pkt_max_len,
                                            rohc_packet_t *const packet_type,
                                            size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));
static int rohc_comp_rfc5225_ip_code_IR_packet(const struct rohc_comp_ctxt *const context,
                                               const struct net_pkt *const uncomp_pkt,
                                               uint8_t *const rohc_pkt,
                                               const size_t rohc_pkt_max_len,
                                               size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static int rohc_comp_rfc5225_ip_code_normal_packet(const struct rohc_comp_ctxt *const context,
                                                   const struct net_pkt *const uncomp_pkt,
                                                   uint8_t *const rohc_pkt,
                                                   const size_t rohc_pkt_max_len,
                                                   size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

/* deliver feedbacks */
static bool rohc_comp_rfc5225_ip_feedback(struct rohc_comp_ctxt *const context,
                                          const enum rohc_feedback_type feedback_type,
                                          const uint8_t *const packet,
                                          const size_t packet_len,
                                          const uint8_t *const feedback_data,
                                          const size_t feedback_data_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 5)));

/* mode and state transitions */
static void rohc_comp_rfc5225_ip_decide_state(struct rohc_comp_ctxt *const context,
                                              const struct rohc_ts pkt_time,
                                              const ip_version ip_vers)
	__attribute__((nonnull(1)));



/*
 * Definitions of private functions
 */


/**
 * @brief Create a new ROHCv2 IP-only context and initialize it thanks
 *        to the given uncompressed packet
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The packet given to initialize the new context
 * @return         true if successful, false otherwise
 */
static bool rohc_comp_rfc5225_ip_create(struct rohc_comp_ctxt *const context,
                                        const struct net_pkt *const packet)
{
	const struct rohc_comp *const comp = context->compressor;
	struct rohc_comp_rfc5225_ip_ctxt *rfc5225_ctxt;
	const uint8_t *remain_data = packet->outer_ip.data;
	size_t remain_len = packet->outer_ip.size;
	uint8_t proto;

	/* create the ROHCv2 IP-only part of the profile context */
	rfc5225_ctxt = calloc(1, sizeof(struct rohc_comp_rfc5225_ip_ctxt));
	if(rfc5225_ctxt == NULL)
	{
		rohc_error(comp, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the ROHCv2 IP-only part of the profile context");
		goto error;
	}
	context->specific = rfc5225_ctxt;

	/* create contexts for IP headers and their extensions */
	rfc5225_ctxt->ip_contexts_nr = 0;
	do
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context =
			&(rfc5225_ctxt->ip_contexts[rfc5225_ctxt->ip_contexts_nr]);

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip->version);
		ip_context->version = ip->version;
		ip_context->ctxt.vx.version = ip->version;

		switch(ip->version)
		{
			case IPV4:
			{
				const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

				assert(remain_len >= sizeof(struct ipv4_hdr));
				proto = ipv4->protocol;

				ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(ipv4->id);
				rohc_comp_debug(context, "IP-ID 0x%04x", ip_context->ctxt.v4.last_ip_id);
				ip_context->ctxt.v4.last_ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
				ip_context->ctxt.v4.ip_id_behavior = ROHC_IP_ID_BEHAVIOR_SEQ;
				ip_context->ctxt.v4.protocol = proto;
				ip_context->ctxt.v4.dscp = ipv4->dscp;
				ip_context->ctxt.v4.df = ipv4->df;
				ip_context->ctxt.v4.ttl = ipv4->ttl;
				ip_context->ctxt.v4.src_addr = ipv4->saddr;
				ip_context->ctxt.v4.dst_addr = ipv4->daddr;

				remain_data += sizeof(struct ipv4_hdr);
				remain_len -= sizeof(struct ipv4_hdr);
				break;
			}
			case IPV6:
			{
				const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

				assert(remain_len >= sizeof(struct ipv6_hdr));
				proto = ipv6->nh;

				ip_context->ctxt.v6.ip_id_behavior = ROHC_IP_ID_BEHAVIOR_RAND;
				ip_context->ctxt.v6.dscp = remain_data[1];
				ip_context->ctxt.v6.hopl = ipv6->hl;
				ip_context->ctxt.v6.flow_label = ipv6_get_flow_label(ipv6);
				memcpy(ip_context->ctxt.v6.src_addr, &ipv6->saddr,
				       sizeof(struct ipv6_addr));
				memcpy(ip_context->ctxt.v6.dest_addr, &ipv6->daddr,
				       sizeof(struct ipv6_addr));

				remain_data += sizeof(struct ipv6_hdr);
				remain_len -= sizeof(struct ipv6_hdr);

				rohc_comp_debug(context, "parse IPv6 extension headers");
				while(rohc_is_ipv6_opt(proto))
				{
					const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
					size_t opt_len;
					assert(remain_len >= sizeof(struct ipv6_opt));
					opt_len = ipv6_opt_get_length(ipv6_opt);
					rohc_comp_debug(context, "  IPv6 extension header is %zu-byte long",
					                opt_len);
					remain_data += opt_len;
					remain_len -= opt_len;
					proto = ipv6_opt->next_header;
				}
				ip_context->ctxt.v6.next_header = proto;
				break;
			}
			default:
			{
				goto free_context;
			}
		}

		rfc5225_ctxt->ip_contexts_nr++;
	}
	while(rohc_is_tunneling(proto) && rfc5225_ctxt->ip_contexts_nr < ROHC_MAX_IP_HDRS);

	/* profile cannot handle the packet if it bypasses internal limit of IP headers */
	if(rohc_is_tunneling(proto))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "too many IP headers for TCP profile (%u headers max)",
		           ROHC_MAX_IP_HDRS);
		goto free_context;
	}

	/* init the Master Sequence Number to a random value */
	rfc5225_ctxt->msn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "MSN = 0x%04x / %u", rfc5225_ctxt->msn, rfc5225_ctxt->msn);

	return true;

free_context:
	free(rfc5225_ctxt);
error:
	return false;
}


/**
 * @brief Destroy the ROHCv2 IP-only context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The ROHCv2 IP-only compression context to destroy
 */
static void rohc_comp_rfc5225_ip_destroy(struct rohc_comp_ctxt *const context)
{
	struct rohc_comp_rfc5225_ip_ctxt *const rfc5225_ctxt = context->specific;

	free(rfc5225_ctxt);
}


/**
 * @brief Check if the given packet corresponds to the ROHCv2 IP-only profile
 *
 * Conditions are:
 *  \li the versions of the IP headers are all 4 or 6
 *  \li none of the IP headers is an IP fragment
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param comp    The ROHC compressor
 * @param packet  The packet to check
 * @return        Whether the packet corresponds to the profile:
 *                  \li true if the packet corresponds to the profile,
 *                  \li false if the packet does not correspond to
 *                      the profile

 */
static bool rohc_comp_rfc5225_ip_check_profile(const struct rohc_comp *const comp,
                                               const struct net_pkt *const packet)
{
	/* TODO: should avoid code duplication by using net_pkt as
	 * rohc_comp_rfc3095_check_profile() does */
	const uint8_t *remain_data;
	size_t remain_len;
	size_t ip_hdrs_nr;
	uint8_t next_proto;

	remain_data = packet->outer_ip.data;
	remain_len = packet->outer_ip.size;

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
			goto bad_profile;
		}

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
				goto bad_profile;
			}

			/* IPv4 options are not supported by the TCP profile */
			if(ipv4->ihl != ipv4_min_words_nr)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: "
				           "IP options are not accepted", ip_hdrs_nr + 1);
				goto bad_profile;
			}

			/* IPv4 total length shall be correct */
			if(rohc_ntoh16(ipv4->tot_len) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: total "
				           "length is %u while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv4->tot_len), remain_len);
				goto bad_profile;
			}

			/* check if the IPv4 header is a fragment */
			if(ipv4_is_fragment(ipv4))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is fragmented", ip_hdrs_nr + 1);
				goto bad_profile;
			}

			/* check if the checksum of the IPv4 header is correct */
			if((comp->features & ROHC_COMP_FEATURE_NO_IP_CHECKSUMS) == 0 &&
			   ip_fast_csum(remain_data, ipv4_min_words_nr) != 0)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not correct (bad checksum)",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}

			next_proto = ipv4->protocol;
			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			size_t ipv6_exts_len;

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "found IPv6");
			if(remain_len < sizeof(struct ipv6_hdr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "uncompressed packet too short for IP header #%zu",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}
			next_proto = ipv6->nh;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* payload length shall be correct */
			if(rohc_ntoh16(ipv6->plen) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: payload "
				           "length is %u while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv6->plen), remain_len);
				goto bad_profile;
			}

			/* reject packets with malformed IPv6 extension headers or IPv6
			 * extension headers that are not compatible with the TCP profile */
			if(!rohc_comp_ipv6_exts_are_acceptable(comp, &next_proto,
			                                       remain_data, remain_len,
			                                       &ipv6_exts_len))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: "
				           "malformed or incompatible IPv6 extension headers "
				           "detected", ip_hdrs_nr + 1);
				goto bad_profile;
			}
			remain_data += ipv6_exts_len;
			remain_len -= ipv6_exts_len;
		}
		else
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported version %u for header #%zu",
			           ip->version, ip_hdrs_nr + 1);
			goto bad_profile;
		}
		ip_hdrs_nr++;
	}
	while(rohc_is_tunneling(next_proto) && ip_hdrs_nr < ROHC_MAX_IP_HDRS);

	/* profile cannot handle the packet if it bypasses internal limit of IP headers */
	if(rohc_is_tunneling(next_proto))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "too many IP headers for TCP profile (%u headers max)",
		           ROHC_MAX_IP_HDRS);
		goto bad_profile;
	}

	return true;

bad_profile:
	return false;
}


/**
 * @brief Check if the IP packet belongs to the given ROHCv2 IP-only context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of all the IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match
 *    the ones in the context
 *  - IPv6 only: the Flow Label of all the IP headers must match the ones the
 *    context
 *

 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context        The compression context
 * @param packet         The IP packet to check
 * @param[out] cr_score  The score of the context for Context Replication (CR)
 * @return               true if the IP packet belongs to the context
 *                       false if it does not belong to the context
 *
 * @todo TODO: the code that parses IP headers in IP/UDP/RTP profiles could
 *             probably be re-used (and maybe enhanced if needed)
 */
static bool rohc_comp_rfc5225_ip_check_context(const struct rohc_comp_ctxt *const context,
                                               const struct net_pkt *const packet,
                                               size_t *const cr_score)
{
	struct rohc_comp_rfc5225_ip_ctxt *const rfc5225_ctxt = context->specific;
	const uint8_t *remain_data = packet->outer_ip.data;
	size_t remain_len = packet->outer_ip.size;
	size_t ip_hdr_pos;
	uint8_t next_proto = ROHC_IPPROTO_IPIP;

	*cr_score = 0; /* Context Replication is not defined for ROHCv2 IP-only profile */

	/* parse the IP headers (lengths already checked while checking profile) */
	for(ip_hdr_pos = 0;
	    ip_hdr_pos < rfc5225_ctxt->ip_contexts_nr && rohc_is_tunneling(next_proto);
	    ip_hdr_pos++)
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		const ip_context_t *const ip_context = &(rfc5225_ctxt->ip_contexts[ip_hdr_pos]);
		size_t ip_ext_pos;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip->version);
		if(ip->version != ip_context->version)
		{
			rohc_comp_debug(context, "  not same IP version");
			goto bad_context;
		}

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			/* check source address */
			if(ipv4->saddr != ip_context->ctxt.v4.src_addr)
			{
				rohc_comp_debug(context, "  not same IPv4 source addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv4 source addresses");

			/* check destination address */
			if(ipv4->daddr != ip_context->ctxt.v4.dst_addr)
			{
				rohc_comp_debug(context, "  not same IPv4 destination addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv4 destination addresses");

			/* check transport protocol */
			next_proto = ipv4->protocol;
			if(next_proto != ip_context->ctxt.v4.protocol)
			{
				rohc_comp_debug(context, "  IPv4 not same protocol");
				goto bad_context;
			}
			rohc_comp_debug(context, "  IPv4 same protocol %d", next_proto);

			/* skip IPv4 header */
			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			/* check source address */
			if(memcmp(&ipv6->saddr, ip_context->ctxt.v6.src_addr,
			          sizeof(struct ipv6_addr)) != 0)
			{
				rohc_comp_debug(context, "  not same IPv6 source addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv6 source addresses");

			/* check destination address */
			if(memcmp(&ipv6->daddr, ip_context->ctxt.v6.dest_addr,
			          sizeof(struct ipv6_addr)) != 0)
			{
				rohc_comp_debug(context, "  not same IPv6 destination addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv6 destination addresses");

			/* check Flow Label */
			if(ipv6_get_flow_label(ipv6) != ip_context->ctxt.v6.flow_label)
			{
				rohc_comp_debug(context, "  not same IPv6 flow label");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv6 flow label");

			/* skip IPv6 base header */
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* find transport header/protocol, skip any IPv6 extension headers */
			next_proto = ipv6->nh;
			for(ip_ext_pos = 0; rohc_is_ipv6_opt(next_proto); ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				size_t opt_len;
				assert(remain_len >= sizeof(struct ipv6_opt));
				opt_len = ipv6_opt_get_length(ipv6_opt);
				remain_data += opt_len;
				remain_len -= opt_len;
				next_proto = ipv6_opt->next_header;
			}

			/* check transport header protocol */
			if(next_proto != ip_context->ctxt.v6.next_header)
			{
				rohc_comp_debug(context, "  IPv6 not same protocol %u", next_proto);
				goto bad_context;
			}
			rohc_comp_debug(context, "  IPv6 same protocol %u", next_proto);
		}
		else
		{
			rohc_comp_warn(context, "unsupported version %u for header #%zu",
			               ip->version, ip_hdr_pos + 1);
			assert(0);
			goto bad_context;
		}
	}

	if(ip_hdr_pos < rfc5225_ctxt->ip_contexts_nr)
	{
		rohc_comp_debug(context, "  less IP headers than context");
		goto bad_context;
	}

	if(rohc_is_tunneling(next_proto))
	{
		rohc_comp_debug(context, "  more IP headers than context");
		goto bad_context;
	}

	return true;

bad_context:
	return false;
}


/**
 * @brief Encode an uncompressed packet according to a pattern decided by
 *        several different factors
 *
 * 1. Decide state\n
 * 2. Code packet\n
 * \n
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the uncompressed
 *                          packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_encode(struct rohc_comp_ctxt *const context,
                                       const struct net_pkt *const uncomp_pkt,
                                       uint8_t *const rohc_pkt,
                                       const size_t rohc_pkt_max_len,
                                       rohc_packet_t *const packet_type,
                                       size_t *const payload_offset)
{
	int size;

	/* STEP 1: decide state */
	rohc_comp_rfc5225_ip_decide_state(context, uncomp_pkt->time,
	                          ip_get_version(&uncomp_pkt->outer_ip));

	/* STEP 2: Code packet */
	size = rohc_comp_rfc5225_ip_code_packet(context, uncomp_pkt,
	                                rohc_pkt, rohc_pkt_max_len,
	                                packet_type, payload_offset);

	return size;
}


/**
 * @brief Update the profile when feedback is received
 *
 * This function is one of the functions that must exist in one profile for
 * the framework to work.
 *
 * @param context            The compression context
 * @param feedback_type      The feedback type among ROHC_FEEDBACK_1 and ROHC_FEEDBACK_2
 * @param packet             The whole feedback packet with CID bits
 * @param packet_len         The length of the whole feedback packet with CID bits
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @return                   true if the feedback was successfully handled,
 *                           false if the feedback could not be taken into account
 */
static bool rohc_comp_rfc5225_ip_feedback(struct rohc_comp_ctxt *const context,
                                          const enum rohc_feedback_type feedback_type,
                                          const uint8_t *const packet __attribute__((unused)),
                                          const size_t packet_len __attribute__((unused)),
                                          const uint8_t *const feedback_data,
                                          const size_t feedback_data_len)
{
	const uint8_t *remain_data = feedback_data;
	size_t remain_len = feedback_data_len;

	/* only FEEDBACK-1 is support by the Uncompressed profile */
	if(feedback_type != ROHC_FEEDBACK_1)
	{
		rohc_comp_warn(context, "feedback type not handled (%d)", feedback_type);
		goto error;
	}

	rohc_comp_debug(context, "FEEDBACK-1 received");
	assert(remain_len == 1);

	/* FEEDBACK-1 profile-specific octet shall be 0 */
	if(remain_data[0] != 0x00)
	{
		rohc_comp_warn(context, "profile-specific byte in FEEDBACK-1 should be zero "
		               "for Uncompressed profile but it is 0x%02x", remain_data[0]);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}

	/* positive ACK received in U-mode: switch to O-mode */
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_change_mode(context, ROHC_O_MODE);
	}

	/* positive ACK received in IR state: the compressor got the confidence that
	 * the decompressor fully received the context, so switch to FO state */
	if(context->state == ROHC_COMP_STATE_IR)
	{
		rohc_comp_change_state(context, ROHC_COMP_STATE_FO);
	}

	return true;

error:
	return false;
}


/**
 * @brief Decide the state that should be used for the next packet
 *
 * @param context  The compression context
 * @param pkt_time The time of packet arrival
 * @param ip_vers  The IP version of the packet among IPV4, IPV6, IP_UNKNOWN,
 *                 IPV4_MALFORMED, or IPV6_MALFORMED
 */
static void rohc_comp_rfc5225_ip_decide_state(struct rohc_comp_ctxt *const context,
                                              const struct rohc_ts pkt_time,
                                              const ip_version ip_vers)
{
	/* non-IPv4/6 packets cannot be compressed with Normal packets because the
	 * first byte could be mis-interpreted as ROHC packet types (see note at
	 * the end of §5.10.2 in RFC 3095) */
	if(ip_vers != IPV4 && ip_vers != IPV6)
	{
		rohc_comp_debug(context, "force IR packet to avoid conflict between "
		                "first payload byte and ROHC packet types");
		rohc_comp_change_state(context, ROHC_COMP_STATE_IR);
	}
	else if(context->state == ROHC_COMP_STATE_IR &&
	        context->ir_count >= MAX_IR_COUNT)
	{
		/* the compressor got the confidence that the decompressor fully received
		 * the context: enough IR packets transmitted or positive ACK received */
		rohc_comp_change_state(context, ROHC_COMP_STATE_FO);
	}

	/* periodic refreshes in U-mode only */
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context, pkt_time);
	}
}


/**
 * @brief Build the ROHC packet to send
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: the offset of the payload in the buffer
 * @return                  The length of the ROHC packet if successful,
 *                         -1 otherwise
 */
static int rohc_comp_rfc5225_ip_code_packet(struct rohc_comp_ctxt *const context,
                                            const struct net_pkt *const uncomp_pkt,
                                            uint8_t *const rohc_pkt,
                                            const size_t rohc_pkt_max_len,
                                            rohc_packet_t *const packet_type,
                                            size_t *const payload_offset)
{
	int (*code_packet)(const struct rohc_comp_ctxt *const _context,
	                   const struct net_pkt *const _uncomp_pkt,
	                   uint8_t *const _rohc_pkt,
	                   const size_t _rohc_pkt_max_len,
	                   size_t *const _payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
	int size;

	/* decide what packet to send depending on state and uncompressed packet */
	if(context->state == ROHC_COMP_STATE_IR)
	{
		/* RFC3095 §5.10.3: IR state: Only IR packets can be sent */
		*packet_type = ROHC_PACKET_IR;
	}
	else if(context->state == ROHC_COMP_STATE_FO)
	{
		/* RFC3095 §5.10.3: Normal state: Only Normal packets can be sent */
		*packet_type = ROHC_PACKET_NORMAL;
	}
	else
	{
		rohc_comp_warn(context, "unknown state, cannot build packet");
		*packet_type = ROHC_PACKET_UNKNOWN;
		assert(0); /* should not happen */
		goto error;
	}

	if((*packet_type) == ROHC_PACKET_IR)
	{
		rohc_comp_debug(context, "build IR packet");
		context->ir_count++;
		code_packet = rohc_comp_rfc5225_ip_code_IR_packet;
	}
	else /* ROHC_PACKET_NORMAL */
	{
		rohc_comp_debug(context, "build normal packet");
		context->fo_count++; /* FO is used instead of Normal */
		code_packet = rohc_comp_rfc5225_ip_code_normal_packet;
	}

	/* code packet according to the selected type */
	size = code_packet(context, uncomp_pkt, rohc_pkt, rohc_pkt_max_len,
	                   payload_offset);

	return size;

error:
	return -1;
}


/**
 * @brief Build the IR packet
 *
 * \verbatim

 IR packet (5.10.1)

     0   1   2   3   4   5   6   7
    --- --- --- --- --- --- --- ---
 1 :         Add-CID octet         : if for small CIDs and (CID != 0)
   +---+---+---+---+---+---+---+---+
 2 | 1   1   1   1   1   1   0 |res|
   +---+---+---+---+---+---+---+---+
   :                               :
 3 /    0-2 octets of CID info     / 1-2 octets if for large CIDs
   :                               :
   +---+---+---+---+---+---+---+---+
 4 |          Profile = 0          | 1 octet
   +---+---+---+---+---+---+---+---+
 5 |              CRC              | 1 octet
   +---+---+---+---+---+---+---+---+
   :                               : (optional)
 6 /      uncompressed packet      / variable length
   :                               :
    --- --- --- --- --- --- --- ---

\endverbatim
 *
 * Part 6 is not managed by this function.
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param payload_offset    OUT: the offset of the payload in the buffer
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_code_IR_packet(const struct rohc_comp_ctxt *context,
                                               const struct net_pkt *const uncomp_pkt __attribute__((unused)),
                                               uint8_t *const rohc_pkt,
                                               const size_t rohc_pkt_max_len,
                                               size_t *const payload_offset)
{
	size_t counter;
	size_t first_position;
	int ret;

	rohc_comp_debug(context, "code IR packet (CID = %zu)", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_pkt_max_len);
		goto error;
	}
	counter = ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %zu byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* part 2 */
	rohc_pkt[first_position] = 0xfc;
	rohc_comp_debug(context, "first byte = 0x%02x", rohc_pkt[first_position]);

	/* is ROHC buffer large enough for parts 4 and 5 ? */
	if((rohc_pkt_max_len - counter) < 2)
	{
		rohc_comp_warn(context, "ROHC packet is too small for profile ID and "
		               "CRC bytes");
		goto error;
	}

	/* part 4 */
	rohc_pkt[counter] = ROHCv2_PROFILE_IP & 0xff;
	rohc_comp_debug(context, "Profile ID = 0x%02x", rohc_pkt[counter]);
	counter++;

	/* part 5 */
	rohc_pkt[counter] = 0;
	rohc_pkt[counter] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt, counter,
	                                  CRC_INIT_8,
	                                  context->compressor->crc_table_8);
	rohc_comp_debug(context, "CRC on %zu bytes = 0x%02x", counter,
	                rohc_pkt[counter]);
	counter++;

	*payload_offset = 0;

	return counter;

error:
	return -1;
}


/**
 * @brief Build the Normal packet
 *
 * \verbatim

 Normal packet (5.10.2)

     0   1   2   3   4   5   6   7
    --- --- --- --- --- --- --- ---
 1 :         Add-CID octet         : if for small CIDs and (CID != 0)
   +---+---+---+---+---+---+---+---+
 2 | first octet of uncomp. packet |
   +---+---+---+---+---+---+---+---+
   :                               :
 3 /    0-2 octets of CID info     / 1-2 octets if for large CIDs
   :                               :
   +---+---+---+---+---+---+---+---+
   |                               |
 4 /  rest of uncompressed packet  / variable length
   |                               |
   +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Part 4 is not managed by this function.
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param payload_offset    OUT: the offset of the payload in the buffer
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int rohc_comp_rfc5225_ip_code_normal_packet(const struct rohc_comp_ctxt *context,
                                                   const struct net_pkt *const uncomp_pkt,
                                                   uint8_t *const rohc_pkt,
                                                   const size_t rohc_pkt_max_len,
                                                   size_t *const payload_offset)
{
	size_t counter;
	size_t first_position;
	int ret;

	rohc_comp_debug(context, "code normal packet (CID = %zu)", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_pkt, rohc_pkt_max_len, &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_pkt_max_len);
		goto error;
	}
	counter = ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %zu byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* part 2 */
	rohc_pkt[first_position] = uncomp_pkt->data[0];

	rohc_comp_debug(context, "header length = %zu, payload length = %zu",
	                counter - 1, uncomp_pkt->len);

	*payload_offset = 1;
	return counter;

error:
	return -1;
}


/**
 * @brief Define the compression part of the ROHCv2 IP-only profile as described
 *        in the RFC 5225
 */
const struct rohc_comp_profile rohc_comp_rfc5225_ip_profile =
{
	.id             = ROHCv2_PROFILE_IP, /* profile ID (RFC5225, ROHCv2 IP) */
	.protocol       = 0,                               /* IP protocol */
	.create         = rohc_comp_rfc5225_ip_create,     /* profile handlers */
	.clone          = NULL,
	.destroy        = rohc_comp_rfc5225_ip_destroy,
	.check_profile  = rohc_comp_rfc5225_ip_check_profile,
	.check_context  = rohc_comp_rfc5225_ip_check_context,
	.encode         = rohc_comp_rfc5225_ip_encode,
	.feedback       = rohc_comp_rfc5225_ip_feedback,
};

