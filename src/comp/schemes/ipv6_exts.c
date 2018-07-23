/*
 * Copyright 2012,2013,2014,2015 Didier Barvaux
 * Copyright 2013,2014,2018 Viveris Technologies
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
 * @file   comp/schemes/ipv6_exts.c
 * @brief  Compression schemes for IPv6 extension headers
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "ipv6_exts.h"
#include "protocols/ip_numbers.h"
#include "protocols/ip.h"
#include "protocols/ipv6.h"


/**
 * @brief Whether IPv6 extension headers are acceptable or not
 *
 * IPv6 options are acceptable if:
 *  - every IPv6 extension header is smaller than \e IPV6_OPT_HDR_LEN_MAX
 *  - the last IPv6 extension header is not truncated,
 *  - no more than \e ROHC_MAX_IP_EXT_HDRS extension headers are present,
 *  - each extension header is present only once (except Destination that may
 *    occur twice).
 *
 * @param comp                The ROHC compressor
 * @param[in,out] next_proto  in: the protocol type of the first extension header
 *                            out: the protocol type of the transport header
 * @param exts                The beginning of the IPv6 extension headers
 * @param max_exts_len        The maximum length (in bytes) of the extension headers
 * @param[out] exts_nr        The number of the parsed IPv6 extension headers
 * @param[out] exts_len       The length (in bytes) of the parsed IPv6 extension headers
 * @return                    true if the IPv6 extension headers are acceptable,
 *                            false if they are not
 *
 * @see ROHC_MAX_IP_EXT_HDRS
 */
bool rohc_comp_ipv6_exts_are_acceptable(const struct rohc_comp *const comp,
                                        uint8_t *const next_proto,
                                        const uint8_t *const exts,
                                        const size_t max_exts_len,
                                        size_t *const exts_nr,
                                        size_t *const exts_len)
{
	uint8_t ipv6_ext_types_count[ROHC_IPPROTO_MAX + 1] = { 0 };
	const uint8_t *remain_data = exts;
	size_t remain_len = max_exts_len;
	size_t ipv6_ext_nr;

	(*exts_len) = 0;

	ipv6_ext_nr = 0;
	while(rohc_is_ipv6_opt(*next_proto) && ipv6_ext_nr < ROHC_MAX_IP_EXT_HDRS)
	{
		size_t ext_len;

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "  found extension header #%zu of type %u",
		           ipv6_ext_nr + 1, *next_proto);

		/* remember the number of IPv6 extension headers of each type */
		if(ipv6_ext_types_count[*next_proto] >= 255)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "too many IPv6 extension header of type 0x%02x", *next_proto);
			goto bad_exts;
		}
		ipv6_ext_types_count[*next_proto]++;

		/* parse the IPv6 extension header */
		switch(*next_proto)
		{
			case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop options */
			case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
			case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination options */
			{
				const struct ipv6_opt *const ipv6_opt =
					(struct ipv6_opt *) remain_data;

				if(remain_len < (sizeof(ipv6_opt) - 1))
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "packet too short for IPv6 extension header");
					goto bad_exts;
				}

				ext_len = ipv6_opt_get_length(ipv6_opt);
				if(remain_len < ext_len)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "packet too short for IPv6 extension header");
					goto bad_exts;
				}
				if(ext_len > IPV6_OPT_HDR_LEN_MAX)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "packet contains at least one %zu-byte IPv6 extension "
					           "header larger than the internal maximum of %u bytes",
					           ext_len, IPV6_OPT_HDR_LEN_MAX);
					goto bad_exts;
				}

				/* RFC 2460 §4 reads:
				 *   The Hop-by-Hop Options header, when present, must
				 *   immediately follow the IPv6 header.
				 *   [...]
				 *   The same action [ie. reject packet] should be taken if a
				 *   node encounters a Next Header value of zero in any header other
				 *   than an IPv6 header. */
				if((*next_proto) == ROHC_IPPROTO_HOPOPTS && ipv6_ext_nr != 0)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed IPv6 header: the Hop-By-Hop extension "
					           "header should be the very first extension header, "
					           "not the #%zu one", ipv6_ext_nr + 1);
					goto bad_exts;
				}

				(*next_proto) = ipv6_opt->next_header;
				break;
			}
			// case ROHC_IPPROTO_ESP : ???
			case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
			case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
			case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
			default:
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "malformed IPv6 header: unsupported IPv6 extension "
				           "header %u detected", *next_proto);
				goto bad_exts;
			}
		}
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "  extension header is %zu-byte long", ext_len);
		remain_data += ext_len;
		remain_len -= ext_len;

		(*exts_len) += ext_len;
		ipv6_ext_nr++;
	}

	/* profile cannot handle the packet if it bypasses internal limit of
	 * IPv6 extension headers */
	if(ipv6_ext_nr > ROHC_MAX_IP_EXT_HDRS)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "IP header got too many IPv6 extension headers for TCP profile "
		           "(%u headers max)", ROHC_MAX_IP_EXT_HDRS);
		goto bad_exts;
	}

	/* RFC 2460 §4.1 reads:
	 *   Each extension header should occur at most once, except for the
	 *   Destination Options header which should occur at most twice (once
	 *   before a Routing header and once before the upper-layer header). */
	{
		unsigned int ext_type;

		for(ext_type = 0; ext_type <= ROHC_IPPROTO_MAX; ext_type++)
		{
			if(ext_type == ROHC_IPPROTO_DSTOPTS && ipv6_ext_types_count[ext_type] > 2)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "malformed IPv6 header: the Destination extension "
				           "header should occur at most twice, but it was "
				           "found %u times", ipv6_ext_types_count[ext_type]);
				goto bad_exts;
			}
			else if(ext_type != ROHC_IPPROTO_DSTOPTS && ipv6_ext_types_count[ext_type] > 1)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "malformed IPv6 header: the extension header of type "
				           "%u header should occur at most once, but it was found "
				           "%u times", ext_type, ipv6_ext_types_count[ext_type]);
				goto bad_exts;
			}
		}
	}

	*exts_nr = ipv6_ext_nr;
	return true;

bad_exts:
	return false;
}

