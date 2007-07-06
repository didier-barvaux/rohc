/**
 * @file c_ip.c
 * @brief ROHC compression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "c_ip.h"


/**
 * @brief Check if an IP packet belongs to the context.
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP packet to check
 * @return        1 if the IP packet belongs to the context,
 *                0 if it does not belong to the context and
 *                -1 if the profile cannot compress it or an error occurs
 */
int c_ip_check_context(struct c_context *context, struct ip_packet ip)
{
	struct c_generic_context *g_context;
	struct ip_header_info *ip_flags;
	struct ip_header_info *ip2_flags;
  	struct ip_packet ip2;
	ip_version version;
	unsigned int ip_proto;
	boolean same_src, same_dest;
	boolean same_src2, same_dest2;

	g_context = (struct c_generic_context *) context->specific;
	ip_flags = &g_context->ip_flags;
	ip2_flags = &g_context->ip2_flags;

	/* check the IP version of the first header */
	version = ip_get_version(ip);
	if(version != IPV4 && version != IPV6)
		goto bad_profile;
	if(version != ip_flags->version)
		goto bad_context;

	/* check if the first header is a fragment */
	if(ip_is_fragment(ip))
		goto bad_profile;

	/* compare the addresses of the first header */
	if(version == IPV4)
	{
		same_src = ip_flags->info.v4.old_ip.saddr == ipv4_get_saddr(ip);
		same_dest = ip_flags->info.v4.old_ip.daddr == ipv4_get_daddr(ip);
	}
	else /* IPV6 */
	{
		same_src = IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_src,
		                         ipv6_get_saddr(&ip));
		same_dest = IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_dst,
		                          ipv6_get_daddr(&ip));
	}

	if(!same_src || !same_dest)
		goto bad_context;

	/* compare the Flow Label of the first header if IPv6 */
	if(version == IPV6 && ipv6_get_flow_label(ip) !=
	   IPV6_GET_FLOW_LABEL(ip_flags->info.v6.old_ip))
		goto bad_context;

	/* check the second IP header */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* check if the context used to have a second IP header */
		if(!g_context->is_ip2_initialized)
			goto bad_context;

		/* get the second IP header */
  		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto error;
		}

		/* check the IP version of the second header */
		version = ip_get_version(ip2);
		if(version != IPV4 && version != IPV6)
			goto bad_profile;
		if(version != ip2_flags->version)
			goto bad_context;

		/* check if the second header is a fragment */
		if(ip_is_fragment(ip2))
			goto bad_profile;

		/* compare the addresses of the second header */
		if(version == IPV4)
		{
			same_src2 = ip2_flags->info.v4.old_ip.saddr == ipv4_get_saddr(ip2);
			same_dest2 = ip2_flags->info.v4.old_ip.daddr == ipv4_get_daddr(ip2);
		}
		else /* IPV6 */
		{
			same_src2 = IPV6_ADDR_CMP(&ip2_flags->info.v6.old_ip.ip6_src,
			                          ipv6_get_saddr(&ip2));
			same_dest2 = IPV6_ADDR_CMP(&ip2_flags->info.v6.old_ip.ip6_dst,
			                           ipv6_get_daddr(&ip2));
		}
	
		if(!same_src2 || !same_dest2)
	 		goto bad_context;

		/* compare the Flow Label of the second header if IPv6 */
		if(version == IPV6 && ipv6_get_flow_label(ip2) !=
		   IPV6_GET_FLOW_LABEL(ip2_flags->info.v6.old_ip))
			goto bad_context;
	}
	else /* no second IP header */
	{
		/* check if the context used not to have a second header */
		if(g_context->is_ip2_initialized)
			goto bad_context;
	}

	return 1;

bad_context:
	return 0;
bad_profile:
error:
	return -1;
}


/**
 * @brief Define the compression part of the IP-only profile as described
 *        in the RFC 3843.
 */
struct c_profile c_ip_profile =
{
	0,                  /* IP protocol */
	NULL,               /* list of UDP ports, not relevant for IP-only */
	ROHC_PROFILE_IP,    /* profile ID (see 5 in RFC 3843) */
	"1.0b",             /* profile version */
	"IP / Compressor",  /* profile description */
	c_generic_create,   /* profile handlers */
	c_generic_destroy,
	c_ip_check_context,
	c_generic_encode,
	c_generic_feedback,
};

