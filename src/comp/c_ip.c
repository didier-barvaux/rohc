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
 *  - IP packet must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 * 
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP packet to check
 * @return        1 if the IP packet belongs to the context,
 *                0 if it does not belong to the context and
 *                -1 if an error occurs
 */
int c_ip_check_context(struct c_context *context, const struct iphdr *ip)
{
	struct c_generic_context *g_context;
  	struct iphdr *ip2;
	boolean same_src, same_dest;
	boolean same_src2, same_dest2;

	g_context = (struct c_generic_context *) context->specific;

	/* discard IP fragments:
	 *  - the R (Reserved) and MF (More Fragments) bits must be zero
	 *  - the Fragment Offset field must be zero
	 *  => ip->frag_off must be zero except the DF (Don't Fragment) bit
	 */
	if((ntohs(ip->frag_off) & (~IP_DF)) != 0)
	{
		rohc_debugf(0, "Fragment error in outer IP header (0x%04x)\n", ntohs(ip->frag_off));
		goto error;
	}
	
	if(ip->protocol == IPPROTO_IPIP)
	{
  		ip2 = (struct iphdr *) (ip + 1);

		same_src = g_context->ip_flags.old_ip.saddr == ip->saddr;
		same_dest = g_context->ip_flags.old_ip.daddr == ip->daddr;

		same_src2 = g_context->ip2_flags.old_ip.saddr == ip2->saddr;
		same_dest2 = g_context->ip2_flags.old_ip.daddr == ip2->daddr;
	}
	else
	{
		ip2 = NULL;

		same_src = g_context->ip_flags.old_ip.saddr == ip->saddr;
		same_dest = g_context->ip_flags.old_ip.daddr == ip->daddr;

		same_src2 = 1;
		same_dest2 = 1;
	}

	if(ip2 != NULL && (ntohs(ip2->frag_off) & (~IP_DF)) != 0)
	{
		rohc_debugf(0, "Fragment error in inner IP header (0x%04x)\n", ntohs(ip2->frag_off));
		goto error;
	}

	return (same_src && same_dest && same_src2 && same_dest2);

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
	ROHC_PROFILE_IP,    /* profile ID (see 5 in RFC 3843) */
	"1.0b",             /* profile version */
	"IP / Compressor",  /* profile description */
	c_generic_create,   /* profile handlers */
	c_generic_destroy,
	c_ip_check_context,
	c_generic_encode,
	c_generic_feedback,
};

