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
 * @file   c_esp.c
 * @brief  ROHC ESP compression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "c_esp.h"
#include "c_generic.h"
#include "c_ip.h"
#include "rohc_traces.h"
#include "crc.h"
#include "protocols/esp.h"
#include "rohc_utils.h"

#include <stdbool.h>
#include <string.h>
#include <assert.h>


/*
 * Private structures and types
 */

/**
 * @brief Define the ESP part of the profile decompression context
 *
 * This object must be used with the generic part of the decompression
 * context c_generic_context.
 *
 * @see c_generic_context
 */
struct sc_esp_context
{
	/// The previous ESP header
	struct esphdr old_esp;
};


/*
 * Private function prototypes
 */

static int c_esp_create(struct c_context *const context,
                        const struct ip_packet *ip);

static int c_esp_check_context(const struct c_context *context,
                               const struct ip_packet *ip);

static int c_esp_encode(struct c_context *const context,
                        const struct ip_packet *ip,
                        const int packet_size,
                        unsigned char *const dest,
                        const int dest_size,
                        rohc_packet_t *const packet_type,
                        int *const payload_offset);

static uint32_t c_esp_get_next_sn(const struct c_context *context,
                                  const struct ip_packet *outer_ip,
                                  const struct ip_packet *inner_ip);

static int esp_code_static_esp_part(const struct c_context *context,
                                    const unsigned char *next_header,
                                    unsigned char *const dest,
                                    int counter);

static int esp_code_dynamic_esp_part(const struct c_context *context,
                                     const unsigned char *next_header,
                                     unsigned char *const dest,
                                     int counter);


/*
 * Private function definitions
 */

/**
 * @brief Create a new ESP context and initialize it thanks to the given IP/ESP
 *        packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/ESP packet given to initialize the new context
 * @return        1 if successful, 0 otherwise
 */
static int c_esp_create(struct c_context *const context,
                        const struct ip_packet *ip)
{
	struct c_generic_context *g_context;
	struct sc_esp_context *esp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct esphdr *esp;
	unsigned int ip_proto;

	assert(context != NULL);
	assert(ip != NULL);

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_ESP_SN, ip))
	{
		rohc_debugf(0, "generic context creation failed\n");
		goto quit;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* check if packet is IP/ESP or IP/IP/ESP */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto clean;
		}

		/* two IP headers, the last IP header is the second one */
		last_ip_header = &ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	if(ip_proto != ROHC_IPPROTO_ESP)
	{
		rohc_debugf(0, "next header is not ESP (%d), cannot use this profile\n",
		            ip_proto);
		goto clean;
	}

	esp = (struct esphdr *) ip_get_next_layer(last_ip_header);

	/* initialize SN with the SN found in the ESP header */
	g_context->sn = ntohl(esp->sn);
	rohc_debugf(1, "initialize context(SN) = hdr(SN) of first packet = %u\n",
	            g_context->sn);

	/* create the ESP part of the profile context */
	esp_context = malloc(sizeof(struct sc_esp_context));
	if(esp_context == NULL)
	{
	  rohc_debugf(0, "no memory for the ESP part of the profile context\n");
	  goto clean;
	}
	g_context->specific = esp_context;

	/* initialize the ESP part of the profile context */
	memcpy(&(esp_context->old_esp), esp, sizeof(struct esphdr));

	/* init the ESP-specific variables and functions */
	g_context->next_header_proto = ROHC_IPPROTO_ESP;
	g_context->next_header_len = sizeof(struct esphdr);
	g_context->encode_uncomp_fields = NULL;
	g_context->decide_state = decide_state;
	g_context->decide_FO_packet = c_ip_decide_FO_packet;
	g_context->decide_SO_packet = c_ip_decide_SO_packet;
	g_context->decide_extension = decide_extension;
	g_context->init_at_IR = NULL;
	g_context->get_next_sn = c_esp_get_next_sn;
	g_context->code_static_part = esp_code_static_esp_part;
	g_context->code_dynamic_part = esp_code_dynamic_esp_part;
	g_context->code_ir_remainder = NULL;
	g_context->code_UO_packet_head = NULL;
	g_context->code_uo_remainder = NULL;
	g_context->compute_crc_static = esp_compute_crc_static;
	g_context->compute_crc_dynamic = esp_compute_crc_dynamic;

	return 1;

clean:
	c_generic_destroy(context);
quit:
	return 0;
}


/**
 * @brief Check if the IP/ESP packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - the transport protocol must be ESP
 *  - the security parameters index of the ESP header must match the one in
 *    the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/ESP packet to check
 * @return        1 if the IP/ESP packet belongs to the context,
 *                0 if it does not belong to the context and
 *                -1 if the profile cannot compress it or an error occurs
 */
int c_esp_check_context(const struct c_context *context,
                        const struct ip_packet *ip)
{
	struct c_generic_context *g_context;
	struct sc_esp_context *esp_context;
	struct ip_header_info *ip_flags;
	struct ip_header_info *ip2_flags;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct esphdr *esp;
	ip_version version;
	unsigned int ip_proto;
	bool is_ip_same;
	bool is_esp_same;

	assert(context != NULL);
	assert(ip != NULL);

	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	esp_context = (struct sc_esp_context *) g_context->specific;
	ip_flags = &g_context->ip_flags;
	ip2_flags = &g_context->ip2_flags;

	/* check the IP version of the first header */
	version = ip_get_version(ip);
	if(version != ip_flags->version)
	{
		goto bad_context;
	}

	/* compare the addresses of the first header */
	if(version == IPV4)
	{
		is_ip_same = ip_flags->info.v4.old_ip.saddr == ipv4_get_saddr(ip) &&
		             ip_flags->info.v4.old_ip.daddr == ipv4_get_daddr(ip);
	}
	else /* IPV6 */
	{
		is_ip_same =
			IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_src, ipv6_get_saddr(ip)) &&
			IPV6_ADDR_CMP(&ip_flags->info.v6.old_ip.ip6_dst, ipv6_get_daddr(ip));
	}

	if(!is_ip_same)
	{
		goto bad_context;
	}

	/* compare the Flow Label of the first header if IPv6 */
	if(version == IPV6 && ipv6_get_flow_label(ip) !=
	   IPV6_GET_FLOW_LABEL(ip_flags->info.v6.old_ip))
	{
		goto bad_context;
	}

	/* check the second IP header */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		bool is_ip2_same;

		/* check if the context used to have a second IP header */
		if(!g_context->is_ip2_initialized)
		{
			goto bad_context;
		}

		/* get the second IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto error;
		}

		/* check the IP version of the second header */
		version = ip_get_version(&ip2);
		if(version != ip2_flags->version)
		{
			goto bad_context;
		}

		/* compare the addresses of the second header */
		if(version == IPV4)
		{
			is_ip2_same = ip2_flags->info.v4.old_ip.saddr == ipv4_get_saddr(&ip2) &&
			              ip2_flags->info.v4.old_ip.daddr == ipv4_get_daddr(&ip2);
		}
		else /* IPV6 */
		{
			is_ip2_same = IPV6_ADDR_CMP(&ip2_flags->info.v6.old_ip.ip6_src,
			                            ipv6_get_saddr(&ip2)) &&
			              IPV6_ADDR_CMP(&ip2_flags->info.v6.old_ip.ip6_dst,
			                            ipv6_get_daddr(&ip2));
		}

		if(!is_ip2_same)
		{
			goto bad_context;
		}

		/* compare the Flow Label of the second header if IPv6 */
		if(version == IPV6 && ipv6_get_flow_label(&ip2) !=
		   IPV6_GET_FLOW_LABEL(ip2_flags->info.v6.old_ip))
		{
			goto bad_context;
		}

		/* get the last IP header */
		last_ip_header = &ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(&ip2);
	}
	else /* no second IP header */
	{
		/* check if the context used not to have a second header */
		if(g_context->is_ip2_initialized)
		{
			goto bad_context;
		}

		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	/* check the transport protocol */
	if(ip_proto != ROHC_IPPROTO_ESP)
	{
		goto bad_context;
	}

	/* check Security parameters index (SPI) */
	esp = (struct esphdr *) ip_get_next_layer(last_ip_header);
	is_esp_same = esp_context->old_esp.spi == esp->spi;

	return is_esp_same;

bad_context:
	return 0;
error:
	return -1;
}


/**
 * @brief Encode an IP/ESP packet according to a pattern decided by several
 *        different factors.
 *
 * @param context        The compression context
 * @param ip             The IP packet to encode
 * @param packet_size    The length of the IP packet to encode
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param packet_type    OUT: The type of ROHC packet that is created
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 *                       or -1 in case of failure
 */
static int c_esp_encode(struct c_context *const context,
                        const struct ip_packet *ip,
                        const int packet_size,
                        unsigned char *const dest,
                        const int dest_size,
                        rohc_packet_t *const packet_type,
                        int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_esp_context *esp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct esphdr *esp;
	unsigned int ip_proto;
	int size;

	assert(context != NULL);
	assert(ip != NULL);
	assert(dest != NULL);
	assert(packet_type != NULL);

	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	esp_context = (struct sc_esp_context *) g_context->specific;

	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			return -1;
		}
		last_ip_header = &ip2;

		/* get the transport protocol */
		ip_proto = ip_get_protocol(last_ip_header);
	}
	else
	{
		/* only one single IP header, the last IP header is the first one */
		last_ip_header = ip;
	}

	if(ip_proto != ROHC_IPPROTO_ESP)
	{
		rohc_debugf(0, "packet is not an ESP packet\n");
		return -1;
	}
	esp = (struct esphdr *) ip_get_next_layer(last_ip_header);

	/* encode the IP packet */
	size = c_generic_encode(context, ip, packet_size, dest, dest_size,
	                        packet_type, payload_offset);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new ESP header */
	if(g_context->tmp.packet_type == PACKET_IR ||
	   g_context->tmp.packet_type == PACKET_IR_DYN)
	{
		memcpy(&(esp_context->old_esp), esp, sizeof(struct esphdr));
	}

quit:
	return size;
}


/**
 * @brief Determine the SN value for the next packet
 *
 * Profile SN is the ESP SN.
 *
 * @param context   The compression context
 * @param outer_ip  The outer IP header
 * @param inner_ip  The inner IP header if it exists, NULL otherwise
 * @return          The SN
 */
static uint32_t c_esp_get_next_sn(const struct c_context *context,
                                  const struct ip_packet *outer_ip,
                                  const struct ip_packet *inner_ip)
{
	struct c_generic_context *g_context;
	struct esphdr *esp;

	g_context = (struct c_generic_context *) context->specific;

	/* get ESP header */
	if(g_context->tmp.nr_of_ip_hdr > 1)
	{
		esp = (struct esphdr *) ip_get_next_layer(inner_ip);
	}
	else
	{
		esp = (struct esphdr *) ip_get_next_layer(outer_ip);
	}

	return ntohl(esp->sn);
}


/**
 * @brief Build the static part of the ESP header
 *
 * \verbatim

 Static part of ESP header (5.7.7.7):

    +---+---+---+---+---+---+---+---+
 1  /              SPI              /   4 octets
    +---+---+---+---+---+---+---+---+

 SPI = Security Parameters Index

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The ESP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int esp_code_static_esp_part(const struct c_context *context,
                                    const unsigned char *next_header,
                                    unsigned char *const dest,
                                    int counter)
{
	const struct esphdr *esp = (struct esphdr *) next_header;

	/* part 1 */
	rohc_debugf(3, "ESP SPI = 0x%08x\n", ntohl(esp->spi));
	memcpy(&dest[counter], &esp->spi, sizeof(uint32_t));
	counter += sizeof(uint32_t);

	return counter;
}


/**
 * @brief Build the dynamic part of the ESP header
 *
 * \verbatim

 Dynamic part of ESP header (5.7.7.7):

    +---+---+---+---+---+---+---+---+
 1  /       Sequence Number         /   4 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param next_header The ESP header
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static int esp_code_dynamic_esp_part(const struct c_context *context,
                                     const unsigned char *next_header,
                                     unsigned char *const dest,
                                     int counter)
{
	const struct esphdr *esp;

	assert(context != NULL);
	assert(next_header != NULL);
	assert(dest != NULL);

	esp = (struct esphdr *) next_header;

	/* part 1 */
	rohc_debugf(3, "ESP SN = 0x%08x\n", ntohl(esp->sn));
	memcpy(&dest[counter], &esp->sn, sizeof(uint32_t));
	counter += sizeof(uint32_t);

	return counter;
}


/**
 * @brief Define the compression part of the ESP profile as described
 *        in the RFC 3095.
 */
struct c_profile c_esp_profile =
{
	ROHC_IPPROTO_ESP,    /* IP protocol */
	NULL,                /* list of UDP ports, not relevant for UDP */
	ROHC_PROFILE_ESP,    /* profile ID (see 8 in RFC 3095) */
	"ESP / Compressor",  /* profile description */
	c_esp_create,        /* profile handlers */
	c_generic_destroy,
	c_esp_check_context,
	c_esp_encode,
	c_generic_feedback,
};

