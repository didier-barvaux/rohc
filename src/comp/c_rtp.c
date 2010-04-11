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
 * @file c_rtp.c
 * @brief ROHC compression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "c_rtp.h"
#include "rohc_traces.h"
#include "rohc_packets.h"

#include <assert.h>


/*
 * Private function prototypes.
 */

int rtp_code_static_rtp_part(const struct c_context *context,
                             const unsigned char *next_header,
                             unsigned char *const dest,
                             int counter);

int rtp_code_dynamic_rtp_part(const struct c_context *context,
                              const unsigned char *next_header,
                              unsigned char *const dest,
                              int counter);

int rtp_changed_rtp_dynamic(const struct c_context *context,
                            const struct udphdr *udp);


/**
 * @brief Create a new RTP context and initialize it thanks to the given
 *        IP/UDP/RTP packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/UDP/RTP packet given to initialize the new context
 * @return        1 if successful, 0 otherwise
 */
int c_rtp_create(struct c_context *const context, const struct ip_packet *ip)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	unsigned int ip_proto;

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ip))
	{
		rohc_debugf(0, "generic context creation failed\n");
		goto quit;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* check if packet is IP/UDP/RTP or IP/IP/UDP/RTP */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* get the last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto clean;
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

	if(ip_proto != IPPROTO_UDP)
	{
		rohc_debugf(0, "next header is not UDP (%d), cannot use this profile\n",
		            ip_proto);
		goto clean;
	}

	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);

	/* create the RTP part of the profile context */
	rtp_context = malloc(sizeof(struct sc_rtp_context));
	if(rtp_context == NULL)
	{
		rohc_debugf(0, "no memory for the RTP part of the profile context\n");
		goto clean;
	}
	g_context->specific = rtp_context;

	/* initialize the RTP part of the profile context */
	rtp_context->udp_checksum_change_count = 0;
	rtp_context->old_udp = *udp;
	rtp_context->old_rtp = *((struct rtphdr *) (udp + 1));
	rtp_context->ts_window = c_create_wlsb(32, C_WINDOW_WIDTH, 2);
	if(!c_create_sc(&rtp_context->ts_sc))
	{
		rohc_debugf(0, "cannot create scaled RTP Timestamp encoding\n");
		goto clean;
	}

	/* init the RTP-specific temporary variables */
	rtp_context->tmp_variables.send_rtp_dynamic = -1;
	rtp_context->tmp_variables.timestamp = 0;
	rtp_context->tmp_variables.ts_send = 0;
	rtp_context->tmp_variables.nr_ts_bits = 0;
	rtp_context->tmp_variables.m = 0;
	rtp_context->tmp_variables.m_changed = 0;
	rtp_context->tmp_variables.rtp_pt_changed = 0;

	/* init the RTP-specific variables and functions */
	g_context->next_header_proto = IPPROTO_UDP;
	g_context->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	g_context->decide_state = rtp_decide_state;
	g_context->init_at_IR = NULL;
	g_context->code_static_part = rtp_code_static_rtp_part;
	g_context->code_dynamic_part = rtp_code_dynamic_rtp_part;
	g_context->code_UO_packet_head = NULL;
	g_context->code_UO_packet_tail = udp_code_UO_packet_tail;
	g_context->compute_crc_static = rtp_compute_crc_static;
	g_context->compute_crc_dynamic = rtp_compute_crc_dynamic;

	return 1;

clean:
	c_generic_destroy(context);
quit:
	return 0;
}


/**
 * @brief Destroy the RTP context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The RTP compression context to destroy
 */
void c_rtp_destroy(struct c_context *const context)
{
	struct c_generic_context *g_context =
		(struct c_generic_context *) context->specific;

	if(g_context != NULL)
	{
		struct sc_rtp_context *rtp_context =
			(struct sc_rtp_context *) g_context->specific;

		c_destroy_sc(&rtp_context->ts_sc);
	}

	c_generic_destroy(context);
}


/**
 * @brief Check if the IP/UDP/RTP packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - the transport protocol must be UDP
 *  - the source and destination ports of the UDP header must match the ones in
 *    the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *  - the SSRC field of the RTP header must match the one in the context
 *
 * All the context but the last one are done by the c_udp_check_context()
 * function.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/UDP/RTP packet to check
 * @return        1 if the IP/UDP/RTP packet belongs to the context,
 *                0 if it does not belong to the context and
 *                -1 if an error occurs
 *
 * @see c_udp_check_context
 */
int c_rtp_check_context(const struct c_context *context,
                        const struct ip_packet *ip)
{
	const struct c_generic_context *g_context;
	const struct sc_rtp_context *rtp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	unsigned int ip_proto;
	int udp_check;
	int is_rtp_same;

	/* check IP and UDP headers */
	udp_check = c_udp_check_context(context, ip);
	if(udp_check != 1)
		goto quit;

	/* get the last IP header */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* second IP header is last IP header */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto error;
		}
		last_ip_header = &ip2;
	}
	else
	{
		/* first IP header is last IP header */
		last_ip_header = ip;
	}

	/* get UDP and RTP headers */
	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);
	rtp = (struct rtphdr *) (udp + 1);

	/* check the RTP SSRC field */
	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	is_rtp_same = (rtp_context->old_rtp.ssrc == rtp->ssrc);

	return is_rtp_same;

quit:
	return udp_check;
error:
	return -1;
}


/**
 * @brief Encode an IP/UDP/RTP packet according to a pattern decided by several
 *        different factors.
 *
 * @param context        The compression context
 * @param ip             The IP packet to encode
 * @param packet_size    The length of the IP packet to encode
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 */
int c_rtp_encode(struct c_context *const context,
                 const struct ip_packet *ip,
                 const int packet_size,
                 unsigned char *const dest,
                 const int dest_size,
                 int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct ip_packet ip2;
	const struct ip_packet *last_ip_header;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	unsigned int ip_proto;
	int size;

	g_context = (struct c_generic_context *) context->specific;
	if(g_context == NULL)
	{
		rohc_debugf(0, "generic context not valid\n");
		return -1;
	}

	rtp_context = (struct sc_rtp_context *) g_context->specific;
	if(rtp_context == NULL)
	{
		rohc_debugf(0, "RTP context not valid\n");
		return -1;
	}

	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
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

	if(ip_proto != IPPROTO_UDP)
	{
		rohc_debugf(0, "packet is not an UDP packet\n");
		return -1;
	}
	udp = (struct udphdr *) ip_get_next_layer(last_ip_header);
	rtp = (struct rtphdr *) (udp + 1);

	/* how many UDP/RTP fields changed? */
	rtp_context->tmp_variables.send_rtp_dynamic = rtp_changed_rtp_dynamic(context, udp);

	/* encode the IP packet */
	size = c_generic_encode(context, ip, packet_size, dest, dest_size, payload_offset);
	if(size < 0)
		goto quit;

	/* update the context with the new UDP/RTP headers */
	if(g_context->tmp_variables.packet_type == PACKET_IR ||
	   g_context->tmp_variables.packet_type == PACKET_IR_DYN)
	{
		rtp_context->old_udp = *udp;
		rtp_context->old_rtp = *rtp;
	}

	/* update the context with new timestamp value */
	rtp_context->tmp_variables.timestamp = ntohl(rtp->timestamp);

quit:
	return size;
}


/**
 * @brief Decide the state that should be used for the next packet compressed
 *        with the ROHC RTP profile.
 *
 * The three states are:
 *  - Initialization and Refresh (IR),
 *  - First Order (FO),
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
void rtp_decide_state(struct c_context *const context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	if(rtp_context->ts_sc.state == INIT_TS)
		change_state(context, IR);
	else if(context->state == IR &&
	        rtp_context->ts_sc.state == INIT_STRIDE &&
	        is_ts_constant(rtp_context->ts_sc))
	{
		/* init ts_stride but timestamp is constant so we stay in IR */
		rohc_debugf(3, "init ts_stride but timestamp is constant -> stay in IR\n");
		change_state(context, IR);
	}
	else if(rtp_context->tmp_variables.send_rtp_dynamic == 1 &&
	        rtp_context->tmp_variables.m_changed == 1 &&
	        context->state != IR)
	{
		/* only M bit changed */
		rohc_debugf(3, "only M bit changed -> stay in FO\n");
		change_state(context, FO);
	}
	else if(rtp_context->ts_sc.state == INIT_STRIDE &&
	        context->state != IR &&
	        is_ts_constant(rtp_context->ts_sc))
	{
		/* init ts_stride but timestamp is contant -> FO */
		rohc_debugf(3, "init ts_stride but timestamp is constant -> FO\n");
		change_state(context, FO);
	}
	else if(rtp_context->tmp_variables.send_rtp_dynamic &&
	        context->state != IR)
	{
		rohc_debugf(3, "send_rtp_dynamic != 0 -> FO\n");
		change_state(context, FO);
	}
	else
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		decide_state(context);
}


/**
 * @brief Build the static part of the UDP/RTP headers.
 *
 * \verbatim

 Static part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /          Source Port          /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /       Destination Port        /   2 octets
    +---+---+---+---+---+---+---+---+

 Static part of RTP header (5.7.7.6):

    +---+---+---+---+---+---+---+---+
 3  /             SSRC              /   4 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 1 & 2 are done by the udp_code_static_udp_part() function. Part 3 is
 * done by this function.
 *
 * @param context     The compression context
 * @param next_header The UDP/RTP headers
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 *
 * @see udp_code_static_udp_part
 */
int rtp_code_static_rtp_part(const struct c_context *context,
                             const unsigned char *next_header,
                             unsigned char *const dest,
                             int counter)
{
	struct udphdr *udp = (struct udphdr *) next_header;
	struct rtphdr *rtp = (struct rtphdr *) (udp + 1);

	/* parts 1 & 2 */
	counter = udp_code_static_udp_part(context, next_header, dest, counter);

	/* part 3 */
	rohc_debugf(3, "RTP SSRC = 0x%x\n", rtp->ssrc);
	memcpy(&dest[counter], &rtp->ssrc, 4);
	counter += 4;

	return counter;
}


/**
 * @brief Build the dynamic part of the UDP/RTP headers.
 *
 * \verbatim

 Dynamic part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /           Checksum            /   2 octets
    +---+---+---+---+---+---+---+---+

 Dynamic part of RTP header (5.7.7.6):

    +---+---+---+---+---+---+---+---+
 2  |  V=2  | P | RX|      CC       |  (RX is NOT the RTP X bit)
    +---+---+---+---+---+---+---+---+
 3  | M |            PT             |
    +---+---+---+---+---+---+---+---+
 4  /      RTP Sequence Number      /  2 octets
    +---+---+---+---+---+---+---+---+
 5  /   RTP Timestamp (absolute)    /  4 octets
    +---+---+---+---+---+---+---+---+
 6  /      Generic CSRC list        /  variable length
    +---+---+---+---+---+---+---+---+
 7  : Reserved  | X |  Mode |TIS|TSS:  if RX = 1
    +---+---+---+---+---+---+---+---+
 8  :         TS_Stride             :  1-4 octets, if TSS = 1
    +---+---+---+---+---+---+---+---+
 9  :         Time_Stride           :  1-4 octets, if TIS = 1
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 6 & 9 are not supported yet. The TIS flag in part 7 is not supported.
 *
 * @param context     The compression context
 * @param next_header The UDP/RTP headers
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int rtp_code_dynamic_rtp_part(const struct c_context *context,
                              const unsigned char *next_header,
                              unsigned char *const dest,
                              int counter)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct udphdr *udp;
	struct rtphdr *rtp;
	unsigned char byte;
	unsigned int rx_byte = 0;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	udp = (struct udphdr *) next_header;
	rtp = (struct rtphdr *) (udp + 1);

	/* part 1 */
	rohc_debugf(3, "UDP checksum = 0x%04x\n", udp->check);
	memcpy(&dest[counter], &udp->check, 2);
	counter += 2;
	rtp_context->udp_checksum_change_count++;

	/* part 2 */
	byte = 0;
	if(!is_ts_constant(rtp_context->ts_sc) &&
	   (rtp_context->ts_sc.state == INIT_STRIDE ||
	    (g_context->tmp_variables.packet_type == PACKET_IR &&
	     rtp_context->ts_sc.state == SEND_SCALED)))
	{
		/* send ts_stride */
		rx_byte = 1;
		byte |= 1 << 4;
	}
	byte |= (rtp->version & 0x03) << 6;
	byte |= (rtp->padding & 0x01) << 5;
	byte |= rtp->cc & 0x0f;
	dest[counter] = byte;
	rohc_debugf(3, "part 2 = 0x%02x\n", dest[counter]);
	counter++;

	/* part 3 */
	byte = 0;
	byte |= (rtp->m & 0x01) << 7;
	byte |= rtp->pt & 0x7f;
	dest[counter] = byte;
	rohc_debugf(3, "part 3 = 0x%02x\n", dest[counter]);
	counter++;
	rtp_context->rtp_pt_change_count++;

	/* part 4 */
	memcpy(&dest[counter], &rtp->sn, 2);
	rohc_debugf(3, "part 4 = 0x%02x 0x%02x\n", dest[counter], dest[counter + 1]);
	counter += 2;

	/* part 5 */
	memcpy(&dest[counter], &rtp->timestamp, 4);
	rohc_debugf(3, "part 5 = 0x%02x 0x%02x 0x%02x 0x%02x\n", dest[counter],
	            dest[counter + 1], dest[counter + 2], dest[counter + 3]);
	counter += 4;

	/* part 6 not supported yet  but the field is mandatory,
	   so add a zero byte */
	dest[counter] = 0x00;
	counter++;

	/* parts 7, 8 & 9 */
	if(rx_byte)
	{
		int tis;
		int tss;

		/* part 7 */
		tis = 0; /* TIS flag not supported yet */
		tss = rtp_context->ts_sc.state != INIT_TS ? 1 : 0;

		byte = 0;
		byte |= (rtp->extension & 0x01) << 4;
		byte |= (context->mode & 0x03) << 2;
		byte |= (tis & 0x01) << 1;
		byte |= tss & 0x01;
		dest[counter] = byte;
		rohc_debugf(3, "part 7 = 0x%02x\n", dest[counter]);
		counter++;

		/* part 8 */
		if(tss)
		{
			uint32_t ts_stride;
			unsigned short ts_stride_sdvl_len;
			int ret;

			/* get the TS_STRIDE to send in packet */
			ts_stride = get_ts_stride(rtp_context->ts_sc);

			/* how many bytes are required by SDVL to encode TS_STRIDE ? */
			ts_stride_sdvl_len = c_bytesSdvl(ts_stride, -1);
			assert(ts_stride_sdvl_len >= 1 && ts_stride_sdvl_len <= 4);

			rohc_debugf(3, "send ts_stride = 0x%08x encoded with SDVL "
			            "on %u bytes\n", ts_stride, ts_stride_sdvl_len);

			/* encode TS_STRIDE in SDVL and write it to packet */
			ret = c_encodeSdvl(&dest[counter], ts_stride, -1);
			assert(ret == 1);

			/* skip the bytes used to encode TS_STRIDE in SDVL */
			counter += ts_stride_sdvl_len;

			if(rtp_context->ts_sc.state == INIT_STRIDE)
				rtp_context->ts_sc.state = SEND_SCALED;
		}

		/* part 9 not supported yet */
	}

	if(rtp_context->ts_sc.state == INIT_TS)
		rtp_context->ts_sc.state = INIT_STRIDE;

	return counter;
}


/**
 * @brief Check if the dynamic part of the UDP/RTP headers changed.
 *
 * @param context The compression context
 * @param udp     The UDP/RTP headers
 * @return        The number of UDP/RTP fields that changed
 */
int rtp_changed_rtp_dynamic(const struct c_context *context,
                            const struct udphdr *udp)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct rtphdr *rtp;
	int fields = 0;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	rtp = (struct rtphdr *) (udp + 1);

	rohc_debugf(2, "find changes in RTP dynamic fields\n");

	/* check UDP checksum field */
	if((udp->check != 0 && rtp_context->old_udp.check == 0) ||
	   (udp->check == 0 && rtp_context->old_udp.check != 0) ||
	   (rtp_context->udp_checksum_change_count < MAX_IR_COUNT))
	{
		if((udp->check != 0 && rtp_context->old_udp.check == 0) ||
		   (udp->check == 0 && rtp_context->old_udp.check != 0))
		{
			rohc_debugf(3, "UDP checksum field changed\n");
			rtp_context->udp_checksum_change_count = 0;
		}
		else
		{
			rohc_debugf(3, "UDP checksum field did not change "
			            "but changed in the last few packets\n");
		}

		fields++;
	}

	/* check RTP CSRC Counter and CSRC field */
	if(rtp->cc != rtp_context->old_rtp.cc)
	{
		rohc_debugf(3, "RTP CC field changed\n");
		fields += 2;
	}

	/* check SSRC field */
	if(rtp->ssrc != rtp_context->old_rtp.ssrc)
	{
		rohc_debugf(3, "RTP SSRC field changed\n");
		fields++;
	}

	/* check RTP Marker field */
	if(rtp->m != rtp_context->old_rtp.m)
	{
		rohc_debugf(3, "RTP M field changed\n");
		rtp_context->tmp_variables.m_changed = 1;
		fields++;
	}
	else
		rtp_context->tmp_variables.m_changed = 0;

	/* check RTP Payload Type field */
	if(rtp->pt != rtp_context->old_rtp.pt ||
	   rtp_context->rtp_pt_change_count < MAX_IR_COUNT)
	{
		if(rtp->pt != rtp_context->old_rtp.pt)
		{
			rohc_debugf(3, "RTP Payload Type (PT) field changed\n");
			rtp_context->tmp_variables.rtp_pt_changed = 1;
			rtp_context->rtp_pt_change_count = 0;
		}
		else
		{
			rohc_debugf(3, "RTP Payload Type (PT) field did not change "
			            "but changed in the last few packets\n");
		}

		fields++;
	}
	else
	{
		rtp_context->tmp_variables.rtp_pt_changed = 0;
	}

	/* we verify if ts_stride changed */
	rtp_context->tmp_variables.timestamp = ntohl(rtp->timestamp);

	rohc_debugf(2, "%d RTP dynamic fields changed\n", fields);

	return fields;
}


/// List of UDP ports which are associated with RTP streams
int rtp_ports[] = { RTP_PORTS, 0 };


/**
 * @brief Define the compression part of the RTP profile as described
 *        in the RFC 3095.
 */
struct c_profile c_rtp_profile =
{
	IPPROTO_UDP,         /* IP protocol */
	rtp_ports,           /* list of UDP ports */
	ROHC_PROFILE_RTP,    /* profile ID */
	"RTP / Compressor",  /* profile description */
	c_rtp_create,        /* profile handlers */
	c_rtp_destroy,
	c_rtp_check_context,
	c_rtp_encode,
	c_generic_feedback,
};

