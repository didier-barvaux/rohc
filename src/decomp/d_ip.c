/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2008,2009,2010,2012 Viveris Technologies
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file d_ip.c
 * @brief ROHC decompression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "d_ip.h"
#include "rohc_traces_internal.h"
#include "rohc_bit_ops.h"
#include "rohc_packets.h"
#include "rohc_debug.h" /* for zfree() */
#include "rohc_utils.h"
#include "rohc_decomp_detect_packet.h"

#include <assert.h>


/*
 * Private function prototypes.
 */

static void d_ip_destroy(void *const context)
	__attribute__((nonnull(1)));


/**
 * @brief Create the IP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The decompression context
 * @return         The newly-created IP decompression context
 */
void * d_ip_create(const struct rohc_decomp_ctxt *const context)
{
	struct d_generic_context *g_context;

	assert(context != NULL);
	assert(context->decompressor != NULL);
	assert(context->profile != NULL);

	/* create the generic context */
	g_context = d_generic_create(context,
	                             context->decompressor->trace_callback,
	                             context->profile->id);
	if(g_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the generic decompression context");

		goto quit;
	}
	g_context->specific = NULL;

	/* create the LSB decoding context for SN */
	g_context->sn_lsb_ctxt = rohc_lsb_new(ROHC_LSB_SHIFT_SN, 16);
	if(g_context->sn_lsb_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the LSB decoding context for SN");
		goto free_context;
	}

	/* some IP-specific values and functions */
	g_context->parse_dyn_next_hdr = ip_parse_dynamic_ip;
	g_context->parse_ext3 = ip_parse_ext3;

	return g_context;

free_context:
	zfree(g_context);
quit:
	return NULL;
}


/**
 * @brief Destroy the given IP-only context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
void d_ip_destroy(void *const context)
{
	struct d_generic_context *g_context;

	assert(context != NULL);
	g_context = (struct d_generic_context *) context;

	rohc_lsb_free(g_context->sn_lsb_ctxt);
	d_generic_destroy(context);
}


/**
 * @brief Detect the type of ROHC packet for IP-based non-RTP profiles
 *
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
rohc_packet_t ip_detect_packet_type(const struct rohc_decomp_ctxt *const context,
                                    const uint8_t *const rohc_packet,
                                    const size_t rohc_length,
                                    const size_t large_cid_len __attribute__((unused)))
{
	rohc_packet_t type;

	if(rohc_length < 1)
	{
		rohc_decomp_warn(context, "ROHC packet too small to read the packet "
		                 "type (len = %zu)", rohc_length);
		goto error;
	}

	if(rohc_decomp_packet_is_uo0(rohc_packet, rohc_length))
	{
		/* UO-0 packet */
		type = ROHC_PACKET_UO_0;
	}
	else if(rohc_decomp_packet_is_uo1(rohc_packet, rohc_length))
	{
		/* UO-1 packet */
		type = ROHC_PACKET_UO_1;
	}
	else if(rohc_decomp_packet_is_uor2(rohc_packet, rohc_length))
	{
		/* UOR-2 packet */
		type = ROHC_PACKET_UOR_2;
	}
	else if(rohc_decomp_packet_is_irdyn(rohc_packet, rohc_length))
	{
		/* IR-DYN packet */
		type = ROHC_PACKET_IR_DYN;
	}
	else if(rohc_decomp_packet_is_ir(rohc_packet, rohc_length))
	{
		/* IR packet */
		type = ROHC_PACKET_IR;
	}
	else
	{
		/* unknown packet */
		rohc_decomp_warn(context, "failed to recognize the packet type in byte "
		                 "0x%02x", rohc_packet[0]);
		type = ROHC_PACKET_UNKNOWN;
	}

	return type;

error:
	return ROHC_PACKET_UNKNOWN;
}


/**
 * @brief Parse the IP dynamic part of the ROHC packet.
 *
 * @param context      The decompression context
 * @param packet       The ROHC packet to parse
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the ROHC header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
int ip_parse_dynamic_ip(const struct rohc_decomp_ctxt *const context,
                        const uint8_t *packet,
                        const size_t length,
                        struct rohc_extr_bits *const bits)
{
	size_t read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the SN field */
	if(length < 2)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* parse 16-bit SN */
	bits->sn = rohc_ntoh16(GET_NEXT_16_BITS(packet));
	bits->sn_nr = 16;
	bits->is_sn_enc = false;
	rohc_decomp_debug(context, "SN = %u (0x%04x)", bits->sn, bits->sn);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += 2;
#endif
	read += 2;

	return read;

error:
	return -1;
}


/**
 * @brief Parse the extension 3 of the UOR-2 packet
 *
 * \verbatim

 Extension 3 for non-RTP profiles (5.7.5 & 5.11.4):

       0     1     2     3     4     5     6     7
    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |  1     1  |  S  |   Mode    |  I  | ip  | ip2 |
    +-----+-----+-----+-----+-----+-----+-----+-----+
 2  |            Inner IP header flags        |     |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 3  |            Outer IP header flags              |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 4  |                      SN                       |  if S = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 5  /            Inner IP header fields             /  variable,
    |                                               |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 6  |                     IP-ID                     |  2 octets, if I = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 7  /            Outer IP header fields             /  variable,
    |                                               |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+

\endverbatim
 *
 * @param context           The decompression context
 * @param rohc_data         The ROHC data to parse
 * @param rohc_data_len     The length of the ROHC data to parse
 * @param packet_type       The type of ROHC packet to parse
 * @param bits              IN: the bits already found in base header
 *                          OUT: the bits found in the extension header 3
 * @return                  The data length read from the ROHC packet,
 *                          -1 in case of error
 */
int ip_parse_ext3(const struct rohc_decomp_ctxt *const context,
                  const unsigned char *const rohc_data,
                  const size_t rohc_data_len,
                  const rohc_packet_t packet_type,
                  struct rohc_extr_bits *const bits)
{
	struct d_generic_context *g_context;
	const unsigned char *ip_flags_pos = NULL;
	const unsigned char *ip2_flags_pos = NULL;
	uint8_t S, I, ip, ip2;
	uint16_t I_bits;
	int size;

	/* remaining ROHC data */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* sanity checks */
	assert(context != NULL);
	assert(context->specific != NULL);
	assert(rohc_data != NULL);
	assert(packet_type == ROHC_PACKET_UOR_2);
	assert(bits != NULL);

	g_context = context->specific;

	rohc_decomp_debug(context, "decode extension 3");

	rohc_remain_data = rohc_data;
	rohc_remain_len = rohc_data_len;

	/* check the minimal length to decode the flags */
	if(rohc_remain_len < 1)
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_remain_len);
		goto error;
	}

	/* extract flags */
	S = GET_REAL(GET_BIT_5(rohc_remain_data));
	bits->mode = GET_BIT_3_4(rohc_remain_data);
	bits->mode_nr = 2;
	I = GET_REAL(GET_BIT_2(rohc_remain_data));
	ip = GET_REAL(GET_BIT_1(rohc_remain_data));
	ip2 = GET_REAL(GET_BIT_0(rohc_remain_data));
	rohc_decomp_debug(context, "S = %u, mode = 0x%x, I = %u, ip = %u, "
	                  "ip2 = %u", S, bits->mode, I, ip, ip2);
	rohc_remain_data++;
	rohc_remain_len--;

	/* check the minimal length to decode the inner & outer IP header flags
	 * and the SN */
	if(rohc_remain_len < ((size_t) (ip + ip2 + S)))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 rohc_remain_len);
		goto error;
	}

	/* remember position of inner IP header flags if present */
	if(ip)
	{
		rohc_decomp_debug(context, "inner IP header flags field is present in "
		                  "EXT-3 = 0x%02x", GET_BIT_0_7(rohc_remain_data));
		if(g_context->multiple_ip)
		{
			ip2_flags_pos = rohc_remain_data;
		}
		else
		{
			ip_flags_pos = rohc_remain_data;
		}
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* remember position of outer IP header flags if present */
	if(ip2)
	{
		rohc_decomp_debug(context, "outer IP header flags field is present in "
		                  "EXT-3 = 0x%02x", GET_BIT_0_7(rohc_remain_data));
		ip_flags_pos = rohc_remain_data;
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* extract the SN if present */
	if(S)
	{
		APPEND_SN_BITS(ROHC_EXT_3, bits, GET_BIT_0_7(rohc_remain_data), 8);
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* decode the inner IP header fields (pointed by packet) according to the
	 * inner IP header flags (pointed by ip(2)_flags_pos) if present */
	if(ip)
	{
		if(g_context->multiple_ip)
		{
			size = parse_inner_header_flags(context, ip2_flags_pos,
			                                rohc_remain_data, rohc_remain_len,
			                                &bits->inner_ip);
		}
		else
		{
			size = parse_inner_header_flags(context, ip_flags_pos,
			                                rohc_remain_data, rohc_remain_len,
			                                &bits->outer_ip);
		}
		if(size < 0)
		{
			rohc_decomp_warn(context, "cannot decode the inner IP header flags "
			                 "& fields");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
	}

	/* skip the IP-ID if present, it will be parsed later once all RND bits
	 * have been parsed (ie. outer IP header flags), otherwise a problem
	 * may occur: if you have context(outer RND) = 1 and context(inner RND) = 0
	 * and value(outer RND) = 0 and value(inner RND) = 1, then here in the
	 * code, we have no IP header with non-random IP-ID */
	if(I)
	{
		/* check the minimal length to decode the IP-ID field */
		if(rohc_remain_len < 2)
		{
			rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
			                 rohc_remain_len);
			goto error;
		}

		/* both inner and outer IP-ID fields are 2-byte long */
		I_bits = rohc_ntoh16(GET_NEXT_16_BITS(rohc_remain_data));
		rohc_remain_data += 2;
		rohc_remain_len -= 2;
	}
	else
	{
		I_bits = 0;
	}

	/* decode the outer IP header fields according to the outer IP header
	 * flags if present */
	if(ip2)
	{
		size = parse_outer_header_flags(context, ip_flags_pos, rohc_remain_data,
		                                rohc_remain_len, &bits->outer_ip);
		if(size == -1)
		{
			rohc_decomp_warn(context, "cannot decode the outer IP header flags "
			                 "& fields");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead increment */
		rohc_remain_data += size;
#endif
		rohc_remain_len -= size;
	}

	if(I)
	{
		/* determine which IP header is the innermost IPv4 header with
		 * non-random IP-ID */
		if(g_context->multiple_ip && is_ipv4_non_rnd_pkt(bits->inner_ip))
		{
			/* inner IP header is IPv4 with non-random IP-ID */
			if(bits->inner_ip.id_nr > 0 && bits->inner_ip.id != 0)
			{
				rohc_decomp_warn(context, "IP-ID field present (I = 1) but inner "
				                 "IP-ID already updated");
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
				goto error;
#endif
			}
			bits->inner_ip.id = I_bits;
			bits->inner_ip.id_nr = 16;
			rohc_decomp_debug(context, "%zd bits of inner IP-ID in EXT3 = 0x%x",
			                  bits->inner_ip.id_nr, bits->inner_ip.id);
		}
		else if(is_ipv4_non_rnd_pkt(bits->outer_ip))
		{
			/* inner IP header is not 'IPv4 with non-random IP-ID', but outer
			 * IP header is */
			if(bits->outer_ip.id_nr > 0 && bits->outer_ip.id != 0)
			{
				rohc_decomp_warn(context, "IP-ID field present (I = 1) but outer "
				                 "IP-ID already updated");
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
				goto error;
#endif
			}
			bits->outer_ip.id = I_bits;
			bits->outer_ip.id_nr = 16;
			rohc_decomp_debug(context, "%zd bits of outer IP-ID in EXT3 = 0x%x",
			                  bits->outer_ip.id_nr, bits->outer_ip.id);
		}
		else
		{
			rohc_decomp_warn(context, "extension 3 cannot contain IP-ID bits "
			                 "because no IP header is IPv4 with non-random IP-ID");
			goto error;
		}
	}

	return (rohc_data_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Parse the inner IP header flags and fields.
 *
 * Store the values in an IP header info structure.
 *
 * \verbatim

  Inner IP header flags (5.7.5):

       0     1     2     3     4     5     6     7
     ..... ..... ..... ..... ..... ..... ..... .....
    | TOS | TTL | DF  | PR  | IPX | NBO | RND | ip2 |  if ip = 1
     ..... ..... ..... ..... ..... ..... ..... .....

  Inner IP header fields (5.7.5):

    ..... ..... ..... ..... ..... ..... ..... .....
   |         Type of Service/Traffic Class         |  if TOS = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   |         Time to Live/Hop Limit                |  if TTL = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   |         Protocol/Next Header                  |  if PR = 1
    ..... ..... ..... ..... ..... ..... ..... .....
   /         IP extension headers                  /  variable,
    ..... ..... ..... ..... ..... ..... ..... .....   if IPX = 1

\endverbatim
 *
 * @param context     The decompression context
 * @param flags       The ROHC flags that indicate which IP fields are present
 *                    in the packet
 * @param fields      The ROHC packet part that contains some IP header fields
 * @param length      The length of the ROHC packet part that contains some IP
 *                    header fields
 * @param bits        OUT: The bits extracted from extension 3
 * @return            The data length read from the ROHC packet,
 *                    -1 in case of error
 */
int parse_inner_header_flags(const struct rohc_decomp_ctxt *const context,
                             const unsigned char *const flags,
                             const unsigned char *fields,
                             const size_t length,
                             struct rohc_extr_ip_bits *const bits)
{
	uint8_t is_tos, is_ttl, is_pr, is_ipx;
	uint8_t df, nbo, rnd;
	int read = 0;

	assert(context != NULL);
	assert(context->specific != NULL);
	assert(flags != NULL);
	assert(fields != NULL);
	assert(bits != NULL);

	/* get the inner IP header flags */
	is_tos = GET_REAL(GET_BIT_7(flags));
	is_ttl = GET_REAL(GET_BIT_6(flags));
	df = GET_REAL(GET_BIT_5(flags));
	is_pr = GET_REAL(GET_BIT_4(flags));
	is_ipx = GET_REAL(GET_BIT_3(flags));
	nbo = GET_REAL(GET_BIT_2(flags));
	rnd = GET_REAL(GET_BIT_1(flags));
	rohc_decomp_debug(context, "header flags: TOS = %u, TTL = %u, PR = %u, "
	                  "IPX = %u, NBO = %u, RND = %u", is_tos, is_ttl, is_pr,
	                  is_ipx, nbo, rnd);

	/* force the NBO flag to 1 if RND is detected */
	if(rnd)
	{
		nbo = 1;
	}

	/* check the minimal length to decode the header fields */
	if(length < ((size_t) (is_tos + is_ttl + is_pr + is_ipx)))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)", length);
		goto error;
	}

	/* get the TOS/TC field if present */
	if(is_tos)
	{
		bits->tos = *fields;
		bits->tos_nr = 8;
		rohc_decomp_debug(context, "TOS/TC = 0x%02x", bits->tos);
		fields++;
		read++;
	}

	/* get the TTL/HL field if present */
	if(is_ttl)
	{
		bits->ttl = *fields;
		bits->ttl_nr = 8;
		rohc_decomp_debug(context, "TTL/HL = 0x%02x", bits->ttl);
		fields++;
		read++;
	}

	/* get the DF flag if IPv4 */
	if(bits->version == IPV4)
	{
		bits->df = df;
		bits->df_nr = 1;
		rohc_decomp_debug(context, "DF = %d", bits->df);
	}
	else if(df) /* IPv6 and DF flag set */
	{
		rohc_decomp_warn(context, "DF flag set and IP header is IPv6");
		goto error;
	}

	/* get the Protocol field if present */
	if(is_pr)
	{
		bits->proto = *fields;
		bits->proto_nr = 8;
		rohc_decomp_debug(context, "Protocol/Next Header = 0x%02x", bits->proto);
		fields++;
		read++;
	}

	/* get the IP extension headers */
	if(is_ipx)
	{
		/* TODO: list compression */
		rohc_decomp_warn(context, "IP extension headers list compression is "
		                 "not supported");
		goto error;
	}

	/* get the NBO and RND flags if IPv4 */
	if(bits->version == IPV4)
	{
		bits->nbo = nbo;
		bits->nbo_nr = 1;
		bits->rnd = rnd;
		bits->rnd_nr = 1;
	}
	else
	{
		/* IPv6 and NBO flag set */
		if(nbo)
		{
			rohc_decomp_warn(context, "NBO flag set and IP header is IPv6");
			goto error;
		}

		/* IPv6 and RND flag set */
		if(rnd)
		{
			rohc_decomp_warn(context, "RND flag set and IP header is IPv6");
			goto error;
		}
	}

	return read;

error:
	return -1;
}


/**
 * @brief Parse the outer IP header flags and fields.
 *
 * Store the values in an IP header info structure.
 *
 * \verbatim

  Outer IP header flags (5.7.5):

       0     1     2     3     4     5     6     7
     ..... ..... ..... ..... ..... ..... ..... .....
    | TOS2| TTL2| DF2 | PR2 |IPX2 |NBO2 |RND2 |  I2 |  if ip2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....

  Outer IP header fields

     ..... ..... ..... ..... ..... ..... ..... .....
    |      Type of Service/Traffic Class            |  if TOS2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    |         Time to Live/Hop Limit                |  if TTL2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    |         Protocol/Next Header                  |  if PR2 = 1
     ..... ..... ..... ..... ..... ..... ..... .....
    /         IP extension header(s)                /  variable,
     ..... ..... ..... ..... ..... ..... ..... .....    if IPX2 = 1
    |                  IP-ID                        |  2 octets,
     ..... ..... ..... ..... ..... ..... ..... .....    if I2 = 1

\endverbatim
 *
 * @param context             The decompression context
 * @param flags               The ROHC flags that indicate which IP fields are
 *                            present in the packet
 * @param fields              The ROHC packet part that contain some IP header
 *                            fields
 * @param length              The length of the ROHC packet part that contains
 *                            some IP header fields
 * @param bits                OUT: The bits extracted from extension 3
 * @return                    The data length read from the ROHC packet,
 *                            -1 in case of error
 */
int parse_outer_header_flags(const struct rohc_decomp_ctxt *const context,
                             const unsigned char *const flags,
                             const unsigned char *fields,
                             const size_t length,
                             struct rohc_extr_ip_bits *const bits)
{
	size_t inner_header_flags;
	uint8_t is_I2;
	int read;

	/* decode some outer IP header flags and fields that are identical
	 * to inner IP header flags and fields */
	read = parse_inner_header_flags(context, flags, fields, length, bits);
	if(read == -1)
	{
		goto error;
	}
	inner_header_flags = read;

	/* get other outer IP header flags */
	is_I2 = GET_REAL(GET_BIT_0(flags));
	rohc_decomp_debug(context, "header flags: I2 = %u", is_I2);

	/* check the minimal length to decode the outer header fields */
	if(length < (inner_header_flags + is_I2 * 2))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu)",
		                 length - inner_header_flags);
		goto error;
	}

	/* get the outer IP-ID if IPv4 */
	if(is_I2)
	{
		if(bits->version != IPV4)
		{
			rohc_decomp_warn(context, "IP-ID field present (I2 = 1) and IP "
			                 "header is IPv6");
			goto error;
		}

		assert(bits->rnd_nr == 1);
		if(bits->rnd)
		{
			rohc_decomp_warn(context, "IP-ID field present (I2 = 1) and IPv4 "
			                 "header got a random IP-ID");
			goto error;
		}


		if(bits->id_nr > 0 && bits->id != 0)
		{
			rohc_decomp_warn(context, "IP-ID field present (I2 = 1) but IP-ID "
			                 "already updated");
			goto error;
		}

		bits->id = rohc_ntoh16(GET_NEXT_16_BITS(fields));
		bits->id_nr = 16;

		rohc_decomp_debug(context, "%zd bits of outer IP-ID in EXT3 = 0x%x",
		                  bits->id_nr, bits->id);

#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		fields += 2;
#endif
		read += 2;
	}

	return read;

error:
	return -1;
}


/**
 * @brief Define the decompression part of the IP-only profile as described
 *        in the RFC 3843.
 */
const struct rohc_decomp_profile d_ip_profile =
{
	.id              = ROHC_PROFILE_IP, /* profile ID (see 5 in RFC 3843) */
	.new_context     = d_ip_create,
	.free_context    = d_ip_destroy,
	.decode          = d_generic_decode,
	.detect_pkt_type = ip_detect_packet_type,
	.get_sn          = d_generic_get_sn,
};

