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
 * @file d_rtp.c
 * @brief ROHC decompression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "d_rtp.h"
#include "rohc_traces.h"
#include "ts_sc_decomp.h"

#include <netinet/ip.h>
#include <netinet/udp.h>


/**
 * @brief The size (in bytes) of the constant RTP dynamic part
 *
 * According to RFC3095 section 5.7.7.6:
 *   1 (flags V, P, RX, CC) + 1 (flags M, PT) + 2 (RTP SN) +
 *   4 (RTP TS) + 1 (CSRC list) = 9 bytes
 *
 * The size of the Generic CSRC list field is considered constant because
 * generic CSRC list is not supported yet and thus 1 byte of zero is used.
 */
#define RTP_CONST_DYN_PART_SIZE  9


/*
 * Private function prototypes.
 */

unsigned int rtp_detect_ir_size(struct d_context *context,
                                unsigned char *packet,
                                unsigned int plen,
                                unsigned int large_cid_len);

unsigned int rtp_detect_ir_dyn_size(struct d_context *context,
                                    unsigned char *packet,
                                    unsigned int plen,
                                    unsigned int large_cid_len);

int rtp_decode_uo_tail_rtp(struct d_generic_context *context,
                           const unsigned char *packet,
                           unsigned int length,
                           unsigned char *dest);


/**
 * @brief Create the RTP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return The newly-created RTP decompression context
 */
void * d_rtp_create(void)
{
	struct d_generic_context *context;
	struct d_rtp_context *rtp_context;

	/* create the generic context */
	context = d_generic_create();
	if(context == NULL)
		goto quit;

	/* create the RTP-specific part of the context */
	rtp_context = malloc(sizeof(struct d_rtp_context));
	if(rtp_context == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the RTP-specific context\n");
		goto destroy_context;
	}
	bzero(rtp_context, sizeof(struct d_rtp_context));
	context->specific = rtp_context;

	/* the UDP checksum field present flag will be initialized
	 * with the IR packets */
	rtp_context->udp_checksum_present = -1;

	/* some RTP-specific values and functions */
	context->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	context->build_next_header = rtp_build_uncompressed_rtp;
	context->decode_static_next_header = rtp_decode_static_rtp;
	context->decode_dynamic_next_header = rtp_decode_dynamic_rtp;
	context->decode_uo_tail = rtp_decode_uo_tail_rtp;
	context->compute_crc_static = rtp_compute_crc_static;
	context->compute_crc_dynamic = rtp_compute_crc_dynamic;

	/* create the UDP-specific part of the header changes */
	context->last1->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	context->last1->next_header = malloc(sizeof(struct udphdr) + sizeof(struct rtphdr));
	if(context->last1->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the RTP-specific "
		               "part of the header changes last1\n");
		goto free_rtp_context;
	}
	bzero(context->last1->next_header, sizeof(struct udphdr) + sizeof(struct rtphdr));

	context->last2->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	context->last2->next_header = malloc(sizeof(struct udphdr) + sizeof(struct rtphdr));
	if(context->last2->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the RTP-specific "
		               "part of the header changes last2\n");
		goto free_last1_next_header;
	}
	bzero(context->last2->next_header, sizeof(struct udphdr) + sizeof(struct rtphdr));

	context->active1->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	context->active1->next_header = malloc(sizeof(struct udphdr) + sizeof(struct rtphdr));
	if(context->active1->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the RTP-specific "
		               "part of the header changes active1\n");
		goto free_last2_next_header;
	}
	bzero(context->active1->next_header, sizeof(struct udphdr) + sizeof(struct rtphdr));

	context->active2->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	context->active2->next_header = malloc(sizeof(struct udphdr) + sizeof(struct rtphdr));
	if(context->active2->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the RTP-specific "
		               "part of the header changes active2\n");
		goto free_active1_next_header;
	}
	bzero(context->active2->next_header, sizeof(struct udphdr) + sizeof(struct rtphdr));

	/* set next header to UDP */
	context->next_header_proto = IPPROTO_UDP;

	/* init timestamp and TS received variables */
	rtp_context->timestamp = 0;
	rtp_context->ts_received = 0;

	/* init the scaled RTP Timestamp decoding */
	d_create_sc(&rtp_context->ts_sc);

	return context;

free_active1_next_header:
	zfree(context->active1->next_header);
free_last2_next_header:
	zfree(context->last2->next_header);
free_last1_next_header:
	zfree(context->last1->next_header);
free_rtp_context:
	zfree(rtp_context);
destroy_context:
	d_generic_destroy(context);
quit:
	return NULL;
}


/**
 * @brief Get the size of the static part of an IR packet
 *
 * @return  The size of the static part of an IR packet
 */
int rtp_get_static_part(void)
{
	/* UDP static part (source and destination ports = 4 bytes) and
	   RTP static part (RTP SSRC = 4 bytes) */
	return 8;
}


/**
 * @brief Find the length of the IR header.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * \verbatim

 Basic structure of the IR packet (5.7.7.1):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  |         Add-CID octet         |  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   1   0 | D |
    +---+---+---+---+---+---+---+---+
    |                               |
 3  /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
 4  |            Profile            |  1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              |  1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  |         Static chain          |  variable length
    |                               |
    +---+---+---+---+---+---+---+---+
    |                               |
 7  |         Dynamic chain         |  present if D = 1, variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 8  |             SN                |  2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    |                               |
 9  |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * The function computes the length of the fields 2 + 4-8, ie. the first byte,
 * the Profile and CRC fields and the static and dynamic chains (outer and inner
 * IP headers + UDP header + RTP header) and the SN (0 byte in case of RTP).
 *
 * @param context         The decompression context
 * @param packet          The pointer on the IR packet minus the Add-CID byte
 *                        (ie. the field 2 in the figure)
 * @param plen            The length of the IR packet minus the Add-CID byte
 * @param large_cid_len   The size of the large CID field
 *                        (ie. field 3 in the figure)
 * @return                The length of the IR header,
 *                        0 if an error occurs
 */
unsigned int rtp_detect_ir_size(struct d_context *context,
                                unsigned char *packet,
                                unsigned int plen,
                                unsigned int large_cid_len)
{
	unsigned int length;
	unsigned int udp_rtp_static_part;
	int offset; /* offset for RX, TIS and TSS flags (RTP dynamic chain) */
	int rx;

	/* Profile and CRC fields + IP static & dynamic chains */
	length = d_generic_detect_ir_size(context, packet, plen, large_cid_len);
	offset = large_cid_len + length;

	/* UDP static chain + RTP static chain*/
	udp_rtp_static_part = rtp_get_static_part();
	length += udp_rtp_static_part;
	offset += udp_rtp_static_part;

	/* UDP dynamic chain */
	length += 2;
	offset += 2;

	/* RTP dynamic chain (constant part) */
	length += RTP_CONST_DYN_PART_SIZE;

	/* RTP dynamic chain (variable part that depends on RX flag) */
	rx = (packet[offset] >> 4) & 0x01;
	if(rx)
	{
		int tis, tss;

		rohc_debugf(3, "RX flag set\n");
		length++;
		offset += RTP_CONST_DYN_PART_SIZE;

		/* check TSS flag */
		tss = packet[offset] & 0x01;
		if(tss)
		{
			unsigned short tss_offset;
			int ts_stride_sdvl_len;

			rohc_debugf(3, "TSS flag set\n");

			/* check that packet is large enough for 1st byte of TS_STRIDE field */
			tss_offset = offset + 1;
			if(plen < (tss_offset + 1))
			{
				rohc_debugf(0, "packet is too short (%u bytes) for 1st byte "
				            "of SDVL-encoded TS_STRIDE\n", plen);
				goto error;
			}

			/* get the size of the SDVL-encoded TS_STRIDE field */
			ts_stride_sdvl_len = d_sdvalue_size(&packet[offset + 1]);
			if(ts_stride_sdvl_len < 1 || ts_stride_sdvl_len > 4)
			{
				rohc_debugf(0, "invalid size (%d bytes) for SDVL-encoded "
				            "TS_STRIDE field\n", ts_stride_sdvl_len);
				goto error;
			}

			length += ts_stride_sdvl_len;
		}
		else
		{
			rohc_debugf(3, "TSS flag not set\n");
		}

		/* check TIS flags */
		tis = (packet[offset] >> 1) & 0x01;
		if(tis)
		{
			rohc_debugf(3, "TIS flag set\n");
			rohc_debugf(0, "TIS flag set is not supported yet\n");
			goto error;
		}
		else
		{
			rohc_debugf(3, "TIS flag not set\n");
		}
	}
	else
	{
		rohc_debugf(3, "RX flag not set\n");
	}

	return length;

error:
	return 0;
}


/**
 * @brief Find the length of the IR-DYN header.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * \verbatim

 Basic structure of the IR-DYN packet (5.7.7.2):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         : if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   0   0   0 | IR-DYN packet type
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /     0-2 octets of CID info    / 1-2 octets if for large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
 4  |            Profile            | 1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              | 1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /         Dynamic chain         / variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 7  |             SN                | 2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    :                               :
 8  /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * The function computes the length of the fields 2 + 4-7, ie. the first byte,
 * the Profile and CRC fields and the dynamic chains (outer and inner IP
 * headers + UDP header + RTP header) and the SN (0 byte in case of RTP).
 *
 * @param context         The decompression context
 * @param packet          The IR-DYN packet after the Add-CID byte if present
 *                        (ie. the field 2 in the figure)
 * @param plen            The length of the IR-DYN packet minus the Add-CID byte
 * @param large_cid_len   The size of the large CID field
 *                        (ie. field 3 in the figure)
 * @return                The length of the IR-DYN header,
 *                        0 if an error occurs
 */
unsigned int rtp_detect_ir_dyn_size(struct d_context *context,
                                    unsigned char *packet,
                                    unsigned int plen,
                                    unsigned int large_cid_len)
{
	unsigned int length;
	int offset; /* offset for RX, TIS and TSS flags (RTP dynamic chain) */
	int rx;

	/* Profile and CRC fields + IP dynamic chain */
	length = d_generic_detect_ir_dyn_size(context, packet, plen, large_cid_len);
	offset = large_cid_len + length;

	/* UDP dynamic chain */
	length += 2;
	offset += 2;

	/* RTP dynamic chain */
	length += RTP_CONST_DYN_PART_SIZE;

	/* check RX flag */
	rx = (packet[offset] >> 4) & 0x01;
	if(rx)
	{
		int tis, tss;

		rohc_debugf(3, "RX flag set\n");
		length++;
		offset += RTP_CONST_DYN_PART_SIZE;

		/* check TSS flag */
		tss = packet[offset] & 0x01;
		if(tss)
		{
			unsigned short tss_offset;
			int ts_stride_sdvl_len;

			rohc_debugf(3, "TSS flag set\n");

			/* check that packet is large enough for 1st byte of TS_STRIDE field */
			tss_offset = offset + 1;
			if(plen < (tss_offset + 1))
			{
				rohc_debugf(0, "packet is too short (%u bytes) for 1st byte "
				            "of SDVL-encoded TS_STRIDE\n", plen);
				goto error;
			}

			/* get the size of the SDVL-encoded TS_STRIDE field */
			ts_stride_sdvl_len = d_sdvalue_size(&packet[offset + 1]);
			if(ts_stride_sdvl_len < 1 || ts_stride_sdvl_len > 4)
			{
				rohc_debugf(0, "invalid size (%d bytes) for SDVL-encoded "
				            "TS_STRIDE field\n", ts_stride_sdvl_len);
				goto error;
			}

			length += ts_stride_sdvl_len;
		}
		else
		{
			rohc_debugf(3, "TSS flag not set\n");
		}

		/* check TIS flags */
		tis = (packet[offset] >> 1) & 0x01;
		if(tis)
		{
			rohc_debugf(3, "TIS flag set\n");
			rohc_debugf(0, "TIS flag set is not supported yet\n");
			goto error;
		}
		else
		{
			rohc_debugf(3, "TIS flag not set\n");
		}
	}
	else
	{
		rohc_debugf(3, "RX flag not set\n");
	}

	return length;

error:
	return 0;
}


/**
 * @brief Decode the UDP/RTP static part of the ROHC packet.
 *
 * @param context The generic decompression context
 * @param packet  The ROHC packet to decode
 * @param length  The length of the ROHC packet
 * @param dest    The decoded UDP/RTP header
 * @return        The number of bytes read in the ROHC packet,
 *                -1 in case of failure
 */
int rtp_decode_static_rtp(struct d_generic_context *context,
                          const unsigned char *packet,
                          unsigned int length,
                          unsigned char *dest)
{
	struct udphdr *udp = (struct udphdr *) dest;
	struct rtphdr *rtp = (struct rtphdr *) (udp + 1);
	int read = 0; /* number of bytes read from the packet */

	/* decode UDP static part */
	read = udp_decode_static_udp(context, packet, length, dest);
	if(read == -1)
		goto error;
	packet += read;
	length -= read;

	/* check the minimal length to decode the RTP static part */
	if(length < 4)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* decode RTP static part */
	rtp->ssrc = *((uint32_t *) packet );
	rohc_debugf(3, "SSRC = 0x%x\n", rtp->ssrc);
	packet += 4;
	read += 4;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the UDP/RTP dynamic part of the ROHC packet.
 *
 * @param context      The generic decompression context
 * @param packet       The ROHC packet to decode
 * @param length       The length of the ROHC packet
 * @param dest         The decoded UDP/RTP header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
int rtp_decode_dynamic_rtp(struct d_generic_context *context,
                           const unsigned char *packet,
                           unsigned int length,
                           unsigned char *dest)
{
	struct d_rtp_context *rtp_context;
	struct udphdr *udp;
	struct rtphdr *rtp;
	int read = 0; /* number of bytes read from the packet */
	unsigned char byte;
	int rx;
	int sn;

	rtp_context = context->specific;
	udp = (struct udphdr *) dest;
	rtp = (struct rtphdr *) (udp + 1);

	/* part 1 */
	/* UDP checksum if necessary:
	 *  udp_checksum_present < 0 <=> not initialized
	 *  udp_checksum_present = 0 <=> UDP checksum field not present
	 *  udp_checksum_present > 0 <=> UDP checksum field present */
	if(rtp_context->udp_checksum_present != 0)
	{
		/* check the minimal length to decode the UDP dynamic part */
		if(length < 2)
		{
			rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
			goto error;
		}

		/* retrieve the UDP checksum from the ROHC packet */
		udp->check = GET_NEXT_16_BITS(packet);
		rohc_debugf(3, "UDP checksum = 0x%04x\n", ntohs(udp->check));
		packet += 2;
		read += 2;
		length -= 2;

		/* init the UDP context if necessary */
		if(rtp_context->udp_checksum_present < 0)
			rtp_context->udp_checksum_present = udp->check;
	}

	/* check the minimal length to decode the constant part of the RTP
	   dynamic part (parts 2-6) */
	if(length < RTP_CONST_DYN_PART_SIZE)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	/* part 2 */
	byte = *packet;
	rtp->version = (byte >> 6) & 0x03;
	rtp->padding = (byte >> 5) & 0x01;
	rtp->cc = byte & 0x0f;
	rx = (byte >> 4) & 0x01;
	packet++;
	read++;
	length--;
	rohc_debugf(3, "version = 0x%x\n", rtp->version);
	rohc_debugf(3, "padding = 0x%x\n", rtp->padding);
	rohc_debugf(3, "cc = 0x%x\n", rtp->cc);

	/* part 3 */
	byte = *packet;
	rtp->m = (byte >> 7) & 0x01;
	rtp_context->m = rtp->m;
	rohc_debugf(3, "M = 0x%x\n", rtp->m);
	rtp->pt = byte & 0x7f;
	rtp_context->pt = rtp->pt;
	rohc_debugf(3, "payload type = %d / 0x%x\n", ntohs(rtp->pt), rtp->pt);
	packet++;
	read++;
	length--;

	/* part 4 */
	rtp->sn = GET_NEXT_16_BITS(packet);
	packet += 2;
	read += 2;
	length -= 2;
	rohc_debugf(3, "SN = %d\n", ntohs(rtp->sn));

	/* init SN and IP-IDs (IPv4 only) */
	sn = ntohs(rtp->sn);
	d_lsb_init(&context->sn, sn, 3);
	if(ip_get_version(context->active1->ip) == IPV4)
		d_ip_id_init(&context->ip_id1, ntohs(ipv4_get_id(context->active1->ip)), sn);
	if(context->multiple_ip && ip_get_version(context->active2->ip) == IPV4)
		d_ip_id_init(&context->ip_id2, ntohs(ipv4_get_id(context->active2->ip)), sn);

	/* part 5 */
	rtp->timestamp = *((uint32_t *) packet);
	if(rtp_context->timestamp != 0)
	{
		/* we can evaluate TS delta */
		rtp_context->ts_received = ntohl(rtp->timestamp) - rtp_context->timestamp;
	}

	/* add the timestamp to the context */
	rtp_context->timestamp = ntohl(rtp->timestamp);

	read += 4;
	packet += 4;
	length -= 4;
	rohc_debugf(3, "timestamp = 0x%x\n", rtp_context->timestamp);

	/* part 6 is not supported yet, ignore the byte which should be set to 0 */
	if(GET_BIT_0_7(packet) != 0x00)
	{
		rohc_debugf(0, "generic CSRC list not supported yet\n");
		goto error;
	}
	packet++;
	read++;
	length--;

	/* part 7 */
	if(rx)
	{
		int x, mode, tis, tss;

		/* check the minimal length to decode the flags that are only present
		   if RX flag is set */
		if(length < 1)
		{
			rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
			goto error;
		}

		byte = *packet;
		x = (byte & 0x10) >> 4;
		mode = (byte >> 2) & 0x11;
		tis = (byte >> 1) & 0x01;
		tss = byte & 0x01;
		rohc_debugf(3, "x = %d, rohc_mode = %d, tis = %d, tss = %d, \n",
		            x, mode, tis, tss);
		read++;
		packet++;
		length--;

		/* part 8 */
		if(tss)
		{
			int ts_stride_sdvl_len;
			uint32_t ts_stride;

			/* check the minimal length to decode the SDVL-encoded TS_STRIDE */
			if(length < 1)
			{
				rohc_debugf(0, "ROHC packet too small (len = %d) for 1st byte "
				            "of SDVL-encoded TS_STRIDE\n", length);
				goto error;
			}

			/* how many bytes for the SDVL-encoded TS_STRIDE ? */
			ts_stride_sdvl_len = d_sdvalue_size(packet);
			if(ts_stride_sdvl_len < 1 || ts_stride_sdvl_len > 4)
			{
				rohc_debugf(0, "invalid size (%d bytes) for SDVL-encoded "
				            "TS_STRIDE field\n", ts_stride_sdvl_len);
				goto error;
			}

			/* check the length to decode the full SDVL-encoded TS_STRIDE */
			if(length < ts_stride_sdvl_len)
			{
				rohc_debugf(0, "ROHC packet too small (len = %d) for the full "
				            "%d-byte SDVL-encoded TS_STRIDE\n", length,
				            ts_stride_sdvl_len);
				goto error;
			}

			/* decode the SDVL-encoded TS_STRIDE field */
			ts_stride = d_sdvalue_decode(packet);
			rohc_debugf(3, "ts_stride read = %u / 0x%x\n", ts_stride, ts_stride);

			/* skip the SDVL-encoded TS_STRIDE field in packet */
			read += ts_stride_sdvl_len;
			packet += ts_stride_sdvl_len;
			length -= ts_stride_sdvl_len;

			/* update context with the decoded TS_STRIDE */
			d_add_ts_stride(&rtp_context->ts_sc, ts_stride);
		}

		/* part 9 */
		if(tis)
		{
			/* check the minimal length to decode the SDVL-encoded TIME_STRIDE */
			if(length < 1)
			{
				rohc_debugf(0, "ROHC packet too small (len = %d) for 1st byte "
				            "of SDVL-encoded TIME_STRIDE\n", length);
				goto error;
			}

			/* not supported yet */
			rohc_debugf(0, "TIME_STRIDE field not supported yet\n");
			goto error;
		}
	}

	/* add the timestamp to the ts_sc object */
	d_add_ts(&rtp_context->ts_sc, ntohl(rtp->timestamp), ntohs(rtp->sn));

	return read;

error:
	return -1;
}


/**
 * @brief Decode the UDP/RTP tail of the UO* ROHC packets.
 *
 * @param context      The generic decompression context
 * @param packet       The ROHC packet to decode
 * @param length       The length of the ROHC packet
 * @param dest         The decoded UDP/RTP header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
int rtp_decode_uo_tail_rtp(struct d_generic_context *context,
                           const unsigned char *packet,
                           unsigned int length,
                           unsigned char *dest)

{
	struct d_rtp_context *rtp_context;
	struct udphdr *udp;
	int read = 0; /* number of bytes read from the packet */

	rtp_context = context->specific;
	udp = (struct udphdr *) dest;

	/* UDP checksum if necessary:
	 *  udp_checksum_present < 0 <=> not initialized
	 *  udp_checksum_present = 0 <=> UDP checksum field not present
	 *  udp_checksum_present > 0 <=> UDP checksum field present */
	if(rtp_context->udp_checksum_present > 0)
	{
		/* check the minimal length to decode the UDP checksum */
		if(length < 2)
		{
			rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
			goto error;
		}

		/* retrieve the UDP checksum from the ROHC packet */
		udp->check = GET_NEXT_16_BITS(packet);
		rohc_debugf(3, "UDP checksum = 0x%04x\n", ntohs(udp->check));
		packet += 2;
		read += 2;
	}
	else if(rtp_context->udp_checksum_present < 0)
	{
		rohc_debugf(0, "udp_checksum_present not initialized and "
		               "packet is not one IR packet\n");
		goto error;
	}

	return read;

error:
	return -1;
}


/**
 * @brief Build an uncompressed UDP/RTP header.
 *
 * @param context      The generic decompression context
 * @param active       The UDP/RTP header changes
 * @param dest         The buffer to store the UDP/RTP header (MUST be at least
 *                     of sizeof(struct udphdr) + sizeof(struct rtphdr) length)
 * @param payload_size The length of the UDP/RTP payload
 * @return             The length of the next header (ie. the UDP/RTP header),
 *                     -1 in case of error
 */
int rtp_build_uncompressed_rtp(struct d_generic_context *context,
                               struct d_generic_changes *active,
                               unsigned char *dest,
                               int payload_size)
{
	struct d_rtp_context *rtp_context = context->specific;
	struct udphdr *udp_active = (struct udphdr *) active->next_header;
	struct udphdr *udp = (struct udphdr *) dest;

	/* static + checksum */
	memcpy(dest, udp_active, sizeof(struct udphdr) + sizeof(struct rtphdr));

	/* UDP checksum:
	 *  - error if udp_checksum_present not initialized,
	 *    ie. udp_checksum_present < 0
	 *  - already copied if checksum is present,
	 *    ie. udp_checksum_present > 0
	 *  - set checksum to zero if checksum is not present,
	 *    ie. udp_checksum_present = 0  */
	if(rtp_context->udp_checksum_present < 0)
	{
		rohc_debugf(0, "udp_checksum_present not initialized\n");
		goto error;
	}
	else if(rtp_context->udp_checksum_present == 0)
		udp->check = 0;
	rohc_debugf(3, "UDP checksum = 0x%04x\n", ntohs(udp->check));

	/* interfered fields */
	udp->len = htons(payload_size + sizeof(struct udphdr) +
	                 sizeof(struct rtphdr));
	rohc_debugf(3, "UDP + RTP length = 0x%04x\n", ntohs(udp->len));

	return sizeof(struct udphdr) + sizeof(struct rtphdr);

error:
	return -1;
}


/**
 * @brief Define the decompression part of the RTP profile as described
 *        in the RFC 3095.
 */
struct d_profile d_rtp_profile =
{
	ROHC_PROFILE_RTP,       /* profile ID (see 8 in RFC 3095) */
	"beta",                 /* profile version */
	"RTP / Decompressor",   /* profile description */
	d_generic_decode,       /* profile handlers */
	d_udp_decode_ir,
	d_rtp_create,
	d_udp_destroy,
	rtp_detect_ir_size,
	rtp_detect_ir_dyn_size,
	rtp_get_static_part,
	d_generic_get_sn,
};

