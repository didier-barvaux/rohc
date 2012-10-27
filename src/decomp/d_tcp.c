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
 * @file d_tcp.c
 * @brief ROHC decompression context for the TCP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 * @author FWX <rohc_team@dialine.fr>
 */

#include "d_tcp.h"
#include "rohc_bit_ops.h"
#include "rohc_traces.h"
#include "rohc_debug.h"
#include "crc.h"
#include "trace.h"
#include "rfc4996_decoding.h"
#include "wlsb.h"
#include "rohc_time.h"
#include "protocols/ipproto.h"

#include <netinet/ip.h>

#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif

/*
 * Private function prototypes.
 */

static void d_tcp_destroy(void *context);

static int tcp_decode_static_ipv6_option(struct d_tcp_context *tcp_context,
                                         ip_context_ptr_t ip_context,
                                         u_int8_t protocol,
                                         multi_ptr_t c_base_header,
                                         unsigned int length,
                                         base_header_ip_t base_header);
static unsigned int tcp_copy_static_ipv6_option(u_int8_t protocol,
                                                ip_context_ptr_t ip_context,
                                                base_header_ip_t base_header);
static int tcp_decode_dynamic_ipv6_option(struct d_tcp_context *tcp_context,
                                          ip_context_ptr_t ip_context,
                                          u_int8_t protocol,
                                          multi_ptr_t c_base_header,
                                          unsigned int length,
                                          base_header_ip_t base_header);
#if 0 /* not used at the moment */
static u_int8_t * tcp_decode_irregular_ipv6_option(struct d_tcp_context *tcp_context,
                                                   ip_context_ptr_t ip_context,
                                                   u_int8_t protocol,
                                                   multi_ptr_t mptr,
                                                   base_header_ip_t base_header);
#endif

static int tcp_decode_static_ip(struct d_tcp_context *tcp_context,
                                ip_context_ptr_t ip_context,
                                multi_ptr_t c_base_header,
                                unsigned int length,
                                unsigned char *dest);
static unsigned int tcp_copy_static_ip(ip_context_ptr_t ip_context,
                                       base_header_ip_t base_header);
static int tcp_decode_dynamic_ip(struct d_tcp_context *tcp_context,
                                 ip_context_ptr_t ip_context,
                                 multi_ptr_t c_base_header,
                                 unsigned int length,
                                 unsigned char *dest);
static u_int8_t * tcp_decode_irregular_ip(struct d_tcp_context *tcp_context,
                                          ip_context_ptr_t ip_context,
                                          base_header_ip_t base_header,
                                          multi_ptr_t mptr,
                                          int is_innermost,
                                          int ttl_irregular_chain_flag,
                                          int ip_inner_ecn);
static int tcp_decode_static_tcp(struct d_tcp_context *tcp_context,
                                 tcp_static_t *tcp_static,
                                 unsigned int length,
                                 tcphdr_t *tcp);
static unsigned int tcp_copy_static_tcp(struct d_tcp_context *tcp_context,
                                        tcphdr_t *tcp);
static int tcp_decode_dynamic_tcp(struct d_generic_context *context,
                                  tcp_dynamic_t *tcp_dynamic,
                                  unsigned int length,
                                  tcphdr_t *tcp);

static int d_tcp_decode_ir(struct rohc_decomp *decomp,
                           struct d_context *context,
                           const unsigned char *const rohc_packet,
                           const unsigned int rohc_length,
                           const size_t add_cid_len,
                           const size_t large_cid_len,
                           unsigned char *dest);
static int d_tcp_decode_CO(struct rohc_decomp *decomp,
                           struct d_context *context,
                           const unsigned char *const rohc_packet,
                           const unsigned int rohc_length,
                           const size_t add_cid_len,
                           const size_t large_cid_len,
                           unsigned char *dest);

/**
 * @brief This is a version of ip_compute_csum() optimized for IP headers,
 *        which always checksum on 4 octet boundaries.
 *
 * @param iph The IPv4 header
 * @param ihl The length of the IPv4 header
 * @return    The IPv4 checksum
 */

static uint16_t my_ip_fast_csum(const void *iph, unsigned int ihl)
{
	u_int32_t checksum = 0;
	multi_ptr_t mptr;
	WB_t wb;
	int i;

	rohc_debugf(3, "iph %p ihl %d \n",iph,ihl * 4);

	mptr.uint8 = (u_int8_t*) iph;

	i = ihl << 1;

	while(i-- != 0)
	{
		  #if __BYTE_ORDER == __LITTLE_ENDIAN
		wb.uint8[1] = *(mptr.uint8++);
		wb.uint8[0] = *(mptr.uint8++);
		  #elif __BYTE_ORDER == __BIG_ENDIAN
		wb.uint16 = READ16_FROM_MPTR(mptr);
		  #endif
		checksum += wb.uint16;
		rohc_debugf(3, "checksum %Xh value %4.4X\n",checksum,wb.uint16);
	}

	while( ( checksum & 0xFFFF0000 ) != 0)
	{
		checksum = ( checksum & 0xFFFF ) + ( checksum >> 16 );
	}

	wb.uint16 = ~checksum;
	rohc_debugf(3, "checksum %Xh\n",wb.uint16);
	return htons( wb.uint16 );
}


/**
 * @brief Create the TCP decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return The newly-created TCP decompression context
 */
void * d_tcp_create(void)
{
	struct d_generic_context *context;
	struct d_tcp_context *tcp_context;

	/* create the generic context */
	context = d_generic_create();
	if(context == NULL)
	{
		goto quit;
	}

	/* create the TCP-specific part of the context */
	tcp_context = malloc(sizeof(struct d_tcp_context));
	if(tcp_context == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the TCP-specific context\n");
		goto destroy_context;
	}
	bzero(tcp_context, sizeof(struct d_tcp_context));
	context->specific = tcp_context;

	/* the TCP source and destination ports will be initialized
	 * with the IR packets */
	tcp_context->tcp_src_port = 0xFFFF;
	tcp_context->tcp_dst_port = 0xFFFF;

	memset(tcp_context->tcp_options_list,0xFF,16);

	/* some TCP-specific values and functions */
	context->next_header_len = sizeof(tcphdr_t);
	context->build_next_header = NULL;
//	context->decode_static_next_header = tcp_decode_static_tcp;
//	context->decode_dynamic_next_header = tcp_decode_dynamic_tcp;  // A REVOIR
//	context->decode_uo_tail = NULL;
	context->compute_crc_static = tcp_compute_crc_static;
	context->compute_crc_dynamic = tcp_compute_crc_dynamic;


	// DBX ???

	/* create the TCP-specific part of the header changes */
	context->outer_ip_changes->next_header_len = sizeof(tcphdr_t);
	context->outer_ip_changes->next_header = malloc(sizeof(tcphdr_t));
	if(context->outer_ip_changes->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the TCP-specific "
		            "part of the outer IP header changes\n");
		goto free_tcp_context;
	}
	memset(context->outer_ip_changes->next_header, 0, sizeof(tcphdr_t));

	context->inner_ip_changes->next_header_len = sizeof(tcphdr_t);
	context->inner_ip_changes->next_header = malloc(sizeof(tcphdr_t));
	if(context->inner_ip_changes->next_header == NULL)
	{
		rohc_debugf(0, "cannot allocate memory for the TCP-specific "
		            "part of the inner IP header changes\n");
		goto free_outer_next_header;
	}
	memset(context->inner_ip_changes->next_header, 0, sizeof(tcphdr_t));

	/* set next header to TCP */
	context->next_header_proto = IPPROTO_TCP;

	rohc_debugf(3, "TCP context created (%p)\n",context);

	return context;

free_outer_next_header:
	zfree(context->outer_ip_changes->next_header);
free_tcp_context:
	zfree(tcp_context);
destroy_context:
	d_generic_destroy(context);
quit:
	return NULL;
}


/**
 * @brief Destroy the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
static void d_tcp_destroy(void *context)
{
	struct d_generic_context *g_context = context;

	assert(context != NULL);

	/* clean TCP-specific memory */
	assert(g_context->outer_ip_changes != NULL);
	assert(g_context->outer_ip_changes->next_header != NULL);
	zfree(g_context->outer_ip_changes->next_header);
	assert(g_context->inner_ip_changes != NULL);
	assert(g_context->inner_ip_changes->next_header != NULL);
	zfree(g_context->inner_ip_changes->next_header);

#if 0 /* TODO: sn_lsb_ctxt is not initialized, either remove it or use it fully */
	/* destroy the LSB decoding context for SN */
	rohc_lsb_free(g_context->sn_lsb_ctxt);
#endif

	rohc_debugf(3, "TCP context destroyed (%p)\n",context);

	/* destroy the generic decompression context (g_context->specific is
	 * destroyed by d_generic_destroy) */
	d_generic_destroy(g_context);
}


/**
 * @brief Decode one IR, IR-DYN, IR-CO IR-CR packet for TCP profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param add_cid_len    The length of the optional Add-CID field
 * @param large_cid_len  The length of the optional large CID field
 * @param dest           OUT: The decoded IP packet
 * @return               The length of the uncompressed IP packet
 *                       or ROHC_ERROR if an error occurs
 *                       or ROHC_ERROR_CRC if a CRC error occurs
 */
int d_tcp_decode(struct rohc_decomp *decomp,
                 struct d_context *context,
                 const unsigned char *const rohc_packet,
                 const unsigned int rohc_length,
	              const size_t add_cid_len,
	              const size_t large_cid_len,
                 unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_tcp_context *tcp_context = g_context->specific;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header;
	multi_ptr_t c_base_header;
	tcphdr_t *tcp;
	unsigned int payload_size;
	int length = ROHC_ERROR;
	u_int8_t packet_type;
	u_int8_t protocol;
	int size;
	int read;

	rohc_debugf(3, "decomp %p context %p rohc_packet %p rohc_length %d "
	            "add_cid_len %zd large_cid_len %zd dest %p\n",
	            decomp, context, rohc_packet, rohc_length, add_cid_len,
	            large_cid_len, dest);

	TraceData((unsigned char*)rohc_packet,rohc_length);

	packet_type = *rohc_packet;
	rohc_debugf(3, "Packet id %2.2Xh\n",packet_type);

	ip_context.uint8 = tcp_context->ip_context;

	if(packet_type == PACKET_TYPE_IR)
	{
		size = d_tcp_decode_ir(decomp, context, rohc_packet, rohc_length,
		                       add_cid_len, large_cid_len, dest);
	}
	else if(packet_type == PACKET_TYPE_IR_DYN)
	{
		/* skip:
		 *  - the first byte of the ROHC packet (field 2)
		 *  - the Profile byte (field 4) */
		length = 2;
		c_base_header.uint8 = (u_int8_t*)( rohc_packet + large_cid_len + length);

		/* parse CRC */
		/* TODO Didier */
		c_base_header.uint8++;
		length++;

		base_header.uint8 = dest;
		ip_context.uint8 = tcp_context->ip_context;
		size = 0;

		do
		{
			/* Init static part in IP header */
			size += tcp_copy_static_ip(ip_context,base_header);

			/* Decode dynamic part */
			read = tcp_decode_dynamic_ip(tcp_context,ip_context,c_base_header,rohc_length - length,
			                             base_header.uint8);
			length += read;
			c_base_header.uint8 += read;
			rohc_debugf(3, "length %d read %d size %d\n",length,read,size);

			if(ip_context.vx->version == IPV4)
			{
				protocol = ip_context.v4->protocol;
				++base_header.ipv4;
				++ip_context.v4;
			}
			else
			{
				protocol = ip_context.v6->next_header;
				++base_header.ipv6;
				++ip_context.v6;
				while( ( ipproto_specifications[protocol] & IPV6_OPTION ) != 0)
				{
					size += tcp_copy_static_ipv6_option(protocol,ip_context,base_header);
					protocol = ip_context.v6_option->next_header;
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
			}

			assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );

		}
		while( ( ipproto_specifications[protocol] & IP_TUNNELING ) != 0);

		tcp = base_header.tcphdr;

		tcp_copy_static_tcp(tcp_context,tcp);

// A COMPLETER ??? boucle sur dynamic chain ???
		read = tcp_decode_dynamic_tcp(g_context,c_base_header.tcp_dynamic,rohc_length - length,tcp);

		rohc_debugf(3, "Current IP packet\n");
		TraceData(dest,size);

		length += read;
		c_base_header.uint8 += read;

		rohc_debugf(3, "read %d length %d size %d\n",read,length,size);

		memcpy(&tcp_context->old_tcphdr,tcp,sizeof(tcphdr_t));

		// Add TCP header size
		size += sizeof(tcphdr_t);

		payload_size = rohc_length - length - large_cid_len;

		// Calculate scaled value and residue (see RFC4996 page 32/33)
		if(payload_size != 0)
		{
			tcp_context->seq_number_scaled = ntohl(tcp->seq_number) / payload_size;
			tcp_context->seq_number_residue = ntohl(tcp->seq_number) % payload_size;
		}

		// copy payload datas
		memcpy(((u_int8_t*)tcp) + sizeof(tcphdr_t),c_base_header.uint8,payload_size);
		rohc_debugf(3, "copy %d bytes of payload\n",payload_size);

		// Add payload size
		size += payload_size;

		base_header.uint8 = dest;
		ip_context.uint8 = tcp_context->ip_context;

		length = size;

		do
		{

			if(ip_context.vx->version == IPV4)
			{
				base_header.ipv4->length = htons(length);
				base_header.ipv4->checksum = 0;
				base_header.ipv4->checksum = my_ip_fast_csum(base_header.uint8,
				                                             base_header.ipv4->header_length);
//				base_header.ipv4->checksum = ip_fast_csum(base_header.uint8,base_header.ipv4->header_length);
				rohc_debugf(3, "IP checksum = 0x%04x for %d\n", ntohs(
				               base_header.ipv4->checksum), base_header.ipv4->header_length);
				TraceIpV4(base_header.ipv4);
				protocol = ip_context.v4->protocol;
				length -= sizeof(base_header_ip_v4_t);
				++base_header.ipv4;
				++ip_context.v4;
			}
			else
			{
				length -= sizeof(base_header_ip_v6_t);
				base_header.ipv6->payload_length = htons(length);
				rohc_debugf(3, "payload_length %d\n",ntohs(base_header.ipv6->payload_length));
				TraceIpV6(base_header.ipv6);
				protocol = ip_context.v6->next_header;
				++base_header.ipv6;
				++ip_context.v6;
				while( ( ipproto_specifications[protocol] & IPV6_OPTION ) != 0)
				{
					protocol = ip_context.v6_option->next_header;
					length -= ip_context.v6_option->option_length;
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
			}

			assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );

		}
		while( ( ipproto_specifications[protocol] & IP_TUNNELING ) != 0);

		TraceTcp(base_header.tcphdr);

		rohc_debugf(3, "new msn %Xh\n",tcp_context->msn);

		rohc_debugf(3, "Total length %d\n",size);
	}
	else
	{
		// Uncompressed CO packet
		size = d_tcp_decode_CO(decomp, context, rohc_packet, rohc_length,
		                      add_cid_len, large_cid_len, dest);
	}

	rohc_debugf(3, "return %d\n", size );
	return size;
}


/**
 * @brief Decode one IR packet for the TCP profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param rohc_packet     The ROHC packet to decode
 * @param rohc_length     The length of the ROHC packet to decode
 * @param add_cid_len     The length of the optional Add-CID field
 * @param large_cid_len   The length of the optional large CID field
 * @param dest            The decoded IP packet
 * @return                The length of the uncompressed IP packet
 *                        or ROHC_OK_NO_DATA if packet is feedback only
 *                        or ROHC_ERROR if an error occurs
 */
static int d_tcp_decode_ir(struct rohc_decomp *decomp,
                           struct d_context *context,
                           const unsigned char *const rohc_packet,
                           const unsigned int rohc_length,
                           const size_t add_cid_len,
                           const size_t large_cid_len,
                           unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_tcp_context *tcp_context = g_context->specific;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header;
	multi_ptr_t c_base_header;
	tcphdr_t *tcp;
	unsigned int payload_size;
	unsigned int length;
	u_int8_t protocol;
	u_int16_t size;
	int read;

	rohc_debugf(3, "decomp %p context %p rohc_packet %p rohc_length %d "
	            "add_cid_len %zd large_cid_len %zd dest %p\n",
	            decomp, context, rohc_packet, rohc_length, add_cid_len,
	            large_cid_len, dest);

	TraceData((unsigned char*)rohc_packet,rohc_length);

	/* skip:
	 * - the first byte of the ROHC packet (field 2)
	 * - the Profile byte (field 4) */
	length = 2;
	c_base_header.uint8 = (u_int8_t*)( rohc_packet + large_cid_len + length);

	/* parse CRC */
	/* TODO Didier */
	c_base_header.uint8++;
	length++;

	base_header.uint8 = dest;
	ip_context.uint8 = tcp_context->ip_context;

	size = 0;
	do
	{
		read = tcp_decode_static_ip(tcp_context,ip_context,c_base_header,rohc_length - length,
		                            base_header.uint8);
		length += read;
		c_base_header.uint8 += read;
		protocol = ip_context.vx->next_header;
		ip_context.uint8 += ip_context.vx->context_length;
		if(base_header.ipvx->version == IPV4)
		{
			++base_header.ipv4;
			size += sizeof(base_header_ip_v4_t);
		}
		else
		{
			++base_header.ipv6;
			size += sizeof(base_header_ip_v6_t);
			while( ( ipproto_specifications[protocol] & IPV6_OPTION ) != 0)
			{
				read =
				   tcp_decode_static_ipv6_option(tcp_context,ip_context,protocol,c_base_header,length,
				                                 base_header);
				length += read;
				c_base_header.uint8 += read;
				size += ip_context.v6_option->option_length;
				protocol = ip_context.v6_option->next_header;
				base_header.uint8 += ip_context.v6_option->option_length;
				ip_context.uint8 += ip_context.v6_option->context_length;
			}
		}
		rohc_debugf(3, "length %d read %d size %d\n",length,read,size);
		assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );
		rohc_debugf(3, "Current IP packet\n");
		TraceData(dest,size);
	}
	while( ( ipproto_specifications[protocol] & IP_TUNNELING ) != 0);

	tcp = base_header.tcphdr;

	read = tcp_decode_static_tcp(tcp_context,c_base_header.tcp_static,rohc_length - length,tcp);

	rohc_debugf(3, "Current IP packet\n");
	TraceData(dest,size);

	length += read;
	c_base_header.uint8 += read;
	rohc_debugf(3, "length %d read %d size %d\n",length,read,size);

	/* dynamic chain */

	base_header.uint8 = dest;
	ip_context.uint8 = tcp_context->ip_context;

	do
	{
		read = tcp_decode_dynamic_ip(tcp_context,ip_context,c_base_header,rohc_length - length,
		                             base_header.uint8);
		length += read;
		c_base_header.uint8 += read;
		rohc_debugf(3, "length %d read %d\n",length,read);
		protocol = ip_context.vx->next_header;
		ip_context.uint8 += ip_context.vx->context_length;
		if(base_header.ipvx->version == IPV4)
		{
			++base_header.ipv4;
		}
		else
		{
			++base_header.ipv6;
			while( ( ipproto_specifications[protocol] & IPV6_OPTION ) != 0)
			{
				read =
				   tcp_decode_dynamic_ipv6_option(tcp_context,ip_context,protocol,c_base_header,length,
				                                  base_header);
				length += read;
				c_base_header.uint8 += read;
				protocol = ip_context.v6_option->next_header;
				base_header.uint8 += ip_context.v6_option->option_length;
				ip_context.uint8 += ip_context.v6_option->context_length;
			}
		}
		assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );
		rohc_debugf(3, "Current IP packet\n");
		TraceData(dest,size);
	}
	while( ( ipproto_specifications[protocol] & IP_TUNNELING ) != 0);

	rohc_debugf(3, "length %d read %d size %d\n",length,read,size);

	read = tcp_decode_dynamic_tcp(g_context,c_base_header.tcp_dynamic,rohc_length - length,tcp);

	rohc_debugf(3, "Current IP packet\n");
	TraceData(dest,size + sizeof(tcphdr_t));

	length += read;
	c_base_header.uint8 += read;
	rohc_debugf(3, "length %d read %d size %d\n",length,read,size);

	memcpy(&tcp_context->old_tcphdr,tcp,sizeof(tcphdr_t));

	// Add TCP header size
	size += sizeof(tcphdr_t);
	rohc_debugf(3, "size %d\n",size);

	payload_size = rohc_length - length - large_cid_len;

	// Calculate scaled value and residue (see RFC4996 page 32/33)
	if(payload_size != 0)
	{
		tcp_context->seq_number_scaled = ntohl(tcp->seq_number) / payload_size;
		tcp_context->seq_number_residue = ntohl(tcp->seq_number) % payload_size;
	}

	// copy payload
	memcpy(((u_int8_t*)tcp) + sizeof(tcphdr_t),c_base_header.uint8,payload_size);
	rohc_debugf(3, "copy %d bytes of payload\n",payload_size);

	// Add payload size
	size += payload_size;
	rohc_debugf(3, "payload_size %d size %d\n",payload_size,size);

	rohc_debugf(3, "Total length %d\n",size);

	base_header.uint8 = dest;
	ip_context.uint8 = tcp_context->ip_context;

	length = size;

	do
	{
		if(base_header.ipvx->version == IPV4)
		{
			protocol = base_header.ipv4->protocol;
			base_header.ipv4->length = htons(length);
			base_header.ipv4->checksum = 0;
			base_header.ipv4->checksum = my_ip_fast_csum(base_header.uint8,
			                                             base_header.ipv4->header_length);
//			base_header.ipv4->checksum = ip_fast_csum(base_header.uint8,base_header.ipv4->header_length);
			rohc_debugf(3, "IP checksum = 0x%04x for %d\n", ntohs(
			               base_header.ipv4->checksum), base_header.ipv4->header_length);
			TraceIpV4(base_header.ipv4);
			++base_header.ipv4;
			++ip_context.v4;
			length -= sizeof(base_header_ip_v4_t);
		}
		else
		{
			protocol = base_header.ipv6->next_header;
			length -= sizeof(base_header_ip_v6_t);
			base_header.ipv6->payload_length = htons(length);
			rohc_debugf(3, "payload_length %d\n",ntohs(base_header.ipv6->payload_length));
			TraceIpV6(base_header.ipv6);
			++base_header.ipv6;
			++ip_context.v6;
			while( ( ipproto_specifications[protocol] & IPV6_OPTION ) != 0)
			{
				length -= ip_context.v6_option->option_length;
				protocol = base_header.ipv6_opt->next_header;
				base_header.uint8 += ip_context.v6_option->option_length;
				ip_context.uint8 += ip_context.v6_option->context_length;
			}
		}
		assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );

	}
	while( ( ipproto_specifications[protocol] & IP_TUNNELING ) != 0);

	TraceTcp(base_header.tcphdr);

	rohc_debugf(3, "return %d\n", size );
	return size;
}


/**
 * @brief Find the length of the dynamic TCP part.
 *
 * @param tcp_dynamic     The dynamic part of the rohc packet
 * @param length          The remain length of the rohc packet
 * @return                The length of dynamic TCP part
 *                        0 if an error occurs
 */
unsigned int tcp_detect_tcp_dynamic_size(tcp_dynamic_t *tcp_dynamic,
                                         unsigned int length)
{
	u_int8_t *pBeginList;
	u_int8_t *options;
	unsigned int size;
	u_int8_t present;
	u_int8_t PS;
	u_int8_t m;
	u_int8_t i;

	/* TCP dynamic part (see RFC 4996 page 73/74) */
	/* tcp_dynamic + window + checksum */
	size = sizeof(tcp_dynamic_t) + 2 + 2;

	rohc_debugf(3, "tcp_dynamic %p size %d\n", tcp_dynamic,size);
	rohc_debugf(3, "ack_zero %d urp_zero %d ack_stride_flag %d\n",tcp_dynamic->ack_zero,
	            tcp_dynamic->urp_zero,
	            tcp_dynamic->ack_stride_flag);

	if(tcp_dynamic->ack_zero == 0)
	{
		/* Add ack_number field size */
		size += 4;
		rohc_debugf(3, "add ack_number size -> size %d\n",size);
	}
	if(tcp_dynamic->urp_zero == 0)
	{
		/* Add urg_ptr field size */
		size += 2;
		rohc_debugf(3, "add urg_ptr size -> size %d\n",size);
	}
	if(tcp_dynamic->ack_stride_flag == 0)
	{
		/* Add ack_stride field size */
		size += 2;
		rohc_debugf(3, "add ack_stride -> size %d\n",size);
	}
	rohc_debugf(3, "size %u\n", size);

	/* init pointer at the begin of the list */
	pBeginList = ((u_int8_t*)tcp_dynamic) + size;

	// if compressed list of TCP options
	if( ( (*pBeginList) & 0x0F ) != 0)
	{

		/* init number of index */
		m = (*pBeginList) & 0x0F;
		PS = *pBeginList & 0x10;
		rohc_debugf(3, "TCP Begin of compressed list at %p %2.2Xh %2.2Xh PS=%c\n",pBeginList,
		            *pBeginList,*(pBeginList + 1),
		            PS == 0 ? '0' : '1');
		++pBeginList;
		/* if 8-bit XI fields */
		if(PS != 0)
		{
			size += 1 + m;
			options = pBeginList + m;
		}
		else
		{
			size += 1 + ( ( m + 1 ) >> 1 );
			options = pBeginList + ( ( m + 1 ) >> 1 );
		}
		for(i = 0; i < m; ++i)
		{
			if(PS != 0)
			{
				present = *(pBeginList++) & 0x80;
			}
			else
			{
				if(i & 1)
				{
					present = *(pBeginList++) & 0x08;
				}
				else
				{
					present = *pBeginList & 0x80;
				}
			}
			if(present != 0)
			{
				switch(*options)
				{
					case TCP_OPT_EOL:
						rohc_debugf(3, "TCP OPT EOL\n");
						++options;
						++size;
						break;
					case TCP_OPT_NOP:
						rohc_debugf(3, "TCP OPT NOP\n");
						++options;
						++size;
						break;
					case TCP_OPT_MAXSEG:
						rohc_debugf(3, "TCP OPT MAXSEG\n");
						options += TCP_OLEN_MAXSEG;
						size += TCP_OLEN_MAXSEG;
						break;
					case TCP_OPT_WINDOW:
						rohc_debugf(3, "TCP OPT WINDOW\n");
						options += TCP_OLEN_WINDOW;
						size += TCP_OLEN_WINDOW;
						break;
					case TCP_OPT_SACK_PERMITTED:
						rohc_debugf(3, "TCP OPT SACK PERMITTED\n");
						options += TCP_OLEN_SACK_PERMITTED;
						size += TCP_OLEN_SACK_PERMITTED;
						break;
					case TCP_OPT_SACK:
						rohc_debugf(3, "TCP OPT SACK\n");
						++options;
						++size;
						break;
					case TCP_OPT_TIMESTAMP:
						rohc_debugf(3, "TCP OPT TIMSESTAMP\n");
						options += TCP_OLEN_TIMESTAMP;
						size += TCP_OLEN_TIMESTAMP;
						// TCP_OLEN_TSTAMP_APPA    (TCP_OLEN_TIMESTAMP+2) /* appendix A */
						break;
					/*
					case TCP_OPT_TSTAMP_HDR:
					                  rohc_debugf(3, "TCP OPT TIMSESTAMP HDR\n");
					                  i = 0;
					                  break;
					*/
					default:
						rohc_debugf(3, "TCP OPT unknown %Xh\n",*options);
						size += *(options + 1);
						options += *(options + 1);
						break;
				}
			}
		}
	}
	else
	{
		rohc_debugf(3, "TCP no XI items in compressed list\n");
		// size of begin list
		++size;
	}

	rohc_debugf(3, "TCP dynamic part length %d\n",size);
	TraceData((unsigned char*)tcp_dynamic,size);

	return size;
}


/**
 * @brief Decode the static IP v6 option header of the rohc packet.
 *
 * @param tcp_context    The specific TCP decompression context
 * @param ip_context     The specific IP decompression context
 * @param protocol       The IPv6 protocol option
 * @param c_base_header  The compressed IP header of the rohc packet
 * @param length         The remain length of the rohc packet
 * @param base_header    The decoded IP packet
 * @return               The length of static IP header
 *                       0 if an error occurs
 */
static int tcp_decode_static_ipv6_option(struct d_tcp_context *tcp_context,
                                         ip_context_ptr_t ip_context,
                                         u_int8_t protocol,
                                         multi_ptr_t c_base_header,
                                         unsigned int length,
                                         base_header_ip_t base_header)
{
	int size;

	rohc_debugf(
	   3, "tcp_context %p ip_context %p protocol %d c_base_header %p length %d base_header %p\n",
	   tcp_context,ip_context.uint8,protocol,c_base_header.uint8,length,base_header.uint8);

	ip_context.v6_option->next_header = c_base_header.ip_opt_static->next_header;
	base_header.ipv6_opt->next_header = c_base_header.ip_opt_static->next_header;

	switch(protocol)
	{
		case IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
			ip_context.v6_option->option_length = ( c_base_header.ip_opt_static->length + 1 ) << 3;
			ip_context.v6_option->context_length = 2 + ip_context.v6_option->option_length;
			rohc_debugf(3, "IP v6 option Hop-by-Hop length %d context_length %d option_length %d\n",
			            c_base_header.ip_opt_static->length,ip_context.v6_option->context_length,
			            ip_context.v6_option->option_length);
			ip_context.v6_option->length = c_base_header.ip_opt_static->length;
			base_header.ipv6_opt->length = ip_context.v6_option->length;
			size = sizeof(ip_hop_opt_static_t);
			break;
		case IPPROTO_ROUTING:  // IPv6 routing header
			size = ( c_base_header.ip_opt_static->length + 1 ) << 3;
			ip_context.v6_option->context_length = 2 + size;
			ip_context.v6_option->option_length = size;
			memcpy(&ip_context.v6_option->length,&c_base_header.ip_rout_opt_static->length,size - 1);
			memcpy(&base_header.ipv6_opt->length,&ip_context.v6_option->length,size - 1);
			break;
		case IPPROTO_GRE:
			ip_context.v6_option->context_length = sizeof(ipv6_gre_option_context_t);
			size = c_base_header.ip_gre_opt_static->c_flag +
			       c_base_header.ip_gre_opt_static->k_flag +
			       c_base_header.ip_gre_opt_static->s_flag + 1;
			ip_context.v6_option->option_length = size << 3;
			if( ( ip_context.v6_gre_option->protocol ==
			      c_base_header.ip_gre_opt_static->protocol ) == 0)
			{
				base_header.ip_gre_opt->protocol = htons(0x0800);
			}
			else
			{
				base_header.ip_gre_opt->protocol = htons(0x86DD);
			}
			ip_context.v6_gre_option->c_flag = c_base_header.ip_gre_opt_static->c_flag;
			base_header.ip_gre_opt->c_flag = ip_context.v6_gre_option->c_flag;
			ip_context.v6_gre_option->s_flag = c_base_header.ip_gre_opt_static->s_flag;
			base_header.ip_gre_opt->s_flag = ip_context.v6_gre_option->s_flag;
			if( ( ip_context.v6_gre_option->k_flag = c_base_header.ip_gre_opt_static->k_flag ) != 0)
			{
				base_header.ip_gre_opt->k_flag = 1;
				ip_context.v6_gre_option->key = c_base_header.ip_gre_opt_static->key;
				base_header.ip_gre_opt->datas[ip_context.v6_gre_option->c_flag] =
				   ip_context.v6_gre_option->key;
				size = sizeof(ip_gre_opt_static_t);
				break;
			}
			base_header.ip_gre_opt->k_flag = 0;
			size = sizeof(ip_gre_opt_static_t) - sizeof(u_int32_t);
			break;
		case IPPROTO_DSTOPTS:  // IPv6 destination options
			ip_context.v6_option->option_length = ( c_base_header.ip_opt_static->length + 1 ) << 3;
			ip_context.v6_option->context_length = 2 + ip_context.v6_option->option_length;
			rohc_debugf(3, "IP v6 option Destination length %d context_length %d option_length %d\n",
			            c_base_header.ip_opt_static->length,ip_context.v6_option->context_length,
			            ip_context.v6_option->option_length);
			ip_context.v6_option->length = c_base_header.ip_dest_opt_static->length;
			base_header.ipv6_opt->length = ip_context.v6_option->length;
			size = sizeof(ip_dest_opt_static_t);
			break;
		case IPPROTO_MIME:
			ip_context.v6_option->context_length = sizeof(ipv6_mime_option_context_t);
			ip_context.v6_option->option_length = ( 2 + c_base_header.ip_mime_opt_static->s_bit ) << 3;
			ip_context.v6_mime_option->s_bit = c_base_header.ip_mime_opt_static->s_bit;
			base_header.ip_mime_opt->s_bit = ip_context.v6_mime_option->s_bit;
			ip_context.v6_mime_option->res_bits = c_base_header.ip_mime_opt_static->res_bits;
			base_header.ip_mime_opt->res_bits = ip_context.v6_mime_option->res_bits;
			ip_context.v6_mime_option->orig_dest = c_base_header.ip_mime_opt_static->orig_dest;
			base_header.ip_mime_opt->orig_dest = ip_context.v6_mime_option->orig_dest;
			if(ip_context.v6_mime_option->s_bit != 0)
			{
				ip_context.v6_mime_option->orig_src = c_base_header.ip_mime_opt_static->orig_src;
				base_header.ip_mime_opt->orig_src = ip_context.v6_mime_option->orig_src;
				size = sizeof(ip_mime_opt_static_t);
				break;
			}
			size = sizeof(ip_mime_opt_static_t) - sizeof(u_int32_t);
			break;
		case IPPROTO_AH:
			ip_context.v6_option->context_length = sizeof(ipv6_ah_option_context_t);
			ip_context.v6_option->option_length = sizeof(ip_ah_opt_t) - sizeof(u_int32_t) +
			                                      ( c_base_header.ip_ah_opt_static->length <<
			                                        4 ) - sizeof(int32_t);
			ip_context.v6_ah_option->length = c_base_header.ip_ah_opt_static->length;
			base_header.ipv6_opt->length = ip_context.v6_ah_option->length;
			ip_context.v6_ah_option->spi = c_base_header.ip_ah_opt_static->spi;
			base_header.ip_ah_opt->spi = ip_context.v6_ah_option->spi;
			size = sizeof(ip_ah_opt_static_t);
			break;
		default:
			size = 0;
			break;
	}

	#if ROHC_TCP_DEBUG
	rohc_debugf(3, "IP v6 option static part length %d\n",size);
	TraceData(c_base_header.uint8,size);
	#endif

	return size;
}


/**
 * @brief Copy the static IP part to the IPv6 option header
 *
 * @param protocol       The IPv6 protocol option
 * @param ip_context     The specific IP decompression context
 * @param base_header    The IP header
 * @return               The size of the static part
 */
static unsigned int tcp_copy_static_ipv6_option(u_int8_t protocol,
                                                ip_context_ptr_t ip_context,
                                                base_header_ip_t base_header)
{
	int size;

	rohc_debugf(3, "protocol %d ip_context %p base_header %p\n",protocol,ip_context.uint8,
	            base_header.ipvx);

	base_header.ipv6_opt->next_header = ip_context.v6_option->next_header;

	switch(protocol)
	{
		case IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
			//             base_header.ipv6_opt->length = ip_context.v6_option->length;
			size = ( ip_context.v6_option->length + 1 ) << 3;
			memcpy(&base_header.ipv6_opt->length,&ip_context.v6_option->length,size - 1);
			break;
		case IPPROTO_ROUTING:  // IPv6 routing header
			size = (ip_context.v6_option->length + 1) << 3;
			memcpy(&base_header.ipv6_opt->length,&ip_context.v6_option->length,size - 1);
			break;
		case IPPROTO_GRE:
			base_header.ip_gre_opt->r_flag = 0;
						 #if __BYTE_ORDER == __LITTLE_ENDIAN
			base_header.ip_gre_opt->reserved1 = 0;
			base_header.ip_gre_opt->reserved2 = 0;
						 #elif __BYTE_ORDER == __BIG_ENDIAN
			base_header.ip_gre_opt->reserved0 = 0;
						 #endif
			base_header.ip_gre_opt->version = 0;
			if(ip_context.v6_gre_option->protocol == 0)
			{
				base_header.ip_gre_opt->protocol = htons(0x0800);
			}
			else
			{
				base_header.ip_gre_opt->protocol = htons(0x86DD);
			}
			base_header.ip_gre_opt->c_flag = ip_context.v6_gre_option->c_flag;
			base_header.ip_gre_opt->s_flag = ip_context.v6_gre_option->s_flag;
			if( ( base_header.ip_gre_opt->k_flag = ip_context.v6_gre_option->k_flag ) != 0)
			{
				base_header.ip_gre_opt->datas[ip_context.v6_gre_option->c_flag] =
				   ip_context.v6_gre_option->key;
			}
			size = sizeof(ip_gre_opt_t) - sizeof(u_int32_t) +
			       ( ( ip_context.v6_gre_option->c_flag + ip_context.v6_gre_option->k_flag +
			           ip_context.v6_gre_option->s_flag ) * sizeof(u_int32_t) );
			break;
		case IPPROTO_DSTOPTS:  // IPv6 destination options
			//     base_header.ipv6_opt->length = ip_context.v6_option->length;
			size = ( ip_context.v6_option->length + 1 ) << 3;
			memcpy(&base_header.ipv6_opt->length,&ip_context.v6_option->length,size - 1);
			break;
		case IPPROTO_MIME:

			base_header.ip_mime_opt->s_bit = ip_context.v6_mime_option->s_bit;
			base_header.ip_mime_opt->res_bits = ip_context.v6_mime_option->res_bits;
			base_header.ip_mime_opt->orig_dest = ip_context.v6_mime_option->orig_dest;
			if(ip_context.v6_mime_option->s_bit != 0)
			{
				base_header.ip_mime_opt->orig_src = ip_context.v6_mime_option->orig_src;
				size = sizeof(ip_mime_opt_t);
				break;
			}
			size = sizeof(ip_mime_opt_t) - sizeof(u_int32_t);
			break;
		case IPPROTO_AH:
			base_header.ip_ah_opt->length = ip_context.v6_ah_option->length;
			base_header.ip_ah_opt->res_bits = 0;
			base_header.ip_ah_opt->spi = ip_context.v6_ah_option->spi;
			size = sizeof(ip_ah_opt_t) + ( ip_context.v6_ah_option->length << 4 );
			break;
		default:
			size = 0;
			break;
	}

	return size;
}


/**
 * @brief Decode the dynamic IP v6 option header of the rohc packet.
 *
 * @param tcp_context    The specific TCP decompression context
 * @param ip_context     The specific IP decompression context
 * @param protocol       The IPv6 protocol option
 * @param c_base_header  The compressed IP header of the rohc packet
 * @param length         The remain length of the rohc packet
 * @param base_header    The decoded IP packet
 * @return               The length of dynamic IP header
 *                       0 if an error occurs
 */
static int tcp_decode_dynamic_ipv6_option(struct d_tcp_context *tcp_context,
                                          ip_context_ptr_t ip_context,
                                          u_int8_t protocol,
                                          multi_ptr_t c_base_header,
                                          unsigned int length,
                                          base_header_ip_t base_header)
{
	int size;

	rohc_debugf(
	   3, "tcp_context %p ip_context %p protocol %d c_base_header %p length %d base_header %p\n",
	   tcp_context,ip_context.uint8,protocol,c_base_header.uint8,length,base_header.uint8);

	switch(protocol)
	{
		case IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
		case IPPROTO_DSTOPTS:  // IPv6 destination options
			size = ( (ip_context.v6_option->length + 1) << 3 ) - 2;
			memcpy(ip_context.v6_option->value,c_base_header.uint8,size);
			memcpy(base_header.ipv6_opt->value,ip_context.v6_option->value,size);
			break;
		case IPPROTO_ROUTING:  // IPv6 routing header
			size = 0;
			break;
		case IPPROTO_GRE:
			size = 0;
			if(ip_context.v6_gre_option->c_flag != 0)
			{
				base_header.ip_gre_opt->datas[0] = READ32_FROM_MPTR(c_base_header);
				size += sizeof(u_int32_t);
			}
			if(ip_context.v6_gre_option->s_flag != 0)
			{
				base_header.ip_gre_opt->datas[ip_context.v6_gre_option->c_flag] = READ32_FROM_MPTR(
				   c_base_header);
				size += sizeof(u_int32_t);
			}
								#if ROHC_TCP_DEBUG
			c_base_header.uint8 -= size;
								#endif
			break;
		case IPPROTO_MIME:
			size = 0;
			break;
		case IPPROTO_AH:
			ip_context.v6_ah_option->sequence_number =
			   c_base_header.ip_ah_opt_dynamic->sequence_number;
			size = (ip_context.v6_ah_option->length - 1) << 2;
			memcpy(ip_context.v6_ah_option->auth_data,c_base_header.ip_ah_opt_dynamic->auth_data,size);
			size += sizeof(u_int32_t);
			break;
		default:
			size = 0;
			break;
	}

	#if ROHC_TCP_DEBUG
	rohc_debugf(3, "IP v6 option %d dynamic part length %d\n",protocol,size);
	TraceData(c_base_header.uint8,size);
	#endif

	return size;
}


#if 0 /* not used at the moment */
/**
 * @brief Decode the irregular IP v6 option header of the rohc packet.
 *
 * @param tcp_context    The specific TCP decompression context
 * @param ip_context     The specific IP decompression context
 * @param protocol       The IP v6 protocol option
 * @param mptr           The compressed IP header of the rohc packet
 * @param base_header    The decoded IP packet
 * @return               The length of dynamic IP header
 *                       0 if an error occurs
 */
static u_int8_t * tcp_decode_irregular_ipv6_option(struct d_tcp_context *tcp_context,
                                                   ip_context_ptr_t ip_context,
                                                   u_int8_t protocol,
                                                   multi_ptr_t mptr,
                                                   base_header_ip_t base_header)
{
	#if ROHC_TCP_DEBUG
	u_int8_t *ptr = mptr.uint8;
	#endif
	u_int32_t sequence_number;
	int size;

	rohc_debugf(3, "tcp_context %p ip_context %p protocol %d mptr %p base_header %p\n",tcp_context,
	            ip_context.uint8,protocol,mptr.uint8,
	            base_header.uint8);

	switch(protocol)
	{
		case IPPROTO_GRE:
			if(ip_context.v6_gre_option->c_flag != 0)
			{
				base_header.ip_gre_opt->datas[0] = READ32_FROM_MPTR(mptr);
			}
			if(ip_context.v6_gre_option->s_flag != 0)
			{
				if( ( *mptr.uint8 & 0x80 ) == 0)
				{
					// discriminator =:= '0'
					sequence_number =
					   ( ip_context.v6_gre_option->sequence_number & 0xFFFFFF80 ) | *(mptr.uint8++);
				}
				else
				{
					// discriminator =:= '1'
					sequence_number = ( ip_context.v6_gre_option->sequence_number & 0x80000000 ) | ntohl(
					   READ32_FROM_MPTR(mptr));
				}
				base_header.ip_gre_opt->datas[ip_context.v6_gre_option->c_flag] = htonl(sequence_number);
				ip_context.v6_gre_option->sequence_number = sequence_number;
			}
			break;
		case IPPROTO_AH:
			// sequence_number =:= lsb_7_or_31
			if( ( *mptr.uint8 & 0x80 ) == 0)
			{
				// discriminator =:= '0'
				sequence_number =
				   ( ip_context.v6_ah_option->sequence_number & 0xFFFFFF80 ) | *(mptr.uint8++);
			}
			else
			{
				// discriminator =:= '1'
				sequence_number = ( ip_context.v6_ah_option->sequence_number & 0x80000000 ) | ntohl(
				   READ32_FROM_MPTR(mptr));
			}
			ip_context.v6_ah_option->sequence_number = sequence_number;
			base_header.ip_ah_opt->sequence_number = htonl(sequence_number);
			size = (ip_context.v6_ah_option->length - 1) << 2;
			memcpy(ip_context.v6_ah_option->auth_data,mptr.uint8,size);
			mptr.uint8 += size;
			break;
		default:
			break;
	}

	#if ROHC_TCP_DEBUG
	rohc_debugf(3, "IP v6 option irregular part length %d\n",(int)(mptr.uint8 - ptr));
	TraceData(ptr,mptr.uint8 - ptr);
	#endif

	return mptr.uint8;
}
#endif


/**
 * @brief Decode the static IP header of the rohc packet.
 *
 * @param tcp_context    The specific TCP decompression context
 * @param ip_context     The specific IP decompression context
 * @param c_base_header  The compressed IP header of the rohc packet
 * @param length         The remain length of the rohc packet
 * @param dest           The decoded IP packet
 * @return               The length of static IP header
 *                       0 if an error occurs
 */
static int tcp_decode_static_ip(struct d_tcp_context *tcp_context,
                                ip_context_ptr_t ip_context,
                                multi_ptr_t c_base_header,
                                unsigned int length,
                                unsigned char *dest)
{
	base_header_ip_t base_header;   // Destination
	int size;

	rohc_debugf(3, "tcp_context %p ip_context %p base_header %p length %d dest %p\n",tcp_context,
	            ip_context.uint8,c_base_header.uint8,length,
	            dest);

	base_header.uint8 = dest;

	if(c_base_header.ipv4_static->version_flag == 0)
	{
		base_header.ipv4->version = IPV4;
		base_header.ipv4->header_length = sizeof(base_header_ip_v4_t) >> 2;
		base_header.ipv4->protocol = c_base_header.ipv4_static->protocol;
		base_header.ipv4->src_addr = c_base_header.ipv4_static->src_addr;
		base_header.ipv4->dest_addr = c_base_header.ipv4_static->dst_addr;

		ip_context.v4->version = IPV4;
		ip_context.v4->context_length = sizeof(ipv4_context_t);
		ip_context.v4->protocol = c_base_header.ipv4_static->protocol;
		ip_context.v4->src_addr = c_base_header.ipv4_static->src_addr;
		ip_context.v4->dst_addr = c_base_header.ipv4_static->dst_addr;
		size = sizeof(ipv4_static_t);
	}
	else
	{
		base_header.ipv6->version = IPV6;
		ip_context.v6->version = IPV6;
		ip_context.v6->context_length = sizeof(ipv6_context_t);
		if(c_base_header.ipv6_static1->flow_label_enc_discriminator == 0)
		{
			base_header.ipv6->flow_label1 = 0;
			base_header.ipv6->flow_label2 = 0;
			base_header.ipv6->next_header = c_base_header.ipv6_static1->next_header;
			memcpy(base_header.ipv6->src_addr,c_base_header.ipv6_static1->src_addr,
			       sizeof(u_int32_t) * 4 * 2);

			ip_context.v6->flow_label1 = 0;
			ip_context.v6->flow_label2 = 0;
			ip_context.v6->next_header = c_base_header.ipv6_static1->next_header;
			memcpy(ip_context.v6->src_addr,c_base_header.ipv6_static1->src_addr,
			       sizeof(u_int32_t) * 4 * 2);
			size = sizeof(ipv6_static1_t);
		}
		else
		{
			base_header.ipv6->flow_label1 = c_base_header.ipv6_static2->flow_label1;
			base_header.ipv6->flow_label2 = c_base_header.ipv6_static2->flow_label2;
			base_header.ipv6->next_header = c_base_header.ipv6_static2->next_header;
			memcpy(base_header.ipv6->src_addr,c_base_header.ipv6_static2->src_addr,
			       sizeof(u_int32_t) * 4 * 2);

			ip_context.v6->flow_label1 = c_base_header.ipv6_static2->flow_label1;
			ip_context.v6->flow_label2 = c_base_header.ipv6_static2->flow_label2;
			ip_context.v6->next_header = c_base_header.ipv6_static2->next_header;
			memcpy(ip_context.v6->src_addr,c_base_header.ipv6_static2->src_addr,
			       sizeof(u_int32_t) * 4 * 2);
			size = sizeof(ipv6_static2_t);
		}
	}
	rohc_debugf(3, "IP v%d static part length %d\n",c_base_header.ipv4_static->version_flag ==
	            0 ? 4 : 6,
	            size);
	TraceData(c_base_header.uint8,size);

	return size;
}


/**
 * @brief Copy the static IP part to the IP header
 *
 * @param ip_context    The specific IP decompression context
 * @param base_header   The IP header
 * @return              The size of the static part
 */
static unsigned int tcp_copy_static_ip(ip_context_ptr_t ip_context,
                                       base_header_ip_t base_header)
{
	rohc_debugf(3, "ip_context %p base_header %p\n",ip_context.uint8,base_header.ipvx);

	if(ip_context.vx->version == IPV4)
	{
		base_header.ipv4->version = IPV4;
		base_header.ipv4->header_length = sizeof(base_header_ip_v4_t) >> 2;
		base_header.ipv4->protocol = ip_context.v4->protocol;
		base_header.ipv4->src_addr = ip_context.v4->src_addr;
		base_header.ipv4->dest_addr = ip_context.v4->dst_addr;
		return sizeof(base_header_ip_v4_t);
	}
	else
	{
		base_header.ipv6->version = IPV6;
		base_header.ipv6->flow_label1 = ip_context.v6->flow_label1;
		base_header.ipv6->flow_label2 = ip_context.v6->flow_label2;
		base_header.ipv6->next_header = ip_context.v6->next_header;
		memcpy(base_header.ipv6->src_addr,ip_context.v6->src_addr,sizeof(u_int32_t) * 4 * 2);
		return sizeof(base_header_ip_v6_t);
	}
}


/**
 * @brief Decode the dynamic IP header of the rohc packet.
 *
 * @param tcp_context    The specific TCP decompression context
 * @param ip_context     The specific IP decompression context
 * @param c_base_header  The dynamic compressed IP header of the rohc packet
 * @param length         The remain length of the rohc packet
 * @param dest           The decoded IP packet
 * @return               The length of dynamic IP header
 *                       0 if an error occurs
 */
static int tcp_decode_dynamic_ip(struct d_tcp_context *tcp_context,
                                 ip_context_ptr_t ip_context,
                                 multi_ptr_t c_base_header,
                                 unsigned int length,
                                 unsigned char *dest)
{
	base_header_ip_t base_header;   // Destination
	int size;

	rohc_debugf(3, "tcp_context %p ip_context %p base_header %p length %d dest %p\n",tcp_context,
	            ip_context.uint8,c_base_header.uint8,length,
	            dest);

	base_header.uint8 = dest;

	if(ip_context.vx->version == IPV4)
	{
		base_header.ipv4->rf = 0;
		base_header.ipv4->df = c_base_header.ipv4_dynamic1->df;
		base_header.ipv4->mf = 0;
		base_header.ipv4->dscp = c_base_header.ipv4_dynamic1->dscp;
		base_header.ipv4->ip_ecn_flags = c_base_header.ipv4_dynamic1->ip_ecn_flags;
		base_header.ipv4->ttl_hopl = c_base_header.ipv4_dynamic1->ttl_hopl;
		rohc_debugf(3, "dscp %Xh ip_ecn_flags %d\n",base_header.ipv4->dscp,
		            base_header.ipv4->ip_ecn_flags);
		#if __BYTE_ORDER == __LITTLE_ENDIAN
		base_header.ipv4->frag_offset1 = 0;
		base_header.ipv4->frag_offset2 = 0;
		#elif __BYTE_ORDER == __BIG_ENDIAN
		base_header.ipv4->frag_offset = 0;
		#endif

		ip_context.v4->df = c_base_header.ipv4_dynamic1->df;
		ip_context.v4->ip_id_behavior = c_base_header.ipv4_dynamic1->ip_id_behavior;
		rohc_debugf(3, "ip_id_behavior %d\n",ip_context.v4->ip_id_behavior);
		ip_context.v4->dscp = c_base_header.ipv4_dynamic1->dscp;
		ip_context.v4->ip_ecn_flags = c_base_header.ipv4_dynamic1->ip_ecn_flags;
		ip_context.v4->ttl_hopl = c_base_header.ipv4_dynamic1->ttl_hopl;
		rohc_debugf(3, "dscp %Xh ip_ecn_flags %d ttl_hopl %Xh\n",ip_context.v4->dscp,
		            ip_context.v4->ip_ecn_flags,
		            ip_context.v4->ttl_hopl);
		// cf RFC4996 page 60/61 ip_id_enc_dyn()
		if(c_base_header.ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
		{
			base_header.ipv4->ip_id = 0;
			ip_context.v4->last_ip_id.uint16 = 0;
			rohc_debugf(3, "new last IP-ID %4.4Xh\n",ip_context.v4->last_ip_id.uint16);
			size = sizeof(ipv4_dynamic1_t);
		}
		else
		{
			if(c_base_header.ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
			{
				base_header.ipv4->ip_id = swab16(c_base_header.ipv4_dynamic2->ip_id);
			}
			else
			{
				base_header.ipv4->ip_id = c_base_header.ipv4_dynamic2->ip_id;
			}
			ip_context.v4->last_ip_id.uint16 = ntohs(base_header.ipv4->ip_id);
			rohc_debugf(3, "new last IP-ID %4.4Xh\n",ip_context.v4->last_ip_id.uint16);
			size = sizeof(ipv4_dynamic2_t);
		}
		rohc_debugf(3, "IP-ID %4.4Xh\n",ntohs(base_header.ipv4->ip_id));
	}
	else
	{
		#if __BYTE_ORDER == __LITTLE_ENDIAN
		base_header.ipv6->dscp1 = c_base_header.ipv6_dynamic->dscp >> 2;
		base_header.ipv6->dscp2 = c_base_header.ipv6_dynamic->dscp & 0x03;
		#elif __BYTE_ORDER == __BIG_ENDIAN
		base_header.ipv6->dscp = c_base_header.ipv6_dynamic->dscp;
		#endif
		base_header.ipv6->ip_ecn_flags = c_base_header.ipv6_dynamic->ip_ecn_flags;
		base_header.ipv6->ttl_hopl = c_base_header.ipv6_dynamic->ttl_hopl;

		ip_context.v6->dscp = c_base_header.ipv6_dynamic->dscp;
		ip_context.v6->ip_ecn_flags = c_base_header.ipv6_dynamic->ip_ecn_flags;
		ip_context.v6->ttl_hopl = c_base_header.ipv6_dynamic->ttl_hopl;
		size = sizeof(ipv6_dynamic_t);
	}

	rohc_debugf(3, "IP v%d dynamic part length %d\n",ip_context.vx->version,size);
	TraceData(c_base_header.uint8,size);

	return size;
}


/**
 * @brief Decode the irregular IP header of the rohc packet.
 *
 * @param tcp_context               The specific TCP decompression context
 * @param ip_context                The specific IP decompression context
 * @param base_header               The IP header under built
 * @param mptr                      The irregular compressed IP header of the rohc packet
 * @param is_innermost              True if the IP header is the innermost of the packet
 * @param ttl_irregular_chain_flag  True if one of the TTL value of header change
 * @param ip_inner_ecn              The ECN flags of inner IP header
 * @return                          The current point of the remain rohc_datas
 */
static u_int8_t * tcp_decode_irregular_ip(struct d_tcp_context *tcp_context,
                                          ip_context_ptr_t ip_context,
                                          base_header_ip_t base_header,
                                          multi_ptr_t mptr,
                                          int is_innermost,
                                          int ttl_irregular_chain_flag,
                                          int ip_inner_ecn)
{
	#if ROHC_TCP_DEBUG
	u_int8_t *ptr = mptr.uint8;
	#endif

	rohc_debugf(3, "tcp_context %p ip_context %p base_header %p mptr %p\n",tcp_context,
	            ip_context.uint8,base_header.uint8,
	            mptr.uint8);
	rohc_debugf(3, "is_innermost %d ttl_irregular_chain_flag %d ip_inner_ecn %d\n",is_innermost,
	            ttl_irregular_chain_flag,
	            ip_inner_ecn);

	if(ip_context.vx->version == IPV4)
	{
		// ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE )
		if(ip_context.v4->ip_id_behavior == IP_ID_BEHAVIOR_RANDOM)
		{
			base_header.ipv4->ip_id = READ16_FROM_MPTR(mptr);
			rohc_debugf(3, "Read ip_id %4.4Xh (ip_id_behavior %d)\n",base_header.ipv4->ip_id,
			            ip_context.v4->ip_id_behavior);
			ip_context.v4->last_ip_id.uint16 = ntohs(base_header.ipv4->ip_id);
			rohc_debugf(3, "new last IP-ID %4.4Xh\n",ip_context.v4->last_ip_id.uint16);
		}
		if(is_innermost == 0)
		{
			// ipv4_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(tcp_context->ecn_used != 0)
			{
				base_header.ipv4->dscp = *mptr.uint8 >> 2;
				base_header.ipv4->ip_ecn_flags = *(mptr.uint8++) & 0x03;
				rohc_debugf(3, "Read dscp %Xh ip_ecn_flags %d\n",base_header.ipv4->dscp,
				            base_header.ipv4->ip_ecn_flags);
			}
			if(ttl_irregular_chain_flag == 1)
			{
				// ipv4_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				base_header.ipv4->ttl_hopl = *(mptr.uint8++);
				rohc_debugf(3, "Read ttl_hopl %Xh\n",base_header.ipv4->ttl_hopl);
			}
			#if ROHC_TCP_DEBUG
			else
			{
				// ipv4_outer_without_ttl_irregular
				// assert( ttl_irregular_chain_flag == 0 );
			}
			#endif
		}
		else
		{
			// ipv4_innermost_irregular
			// assert( ip_inner_ecn == base_header.ipv4->ip_ecn_flags );
			base_header.ipv4->ip_ecn_flags = ip_inner_ecn; // A REVOIR ???
		}
	}
	else
	{
		// IPv6
		if(is_innermost == 0)
		{
			// ipv6_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(tcp_context->ecn_used != 0)
			{
				#if __BYTE_ORDER == __LITTLE_ENDIAN
				base_header.ipv6->dscp1 = *mptr.uint8 >> 4;
				base_header.ipv6->dscp2 = ( *mptr.uint8 >> 2 ) & 0x03;
				#else
				base_header.ipv6->dscp = *mptr.uint8 >> 2;
				#endif
				base_header.ipv4->ip_ecn_flags = *(mptr.uint8++) & 0x03;
			}
			if(ttl_irregular_chain_flag == 1)
			{
				rohc_debugf(3, "irregular ttl_hopl %Xh != %Xh\n",base_header.ipv6->ttl_hopl,
				            ip_context.vx->ttl_hopl);
				// ipv6_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				base_header.ipv6->ttl_hopl = *(mptr.uint8++);
				rohc_debugf(3, "Read ttl_hopl %Xh\n",base_header.ipv6->ttl_hopl);
			}
			#if ROHC_TCP_DEBUG
			else
			{
				// ipv6_outer_without_ttl_irregular
				// assert( ttl_irregular_chain_flag == 0 );
			}
			#endif
		}
		#if ROHC_TCP_DEBUG
		else
		{
			// ipv6_innermost_irregular
			// assert( ip_inner_ecn == base_header.ipv6->ip_ecn_flags );
		}
		#endif
	}

	#if ROHC_TCP_DEBUG
	rohc_debugf(3, "IP v%d irregular part length %d\n",ip_context.vx->version,(int)(mptr.uint8 - ptr));
	TraceData(ptr,mptr.uint8 - ptr);
	#endif

	return mptr.uint8;
}


/**
 * @brief Decode the TCP static part of the ROHC packet.
 *
 * @param tcp_context The TCP specific decompression context
 * @param tcp_static  The TCP static part to decode
 * @param length      The length of the ROHC packet
 * @param tcp         The decoded TCP header
 * @return            The number of bytes read in the ROHC packet,
 *                    -1 in case of failure
 */
static int tcp_decode_static_tcp(struct d_tcp_context *tcp_context,
                                 tcp_static_t *tcp_static,
                                 unsigned int length,
                                 tcphdr_t *tcp)
{
	rohc_debugf(3, "tcp_context %p tcp_context %p tcp_static %p length %d dest %p\n",tcp_context,
	            tcp_context,tcp_static,length,
	            tcp);

	rohc_debugf(3, "TCP tcp_static %p length %d\n",tcp_static,length);
	TraceData((unsigned char*)tcp_static,length);

	/* check the minimal length to decode the TCP static part */
	if(length < 4)
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}
	tcp_context->tcp_src_port =
	   tcp->src_port = tcp_static->src_port;
	tcp_context->tcp_dst_port =
	   tcp->dst_port = tcp_static->dst_port;
	rohc_debugf(3, "TCP source port %d dest port %d\n", ntohs(tcp->src_port), ntohs(tcp->dst_port));

	rohc_debugf(3, "TCP return read %d\n",(int)sizeof(tcp_static_t));

	/* number of bytes read from the packet */
	return sizeof(tcp_static_t);

error:
	return -1;
}


/**
 * @brief Copy the TCP static part of the TCP header.
 *
 * @param tcp_context  The specific TCP decompression context
 * @param tcp          The decoded TCP header
 * @return             The number of bytes copied to the TCP header
 */
static unsigned int tcp_copy_static_tcp(struct d_tcp_context *tcp_context,
                                        tcphdr_t *tcp)
{
	rohc_debugf(3, "tcp_context %p tcp %p\n",tcp_context,tcp);

	tcp->src_port = tcp_context->tcp_src_port;
	tcp->dst_port = tcp_context->tcp_dst_port;

	rohc_debugf(3, "src_port %d (%Xh) dst_port %d (%Xh)\n",ntohs(tcp->src_port),ntohs(
	               tcp->src_port),ntohs(tcp->dst_port),ntohs(tcp->dst_port));

	return sizeof(tcphdr_t);
}


/**
 * @brief Decode the TCP dynamic part of the ROHC packet.
 *
 * @param context      The generic decompression context
 * @param tcp_dynamic  The TCP dynamic part to decode
 * @param length       The length of the ROHC packet
 * @param tcp          The decoded TCP header
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int tcp_decode_dynamic_tcp(struct d_generic_context *context,
                                  tcp_dynamic_t *tcp_dynamic,
                                  unsigned int length,
                                  tcphdr_t *tcp)
{
	struct d_tcp_context *tcp_context;
	multi_ptr_t mptr;
	int read = 0; /* number of bytes read from the packet */

	tcp_context = context->specific;

	rohc_debugf(3, "context %p tcp_context %p tcp_dynamic %p length %d dest %p\n",
	            context,tcp_context,tcp_dynamic,length,tcp);

	rohc_debugf(3, "TCP dynamic part at %p length %d\n",tcp_dynamic,length);
	TraceData((unsigned char*)tcp_dynamic,length);

	/* check the minimal length to decode the TCP dynamic part */
	if(length < sizeof(tcp_dynamic_t) )
	{
		rohc_debugf(0, "ROHC packet too small (len = %d)\n", length);
		goto error;
	}

	mptr.tcp_dynamic = tcp_dynamic + 1;
	rohc_debugf(3, "TCP tcp_dynamic %p mptr.tcp_dynamic+1 %p\n",tcp_dynamic,mptr.tcp_dynamic);

	rohc_debugf(3, "TCP res_flags %d ecn_flags %d rsf_flags %d %s%s%s\n",
	            tcp_dynamic->tcp_res_flags, tcp_dynamic->tcp_ecn_flags, tcp_dynamic->rsf_flags,
	            tcp_dynamic->urg_flag == 1 ? "URG " : "",
	            tcp_dynamic->ack_flag == 1 ? "ACK " : "",
	            tcp_dynamic->psh_flag == 1 ? "PSH" : "" );

	/* retrieve the TCP sequence number from the ROHC packet */
	tcp_context->ecn_used = tcp_dynamic->ecn_used;
	tcp->tcp_res_flags = tcp_dynamic->tcp_res_flags;
	tcp->tcp_ecn_flags = tcp_dynamic->tcp_ecn_flags;
	tcp->urg_flag = tcp_dynamic->urg_flag;
	tcp->ack_flag = tcp_dynamic->ack_flag;
	tcp->psh_flag = tcp_dynamic->psh_flag;
	tcp->rsf_flags = tcp_dynamic->rsf_flags;
	tcp_context->msn = ntohs(tcp_dynamic->msn);
	rohc_debugf(3, "msn %4.4Xh\n", tcp_context->msn);
	tcp->seq_number = tcp_dynamic->seq_number;

	if(tcp_dynamic->ack_zero == 1)
	{
		tcp->ack_number = 0;
	}
	else
	{
		tcp->ack_number = READ32_FROM_MPTR(mptr);
	}

	rohc_debugf(3, "tcp %p seq_number %Xh ack_number %Xh\n",tcp,ntohl(tcp->seq_number),
	            ntohl(tcp->ack_number));

	tcp->window = READ16_FROM_MPTR(mptr);
	tcp->checksum = READ16_FROM_MPTR(mptr);

	rohc_debugf(3, "TCP window %4.4Xh checksum %4.4Xh\n", ntohs(tcp->window), ntohs(tcp->checksum) );

	if(tcp_dynamic->urp_zero == 1)
	{
		tcp->urg_ptr = 0;
	}
	else
	{
		tcp->urg_ptr = READ16_FROM_MPTR(mptr);
	}
	if(tcp_dynamic->ack_stride_flag == 1)
	{
		tcp_context->ack_stride = 0;
	}
	else
	{
		tcp_context->ack_stride = ntohs( READ16_FROM_MPTR(mptr) );
	}
	if(tcp_context->ack_stride != 0)
	{
		// Calculate the Ack Number residue
		tcp_context->ack_number_residue = ntohl(tcp->ack_number) % tcp_context->ack_stride;
	}
	rohc_debugf(3, "TCP urg_ptr %4.4Xh ack_stride %4.4Xh ack_number_residue %4.4Xh\n",
	            ntohs(tcp->urg_ptr), tcp_context->ack_stride, tcp_context->ack_number_residue );

	read = mptr.uint8 - ( (unsigned char *) tcp_dynamic );

	rohc_debugf(3, "TCP length read %d initial length %d rest %d\n",read,length,(int)(length - read));

	/* If TCP option list compression present */
	if( ( (*mptr.uint8) & 0x0F ) != 0)
	{
		u_int8_t *pBeginOptions;
		u_int8_t *pBeginList;
		u_int8_t PS;
		u_int8_t present;
		u_int8_t index;
		u_int8_t m;
		u_int8_t i;
		int size;

		pBeginList = mptr.uint8;
		/* read number of XI item(s) in the compressed list */
		m = *pBeginList & 0x0F;
		PS = *pBeginList & 0x10;
		++pBeginList;
		/* calculate begin of the item(s) list */
		if(PS != 0)
		{
			mptr.uint8 += 1 + m;
		}
		else
		{
			mptr.uint8 += 1 + ( ( m + 1 ) >> 1 );
		}
		/* save the begin of the item(s) */
		pBeginOptions = mptr.uint8;
		/* update length of datas, WITHOUT TCP options length */
		/* because TCP options will be in payload */
		read = pBeginOptions - ( (unsigned char *) tcp_dynamic );
		/* for all item(s) in the list */
		for(i = 0, size = 0; i < m; ++i)
		{
			/* if PS=1 indicating 8-bit XI field */
			if(PS != 0)
			{
				present = (*pBeginList) & 0x80;
				index = (*pBeginList) & 0x0F;
				++pBeginList;
			}
			else
			{
				/* if odd position */
				if(i & 1)
				{
					present = (*pBeginList) & 0x08;
					index = (*pBeginList) & 0x07;
					++pBeginList;
				}
				else
				{
					present = (*pBeginList) & 0x80;
					index = ( (*pBeginList) & 0x70 ) >> 4;
				}
			}
			// item must present in dynamic part
			assert( present != 0 );
			rohc_debugf(3, "TCP index %d %s\n",index,present != 0 ? "present" : "absent");
			/* if item present in the list */
			if(present != 0)
			{
				// if known index (see RFC4996 page 27)
				if(index <= TCP_INDEX_SACK)
				{

					/* save TCP option for this index */
					tcp_context->tcp_options_list[index] = *mptr.uint8;

					switch(*mptr.uint8)
					{
						case TCP_OPT_EOL:
							rohc_debugf(3, "TCP OPT EOL\n");
							++mptr.uint8;
							++size;
							break;
						case TCP_OPT_NOP:
							rohc_debugf(3, "TCP OPT NOP\n");
							++mptr.uint8;
							++size;
							break;
						case TCP_OPT_MAXSEG:
							memcpy(&tcp_context->tcp_option_maxseg,mptr.uint8 + 2,2);
							rohc_debugf(3, "TCP OPT MAXSEG %d (%Xh)\n",
							            ntohs(tcp_context->tcp_option_maxseg),
							            ntohs(tcp_context->tcp_option_maxseg));
							mptr.uint8 += TCP_OLEN_MAXSEG;
							size += TCP_OLEN_MAXSEG;
							break;
						case TCP_OPT_WINDOW:
							tcp_context->tcp_option_window = *(mptr.uint8 + 2);
							rohc_debugf(3, "TCP OPT WINDOW %d\n",tcp_context->tcp_option_window);
							mptr.uint8 += TCP_OLEN_WINDOW;
							size += TCP_OLEN_WINDOW;
							break;
						case TCP_OPT_SACK_PERMITTED:
							rohc_debugf(3, "TCP OPT SACK PERMITTED\n");
							mptr.uint8 += TCP_OLEN_SACK_PERMITTED;
							size += TCP_OLEN_SACK_PERMITTED;
							break;
						case TCP_OPT_SACK:
							tcp_context->tcp_option_sack_length = *(mptr.uint8 + 1) - 2;
							rohc_debugf(3, "TCP OPT SACK Length %d\n",tcp_context->tcp_option_sack_length);
							assert( tcp_context->tcp_option_sack_length <= (8 * 4) );
							memcpy(tcp_context->tcp_option_sackblocks,mptr.uint8 + 2,
							       tcp_context->tcp_option_sack_length);
							size += *(mptr.uint8 + 1);
							mptr.uint8 += *(mptr.uint8 + 1);
							break;
						case TCP_OPT_TIMESTAMP:
							rohc_debugf(3, "TCP OPT TIMSESTAMP\n");
							memcpy(tcp_context->tcp_option_timestamp,mptr.uint8 + 2,8);
							mptr.uint8 += TCP_OLEN_TIMESTAMP;
							size += TCP_OLEN_TIMESTAMP;
							break;
					}
				}
				else
				{
					u_int8_t *pValue;

					// If index never used before
					if(tcp_context->tcp_options_list[index] == 0xFF)
					{
						/* Save TCP option for this index */
						tcp_context->tcp_options_list[index] = *(mptr.uint8++);
						tcp_context->tcp_options_offset[index] = tcp_context->tcp_options_free_offset;
						pValue = tcp_context->tcp_options_values + tcp_context->tcp_options_free_offset;
						// Save length (without option_static)
						*pValue = ( (*mptr.uint8) & 0x7F ) - 2;
						rohc_debugf(3, "TCP OPT %d Length %d\n",tcp_context->tcp_options_list[index],
						            *pValue);
						// Save value
						memcpy(pValue + 1,mptr.uint8 + 1,*pValue);
						// Update first free offset
						tcp_context->tcp_options_free_offset += 1 + (*pValue);
						assert( tcp_context->tcp_options_free_offset < MAX_TCP_OPT_SIZE );
						mptr.uint8 += 1 + *pValue;
					}
					else
					{
						// Verify the value
						rohc_debugf(3, "tcp_options_list[%d] = %d <=> %d\n",index,
						            tcp_context->tcp_options_list[index],
						            *mptr.uint8);
						assert( tcp_context->tcp_options_list[index] == *mptr.uint8 );
						++mptr.uint8;
						pValue = tcp_context->tcp_options_values + tcp_context->tcp_options_offset[index];
						assert( (*pValue) + 2 == ( (*mptr.uint8) & 0x7F ) );
						assert( memcmp(pValue + 1,mptr.uint8 + 1,*pValue) == 0 );
						mptr.uint8 += 1 + *pValue;
					}
				}
			}
		}
		rohc_debugf(3, "TCP Options length %d size %d\n",(int)(mptr.uint8 - pBeginOptions),size);
		TraceData(pBeginOptions, mptr.uint8 - pBeginOptions );
		/* update tcp header with options */
		memcpy( ( (unsigned char *) tcp ) + sizeof(tcphdr_t), pBeginOptions,
		        mptr.uint8 - pBeginOptions );
		/* update data offset */
		tcp->data_offset = ( sizeof(tcphdr_t) + ( size + 3 ) ) >> 2;
		// read += 1 + ( mptr.uint8 - pBeginList );
	}
	else
	{
		/* update data offset */
		tcp->data_offset = sizeof(tcphdr_t) >> 2;
		rohc_debugf(3, "TCP no options!\n");
		++read;
	}

	rohc_debugf(3, "TCP full dynamic part at %p length %d\n",tcp_dynamic,length);
	TraceData((unsigned char*)tcp_dynamic,read);

	rohc_debugf(3, "TCP return read %d\n",read);

	return read;

error:
	return -1;
}


/**
 * @brief Decode the irregular TCP header of the rohc packet.
 *
 * See RFC4996 page 75
 *
 * @param tcp_context               The specific TCP context
 * @param base_header_inner         The inner IP header under built
 * @param tcp                       The TCP header under built
 * @param rohc_datas                The remain datas of the rohc packet
 * @return                          The current remain datas of the rohc packet
 */

static u_int8_t * tcp_decode_irregular_tcp(struct d_tcp_context *tcp_context,
                                           base_header_ip_t base_header_inner,
                                           tcphdr_t *tcp,
                                           u_int8_t *rohc_datas)
{
	multi_ptr_t mptr;

	rohc_debugf(3, "tcp_context %p base_header_inner %p tcp %p rohc_data %p\n",tcp_context,
	            base_header_inner.uint8,tcp,
	            rohc_datas);

	mptr.uint8 = rohc_datas;

	// ip_ecn_flags = := tcp_irreg_ip_ecn(ip_inner_ecn)
	// tcp_res_flags =:= static_or_irreg(ecn_used.CVALUE,4)
	// tcp_ecn_flags =:= static_or_irreg(ecn_used.CVALUE,2)
	if(tcp_context->ecn_used != 0)
	{
		// See RFC4996 page 71
		if(base_header_inner.ipvx->version == IPV4)
		{
			base_header_inner.ipv4->ip_ecn_flags = *mptr.uint8 >> 6;
			rohc_debugf(3, "Read ip_ecn_flags %d\n",base_header_inner.ipv4->ip_ecn_flags);
		}
		else
		{
			base_header_inner.ipv6->ip_ecn_flags = *mptr.uint8 >> 6;
			rohc_debugf(3, "Read ip_ecn_flags %d\n",base_header_inner.ipv6->ip_ecn_flags);
		}
		tcp->tcp_ecn_flags = ( *mptr.uint8 >> 4 ) & 0x03;
		tcp->tcp_res_flags = *(mptr.uint8)++ & 0x0F;
		rohc_debugf(3, "Read TCP ecn_flags %d res_flags %d\n",tcp->tcp_ecn_flags,tcp->tcp_res_flags);
	}
	else
	{
		// See RFC4996 page 71
		if(base_header_inner.ipvx->version == IPV4)
		{
			base_header_inner.ipv4->ip_ecn_flags = 0;
		}
		else
		{
			base_header_inner.ipv6->ip_ecn_flags = 0;
		}
		tcp->tcp_ecn_flags = 0;
		tcp->tcp_res_flags = 0;
		rohc_debugf(3, "ip_ecn_flag, tcp_ecn_flag and tcp_res_flag = 0\n");
	}

	// checksum =:= irregular(16)
	tcp->checksum = READ16_FROM_MPTR(mptr);
	rohc_debugf(3, "Read TCP checksum %4.4Xh\n",ntohs(tcp->checksum));

	rohc_debugf(3, "TCP irregular part length %d\n",(int)(mptr.uint8 - rohc_datas));
	TraceData(rohc_datas,mptr.uint8 - rohc_datas);

	return mptr.uint8;
}


/**
 * @brief Decompress the LSBs bits of TimeStamp TCP option
 *
 * See RFC4996 page 65
 *
 * @param ptr                 Pointer to the compressed value
 * @param context_timestamp   The context value
 * @param pTimestamp          Pointer to the uncompressed value
 * @return                    Pointer to the next compressed value
 */

static u_int8_t * d_ts_lsb( u_int8_t *ptr, u_int32_t *context_timestamp, u_int32_t *pTimestamp )
{
	u_int32_t last_timestamp;
	u_int32_t timestamp;
	#if ROHC_TCP_DEBUG
	u_int8_t *pBegin = ptr;
	#endif

	last_timestamp = ntohl(*context_timestamp);

	if(*ptr & 0x80)
	{
		if(*ptr & 0x40)
		{
			if(*ptr & 0x20)
			{
				// Discriminator '111'
				timestamp = ( *(ptr++) & 0x1F ) << 24;
				timestamp |= *(ptr++) << 16;
				timestamp |= *(ptr++) << 8;
				timestamp |= *(ptr++);
				timestamp |= last_timestamp & 0xE0000000;
			}
			else
			{
				// Discriminator '110'
				timestamp = ( *(ptr++) & 0x1F ) << 16;
				timestamp |= *(ptr++) << 8;
				timestamp |= *(ptr++);
				timestamp |= last_timestamp & 0xFFE00000;
			}
		}
		else
		{
			// Discriminator '10'
			timestamp = ( *(ptr++) & 0x3F ) << 8;
			timestamp |= *(ptr++);
			timestamp |= last_timestamp & 0xFFFFC000;
		}
	}
	else
	{
		// Discriminator '0'
		timestamp = *(ptr++);
		timestamp |= last_timestamp & 0xFFFFFF80;
	}

	#if ROHC_TCP_DEBUG
	rohc_debugf(3, "*pTimestamp %Xh context %Xh => timestamp %Xh\n",ntohl(
	               *pBegin),last_timestamp,timestamp);
	#endif
	*pTimestamp = htonl(timestamp);

	return ptr;
}


/**
 * @brief Calculate the size of TimeStamp compressed TCP option
 *
 * @param ptr   Pointer to the compressed value
 * @return      Return the size of the compressed TCP option
 */

static int d_size_ts_lsb( u_int8_t *ptr )
{
	if(*ptr & 0x80)
	{
		if(*ptr & 0x40)
		{
			if(*ptr & 0x20)
			{
				// Discriminator '111'
				return 4;
			}
			else
			{
				// Discriminator '110'
				return 3;
			}
		}
		else
		{
			// Discriminator '10'
			return 2;
		}
	}
	else
	{
		// Discriminator '0'
		return 1;
	}
}


/**
 * @brief Uncompress the SACK field value.
 *
 * See draft-sandlund-RFC4996bis-00 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr       Pointer to the compressed value
 * @param base      The base value
 * @param field     Pointer to the uncompressed value
 * @return          Pointer to the next compressed value
 */

static u_int8_t * d_sack_pure_lsb( u_int8_t *ptr, u_int32_t base, u_int32_t *field )
{
	u_int32_t sack_field;

	if( ( (*ptr) & 0x80 ) == 0)
	{
		sack_field = *(ptr++) << 8;
		sack_field |= *(ptr++);
	}
	else
	{
		if( ( (*ptr) & 0x40 ) == 0)
		{
			/*
			sack_field = *(ptr++) << 16;
			sack_field |= *(ptr++) << 8;
			sack_field |= *(ptr++);
			*/
			sack_field = *(ptr++);
			sack_field <<= 8;
			sack_field |= *(ptr++);
			sack_field <<= 8;
			sack_field |= *(ptr++);
		}
		else
		{
			/*
			sack_field = *(ptr++) << 24;
			sack_field |= *(ptr++) << 16;
			sack_field |= *(ptr++) << 8;
			sack_field |= *(ptr++);
			*/
			sack_field = *(ptr++);
			sack_field <<= 8;
			sack_field |= *(ptr++);
			sack_field <<= 8;
			sack_field |= *(ptr++);
			sack_field <<= 8;
			sack_field |= *(ptr++);
		}
	}

	*field = htonl( base + sack_field );

	return ptr;
}


/**
 * @brief Uncompress a SACK block
 *
 * See draft-sandlund-RFC4996bis-00 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr        Pointer to the compressed value
 * @param reference  The reference value
 * @param sack_block Pointer to the uncompressed sack_block
 * @return           Pointer to the next compressed value
 */

static u_int8_t * d_sack_block( u_int8_t *ptr, u_int32_t reference, sack_block_t *sack_block )
{
	ptr = d_sack_pure_lsb(ptr,reference,&sack_block->block_start);
	ptr = d_sack_pure_lsb(ptr,reference,&sack_block->block_end);
	rohc_debugf(3, "block_start %Xh block_end %Xh\n",ntohl(sack_block->block_start),
	            ntohl(sack_block->block_end));

	return ptr;
}


/**
 * @brief Uncompress the SACK TCP option
 *
 * See draft-sandlund-RFC4996bis-00 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr        Pointer to the compressed value
 * @param pOptions   Pointer to the uncompressed option
 * @param ack_value  The ack value
 * @return           Pointer to the next compressed value
 */

static u_int8_t * d_tcp_opt_sack( u_int8_t *ptr, u_int8_t * *pOptions, u_int32_t ack_value )
{
	sack_block_t *sack_block;
	u_int8_t discriminator;
	u_int8_t *options;
	int i;

	options = *pOptions;

	if( ( discriminator = *(ptr++) ) < 5)
	{
		// option id
		*(options++) = TCP_OPT_SACK;
		// option length
		*(options++) = ( discriminator << 3 ) + 2;

		sack_block = (sack_block_t *) options;

		for(i = 0; i < discriminator; ++i)
		{
			ptr = d_sack_block(ptr,ack_value,sack_block);
			++sack_block;
		}
		rohc_debugf(3, "TCP option SACK length %d\n",*(options - 1));
		TraceData(options - 2,*(options - 1));
		*pOptions = (u_int8_t*) sack_block;
	}
	else
	{
		rohc_debugf(3, "Warning: invalid discriminator value %d\n",discriminator);
	}

	return ptr;
}


#ifdef PREVIOUS_RFC4996

/**
 * @brief Uncompress the SACK field value.
 *
 * See RFC4996 page 66 (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr        Pointer to the compressed value
 * @param base       The base value
 * @param field      The value to compress
 * @return           Pointer to the next compressed value
 */

static u_int8_t * sack_var_length_dec( u_int8_t *ptr, u_int32_t base, u_int32_t *field )
{
	u_int32_t sack_offset;

	if( ( (*ptr) & 0x80 ) == 0)
	{
		sack_offset = *(ptr++) << 8;
		sack_offset |= *(ptr++);
	}
	else
	{
		if( ( (*ptr) & 0x40 ) == 0)
		{
			/*
			sack_offset = *(ptr++) << 16;
			sack_offset |= *(ptr++) << 8;
			sack_offset |= *(ptr++);
			*/
			sack_offset = *(ptr++);
			sack_offset <<= 8;
			sack_offset |= *(ptr++);
			sack_offset <<= 8;
			sack_offset |= *(ptr++);
		}
		else
		{
			/*
			sack_offset = *(ptr++) << 24;
			sack_offset |= *(ptr++) << 16;
			sack_offset |= *(ptr++) << 8;
			sack_offset |= *(ptr++);
			*/

			sack_offset = *(ptr++);
			sack_offset <<= 8;
			sack_offset |= *(ptr++);
			sack_offset <<= 8;
			sack_offset |= *(ptr++);
			sack_offset <<= 8;
			sack_offset |= *(ptr++);
		}
	}

	*field = htonl( base + sack_offset );

	return ptr;
}


/**
 * @brief Uncompress a SACK block
 *
 * See RFC4996 page 66 (and RFC2018 for Selective Acknowledgement option)
 *
 * @param ptr             Pointer to the compressed sack block
 * @param prev_block_end  The previous block end field
 * @param sack_block      Pointer to the SACK block to uncompressed
 * @return                Pointer to the next compressed value
 */

static u_int8_t * d_sack_block( u_int8_t *ptr, u_int32_t prev_block_end, sack_block_t *sack_block )
{
	ptr = sack_var_length_dec(ptr,prev_block_end,&sack_block->block_start);
	ptr = sack_var_length_dec(ptr,ntohl(sack_block->block_start),&sack_block->block_end);
	rohc_debugf(3, "block_start %Xh block_end %Xh\n",ntohl(sack_block->block_start),
	            ntohl(sack_block->block_end));

	return ptr;
}


/**
 * @brief Uncompress a SACK TCP option
 *
 * See RFC4996 page 67
 *
 * @param ptr          Pointer to the compressed sack block
 * @param pOption      Pointer to the uncompressed SACK TCP option
 * @param ack_value    The ack value
 * @return             Pointer to the next compressed value
 */

static u_int8_t * d_tcp_opt_sack( u_int8_t *ptr, u_int8_t * *pOptions, u_int32_t ack_value )
{
	sack_block_t *sack_block;
	u_int8_t discriminator;
	u_int8_t *options;
	int i;

	options = *pOptions;

	if( ( discriminator = *(ptr++) ) < 5)
	{
		// option id
		*(options++) = TCP_OPT_SACK;
		// option length
		*(options++) = ( discriminator << 3 ) + 2;

		sack_block = (sack_block_t *) options;

		for(i = 0; i < discriminator; ++i)
		{
			ptr = d_sack_block(ptr,ack_value,sack_block);
			ack_value = ntohl(sack_block->block_end);
			++sack_block;
		}
		rohc_debugf(3, "TCP option SACK length %d\n",*(options - 1));
		TraceData(options - 2,*(options - 1));
		*pOptions = (u_int8_t*) sack_block;
	}
	else
	{
		rohc_debugf(3, "Warning: invalid discriminator value %d\n",discriminator);
	}

	return ptr;
}


#endif // PREVIOUS_RFC4996

/**
 * @brief Calculate the size of the compressed SACK field value
 *
 * See RFC4996 page 66
 *
 * @param ptr    Pointer to the compressed sack field value
 * @return       The size (in octets) of the compressed value
 */

static int d_sack_var_length_size_dec( u_int8_t *ptr )
{
	if( ( (*ptr) & 0x80 ) == 0)
	{
		return 2;
	}
	else
	{
		if( ( (*ptr) & 0x40 ) == 0)
		{
			return 3;
		}
		else
		{
			return 4;
		}
	}
}


/**
 * @brief Calculate the size of the compressed SACK block
 *
 * See RFC4996 page 67
 *
 * @param ptr          Pointer to the compressed sack block
 * @return             The size (in octets) of the compressed SACK block
 */

static int d_sack_block_size( u_int8_t *ptr )
{
	int size;

	size = d_sack_var_length_size_dec(ptr);
	ptr += size;
	size += d_sack_var_length_size_dec(ptr);

	return size;
}


/**
 * @brief Calculate the size of the SACK TCP option
 *
 * See RFC4996 page 67
 *
 * @param ptr                Pointer to the compressed SACK TCP option
 * @param uncompressed_size  Pointer to the uncompressed TCP option size
 * @return                   The size (in octets) of the compressed SACK TCP option
 */

static int d_tcp_size_opt_sack( u_int8_t *ptr, u_int16_t *uncompressed_size )
{
	u_int8_t discriminator;
	int size = 1;
	int i;
	int j;

	rohc_debugf(3, "*ptr %2.2Xh\n",*ptr);
	TraceData(ptr,16);

	if( ( discriminator = *(ptr++) ) < 5)
	{
		for(i = 0; i < discriminator; ++i)
		{
			j = d_sack_block_size(ptr);
			size += j;
			ptr += j;
		}
	}
	else
	{
		rohc_debugf(3, "Warning: invalid discriminator value %d\n",discriminator);
	}

	rohc_debugf(3, "return size %d\n",size);

	return size;
}


/**
 * @brief Uncompress a generic TCP option
 *
 * See RFC4996 page 67
 *
 * @param tcp_context  The specific TCP context
 * @param ptr          Pointer to the compressed TCP option
 * @param pOptions     Pointer to the uncompressed TCP option
 * @return             Pointer to the next compressed value
 */

static u_int8_t * d_tcp_opt_generic( struct d_tcp_context *tcp_context, u_int8_t *ptr,
                                     u_int8_t * *pOptions )
{
	u_int8_t *options;

	options = *pOptions;

	// A COMPLETER

	switch(*ptr)
	{
		case 0x00:  // generic_full_irregular
			break;
		case 0xFF:  // generic_stable_irregular
			break;
	}

	*pOptions = options;

	return ptr;
}


/**
 * @brief Calculate the size of a generic TCP option
 *
 * See RFC4996 page 67
 *
 * @param tcp_context        The specific TCP context
 * @param ptr                Pointer to the compressed TCP option
 * @param uncompressed_size  Pointer to the uncompressed TCP option size
 * @return                   Pointer to the next compressed value
 */

static int d_tcp_size_opt_generic( struct d_tcp_context *tcp_context, u_int8_t *ptr,
                                   u_int16_t *uncompressed_size )
{
	int size = 0;

	// A COMPLETER

	return size;
}


/**
 * @brief Uncompress the TCP options
 *
 * @param tcp_context        The specific TCP context
 * @param tcp                The TCP header
 * @param ptr                Pointer to the compressed TCP options
 * @return                   Pointer to the next compressed value
 */

static u_int8_t * tcp_decompress_tcp_options( struct d_tcp_context *tcp_context, tcphdr_t *tcp,
                                              u_int8_t *ptr )
{
	u_int8_t *compressed_options;
	u_int8_t *options;
	u_int8_t present;
	u_int8_t *pValue;
	u_int8_t PS;
	int index;
	int m;
	int i;

	/* init pointer to destination TCP options */
	options = (u_int8_t*) ( tcp + 1 );

	// see RFC4996 page 25-26
	PS = *ptr & 0x10;
	m = *(ptr++) & 0x0F;

	rohc_debugf(3, "tcp %p options %p PS=%Xh m=%d\n",tcp,options,PS,m);

	if(PS == 0)
	{
		compressed_options = ptr + ( (m + 1) >> 1 );
	}
	else
	{
		compressed_options = ptr + m;
	}

	for(i = 0; m != 0; --m)
	{

		/* 4-bit XI fields */
		if(PS == 0)
		{
			/* if odd digit */
			if(i & 1)
			{
				index = *(ptr++);
			}
			else
			{
				index = (*ptr) >> 4;
			}
			present = index & 0x08;
			index &= 0x07;
			++i;
		}
		else
		{
			/* 8-bit XI fields */
			present = (*ptr) & 0x80;
			index = *(ptr++) & 0x0F;
		}

		rohc_debugf(3, "TCP option index %d %s\n",index,present == 0 ? "" : "present");

		if(present)
		{
			switch(index)
			{
				case TCP_INDEX_NOP:  // NOP
					*(options++) = TCP_OPT_NOP;
					break;
				case TCP_INDEX_EOL:  // EOL
					*(options++) = TCP_OPT_EOL;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					*(options++) = TCP_OPT_MAXSEG;
					// Length
					*(options++) = TCP_OLEN_MAXSEG;
					// Max segment size
					memcpy(&tcp_context->tcp_option_maxseg,compressed_options,2);
					*(options++) = *(compressed_options++);
					*(options++) = *(compressed_options++);
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					*(options++) = TCP_OPT_WINDOW;
					// Length
					*(options++) = TCP_OLEN_WINDOW;
					// Window scale
					tcp_context->tcp_option_window =
					   *(options++) = *(compressed_options++);
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					*(options++) = TCP_OPT_TIMESTAMP;
					// Length
					*(options++) = TCP_OLEN_TIMESTAMP;
					// Timestamp
					// compressed_options = d_tcp_opt_ts(compressed_options);
					compressed_options =
					   d_ts_lsb(compressed_options,(u_int32_t*)tcp_context->tcp_option_timestamp,
					            (u_int32_t*)options);
					compressed_options =
					   d_ts_lsb(compressed_options,(u_int32_t*)(tcp_context->tcp_option_timestamp + 4),
					            (u_int32_t*)(options + 4));
					memcpy(tcp_context->tcp_option_timestamp,options,8);
					options += 8;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					*(options++) = TCP_OPT_SACK_PERMITTED;
					// Length
					*(options++) = TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					                   // A COMPLETER : sauvegarde dans le context
					compressed_options =
					   d_tcp_opt_sack(compressed_options,&options,ntohl(tcp->ack_number));
					break;
				default:  // Generic options
					rohc_debugf(3, "TCP option with index %d not treated\n",index);
					// A REVOIR
					compressed_options = d_tcp_opt_generic(tcp_context,compressed_options,&options);
					break;
			}
		}
		else
		{
			switch(index)
			{
				case TCP_INDEX_NOP:  // NOP
					*(options++) = TCP_OPT_NOP;
					break;
				case TCP_INDEX_EOL:  // EOL
					*(options++) = TCP_OPT_EOL;
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					*(options++) = TCP_OPT_MAXSEG;
					// Length
					*(options++) = TCP_OLEN_MAXSEG;
					// Max segment size value
					memcpy(options,&tcp_context->tcp_option_maxseg,2);
					options += TCP_OLEN_MAXSEG - 2;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					*(options++) = TCP_OPT_WINDOW;
					// Length
					*(options++) = TCP_OLEN_WINDOW;
					// Window scale value
					*(options++) = tcp_context->tcp_option_window;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					*(options++) = TCP_OPT_TIMESTAMP;
					// Length
					*(options++) = TCP_OLEN_TIMESTAMP;
					// Timestamp value
					memcpy(options,tcp_context->tcp_option_timestamp,8);
					options += TCP_OLEN_TIMESTAMP - 2;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					*(options++) = TCP_OPT_SACK_PERMITTED;
					// Length
					*(options++) = TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					*(options++) = TCP_OPT_SACK;
					// Length
					*(options++) = tcp_context->tcp_option_sack_length;
					// Value
					memcpy(options,&tcp_context->tcp_option_sackblocks,
					       tcp_context->tcp_option_sack_length);
					options += tcp_context->tcp_option_sack_length;
					break;
				default:  // Generic options
					rohc_debugf(3, "TCP option with index %d not treated\n",index);
					*(options++) = tcp_context->tcp_options_list[index];
					pValue = tcp_context->tcp_options_values + tcp_context->tcp_options_offset[index];
					// Length
					*(options++) = *pValue;
					// Value
					memcpy(options,pValue + 1,*pValue);
					options += (*pValue) + 2;
					break;
			}
		}
	}

	// Pad with nul
	for(i = options - ( (u_int8_t*) tcp ); i &0x03; ++i)
	{
		*(options++) = 0;
	}

	/* Calculate TCP header length with TCP options */
	tcp->data_offset = ( options - ( (u_int8_t*) tcp ) )  >> 2;
	rohc_debugf(3, "TCP data_offset %d %xh\n",tcp->data_offset,tcp->data_offset);
	if(tcp->data_offset > ( sizeof(tcphdr_t) >> 2 ) )
	{
		rohc_debugf(3, "TCP options:\n");
		TraceData((unsigned char*)(tcp + 1),(tcp->data_offset << 2) - sizeof(tcphdr_t));
	}

	return compressed_options;
}


/**
 * @brief Calculate the compressed TCP options size
 *
 * @param tcp_context        The specific TCP context
 * @param ptr                Pointer to the compressed TCP options
 * @param uncompressed_size  Pointer to the uncompressed TCP option size
 * @return                   Pointer to the next compressed value
 */

static int tcp_size_decompress_tcp_options( struct d_tcp_context *tcp_context, u_int8_t *ptr,
                                            u_int16_t *uncompressed_size )
{
	u_int8_t *compressed_options;
	u_int8_t present;
	u_int8_t PS;
	int index;
	int size;
	int m;
	int i;
	int j;

	*uncompressed_size = 0;

	// see RFC4996 page 25-26
	PS = *ptr & 0x10;
	m = *(ptr++) & 0x0F;

	if(PS == 0)
	{
		/* 4-bit XI fields */
		size = (m + 1) >> 1;
	}
	else
	{
		/* 8-bit XI fields */
		size = m;
	}
	compressed_options = ptr + size;
	++size;

	rohc_debugf(3, "TCP compressed options:\n");
	TraceData(ptr - 1,size);

	for(i = 0; m != 0; --m)
	{

		/* 4-bit XI fields */
		if(PS == 0)
		{
			/* if odd digit */
			if(i & 1)
			{
				index = *(ptr++);
			}
			else
			{
				index = (*ptr) >> 4;
			}
			present = index & 0x08;
			index &= 0x07;
			++i;
		}
		else
		{
			/* 8-bit XI fields */
			present = (*ptr) & 0x80;
			index = *(ptr++) & 0x0F;
		}

		// If item present
		if(present)
		{
			switch(index)
			{
				case TCP_INDEX_NOP:  // NOP
					++(*uncompressed_size);
					break;
				case TCP_INDEX_EOL:  // EOL
					++(*uncompressed_size);
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					*uncompressed_size += TCP_OLEN_MAXSEG;
					size += 2;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					*uncompressed_size += TCP_OLEN_WINDOW;
					++size;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					*uncompressed_size += TCP_OLEN_TIMESTAMP;
					j = d_size_ts_lsb(compressed_options);
					compressed_options += j;
					size += j;
					j = d_size_ts_lsb(compressed_options);
					compressed_options += j;
					size += j;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					*uncompressed_size += TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					j = d_tcp_size_opt_sack(compressed_options,uncompressed_size);
					compressed_options += j;
					size += j;
					break;
				default:  // Generic options
					rohc_debugf(3, "TCP option with index %d not treated\n",index);
					j = d_tcp_size_opt_generic(tcp_context,compressed_options,uncompressed_size);
					compressed_options += j;
					size += j;
					break;
			}
			rohc_debugf(3, "TCP option with index %d -> size %d\n",index,size);
		}
		else
		{
			switch(index)
			{
				case TCP_INDEX_NOP:  // NOP
					++(*uncompressed_size);
					break;
				case TCP_INDEX_EOL:  // EOL
					++(*uncompressed_size);
					break;
				case TCP_INDEX_MAXSEG:  // MSS
					*uncompressed_size += TCP_OLEN_MAXSEG;
					break;
				case TCP_INDEX_WINDOW:  // WINDOW SCALE
					*uncompressed_size += TCP_OLEN_WINDOW;
					break;
				case TCP_INDEX_TIMESTAMP:  // TIMESTAMP
					*uncompressed_size += TCP_OLEN_TIMESTAMP;
					break;
				case TCP_INDEX_SACK_PERMITTED:  // SACK-PERMITTED see RFC2018
					*uncompressed_size += TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_INDEX_SACK:  // SACK see RFC2018
					*uncompressed_size +=
					   *( tcp_context->tcp_options_values + tcp_context->tcp_options_list[index] );
					break;
				default:  // Generic options
					*uncompressed_size +=
					   *( tcp_context->tcp_options_values + tcp_context->tcp_options_list[index] );
					break;
			}
		}
	}

	rohc_debugf(3, "return size = %d uncompressed size %d\n",size,*uncompressed_size);

	return size;
}


/**
 * @brief Decode one CO packet.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param add_cid_len    The length of the optional Add-CID field
 * @param large_cid_len  The length of the optional large CID field
 * @param dest           OUT: The decoded IP packet
 * @return               The length of the uncompressed IP packet
 *                       or ROHC_ERROR if an error occurs
 *                       or ROHC_ERROR_CRC if a CRC error occurs
 */
int d_tcp_decode_CO(struct rohc_decomp *decomp,
                    struct d_context *context,
                    const unsigned char *const rohc_packet,
                    const unsigned int rohc_length,
                    const size_t add_cid_len,
                    const size_t large_cid_len,
                    unsigned char *dest)
{
	struct d_generic_context *g_context = context->specific;
	struct d_tcp_context *tcp_context;
	ip_context_ptr_t ip_inner_context;
	ip_context_ptr_t ip_context;
	u_int16_t tcp_options_size = 0;
	u_int8_t seq_number_scaled_used = 0;
	u_int32_t seq_number_scaled = 0;
	u_int8_t header_crc;
	u_int8_t protocol;
	u_int8_t crc;
	u_int16_t msn;
	int size_header;
	int size_options = 0;
	int size = 0;
	WB_t wb;
	int ttl_irregular_chain_flag = 0;
	int ip_inner_ecn;

	/* lengths of ROHC and uncompressed headers to be computed during parsing */
	unsigned int rohc_header_len;
	unsigned int uncomp_header_len;

	/* remaining ROHC data not parsed yet */
	unsigned char *rohc_remain_data = (unsigned char *) rohc_packet;

	/* ROHC and uncompressed payloads (they are the same) */
	unsigned int payload_len;

	base_header_ip_t base_header_inner;
	base_header_ip_t base_header;
	multi_ptr_t c_base_header;
	multi_ptr_t mptr;
	tcphdr_t *tcp;
	WB_t ip_id;
	u_int8_t PacketType = PACKET_TCP_UNKNOWN;


	tcp_context = (struct d_tcp_context *) g_context->specific;

	ip_context.uint8 = tcp_context->ip_context;

	rohc_debugf(3, "context %p g_context %p tcp_context %p add_cid_len %zd "
	            "large_cid_len %zd rohc_packet %p rohc_length %d\n",
	            context, g_context, tcp_context, add_cid_len, large_cid_len,
	            rohc_packet, rohc_length);
	TraceData((unsigned char*)rohc_packet,rohc_length > 0x40 ? 0x40 : rohc_length);

	rohc_debugf(3, "copy octet %2.2Xh to offset %d\n", *rohc_packet,
	            large_cid_len);
	c_base_header.uint8 = (u_int8_t*) rohc_packet + large_cid_len;
	*c_base_header.uint8 = *rohc_packet;
	TraceData((unsigned char*)rohc_packet,rohc_length > 0x40 ? 0x40 : rohc_length);

	/* skip the optional large CID bytes */
	rohc_remain_data += large_cid_len;
	rohc_header_len = large_cid_len;


	rohc_debugf(3, "context %p remain_data %p\n", context, rohc_remain_data);
	TraceData((unsigned char*)rohc_remain_data,
	          rohc_length - large_cid_len > 0x40 ? 0x40 : rohc_length - large_cid_len);

	rohc_debugf(3, "rohc_packet %p compressed base header %p\n",rohc_packet,c_base_header.uint8);

	/* Try to determine the compressed format header used */
	rohc_debugf(3, "Try to determine the header from %Xh ip_id_behavior %d\n", *rohc_packet,
	            ip_context.v4->ip_id_behavior);
	if( (*rohc_packet) & 0x80)
	{
		// common 1111101
		//  rnd_1 101110
		//  rnd_2 1100
		//  rnd_4 1101
		//  rnd_5 100
		//  rnd_6 1010
		//  rnd_7 101111
		//  rnd_8 10110
		//  seq_1 1010
		//  seq_2 11010
		//  seq_3 1001
		//  seq_5 1000
		//  seq_6 11011
		//  seq_7 1100
		//  seq_8 1011
		switch( (*rohc_packet) & 0xF0)
		{
			case 0x80:  // 1000 rnd_5 seq_5
				if(ip_context.v4->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
				{
					// seq_5
					rohc_debugf(3, "Header seq_5\n");
					PacketType = PACKET_TCP_SEQ5;
					goto decode_seq_5;
				}
				else
				{
					// rnd_5
					rohc_debugf(3, "Header rnd_5\n");
					PacketType = PACKET_TCP_RND5;
					goto decode_rnd_5;
				}
				break;
			case 0x90:  // 1001 rnd_5 seq_3
				if(ip_context.v4->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
				{
					// seq_3
					rohc_debugf(3, "Header seq_3\n");
					PacketType = PACKET_TCP_SEQ3;
					goto decode_seq_3;
				}
				else
				{
					// rnd_5
					rohc_debugf(3, "Header rnd_5\n");
					PacketType = PACKET_TCP_RND5;
					goto decode_rnd_5;
				}
				break;
			case 0xA0:  // 1010 rnd_6 seq_1
				if(ip_context.v4->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
				{
					// seq_1
					rohc_debugf(3, "Header seq_1\n");
					PacketType = PACKET_TCP_SEQ1;
					goto decode_seq_1;
				}
				else
				{
					// rnd_6
					rohc_debugf(3, "Header rnd_6\n");
					PacketType = PACKET_TCP_RND6;
					goto decode_rnd_6;
				}
				break;
			case 0xB0:  // 1011 rnd_1 rnd_7 rnd_8 seq_8
				if(ip_context.v4->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
				{
					// seq_8
					rohc_debugf(3, "Header seq_8\n");
					PacketType = PACKET_TCP_SEQ8;
					goto decode_seq_8;
				}
				else
				{
					if( (*rohc_packet) & 0x08)
					{
						// rnd_1 rnd_7
						if( (*rohc_packet) & 0x04)
						{
							// rnd_7
							rohc_debugf(3, "Header rnd_7\n");
							PacketType = PACKET_TCP_RND7;
							goto decode_rnd_7;
						}
						else
						{
							// rnd_1
							rohc_debugf(3, "Header rnd_1\n");
							PacketType = PACKET_TCP_RND1;
							goto decode_rnd_1;
						}
					}
					else
					{
						// rnd_8
						rohc_debugf(3, "Header rnd_8\n");
						PacketType = PACKET_TCP_RND8;
						goto decode_rnd_8;
					}
				}
				break;
			case 0xC0:  // 1100 rnd_2 seq_7
				if(ip_context.v4->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
				{
					// seq_7
					rohc_debugf(3, "Header seq_7\n");
					PacketType = PACKET_TCP_SEQ7;
					goto decode_seq_7;
				}
				else
				{
					// rnd_2
					rohc_debugf(3, "Header rnd_2\n");
					PacketType = PACKET_TCP_RND2;
					goto decode_rnd_2;
				}
				break;
			case 0xD0:  // 1101 rnd_4 seq_2 seq_6
				if(ip_context.v4->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
				{
					if( (*rohc_packet) & 0x08)
					{
						// seq_6
						rohc_debugf(3, "Header seq_6\n");
						PacketType = PACKET_TCP_SEQ6;
						goto decode_seq_6;
					}
					else
					{
						// seq_2
						rohc_debugf(3, "Header seq_2\n");
						PacketType = PACKET_TCP_SEQ2;
						goto decode_seq_2;
					}
				}
				else
				{
					// rnd_4
					rohc_debugf(3, "Header rnd_4\n");
					PacketType = PACKET_TCP_RND4;
					goto decode_rnd_4;
				}
				break;
			case 0xE0:  // 1110
				rohc_debugf(3, "Header unknown\n");
				goto error;
			case 0xF0:  // 1111 common
				if( ( *(rohc_packet) & 0xFE ) == 0xFA)
				{
					// common
					rohc_debugf(3, "Header common\n");
					PacketType = PACKET_TCP_COMMON;
					goto decode_common;
				}
				rohc_debugf(3, "Header unknown\n");
				goto error;
		}
	}
	else
	{
		// rnd_3 0
		// seq_4 0
		if(ip_context.v4->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
		{
			// seq_4
			rohc_debugf(3, "Header seq_4\n");
			PacketType = PACKET_TCP_SEQ4;
			goto decode_seq_4;
		}
		else
		{
			// rnd_3
			rohc_debugf(3, "Header rnd_3\n");
			PacketType = PACKET_TCP_RND3;
			goto decode_rnd_3;
		}
	}

	// Normaly, never go here
	assert( 1 != 1 );

decode_rnd_1:
	assert( c_base_header.rnd1->discriminator == 0x2E ); // '101110'
	size_header = sizeof(rnd_1_t);
	header_crc = c_base_header.rnd1->header_crc;
	c_base_header.rnd1->header_crc = 0;
	msn = c_base_header.rnd1->msn;
	goto test_checksum3;

decode_rnd_2:
	assert( c_base_header.rnd2->discriminator == 0x0C ); // '1100'
	size_header = sizeof(rnd_2_t);
	header_crc = c_base_header.rnd2->header_crc;
	c_base_header.rnd2->header_crc = 0;
	msn = c_base_header.rnd2->msn;
	goto test_checksum3;

decode_rnd_3:
	assert( c_base_header.rnd3->discriminator == 0x00 ); // '0'
	size_header = sizeof(rnd_3_t);
	header_crc = c_base_header.rnd3->header_crc;
	c_base_header.rnd3->header_crc = 0;
	msn = c_base_header.rnd3->msn;
	goto test_checksum3;

decode_rnd_4:
	assert( c_base_header.rnd4->discriminator == 0x0D ); // '1101'
	size_header = sizeof(rnd_4_t);
	header_crc = c_base_header.rnd4->header_crc;
	c_base_header.rnd4->header_crc = 0;
	msn = c_base_header.rnd4->msn;
	goto test_checksum3;

decode_rnd_5:
	assert( c_base_header.rnd5->discriminator == 0x04 ); // '100'
	size_header = sizeof(rnd_5_t);
	header_crc = c_base_header.rnd5->header_crc;
	c_base_header.rnd5->header_crc = 0;
	msn = c_base_header.rnd5->msn;
	goto test_checksum3;

decode_rnd_6:
	assert( c_base_header.rnd6->discriminator == 0x0A ); // '1010'
	size_header = sizeof(rnd_6_t);
	header_crc = c_base_header.rnd6->header_crc;
	c_base_header.rnd6->header_crc = 0;
	msn = c_base_header.rnd6->msn;
	goto test_checksum3;

decode_rnd_7:
	assert( c_base_header.rnd7->discriminator == 0x2F ); // '101111'
	size_header = sizeof(rnd_7_t);
	header_crc = c_base_header.rnd7->header_crc;
	c_base_header.rnd7->header_crc = 0;
	msn = c_base_header.rnd7->msn;
	goto test_checksum3;

decode_rnd_8:
	assert( c_base_header.rnd8->discriminator == 0x16 ); // '10110'
	size_header = sizeof(rnd_8_t);
	header_crc = c_base_header.rnd8->header_crc;
	c_base_header.rnd8->header_crc = 0;
	#if __BYTE_ORDER == __LITTLE_ENDIAN
	msn = ( c_base_header.rnd8->msn1 << 3 ) | c_base_header.rnd8->msn2;
	#elif __BYTE_ORDER == __BIG_ENDIAN
	msn = c_base_header.rnd8->msn;
	#endif
	rohc_debugf(3, "rnd_8 size_header %d\n",size_header);
	if(c_base_header.rnd8->list_present)
	{
		goto add_tcp_list_size;
	}
	goto test_checksum7;

decode_seq_1:
	assert( c_base_header.seq1->discriminator == 0x0A ); // '1010'
	size_header = sizeof(seq_1_t);
	header_crc = c_base_header.seq1->header_crc;
	c_base_header.seq1->header_crc = 0;
	msn = c_base_header.seq1->msn;
	goto test_checksum3;

decode_seq_2:
	assert( c_base_header.seq2->discriminator == 0x1A ); // '11010'
	size_header = sizeof(seq_2_t);
	header_crc = c_base_header.seq2->header_crc;
	c_base_header.seq2->header_crc = 0;
	msn = c_base_header.seq2->msn;
	goto test_checksum3;

decode_seq_3:
	assert( c_base_header.seq3->discriminator == 0x09 ); // '1001'
	size_header = sizeof(seq_3_t);
	header_crc = c_base_header.seq3->header_crc;
	c_base_header.seq3->header_crc = 0;
	msn = c_base_header.seq3->msn;
	goto test_checksum3;

decode_seq_4:
	assert( c_base_header.seq4->discriminator == 0x00 ); // '0'
	size_header = sizeof(seq_4_t);
	header_crc = c_base_header.seq4->header_crc;
	c_base_header.seq4->header_crc = 0;
	msn = c_base_header.seq4->msn;
	goto test_checksum3;

decode_seq_5:
	assert( c_base_header.seq5->discriminator == 0x08 ); // '1000'
	size_header = sizeof(seq_5_t);
	header_crc = c_base_header.seq5->header_crc;
	c_base_header.seq5->header_crc = 0;
	msn = c_base_header.seq5->msn;
	goto test_checksum3;

decode_seq_6:
	assert( c_base_header.seq6->discriminator == 0x1B ); // '11011'
	size_header = sizeof(seq_6_t);
	header_crc = c_base_header.seq6->header_crc;
	c_base_header.seq6->header_crc = 0;
	msn = c_base_header.seq6->msn;
	goto test_checksum3;

decode_seq_7:
	assert( c_base_header.seq7->discriminator == 0x0C ); // '1100'
	size_header = sizeof(seq_7_t);
	header_crc = c_base_header.seq7->header_crc;
	c_base_header.seq7->header_crc = 0;
	msn = c_base_header.seq7->msn;
	goto test_checksum3;

decode_seq_8:
	assert( c_base_header.seq8->discriminator == 0x0B ); // '1011'
	size_header = sizeof(seq_8_t);
	header_crc = c_base_header.seq8->header_crc;
	c_base_header.seq8->header_crc = 0;
	msn = c_base_header.seq8->msn;
	rohc_debugf(3, "seq_8 size_header %d\n",size_header);
	if(c_base_header.seq8->list_present)
	{
		goto add_tcp_list_size;
	}
	goto test_checksum7;

decode_common:
	assert( c_base_header.co_common->discriminator == 0x7D ); // '1111101'
	size_header = sizeof(co_common_t);
	rohc_debugf(3, "size %d seq_indicator %d\n",size, c_base_header.co_common->seq_indicator);
	size_options += variable_length_32_size[c_base_header.co_common->seq_indicator];
	rohc_debugf(3, "size_options %d ack_indicator %d\n",size_options,
	            c_base_header.co_common->ack_indicator);
	size_options += variable_length_32_size[c_base_header.co_common->ack_indicator];
	rohc_debugf(3, "size_options %d ack_stride_indicator %d\n",size_options,
	            c_base_header.co_common->ack_stride_indicator);
	size_options += c_base_header.co_common->ack_stride_indicator << 1;
	rohc_debugf(3, "size_options %d window_indicator %d\n",size_options,
	            c_base_header.co_common->window_indicator);
	size_options += c_base_header.co_common->window_indicator << 1;
	rohc_debugf(3, "size_options %d ip_id_behavior %d ip_id_indicator %d\n",size_options,
	            c_base_header.co_common->ip_id_behavior,
	            c_base_header.co_common->ip_id_indicator);
	if(c_base_header.co_common->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL ||
	   c_base_header.co_common->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
	{
		size_options += c_base_header.co_common->ip_id_indicator + 1;
	}
	rohc_debugf(3, "size_options %d urg_ptr_present %d\n",size_options,
	            c_base_header.co_common->urg_ptr_present);
	size_options += c_base_header.co_common->urg_ptr_present << 1;
	rohc_debugf(3, "size_options %d dscp_present %d\n",size_options,
	            c_base_header.co_common->dscp_present);
	size_options += c_base_header.co_common->dscp_present;
	rohc_debugf(3, "size_options %d ttl_hopl_present %d\n",size_options,
	            c_base_header.co_common->ttl_hopl_present);
	size_options += c_base_header.co_common->ttl_hopl_present;
	rohc_debugf(3, "size_options %d list_present %d\n",size_options,
	            c_base_header.co_common->list_present);

	rohc_debugf(3, "common size %d (%d+%d)\n",size_header + size_options,size_header,size_options);

	/* check the crc */
	header_crc = c_base_header.co_common->header_crc;
	c_base_header.co_common->header_crc = 0;

	msn = c_base_header.co_common->msn;

	if(c_base_header.co_common->list_present)
	{
add_tcp_list_size:
		mptr.uint8 = c_base_header.uint8 + size_header + size_options;
		rohc_debugf(3, "list present at %p: PS_m %Xh\n",mptr.uint8,*mptr.uint8);
		TraceData(mptr.uint8,16);
		size_options += tcp_size_decompress_tcp_options(tcp_context,mptr.uint8,&tcp_options_size);
		rohc_debugf(3, "size header %d (%d+%d)\n",size_header + size_options,size_header,size_options);
	}
	else
	{
		mptr.uint8 = c_base_header.uint8 + size_header + size_options;
	}

test_checksum7:
	crc = crc_calculate(ROHC_CRC_TYPE_7,  c_base_header.uint8, size_header + size_options, CRC_INIT_7,
	                    decomp->crc_table_7);
	goto test_checksum;

test_checksum3:
	mptr.uint8 = c_base_header.uint8 + size_header;
	crc = crc_calculate(ROHC_CRC_TYPE_3,  c_base_header.uint8, size_header, CRC_INIT_3,
	                    decomp->crc_table_3);

test_checksum:
	if(header_crc != crc)
	{
		rohc_debugf(3, "header_crc %Xh != crc %Xh length %d\n",header_crc,crc,size_header);
		goto error;
	}
	rohc_debugf(3, "header_crc %Xh == crc %Xh length %d\n",header_crc,crc,size_header);

	// Check the MSN received with MSN required
	if( ( (tcp_context->msn + 1) & 0x000F ) != msn)
	{
		rohc_debugf(3, "last_msn %4.4Xh, waiting for msn %Xh, received %Xh!\n",tcp_context->msn,
		            (tcp_context->msn + 1) & 0x000F,msn);
		// A COMPLETER !!!
		// Stocker et rearranger les paquets
	}
	else
	{
		rohc_debugf(3, "Last msn %4.4Xh + 1 = %Xh received %Xh\n",tcp_context->msn,tcp_context->msn +
		            1,
		            msn);
	}
	msn = d_lsb(4,4,tcp_context->msn + 1,msn);
	rohc_debugf(3, "msn %4.4Xh\n",msn);

	rohc_debugf(3, "rohc_length %d size header %d -> payload_len %d\n",rohc_length,size_header +
	            size_options,
	            rohc_length - (size_header + size_options));

	rohc_header_len += size_header + size_options;


	payload_len = rohc_length - (size_header + size_options) + large_cid_len;
	rohc_header_len = size_header + size_options + large_cid_len;
	rohc_debugf(3, "payload_len %d\n",payload_len);

	/* reset the correction counter */
	g_context->correction_counter = 0;

	/* build the IP headers */

	base_header.uint8 = (u_int8_t*) dest;
	ip_context.uint8 = tcp_context->ip_context;
	uncomp_header_len = 0;
	size = 0;

	do
	{

		base_header_inner.uint8 = base_header.uint8;
		ip_inner_context.uint8 = ip_context.uint8;

		/* Init static part in IP header */
		uncomp_header_len += tcp_copy_static_ip(ip_context,base_header);

		/* Copy last dynamic ip */
		if(ip_context.vx->version == IPV4)
		{
			base_header.ipv4->dscp = ip_context.v4->dscp;
			ip_inner_ecn =
			   base_header.ipv4->ip_ecn_flags = ip_context.v4->ip_ecn_flags;
			base_header.ipv4->mf = 0;
			base_header.ipv4->rf = 0;
			#if __BYTE_ORDER == __LITTLE_ENDIAN
			base_header.ipv4->frag_offset1 = 0;
			base_header.ipv4->frag_offset2 = 0;
			#elif __BYTE_ORDER == __BIG_ENDIAN
			base_header.ipv4->frag_offset = 0;
			#endif
			base_header.ipv4->ttl_hopl = ip_context.v4->ttl_hopl;
			protocol = ip_context.v4->protocol;
			++base_header.ipv4;
			++ip_context.v4;
		}
		else
		{
			ip_inner_ecn = base_header.ipv6->ip_ecn_flags;
			#if __BYTE_ORDER == __LITTLE_ENDIAN
			base_header.ipv6->dscp1 = ip_context.v6->dscp >> 2;
			base_header.ipv6->dscp2 = ip_context.v6->dscp & 0x03;
			#elif __BYTE_ORDER == __BIG_ENDIAN
			base_header.ipv6->dscp = ip_context.v6->dscp;
			#endif
			base_header.ipv6->ttl_hopl = ip_context.v6->ttl_hopl;
			protocol = ip_context.v6->next_header;
			++base_header.ipv6;
			++ip_context.v6;
		}

		rohc_debugf(3, "Current IP packet:\n");
		TraceData(dest,uncomp_header_len);

		assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );

	}
	while(protocol != IPPROTO_TCP);

	tcp = base_header.tcphdr;
	assert( tcp == (tcphdr_t*)( dest + uncomp_header_len ) );

	/* static TCP part */
	tcp_copy_static_tcp(tcp_context,tcp);

	rohc_debugf(3, "Current IP packet:\n");
	TraceData(dest,uncomp_header_len + sizeof(tcphdr_t));

	/* dynamic part */

	assert( PacketType != PACKET_TCP_UNKNOWN );

	// Reinit pointer
	mptr.uint8 = c_base_header.uint8 + size_header;

	rohc_debugf(3, "PacketType %d Begin compressed options %p\n",PacketType,mptr.uint8);

	if(PacketType == PACKET_TCP_COMMON)
	{
		tcp->tcp_res_flags = tcp_context->old_tcphdr.tcp_res_flags;
		tcp->urg_flag = tcp_context->old_tcphdr.urg_flag;
		tcp->urg_ptr = tcp_context->old_tcphdr.urg_ptr;

		ttl_irregular_chain_flag = c_base_header.co_common->ttl_hopl_outer_flag;
		tcp->ack_flag = c_base_header.co_common->ack_flag;
		tcp->psh_flag = c_base_header.co_common->psh_flag;
		tcp->rsf_flags = rsf_index_dec( c_base_header.co_common->rsf_flags );
		rohc_debugf(3, "ack_flag %d psh_flag %d rsf_flags %d\n",tcp->ack_flag, tcp->psh_flag,
		            tcp->rsf_flags);
		tcp->seq_number = variable_length_32_dec(&mptr,c_base_header.co_common->seq_indicator);
		rohc_debugf(3, "seq_number %Xh\n",ntohl(tcp->seq_number));
		tcp->ack_number = variable_length_32_dec(&mptr,c_base_header.co_common->ack_indicator);
		rohc_debugf(3, "ack_number %Xh\n",ntohl(tcp->ack_number));
		tcp_context->ack_stride =
		   htons( d_static_or_irreg16(&mptr,tcp_context->ack_stride,
		                              c_base_header.co_common->ack_stride_indicator) );
		rohc_debugf(3, "ack_stride %Xh\n",tcp_context->ack_stride);
		tcp->window = d_static_or_irreg16(&mptr,tcp_context->old_tcphdr.window,
		                                  c_base_header.co_common->window_indicator);
		rohc_debugf(3, "window %Xh ( old_window %Xh )\n",ntohs(tcp->window),
		            ntohs(tcp_context->old_tcphdr.window));
		ip_inner_context.v4->ip_id_behavior = c_base_header.co_common->ip_id_behavior;
		d_optional_ip_id_lsb(&mptr,c_base_header.co_common->ip_id_behavior,
		                     c_base_header.co_common->ip_id_indicator,ip_inner_context.v4->last_ip_id,
		                     &ip_id.uint16,
		                     msn);
		rohc_debugf(3, "ip_id_behavior %d ip_id_indicator %d ip_id %Xh\n",
		            c_base_header.co_common->ip_id_behavior,c_base_header.co_common->ip_id_indicator,
		            ip_id.uint16);
		tcp->urg_ptr = d_static_or_irreg16(&mptr,tcp_context->old_tcphdr.urg_ptr,
		                                   c_base_header.co_common->urg_ptr_present);
		rohc_debugf(3, "ecn_used %d\n",c_base_header.co_common->ecn_used);
		tcp_context->ecn_used = c_base_header.co_common->ecn_used;
		if(ip_inner_context.vx->version == IPV4)
		{
			if(ip_inner_context.v4->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL)
			{
				base_header_inner.ipv4->ip_id = htons(ip_id.uint16);
				ip_inner_context.v4->last_ip_id.uint16 = ip_id.uint16;
				rohc_debugf(3, "new last IP-ID %4.4Xh\n",ip_inner_context.v4->last_ip_id.uint16);
			}
			else
			{
				if(ip_inner_context.v4->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
				{
					WB_t swapped_ip_id;
					swapped_ip_id.uint8[0] = ip_id.uint8[1];
					swapped_ip_id.uint8[1] = ip_id.uint8[0];
					base_header_inner.ipv4->ip_id = htons(swapped_ip_id.uint16);
					ip_inner_context.v4->last_ip_id.uint16 = swapped_ip_id.uint16;
					rohc_debugf(3, "new last IP-ID %4.4Xh\n",ip_inner_context.v4->last_ip_id.uint16);
				}
			}
			base_header_inner.ipv4->dscp = dscp_decode(&mptr,ip_inner_context.vx->dscp,
			                                           c_base_header.co_common->dscp_present);
			ip_inner_context.v4->df = c_base_header.co_common->df;
			base_header_inner.ipv4->ttl_hopl = d_static_or_irreg8(
			   &mptr,ip_inner_context.vx->ttl_hopl,c_base_header.co_common->ttl_hopl_present);
			rohc_debugf(3, "ip_id %4.4Xh dscp %Xh ttl_hopl %Xh\n",
			            ntohs(
			               base_header_inner.ipv4->ip_id),base_header_inner.ipv4->dscp,
			            base_header_inner.ipv4->ttl_hopl);
		}
		else
		{
			#if __BYTE_ORDER == __LITTLE_ENDIAN
			{
				u_int8_t dscp;
				dscp = dscp_decode(&mptr,ip_inner_context.vx->dscp,
				                   c_base_header.co_common->dscp_present);
				base_header_inner.ipv6->dscp1 = dscp >> 2;
				base_header_inner.ipv6->dscp2 = dscp & 0x03;
				rohc_debugf(3, "dscp %Xh\n",dscp);
			}
			#elif __BYTE_ORDER == __BIG_ENDIAN
			base_header_inner.ipv6->dscp = dscp_decode(&mptr,ip_inner_context.vx->dscp,
			                                           c_base_header.co_common->dscp_present);
			rohc_debugf(3, "dscp %Xh\n",base_header_inner.ipv6->dscp);
			#endif
			base_header_inner.ipv6->ttl_hopl = d_static_or_irreg8(
			   &mptr,ip_inner_context.vx->ttl_hopl,c_base_header.co_common->ttl_hopl_present);
			rohc_debugf(3, "ttl_hopl %Xh\n",base_header_inner.ipv6->ttl_hopl);
		}
		tcp->urg_flag = c_base_header.co_common->urg_flag;
		/* if TCP options list present */
		if(c_base_header.co_common->list_present)
		{
			// options
			mptr.uint8 = tcp_decompress_tcp_options(tcp_context,tcp,mptr.uint8);
		}
		else
		{
			tcp->data_offset = sizeof(tcphdr_t) >> 2;
		}
	}
	else
	{
		u_int32_t ack_number_scaled;
		u_int8_t ttl_hopl;
		WB_t ip_id;

		tcp->seq_number = tcp_context->old_tcphdr.seq_number;
		tcp->ack_number = tcp_context->old_tcphdr.ack_number;
		tcp->data_offset = sizeof(tcphdr_t) >> 2;
		tcp->tcp_res_flags = tcp_context->old_tcphdr.tcp_res_flags;
		tcp->tcp_ecn_flags = tcp_context->old_tcphdr.tcp_ecn_flags;
		tcp->urg_flag = tcp_context->old_tcphdr.urg_flag;
		tcp->ack_flag = tcp_context->old_tcphdr.ack_flag;
		tcp->rsf_flags = tcp_context->old_tcphdr.rsf_flags;
		tcp->window = tcp_context->old_tcphdr.window;
		tcp->urg_ptr = tcp_context->old_tcphdr.urg_ptr;

		switch(PacketType)
		{
			case PACKET_TCP_RND1:
			{
				u_int32_t seq_number;
				seq_number = ( c_base_header.rnd1->seq_number1 << 16 ) | ntohs(
				   c_base_header.rnd1->seq_number2);
				tcp->seq_number =
				   htonl( d_lsb(18,65535,ntohl(tcp_context->old_tcphdr.seq_number),seq_number) );
			}
				tcp->psh_flag = c_base_header.rnd1->psh_flag;
				break;
			case PACKET_TCP_RND2:
				seq_number_scaled = d_lsb(4,7,tcp_context->seq_number_scaled,
				                          c_base_header.rnd2->seq_number_scaled);
				seq_number_scaled_used = 1;
				tcp->psh_flag = c_base_header.rnd2->psh_flag;
				//  assert( payload_size != 0 );
				// A COMPLETER/REVOIR
				// tcp->seq_number = d_field_scaling(payload_size,seq_number_scaled,seq_number_residue);
				break;
			case PACKET_TCP_RND3:
				// tcp->ack_number = htonl( d_lsb(15,8191,ntohl(tcp_context->old_tcphdr.ack_number),ntohs(c_base_header.rnd3->ack_number)) );
										  #if __BYTE_ORDER == __LITTLE_ENDIAN
				wb.uint8[1] =
				   c_base_header.uint8[OFFSET_RND3_ACK_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_RND3_ACK_NUMBER & 0x07) ];
				wb.uint8[0] = c_base_header.uint8[(OFFSET_RND3_ACK_NUMBER >> 3) + 1];
										  #elif __BYTE_ORDER == __BIG_ENDIAN
				wb.uint8[0] =
				   c_base_header.uint8[OFFSET_RND3_ACK_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_RND3_ACK_NUMBER & 0x07) ];
				wb.uint8[1] = c_base_header.uint8[(OFFSET_RND3_ACK_NUMBER >> 3) + 1];
										  #endif
				tcp->ack_number =
				   htonl( d_lsb(15,8191,ntohl(tcp_context->old_tcphdr.ack_number),wb.uint16) );
				tcp->psh_flag = c_base_header.rnd3->psh_flag;
				break;
			case PACKET_TCP_RND4:
				ack_number_scaled = d_lsb(4,3,ntohl(
				                             tcp_context->old_tcphdr.ack_number),
				                          c_base_header.rnd4->ack_number_scaled);
				assert( tcp_context->ack_stride != 0 );
				tcp->ack_number = d_field_scaling(tcp_context->ack_stride,ack_number_scaled,
				                                  tcp_context->ack_number_residue);
				rohc_debugf(3, "ack_number_scaled %Xh ack_number_residue %Xh -> ack_number %Xh\n",
				            ack_number_scaled,tcp_context->ack_number_residue,ntohl(tcp->ack_number));
				tcp->psh_flag = c_base_header.rnd4->psh_flag;
				break;
			case PACKET_TCP_RND5:
				tcp->psh_flag = c_base_header.rnd5->psh_flag;
				// tcp->seq_number = htonl( d_lsb(14,8191,ntohl(tcp_context->old_tcphdr.seq_number),ntohs(c_base_header.rnd5->seq_number)) );
										  #if __BYTE_ORDER == __LITTLE_ENDIAN
				wb.uint8[1] = ( c_base_header.uint8[OFFSET_RND5_ACK_NUMBER >> 3] & 0x1F ) << 1;
				wb.uint8[1] |= c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 1] << 7;
				wb.uint8[0] = c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 1] << 1;
				wb.uint8[0] |= c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 2] >> 7;
										  #elif __BYTE_ORDER == __BIG_ENDIAN
				wb.uint8[0] = ( c_base_header.uint8[OFFSET_RND5_ACK_NUMBER >> 3] & 0x1F ) << 1;
				wb.uint8[0] |= c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 1] << 7;
				wb.uint8[1] = c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 1] << 1;
				wb.uint8[1] |= c_base_header.uint8[(OFFSET_RND5_ACK_NUMBER >> 3) + 2] >> 7;
										  #endif
				tcp->seq_number =
				   htonl( d_lsb(14,8191,ntohl(tcp_context->old_tcphdr.seq_number),wb.uint16) );
				rohc_debugf(3, "seq_number %Xh uint16 %4.4Xh b0 %2.2Xh b1 %2.2Xh\n",
				            ntohl(tcp->seq_number),wb.uint16,wb.uint8[0],wb.uint8[1]);
				// tcp->ack_number = htonl( d_lsb(15,8191,ntohl(tcp_context->old_tcphdr.ack_number),ntohs(c_base_header.rnd5->ack_number)) );
										  #if __BYTE_ORDER == __LITTLE_ENDIAN
				wb.uint8[1] = c_base_header.uint8[OFFSET_RND5_SEQ_NUMBER >> 3] & 0x7F;
				wb.uint8[0] = c_base_header.uint8[(OFFSET_RND5_SEQ_NUMBER >> 3) + 1] << 1;
										  #elif __BYTE_ORDER == __BIG_ENDIAN
				wb.uint8[0] = c_base_header.uint8[OFFSET_RND5_SEQ_NUMBER >> 3] & 0x7F;
				wb.uint8[1] = c_base_header.uint8[(OFFSET_RND5_SEQ_NUMBER >> 3) + 1] << 1;
										  #endif
				tcp->ack_number =
				   htonl( d_lsb(15,8191,ntohl(tcp_context->old_tcphdr.ack_number),wb.uint16) );
				rohc_debugf(3, "ack_number %Xh uint16 %4.4Xh b0 %2.2Xh b1 %2.2Xh\n",
				            ntohl(tcp->ack_number),wb.uint16,wb.uint8[0],wb.uint8[1]);
				break;
			case PACKET_TCP_RND6:
				tcp->psh_flag = c_base_header.rnd6->psh_flag;
				tcp->ack_number =
				   htonl( d_lsb(16,16383,ntohl(tcp_context->old_tcphdr.ack_number),
				                ntohs(c_base_header.rnd6->ack_number)) );
				seq_number_scaled = d_lsb(4,7,tcp_context->seq_number_scaled,
				                          c_base_header.rnd6->seq_number_scaled);
				seq_number_scaled_used = 1;
				//  assert( payload_size != 0 );
				// A COMPLETER/REVOIR
				// tcp->seq_number = d_field_scaling(payload_size,seq_number_scaled,seq_number_residue);
				break;
			case PACKET_TCP_RND7:
			{
				u_int32_t ack_number;
				// tcp->ack_number = htonl( d_lsb(18,65535,ntohl(tcp_context->old_tcphdr.ack_number),ntohl(c_base_header.rnd7->ack_number)) );
				ack_number = ( c_base_header.rnd7->ack_number1 << 16 ) | ntohs(
				   c_base_header.rnd7->ack_number2);
				tcp->ack_number =
				   htonl( d_lsb(18,65535,ntohl(tcp_context->old_tcphdr.ack_number),ack_number) );
			}
				tcp->window = c_base_header.rnd7->window;
				tcp->psh_flag = c_base_header.rnd7->psh_flag;
				break;
			case PACKET_TCP_RND8:
				tcp->rsf_flags = rsf_index_dec( c_base_header.rnd8->rsf_flags );
				tcp->psh_flag = c_base_header.rnd8->psh_flag;
				ttl_hopl = d_lsb(3,3,ip_inner_context.vx->ttl_hopl,c_base_header.rnd8->ttl_hopl);
				if(ip_inner_context.vx->version == IPV4)
				{
					base_header.ipv4->ttl_hopl = ttl_hopl;
				}
				else
				{
					base_header.ipv6->ttl_hopl = ttl_hopl;
				}
				rohc_debugf(3, "ecn_used %d\n",c_base_header.rnd8->ecn_used);
				tcp_context->ecn_used = c_base_header.rnd8->ecn_used;
				tcp->seq_number =
				   htonl( d_lsb(16,65535,ntohl(tcp_context->old_tcphdr.seq_number),
				                ntohs(c_base_header.rnd8->seq_number)) );
				tcp->ack_number =
				   htonl( d_lsb(16,16383,ntohl(tcp_context->old_tcphdr.ack_number),
				                ntohs(c_base_header.rnd8->ack_number)) );
				if(c_base_header.rnd8->list_present)
				{
					rohc_debugf(3, "compressed TCP options at %p:\n",mptr.uint8);
					TraceData(mptr.uint8,10);
					// options
					mptr.uint8 = tcp_decompress_tcp_options(tcp_context,tcp,mptr.uint8);
					rohc_debugf(3, "End of compressed TCP options at %p:\n",mptr.uint8);
				}
				else
				{
					rohc_debugf(3, "No compressed TCP options. %p\n",mptr.uint8);
					tcp->data_offset = sizeof(tcphdr_t) >> 2;
				}
				break;
			case PACKET_TCP_SEQ1:
				ip_id.uint16 =
				   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,4,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq1->ip_id,
				               msn);
				rohc_debugf(3, "old seq_number %Xh\n",ntohl(tcp_context->old_tcphdr.seq_number));
				tcp->seq_number =
				   htonl( d_lsb(16,32767,ntohl(tcp_context->old_tcphdr.seq_number),
				                ntohs(c_base_header.seq1->seq_number)) );
				tcp->psh_flag = c_base_header.seq1->psh_flag;
				goto all_seq;
			case PACKET_TCP_SEQ2:
										  #if __BYTE_ORDER == __LITTLE_ENDIAN
				{
					u_int8_t ip_id_lsb;
					ip_id_lsb = ( c_base_header.seq2->ip_id1 << 4 ) | c_base_header.seq2->ip_id2;
					ip_id.uint16 =
					   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,7,3,
					               ip_inner_context.v4->last_ip_id,
					               ip_id_lsb,
					               msn);
				}
										  #elif __BYTE_ORDER == __BIG_ENDIAN
				ip_id.uint16 =
				   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,7,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq2->ip_id,
				               msn);
										  #endif
				seq_number_scaled = d_lsb(4,7,tcp_context->seq_number_scaled,
				                          c_base_header.seq2->seq_number_scaled);
				seq_number_scaled_used = 1;
				tcp->psh_flag = c_base_header.seq2->psh_flag;
				//  assert( payload_size != 0 );
				// A COMPLETER/REVOIR
				// tcp->seq_number = d_field_scaling(payload_size,seq_number_scaled,seq_number_residue);
				goto all_seq;
			case PACKET_TCP_SEQ3:
				ip_id.uint16 =
				   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,4,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq3->ip_id,
				               msn);
				tcp->ack_number =
				   htonl( d_lsb(16,16383,ntohl(tcp_context->old_tcphdr.ack_number),
				                ntohs(c_base_header.seq3->ack_number)) );
				tcp->psh_flag = c_base_header.seq3->psh_flag;
				goto all_seq;
			case PACKET_TCP_SEQ4:
				ack_number_scaled = d_lsb(4,3,ntohl(
				                             tcp_context->old_tcphdr.ack_number),
				                          c_base_header.seq4->ack_number_scaled);
				assert( tcp_context->ack_stride != 0 );
				tcp->ack_number = d_field_scaling(tcp_context->ack_stride,ack_number_scaled,
				                                  tcp_context->ack_number_residue);
				rohc_debugf(3, "ack_number_scaled %Xh ack_number_residue %Xh -> ack_number %Xh\n",
				            ack_number_scaled,tcp_context->ack_number_residue,ntohl(tcp->ack_number));
				ip_id.uint16 =
				   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,3,1,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq4->ip_id,
				               msn);
				tcp->psh_flag = c_base_header.seq4->psh_flag;
				goto all_seq;
			case PACKET_TCP_SEQ5:
				ip_id.uint16 =
				   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,4,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq5->ip_id,
				               msn);
				tcp->ack_number =
				   htonl( d_lsb(16,16383,ntohl(tcp_context->old_tcphdr.ack_number),
				                ntohs(c_base_header.seq5->ack_number)) );
				tcp->seq_number =
				   htonl( d_lsb(16,32767,ntohl(tcp_context->old_tcphdr.seq_number),
				                ntohs(c_base_header.seq5->seq_number)) );
				tcp->psh_flag = c_base_header.seq5->psh_flag;
				goto all_seq;
			case PACKET_TCP_SEQ6:
										  #if __BYTE_ORDER == __LITTLE_ENDIAN
				{
					u_int8_t seq_number_scaled_lsb;
					seq_number_scaled_lsb =
					   ( c_base_header.seq6->seq_number_scaled1 <<
					     1 ) | c_base_header.seq6->seq_number_scaled2;
					seq_number_scaled = d_lsb(4,7,tcp_context->seq_number_scaled,seq_number_scaled_lsb);
				}
										  #elif __BYTE_ORDER == __BIG_ENDIAN
				seq_number_scaled = d_lsb(4,7,tcp_context->seq_number_scaled,
				                          c_base_header.seq6->seq_number_scaled);
										  #endif
				seq_number_scaled_used = 1;
				//  assert( payload_size != 0 );
				// A COMPLETER/REVOIR
				// tcp->seq_number = d_field_scaling(payload_size,seq_number_scaled,seq_number_residue);
				ip_id.uint16 =
				   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,7,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq6->ip_id,
				               msn);
				tcp->ack_number =
				   htonl( d_lsb(16,16383,ntohl(tcp_context->old_tcphdr.ack_number),
				                ntohs(c_base_header.seq6->ack_number)) );
				tcp->psh_flag = c_base_header.seq6->psh_flag;
				goto all_seq;
			case PACKET_TCP_SEQ7:
			{
				u_int16_t window;
				// tcp->window = htons( d_lsb(15,16383,ntohs(tcp_context->old_tcphdr.window),ntohs(c_base_header.seq7->window)) );
				window =
				   ( c_base_header.seq7->window1 <<
				     11 ) | ( c_base_header.seq7->window2 << 3 ) | c_base_header.seq7->window3;
				tcp->window = htons( d_lsb(15,16383,ntohs(tcp_context->old_tcphdr.window),window) );
			}
				rohc_debugf(3, "last_ip_id %4.4Xh seq7->ip_id %Xh\n",
				            ip_inner_context.v4->last_ip_id.uint16,
				            c_base_header.seq7->ip_id);
				ip_id.uint16 =
				   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,5,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq7->ip_id,
				               msn);
				rohc_debugf(3, "ip_id %4.4Xh\n",ip_id.uint16);
				tcp->ack_number =
				   htonl( d_lsb(16,32767,ntohl(tcp_context->old_tcphdr.ack_number),
				                ntohs(c_base_header.seq7->ack_number)) );
				tcp->psh_flag = c_base_header.seq7->psh_flag;
				goto all_seq;
			case PACKET_TCP_SEQ8:
				ip_id.uint16 =
				   d_ip_id_lsb(ip_inner_context.v4->ip_id_behavior,4,3,ip_inner_context.v4->last_ip_id,
				               c_base_header.seq8->ip_id,
				               msn);
				tcp->psh_flag = c_base_header.seq8->psh_flag;
				ttl_hopl = d_lsb(3,3,ip_inner_context.vx->ttl_hopl,c_base_header.seq8->ttl_hopl);
				if(ip_inner_context.vx->version == IPV4)
				{
					base_header.ipv4->ttl_hopl = ttl_hopl;
				}
				else
				{
					base_header.ipv6->ttl_hopl = ttl_hopl;
				}
				rohc_debugf(3, "ecn_used %d\n",c_base_header.seq8->ecn_used);
				tcp_context->ecn_used = c_base_header.seq8->ecn_used;
				// tcp->ack_number = htonl( d_lsb(15,8191,ntohl(tcp_context->old_tcphdr.ack_number),ntohs(c_base_header.seq8->ack_number)) );
										  #if __BYTE_ORDER == __LITTLE_ENDIAN
				wb.uint8[1] =
				   c_base_header.uint8[OFFSET_SEQ8_ACK_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_SEQ8_ACK_NUMBER & 0x07) ];
				wb.uint8[0] = c_base_header.uint8[(OFFSET_SEQ8_ACK_NUMBER >> 3) + 1];
										  #elif __BYTE_ORDER == __BIG_ENDIAN
				wb.uint8[0] =
				   c_base_header.uint8[OFFSET_SEQ8_ACK_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_SEQ8_ACK_NUMBER & 0x07) ];
				wb.uint8[1] = c_base_header.uint8[(OFFSET_SEQ8_ACK_NUMBER >> 3) + 1];
										  #endif
				tcp->ack_number =
				   htonl( d_lsb(15,8191,ntohl(tcp_context->old_tcphdr.ack_number),wb.uint16) );
				rohc_debugf(3, "For ack_number: b0 %2.2Xh b1 %2.2Xh => %4.4Xh ack_number %Xh\n",
				            wb.uint8[0],wb.uint8[1],wb.uint16,ntohl(
				               tcp->ack_number));
				tcp->rsf_flags = rsf_index_dec( c_base_header.seq8->rsf_flags );
				// tcp->seq_number = htonl( d_lsb(14,8191,ntohl(tcp_context->old_tcphdr.seq_number),ntohs(c_base_header.seq8->seq_number)) );
										  #if __BYTE_ORDER == __LITTLE_ENDIAN
				wb.uint8[1] =
				   c_base_header.uint8[OFFSET_SEQ8_SEQ_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_SEQ8_SEQ_NUMBER & 0x07) ];
				wb.uint8[0] = c_base_header.uint8[(OFFSET_SEQ8_SEQ_NUMBER >> 3) + 1];
										  #elif __BYTE_ORDER == __BIG_ENDIAN
				wb.uint8[0] =
				   c_base_header.uint8[OFFSET_SEQ8_SEQ_NUMBER >>
				                       3] & lsb_masks[ 8 - (OFFSET_SEQ8_SEQ_NUMBER & 0x07) ];
				wb.uint8[1] = c_base_header.uint8[(OFFSET_SEQ8_SEQ_NUMBER >> 3) + 1];
										  #endif
				tcp->seq_number =
				   htonl( d_lsb(14,8191,ntohl(tcp_context->old_tcphdr.seq_number),wb.uint16) );
				rohc_debugf(3, "For seq_number: b0 %2.2Xh b1 %2.2Xh => %4.4Xh seq_number %Xh\n",
				            wb.uint8[0],wb.uint8[1],wb.uint16,ntohl(
				               tcp->seq_number));
				if(c_base_header.seq8->list_present)
				{
					// options
					mptr.uint8 = tcp_decompress_tcp_options(tcp_context,tcp,mptr.uint8);
				}
				else
				{
					tcp->data_offset = sizeof(tcphdr_t) >> 2;
				}
all_seq:
				rohc_debugf(3, "ip_id %4.4Xh\n",ip_id.uint16);
				if(ip_inner_context.v4->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL)
				{
					// IP_ID_BEHAVIOR_SEQUENTIAL
					base_header_inner.ipv4->ip_id = htons(ip_id.uint16);
					ip_inner_context.v4->last_ip_id.uint16 = ip_id.uint16;
				}
				else
				{
					WB_t swapped_ip_id;

					// IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED
					swapped_ip_id.uint8[0] = ip_id.uint8[1];
					swapped_ip_id.uint8[1] = ip_id.uint8[0];
					base_header_inner.ipv4->ip_id = htons(swapped_ip_id.uint16);
					ip_inner_context.v4->last_ip_id.uint16 = swapped_ip_id.uint16;
				}
				rohc_debugf(3, "new last IP-ID %4.4Xh\n",ip_context.v4->last_ip_id.uint16);
				break;
			default:
				msn = 0;
				break;
		}
	}

	rohc_debugf(3, "Current IP packet:\n");
	TraceData(dest,uncomp_header_len + sizeof(tcphdr_t));

	tcp_context->msn = msn;

	// Now decode irregular chain
	rohc_remain_data = mptr.uint8;

	base_header.uint8 = (u_int8_t*) dest;
	ip_context.uint8 = tcp_context->ip_context;

	do
	{

		mptr.uint8 = tcp_decode_irregular_ip(tcp_context,ip_context,base_header,mptr,
		                                     base_header.uint8 == base_header_inner.uint8, // int is_innermost,
		                                     ttl_irregular_chain_flag,
		                                     ip_inner_ecn);

		if(ip_context.vx->version == IPV4)
		{
			protocol = ip_context.v4->protocol;
			++base_header.ipv4;
			++ip_context.v4;
		}
		else
		{
			protocol = ip_context.v6->next_header;
			++base_header.ipv6;
			++ip_context.v6;
		}

		assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );

	}
	while(protocol != IPPROTO_TCP);


	mptr.uint8 = tcp_decode_irregular_tcp(tcp_context,base_header_inner,tcp,mptr.uint8);

	// Add irregular chain length
	rohc_header_len += mptr.uint8 - rohc_remain_data;

	uncomp_header_len += tcp->data_offset << 2;
	rohc_debugf(3, "uncomp_header_len %d (+%d)\n",uncomp_header_len,tcp->data_offset << 2);
	payload_len = rohc_length - ( mptr.uint8 - (u_int8_t*) rohc_packet );
	rohc_debugf(3, "size compressed %d\n",(int)( mptr.uint8 - (u_int8_t*) rohc_packet ));
	rohc_debugf(3, "size IP header v4 %d V6 %d TCP header %d\n",(int)sizeof(base_header_ip_v4_t),
	            (int)sizeof(base_header_ip_v6_t),(int)sizeof(tcphdr_t));
	rohc_debugf(3, "uncomp_header_length %d payload_len %d total %d\n",uncomp_header_len,payload_len,
	            uncomp_header_len + payload_len);
	rohc_debugf(3, "rohc_packet %p end compressed header %p size %d\n",rohc_packet,mptr.uint8,
	            (int)(mptr.uint8 - (u_int8_t*)rohc_packet));

	if(payload_len != 0)
	{
		rohc_debugf(3, "payload len %d data:\n",payload_len);
		TraceData(mptr.uint8,payload_len);
	}

	if(seq_number_scaled_used != 0)
	{
		assert( payload_len != 0 );
		tcp->seq_number = htonl(
		   ( seq_number_scaled * payload_len ) + tcp_context->seq_number_residue );
		rohc_debugf(3, "seq_number_scaled %Xh seq_number_residue %Xh -> seq_number %Xh\n",
		            seq_number_scaled,tcp_context->seq_number_residue,ntohl(tcp->seq_number));
	}

	base_header.uint8 = (u_int8_t*) dest;
	ip_context.uint8 = tcp_context->ip_context;
	size = uncomp_header_len + payload_len;

	do
	{

		if(ip_context.vx->version == IPV4)
		{
			base_header.ipv4->df = ip_context.v4->df;
			base_header.ipv4->length = htons(size);
			base_header.ipv4->checksum = 0;
			base_header.ipv4->checksum = my_ip_fast_csum(base_header.uint8,
			                                             base_header.ipv4->header_length);
//			base_header.ipv4->checksum = ip_fast_csum(base_header.uint8,base_header.ipv4->header_length);
			rohc_debugf(3, "IP checksum = 0x%04x for %d\n", ntohs(
			               base_header.ipv4->checksum), base_header.ipv4->header_length);
			TraceIpV4(base_header.ipv4);
			protocol = ip_context.v4->protocol;
			size -= sizeof(base_header_ip_v4_t);
			++base_header.ipv4;
			++ip_context.v4;
		}
		else
		{
			// A REVOIR ->payload_length
			base_header.ipv6->payload_length = htons( ( tcp->data_offset << 2 ) + payload_len );
			rohc_debugf(3, "payload_length %d\n",ntohs(base_header.ipv6->payload_length));
			/*
			base_header.ipv6->payload_length = htons( length - sizeof(base_header_ip_v6_t) );
			rohc_debugf(3, "payload_length %d\n",ntohs(base_header.ipv6->payload_length));
			*/
			TraceIpV6(base_header.ipv6);
			protocol = ip_context.v6->next_header;
			size -= sizeof(base_header_ip_v6_t);
			++base_header.ipv6;
			++ip_context.v6;
		}

		assert( ip_context.uint8 < &tcp_context->ip_context[MAX_IP_CONTEXT_SIZE] );

	}
	while(protocol != IPPROTO_TCP);

	rohc_debugf(3, "Current IP+TCP packet:\n");
	if(ip_context.vx->version == IPV4)
	{
		TraceData(dest,sizeof(base_header_ip_v4_t) + sizeof(tcphdr_t));
	}
	else
	{
		TraceData(dest,sizeof(base_header_ip_v6_t) + sizeof(tcphdr_t));
	}

	memcpy(&tcp_context->old_tcphdr,tcp,sizeof(tcphdr_t));

	size = tcp->data_offset << 2;
	rohc_debugf(3, "TCP header size %d %Xh\n",size,size);
	rohc_debugf(3, "Current IP+TCP packet:\n");
	TraceData(dest,(int)(((unsigned char*)tcp) - dest) + size);

	TraceTcp(tcp);

	rohc_debugf(3, "uncomp_header_len %d %Xh\n",uncomp_header_len,uncomp_header_len);

	// A REVOIR DBX !!!
	context->state = FULL_CONTEXT;

	rohc_debugf(3, "size_header %d size_options %d rohc_length %d\n",size_header,size_options,
	            rohc_length);

	/* copy the payload */
	rohc_debugf(3, "ROHC payload (length = %u bytes) starts at offset %u\n",
	            payload_len, rohc_header_len);

	if((rohc_header_len + payload_len) != rohc_length)
	{
		rohc_debugf(0, "ROHC CO header (%u bytes) and payload (%u bytes) "
		            "do not match the full ROHC CO packet (%u bytes)\n",
		            rohc_header_len, payload_len, rohc_length);
		goto error;
	}
	if(payload_len != 0)
	{
		memcpy(((u_int8_t*)(tcp)) + size, mptr.uint8, payload_len);
	}

	memcpy(&tcp_context->old_tcphdr,tcp,sizeof(tcphdr_t));
	rohc_debugf(3, "tcp %p save seq_number %Xh ack_number %Xh\n",tcp,
	            ntohl(tcp_context->old_tcphdr.seq_number),ntohl(tcp_context->old_tcphdr.ack_number));

	/* statistics */
	context->header_compressed_size += rohc_header_len;
	c_add_wlsb(context->header_16_compressed, 0, rohc_header_len);
	context->header_uncompressed_size += uncomp_header_len;
	c_add_wlsb(context->header_16_uncompressed, 0, uncomp_header_len);

	return (uncomp_header_len + payload_len);

error:
	return ROHC_ERROR;
}


/**
 * @brief Get the reference MSN value of the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference MSN value
 */
int d_tcp_get_msn(struct d_context *context)
{
	struct d_generic_context *g_context = context->specific;
	struct d_tcp_context *tcp_context = g_context->specific;

	rohc_debugf(3, "return %Xh\n",tcp_context->msn);

	return tcp_context->msn;
}


/**
 * @brief Define the decompression part of the TCP profile as described
 *        in the RFC 3095.
 */
struct d_profile d_tcp_profile =
{
	ROHC_PROFILE_TCP,       /* profile ID (see 8 in RFC 3095) */
	"TCP / Decompressor",   /* profile description */
	d_tcp_decode,           /* profile handlers */
	d_tcp_create,
	d_tcp_destroy,
	d_tcp_get_msn
};

