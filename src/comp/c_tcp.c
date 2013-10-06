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
 * @file   c_tcp.c
 * @brief  ROHC compression context for the TCP profile.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "rohc_traces_internal.h"
#include "rohc_utils.h"
#include "rohc_packets.h"
#include "protocols/tcp.h"
#include "schemes/cid.h"
#include "schemes/rfc4996.h"
#include "sdvl.h"
#include "crc.h"
#include "c_generic.h"
#include "c_ip.h"

#include <assert.h>
#include <stdlib.h>
#ifdef __KERNEL__
#	include <endian.h>
#else
#	include <string.h>
#endif

#include "config.h" /* for WORDS_BIGENDIAN and ROHC_EXTRA_DEBUG */


#define MAX_TCP_OPTION_INDEX 16

#if ROHC_EXTRA_DEBUG == 1
#define TRACE_GOTO_CHOICE \
	rohc_comp_debug(context, "Compressed format choice LINE %d\n", __LINE__ )
#else
#define TRACE_GOTO_CHOICE
#endif


/**
 * @brief Define the TCP-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the TCP-specific decompression context
 * sc_tcp_context.
 *
 * @see sc_tcp_context
 */
struct tcp_tmp_variables
{
#ifdef TODO  // DBX
	/// The number of TCP fields that changed in the TCP header
	int send_tcp_dynamic;
#endif

	/** The minimal number of bits required to encode the TCP sequence number
	 *  with p = 65535 */
	size_t nr_seq_bits_65535;
	/** The minimal number of bits required to encode the TCP sequence number
	 *  with p = 32767 */
	size_t nr_seq_bits_32767;
	/** The minimal number of bits required to encode the TCP sequence number
	 *  with p = 8191 */
	size_t nr_seq_bits_8191;

	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo request with p = -1 */
	size_t nr_opt_ts_req_bits_minus_1;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo request with p = 0x40000 */
	size_t nr_opt_ts_req_bits_0x40000;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo reply with p = -1 */
	size_t nr_opt_ts_reply_bits_minus_1;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo reply with p = 0x40000 */
	size_t nr_opt_ts_reply_bits_0x40000;
};

#define MAX_IPV6_OPTION_LENGTH        6   // FOR Destination/Hop-by-Hop/Routing/ah
#define MAX_IPV6_CONTEXT_OPTION_SIZE  (2 + ((MAX_IPV6_OPTION_LENGTH + 1) << 3))


/**
 * @brief Define the IPv6 generic option context.
 */
typedef struct __attribute__((packed)) ipv6_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;
	uint8_t length;

	uint8_t value[1];
} ipv6_option_context_t;


/**
 * @brief Define the IPv6 GRE option context.
 */
typedef struct __attribute__((packed)) ipv6_gre_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;

	uint8_t c_flag : 1;
	uint8_t k_flag : 1;
	uint8_t s_flag : 1;
	uint8_t padding : 5;

	uint16_t protocol;

	uint32_t key;               // if k_flag set
	uint32_t sequence_number;   // if s_flag set

} ipv6_gre_option_context_t;


/**
 * @brief Define the IPv6 MIME option context.
 */
typedef struct __attribute__((packed)) ipv6_mime_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;

	uint8_t s_bit : 1;
	uint8_t res_bits : 7;
	uint16_t checksum;
	uint32_t orig_dest;
	uint32_t orig_src;         // if s_bit set

} ipv6_mime_option_context_t;


/**
 * @brief Define the IPv6 AH option context.
 */
typedef struct __attribute__((packed)) ipv6_ah_option_context
{
	uint8_t context_length;
	uint8_t option_length;

	uint8_t next_header;

	uint8_t length;
	uint32_t spi;
	uint32_t sequence_number;
	uint32_t auth_data[1];
} ipv6_ah_option_context_t;


/**
 * @brief Define the common IP header context to IPv4 and IPv6.
 */
typedef struct __attribute__((packed)) ipvx_context
{
	uint8_t version : 4;
	uint8_t unused : 4;

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;

} ipvx_context_t;


/**
 * @brief Define the IPv4 header context.
 */
typedef struct __attribute__((packed)) ipv4_context
{
	uint8_t version : 4;
	uint8_t df : 1;
	uint8_t unused : 3;

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t protocol;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;
	uint16_t last_ip_id;

	uint32_t src_addr;
	uint32_t dst_addr;

} ipv4_context_t;


/**
 * @brief Define the IPv6 header context.
 */
typedef struct __attribute__((packed)) ipv6_context
{
	uint8_t version : 4;
	uint8_t unused : 4;

	uint8_t dscp : 6;
	uint8_t ip_ecn_flags : 2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;

	uint8_t flow_label1 : 4;
	uint16_t flow_label2;

	uint32_t src_addr[4];
	uint32_t dest_addr[4];

} ipv6_context_t;


/**
 * @brief Define union of IP contexts pointers.
 *
 * TODO: merge with same definition in d_tcp.h
 */
typedef union
{
	uint8_t *uint8;
	ipvx_context_t *vx;
	ipv4_context_t *v4;
	ipv6_context_t *v6;
	ipv6_option_context_t *v6_option;
	ipv6_gre_option_context_t *v6_gre_option;
	ipv6_mime_option_context_t *v6_mime_option;
	ipv6_ah_option_context_t *v6_ah_option;
} ip_context_ptr_t;


/**
 * @brief Define the TCP part of the profile decompression context.
 *
 * This object must be used with the generic part of the decompression
 * context c_generic_context.
 *
 * @see c_generic_context
 */
struct sc_tcp_context
{
	/// The number of times the sequence number field was added to the compressed header
	int tcp_seq_number_change_count;

	// Explicit Congestion Notification used
	uint8_t ecn_used;

	uint32_t tcp_last_seq_number;

	uint16_t window;

	uint32_t seq_number;
	struct c_wlsb *seq_wlsb;

	uint32_t ack_number;

	uint32_t seq_number_scaled;
	uint32_t seq_number_residue;

	uint16_t ack_stride;
	uint32_t ack_number_scaled;
	uint32_t ack_number_residue;

	uint8_t tcp_options_list[16];         // see RFC4996 page 27
	uint8_t tcp_options_offset[16];
	uint16_t tcp_option_maxseg;
	uint8_t tcp_option_window;

	struct tcp_option_timestamp tcp_option_timestamp;
	bool tcp_option_timestamp_init;
	struct c_wlsb *opt_ts_req_wlsb;
	struct c_wlsb *opt_ts_reply_wlsb;

	uint8_t tcp_option_sack_length;
	sack_block_t tcp_option_sackblocks[4];
	uint8_t tcp_options_free_offset;
#define MAX_TCP_OPT_SIZE 64
	uint8_t tcp_options_values[MAX_TCP_OPT_SIZE];

	/// The previous TCP header
	tcphdr_t old_tcphdr;

	/// @brief TCP-specific temporary variables that are used during one single
	///        compression of packet
	struct tcp_tmp_variables tmp;

	uint8_t ip_context[1];
};


/*
 * Private datas.
 */

/**
 * @brief Table of TCP option index, from option Id
 *
 * See RFC4996 6.3.4
 * Return item index of TCP option
 */

unsigned char tcp_options_index[16] =
{
	TCP_INDEX_EOL,             // TCP_OPT_EOL             0
	TCP_INDEX_NOP,             // TCP_OPT_NOP             1
	TCP_INDEX_MAXSEG,          // TCP_OPT_MAXSEG          2
	TCP_INDEX_WINDOW,          // TCP_OPT_WINDOW          3
	TCP_INDEX_SACK_PERMITTED,  // TCP_OPT_SACK_PERMITTED  4  (experimental)
	TCP_INDEX_SACK,            // TCP_OPT_SACK            5  (experimental)
	7,                         // TODO ?                  6
	8,                         // TODO ?                  7
	TCP_INDEX_TIMESTAMP,       // TCP_OPT_TIMESTAMP       8
	9,                         // TODO ?                  9
	10,                        // TODO ?                 10
	11,                        // TODO ?                 11
	12,                        // TODO ?                 12
	13,                        // TODO ?                 13
	14,                        // TODO ?                 14
	15                         // TODO ?                 15
};


/*
 * Private function prototypes.
 */

static bool c_tcp_create(struct c_context *const context,
                         const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void c_tcp_destroy(struct c_context *const context)
	__attribute__((nonnull(1)));

static bool c_tcp_check_profile(const struct rohc_comp *const comp,
                                const struct ip_packet *const outer_ip,
                                const struct ip_packet *const inner_ip,
                                const uint8_t protocol,
                                rohc_ctxt_key_t *const ctxt_key)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));

static bool c_tcp_check_context(const struct c_context *const context,
                                const struct ip_packet *const ip)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int c_tcp_encode(struct c_context *const context,
                        const struct ip_packet *ip,
                        const size_t packet_size,
                        unsigned char *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        int *const payload_offset);

#ifdef TODO
static void tcp_decide_state(struct c_context *const context);
#endif

static uint8_t * tcp_code_static_ipv6_option_part(struct c_context *const context,
																  ip_context_ptr_t ip_context,
																  multi_ptr_t mptr,
																  uint8_t protocol,
																  base_header_ip_t base_header,
																  const int packet_size);
static uint8_t * tcp_code_dynamic_ipv6_option_part(struct c_context *const context,
																	ip_context_ptr_t ip_context,
																	multi_ptr_t mptr,
																	uint8_t protocol,
																	base_header_ip_t base_header,
																	const int packet_size);
static uint8_t * tcp_code_irregular_ipv6_option_part(struct c_context *const context,
																	  ip_context_ptr_t ip_context,
																	  multi_ptr_t mptr,
																	  uint8_t protocol,
																	  base_header_ip_t base_header,
																	  const int packet_size);
static uint8_t * tcp_code_static_ip_part(struct c_context *const context,
                                         ip_context_ptr_t ip_context,
                                         base_header_ip_t base_header,
                                         const int packet_size,
                                         multi_ptr_t mptr);
static uint8_t * tcp_code_dynamic_ip_part(const struct c_context *context,
                                          ip_context_ptr_t ip_context,
                                          base_header_ip_t base_header,
                                          const int packet_size,
                                          multi_ptr_t mptr,
                                          int is_innermost);
static uint8_t * tcp_code_irregular_ip_part(struct c_context *const context,
                                            ip_context_ptr_t ip_context,
                                            base_header_ip_t base_header,
                                            const int packet_size,
                                            uint8_t *rohc_data,
                                            int ecn_used,
                                            int is_innermost,
                                            int ttl_irregular_chain_flag,
                                            int ip_inner_ecn);

static uint8_t * tcp_code_static_tcp_part(const struct c_context *context,
                                           const tcphdr_t *tcp,
                                           multi_ptr_t mptr);
static uint8_t * tcp_code_dynamic_tcp_part(const struct c_context *context,
                                            const unsigned char *next_header,
                                            multi_ptr_t mptr);
static uint8_t * tcp_code_irregular_tcp_part(struct c_context *const context,
                                             tcphdr_t *tcp,
                                             uint8_t *const rohc_data,
                                             int ip_inner_ecn);

static int code_CO_packet(struct c_context *const context,
                          const struct ip_packet *ip,
                          const int packet_size,
                          const unsigned char *next_header,
                          unsigned char *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          rohc_packet_t *const packet_type,
                          int *const payload_offset);
static int co_baseheader(struct c_context *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_ptr_t ip_inner_context,
                         base_header_ip_t base_header,
                         unsigned char *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         rohc_packet_t *const packet_type,
                         int size_payload,
                         int ttl_irregular_chain_flag)
	__attribute__((nonnull(1, 2, 5, 7), warn_unused_result));


/*
 * Functions that build the rnd_X packets
 */

static size_t c_tcp_build_rnd_1(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_1_t *const rnd1)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static size_t c_tcp_build_rnd_2(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_2_t *const rnd2)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static size_t c_tcp_build_rnd_3(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_3_t *const rnd3)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static size_t c_tcp_build_rnd_4(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_4_t *const rnd4)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static size_t c_tcp_build_rnd_5(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_5_t *const rnd5)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static size_t c_tcp_build_rnd_6(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_6_t *const rnd6)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static size_t c_tcp_build_rnd_7(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_7_t *const rnd7)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static bool c_tcp_build_rnd_8(struct c_context *const context,
										const ip_context_ptr_t ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										rnd_8_t *const rnd8,
										size_t *const rnd8_len)
	__attribute__((nonnull(1, 3, 5, 6, 7), warn_unused_result));


/*
 * Functions that build the seq_X packets
 */

static size_t c_tcp_build_seq_1(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_1_t *const seq1)
	__attribute__((nonnull(1, 3, 5, 6), warn_unused_result));

static size_t c_tcp_build_seq_2(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_2_t *const seq2)
	__attribute__((nonnull(1, 3, 5, 6), warn_unused_result));

static size_t c_tcp_build_seq_3(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_3_t *const seq3)
	__attribute__((nonnull(1, 3, 5, 6), warn_unused_result));

static size_t c_tcp_build_seq_4(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_4_t *const seq4)
	__attribute__((nonnull(1, 3, 5, 6), warn_unused_result));

static size_t c_tcp_build_seq_5(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_5_t *const seq5)
	__attribute__((nonnull(1, 3, 5, 6), warn_unused_result));

static size_t c_tcp_build_seq_6(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_6_t *const seq6)
	__attribute__((nonnull(1, 3, 5, 6), warn_unused_result));

static size_t c_tcp_build_seq_7(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_7_t *const seq7)
	__attribute__((nonnull(1, 3, 5, 6), warn_unused_result));

static bool c_tcp_build_seq_8(struct c_context *const context,
										const ip_context_ptr_t ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										seq_8_t *const seq8,
										size_t *const seq8_len)
	__attribute__((nonnull(1, 3, 5, 6, 7), warn_unused_result));


/*
 * Misc functions
 */

static bool tcp_compress_tcp_options(struct c_context *const context,
												 const tcphdr_t *const tcp,
												 uint8_t *const comp_opts,
												 size_t *const comp_opts_len)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));



/**
 * @brief Create a new TCP context and initialize it thanks to the given IP/TCP
 *        packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/TCP packet given to initialize the new context
 * @return        true if successful, false otherwise
 */
static bool c_tcp_create(struct c_context *const context,
                         const struct ip_packet *const ip)
{
	const struct rohc_comp *const comp = context->compressor;
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header;   // Source
	const tcphdr_t *tcp;
	uint8_t protocol;
	int size_context;
	int size_option;
	int size;

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_VAR, ip))
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "generic context creation failed\n");
		goto error;
	}
	g_context = (struct c_generic_context *) context->specific;

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *)ip->data;

	size = 0;
	size_context = 0;

	do
	{
		rohc_comp_debug(context, "base_header %p IP version %d\n",
		                base_header.uint8, base_header.ipvx->version);

		switch(base_header.ipvx->version)
		{
			case IPV4:
				// No option
				if(base_header.ipv4->header_length != 5)
				{
					goto free_context;
				}
				// No fragmentation
				if(base_header.ipv4->mf != 0 || base_header.ipv4->rf != 0)
				{
					goto free_context;
				}
				/* get the transport protocol */
				protocol = base_header.ipv4->protocol;
				size += sizeof(base_header_ip_v4_t);
				size_context += sizeof(ipv4_context_t);
				++base_header.ipv4;
				break;
			case IPV6:
				protocol = base_header.ipv6->next_header;
				size += sizeof(base_header_ip_v6_t);
				size_context += sizeof(ipv6_context_t);
				++base_header.ipv6;
				while(rohc_is_ipv6_opt(protocol))
				{
					switch(protocol)
					{
						case ROHC_IPPROTO_HOPOPTS: // IPv6 Hop-by-Hop options
							size_option = ( base_header.ipv6_opt->length + 1 ) << 3;
							size_context += MAX_IPV6_CONTEXT_OPTION_SIZE;
							break;
						case ROHC_IPPROTO_ROUTING: // IPv6 routing header
							size_option = ( base_header.ipv6_opt->length + 1 ) << 3;
							size_context += MAX_IPV6_CONTEXT_OPTION_SIZE;
							break;
						case ROHC_IPPROTO_GRE:
							size_option = base_header.ip_gre_opt->c_flag +
							              base_header.ip_gre_opt->k_flag +
							              base_header.ip_gre_opt->s_flag + 1;
							size_option <<= 3;
							size_context = sizeof(ipv6_gre_option_context_t);
							break;
						case ROHC_IPPROTO_DSTOPTS: // IPv6 destination options
							size_option = ( base_header.ipv6_opt->length + 1 ) << 3;
							size_context += MAX_IPV6_CONTEXT_OPTION_SIZE;
							break;
						case ROHC_IPPROTO_MINE:
							size_option = ( 2 + base_header.ip_mime_opt->s_bit ) << 3;
							size_context = sizeof(ipv6_mime_option_context_t);
							break;
						case ROHC_IPPROTO_AH:
							size_option = sizeof(ip_ah_opt_t) - sizeof(uint32_t) +
							              ( base_header.ip_ah_opt->length << 4 ) - sizeof(int32_t);
							size_context = sizeof(ipv6_ah_option_context_t);
							break;
						// case ROHC_IPPROTO_ESP : ???
						default:
							goto free_context;
					}
					protocol = base_header.ipv6_opt->next_header;
					size += size_option;
					base_header.uint8 += size_option;
				}
				break;
			default:
				goto free_context;
		}

	}
	while(rohc_is_tunneling(protocol) && size < ip->size);

	if(size >= ip->size)
	{
		goto free_context;
	}

	tcp = base_header.tcphdr;

	/* create the TCP part of the profile context */
	tcp_context = malloc(sizeof(struct sc_tcp_context) + size_context + 1);
	if(tcp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the TCP part of the profile context\n");
		goto free_context;
	}
	g_context->specific = tcp_context;

	/* initialize the specific context of the profile context */
	memset(tcp_context->ip_context,0,size_context);

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *)ip->data;
	ip_context.uint8 = tcp_context->ip_context;

	do
	{
		rohc_comp_debug(context, "base_header %p IP version %d\n",
		                base_header.uint8, base_header.ipvx->version);

		ip_context.vx->version = base_header.ipvx->version;
		rohc_comp_debug(context, "ip_context %p version %d\n",
		                ip_context.vx, ip_context.vx->version);

		switch(base_header.ipvx->version)
		{
			case IPV4:
				ip_context.v4->last_ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
				rohc_comp_debug(context, "IP-ID 0x%04x\n", ip_context.v4->last_ip_id);
				ip_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_UNKNOWN;
				/* get the transport protocol */
				protocol = base_header.ipv4->protocol;
				ip_context.v4->protocol = protocol;
				ip_context.v4->dscp = base_header.ipv4->dscp;
				ip_context.v4->df = base_header.ipv4->df;
				ip_context.v4->ttl_hopl = base_header.ipv4->ttl_hopl;
				ip_context.v4->src_addr = base_header.ipv4->src_addr;
				ip_context.v4->dst_addr = base_header.ipv4->dest_addr;
				++base_header.ipv4;
				++ip_context.v4;
				break;
			case IPV6:
				ip_context.v6->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
				/* get the transport protocol */
				protocol = base_header.ipv6->next_header;
				ip_context.v6->next_header = protocol;
				ip_context.v6->dscp = DSCP_V6(base_header.ipv6);
				ip_context.v6->ttl_hopl = base_header.ipv6->ttl_hopl;
				ip_context.v6->flow_label1 = base_header.ipv6->flow_label1;
				ip_context.v6->flow_label2 = base_header.ipv6->flow_label2;
				memcpy(ip_context.v6->src_addr,base_header.ipv6->src_addr,sizeof(uint32_t) * 4 * 2);
				++base_header.ipv6;
				++ip_context.v6;
				while(rohc_is_ipv6_opt(protocol))
				{
					switch(protocol)
					{
						case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
						case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
						case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
							size_option = ( base_header.ipv6_opt->length + 1 ) << 3;
							ip_context.v6_option->context_length = 2 + size_option;
							memcpy(&ip_context.v6_option->next_header,&base_header.ipv6_opt->next_header,
							       size_option);
							break;
						case ROHC_IPPROTO_GRE:
							ip_context.v6_gre_option->context_length = sizeof(ipv6_gre_option_context_t);
							ip_context.v6_gre_option->c_flag = base_header.ip_gre_opt->c_flag;
							ip_context.v6_gre_option->k_flag = base_header.ip_gre_opt->k_flag;
							ip_context.v6_gre_option->s_flag = base_header.ip_gre_opt->s_flag;
							ip_context.v6_gre_option->protocol = base_header.ip_gre_opt->protocol;
							ip_context.v6_gre_option->key =
							   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag];
							ip_context.v6_gre_option->sequence_number =
							   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag +
							                                 base_header.ip_gre_opt->k_flag];
							break;
						case ROHC_IPPROTO_MINE:
							ip_context.v6_mime_option->context_length = sizeof(ipv6_mime_option_context_t);
							ip_context.v6_mime_option->next_header = base_header.ipv6_opt->next_header;
							ip_context.v6_mime_option->s_bit = base_header.ip_mime_opt->s_bit;
							ip_context.v6_mime_option->res_bits = base_header.ip_mime_opt->res_bits;
							ip_context.v6_mime_option->checksum = base_header.ip_mime_opt->checksum;
							ip_context.v6_mime_option->orig_dest = base_header.ip_mime_opt->orig_dest;
							ip_context.v6_mime_option->orig_src = base_header.ip_mime_opt->orig_src;
							break;
						case ROHC_IPPROTO_AH:
							ip_context.v6_ah_option->context_length = sizeof(ipv6_ah_option_context_t);
							ip_context.v6_ah_option->next_header = base_header.ipv6_opt->next_header;
							ip_context.v6_ah_option->length = base_header.ip_ah_opt->length;
							ip_context.v6_ah_option->spi = base_header.ip_ah_opt->spi;
							ip_context.v6_ah_option->sequence_number =
							   base_header.ip_ah_opt->sequence_number;
							break;
						// case ROHC_IPPROTO_ESP : ???
						default:
							goto free_context;
					}
				}
				break;
			default:
				goto free_context;
		}

	}
	while(rohc_is_tunneling(protocol));

	// Last in chain
	ip_context.vx->version = 0;

	tcp_context->tcp_seq_number_change_count = 0;
	tcp_context->tcp_last_seq_number = -1;

	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(tcphdr_t));

	/* TCP sequence number */
	tcp_context->seq_number = rohc_ntoh32(tcp->seq_number);
	tcp_context->seq_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->seq_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP sequence number\n");
		goto free_context;
	}

	tcp_context->ack_number = rohc_ntoh32(tcp->ack_number);

	/* init the TCP-specific temporary variables DBX */
#ifdef TODO
	tcp_context->tmp_variables.send_tcp_dynamic = -1;
#endif

	/* init the Master Sequence Number to a random value */
	g_context->sn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "MSN = 0x%04x\n", g_context->sn);

	tcp_context->ack_stride = 0;

	// Initialize TCP options list index used
	memset(tcp_context->tcp_options_list,0xFF,16);

	tcp_context->tcp_option_timestamp_init = false;
	/* TCP option Timestamp (request) */
	tcp_context->opt_ts_req_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->opt_ts_req_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "request\n");
		goto free_wlsb_seq;
	}
	/* TCP option Timestamp (reply) */
	tcp_context->opt_ts_reply_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->opt_ts_reply_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "reply\n");
		goto free_wlsb_opt_ts_req;
	}

	/* init the TCP-specific variables and functions */
	g_context->next_header_proto = ROHC_IPPROTO_TCP;
	g_context->next_header_len = sizeof(tcphdr_t); // + options ???
#ifdef TODO
	g_context->decide_state = tcp_decide_state;
#endif
	g_context->decide_state = NULL;
	g_context->init_at_IR = NULL;
	g_context->get_next_sn = c_ip_get_next_sn;
	g_context->code_static_part = NULL;
#ifdef TODO
	g_context->code_dynamic_part = tcp_code_dynamic_tcp_part;
#endif
	g_context->code_dynamic_part = NULL;
	g_context->code_UO_packet_head = NULL;
	g_context->code_uo_remainder = NULL;
	g_context->compute_crc_static = tcp_compute_crc_static;
	g_context->compute_crc_dynamic = tcp_compute_crc_dynamic;

	return true;

free_wlsb_opt_ts_req:
	c_destroy_wlsb(tcp_context->opt_ts_req_wlsb);
free_wlsb_seq:
	c_destroy_wlsb(tcp_context->seq_wlsb);
free_context:
	c_generic_destroy(context);
error:
	return false;
}


/**
 * @brief Destroy the TCP context
 *
 * @param context  The TCP compression context to destroy
 */
static void c_tcp_destroy(struct c_context *const context)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	c_destroy_wlsb(tcp_context->opt_ts_reply_wlsb);
	c_destroy_wlsb(tcp_context->opt_ts_req_wlsb);
	c_destroy_wlsb(tcp_context->seq_wlsb);
	c_generic_destroy(context);
}


/**
 * @brief Check if the given packet corresponds to the TCP profile
 *
 * Conditions are:
 *  \li the transport protocol is TCP
 *  \li the version of the outer IP header is 4 or 6
 *  \li the outer IP header is not an IP fragment
 *  \li if there are at least 2 IP headers, the version of the inner IP header
 *      is 4 or 6
 *  \li if there are at least 2 IP headers, the inner IP header is not an IP
 *      fragment
 *
 * @see c_generic_check_profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param comp      The ROHC compressor
 * @param outer_ip  The outer IP header of the IP packet to check
 * @param inner_ip  One of the following 2 values:
 *                  \li The inner IP header of the IP packet to check if the IP
 *                      packet contains at least 2 IP headers,
 *                  \li NULL if the IP packet to check contains only one IP header
 * @param protocol  The transport protocol carried by the IP packet:
 *                    \li the protocol carried by the outer IP header if there
 *                        is only one IP header,
 *                    \li the protocol carried by the inner IP header if there
 *                        are at least two IP headers.
 * @param ctxt_key  The key to help finding the context associated with packet
 * @return          Whether the IP packet corresponds to the profile:
 *                    \li true if the IP packet corresponds to the profile,
 *                    \li false if the IP packet does not correspond to
 *                        the profile
 */
static bool c_tcp_check_profile(const struct rohc_comp *const comp,
                                const struct ip_packet *const outer_ip,
                                const struct ip_packet *const inner_ip,
                                const uint8_t protocol,
                                rohc_ctxt_key_t *const ctxt_key)
{
	const struct ip_packet *last_ip_header;
	const struct tcphdr *tcp_header;
	unsigned int ip_payload_size;
	bool ip_check;

	assert(comp != NULL);
	assert(outer_ip != NULL);
	assert(ctxt_key != NULL);

	/* check that the transport protocol is TCP */
	if(protocol != ROHC_IPPROTO_TCP)
	{
		goto bad_profile;
	}

	/* check that the the versions of outer and inner IP headers are 4 or 6
	   and that outer and inner IP headers are not IP fragments */
	ip_check = c_generic_check_profile(comp, outer_ip, inner_ip, protocol,
	                                   ctxt_key);
	if(!ip_check)
	{
		goto bad_profile;
	}

	/* determine the last IP header */
	if(inner_ip != NULL)
	{
		/* two IP headers, the last IP header is the inner IP header */
		last_ip_header = inner_ip;
	}
	else
	{
		/* only one IP header, last IP header is the outer IP header */
		last_ip_header = outer_ip;
	}

	/* IP payload shall be large enough for UDP header */
	ip_payload_size = ip_get_plen(last_ip_header);
	if(ip_payload_size < sizeof(struct tcphdr))
	{
		goto bad_profile;
	}

	/* retrieve the TCP header */
	tcp_header = (const struct tcphdr *) ip_get_next_layer(last_ip_header);
	if(ip_payload_size < (tcp_header->data_offset * 4))
	{
		goto bad_profile;
	}
	*ctxt_key ^= tcp_header->src_port;
	*ctxt_key ^= tcp_header->dst_port;

	return true;

bad_profile:
	return false;
}


/**
 * @brief Check if the IP/TCP packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match
 *    the ones in the context
 *  - the transport protocol must be TCP
 *  - the source and destination ports of the TCP header must match the ones
 *    in the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP/TCP packet to check
 * @return        true if the IP/TCP packet belongs to the context
 *                false if it does not belong to the context
 */
static bool c_tcp_check_context(const struct c_context *const context,
                                const struct ip_packet *const ip)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header;   // Source
	uint8_t protocol;
	tcphdr_t *tcp;
	bool is_tcp_same;
	int size;

	rohc_comp_debug(context, "context %p ip %p\n", context, ip);

	g_context = (struct c_generic_context *) context->specific;
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *)ip->data;
	ip_context.uint8 = tcp_context->ip_context;
	size = ip->size;

	do
	{
		rohc_comp_debug(context, "base_header %p IP version %d\n",
		                base_header.uint8, base_header.ipvx->version);

		if(base_header.ipvx->version != ip_context.vx->version)
		{
			rohc_comp_debug(context, "  not same IP version\n");
			goto bad_context;
		}

		switch(base_header.ipvx->version)
		{
			case IPV4:
				// No option
				if(base_header.ipv4->header_length != 5)
				{
					goto bad_context;
				}
				// No fragmentation
				if(base_header.ipv4->mf != 0 || base_header.ipv4->rf != 0)
				{
					goto bad_context;
				}
				if(base_header.ipv4->src_addr != ip_context.v4->src_addr ||
				   base_header.ipv4->dest_addr != ip_context.v4->dst_addr)
				{
					rohc_comp_debug(context, "  not same IPv4 addresses\n");
					goto bad_context;
				}
				rohc_comp_debug(context, "  same IPv4 addresses\n");
				/* get the transport protocol */
				protocol = base_header.ipv4->protocol;
				if(base_header.ipv4->protocol != ip_context.v4->protocol)
				{
					rohc_comp_debug(context, "  IPv4 not same protocol\n");
					goto bad_context;
				}
				rohc_comp_debug(context, "  IPv4 same protocol %d\n", protocol);
				++base_header.ipv4;
				++ip_context.v4;
				size -= sizeof(base_header_ip_v4_t);
				break;
			case IPV6:
				if(memcmp(base_header.ipv6->src_addr,ip_context.v6->src_addr,sizeof(uint32_t) * 4 *
				          2) != 0)
				{
					rohc_comp_debug(context, "  not same IPv6 addresses\n");
					goto bad_context;
				}
				rohc_comp_debug(context, "  same IPv6 addresses\n");
				if(base_header.ipv6->flow_label1 != ip_context.v6->flow_label1 ||
				   base_header.ipv6->flow_label2 != ip_context.v6->flow_label2)
				{
					rohc_comp_debug(context, "  not same IPv6 flow label\n");
					goto bad_context;
				}
				protocol = base_header.ipv6->next_header;
				if(protocol != ip_context.v6->next_header)
				{
					rohc_comp_debug(context, "  IPv6 not same protocol %d\n",protocol);
					goto bad_context;
				}
				++base_header.ipv6;
				++ip_context.v6;
				size -= sizeof(base_header_ip_v6_t);
				while(rohc_is_ipv6_opt(protocol) && size < ip->size)
				{
					protocol = base_header.ipv6_opt->next_header;
					if(protocol != ip_context.v6_option->next_header)
					{
						rohc_comp_debug(context, "  not same IPv6 option "
						                "(%d != %d)\n", protocol,
						                ip_context.v6_option->next_header);
						goto bad_context;
					}
					rohc_comp_debug(context, "  same IPv6 option %d\n", protocol);
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
				break;
			default:
				assert(0);
				goto bad_context;
		}

	}
	while(rohc_is_tunneling(protocol) && size >= sizeof(tcphdr_t));

	tcp = base_header.tcphdr;
	is_tcp_same = tcp_context->old_tcphdr.src_port == tcp->src_port &&
	              tcp_context->old_tcphdr.dst_port == tcp->dst_port;
	rohc_comp_debug(context, "  TCP %ssame Source and Destination ports\n",
	                is_tcp_same ? "" : "not ");
	return is_tcp_same;

bad_context:
	return false;
}


/**
 * @brief Encode an IP/TCP packet according to a pattern decided by several
 *        different factors.
 *
 * 1. Check if we have double IP headers.\n
 * 2. Check if the IP-ID fields are random and if they are in NBO.\n
 * 3. Decide in which state to go (IR, FO or SO).\n
 * 4. Decide how many bits are needed to send the IP-ID and SN fields and more
 *    important update the sliding windows.\n
 * 5. Decide which packet type to send.\n
 * 6. Code the packet.\n
 *
 * @param context           The compression context
 * @param ip                The IP packet to encode
 * @param packet_size       The length of the IP packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int c_tcp_encode(struct c_context *const context,
                        const struct ip_packet *ip,
                        const size_t packet_size,
                        unsigned char *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	ip_context_ptr_t ip_inner_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header_inner;   // Source innermost
	base_header_ip_t base_header;   // Source
	multi_ptr_t mptr;
	tcphdr_t *tcp;
	size_t first_position;
	int crc_position;
	int counter;
	uint8_t protocol;
	int ecn_used;
	int size;
#ifdef TODO
	uint8_t new_context_state;
#endif
	bool opt_ts_present = false;
	bool opt_ts_changed = false;
	uint32_t ts = 0;
	uint32_t ts_reply = 0;

	assert(context != NULL);
	assert(rohc_pkt != NULL);

	rohc_comp_debug(context, "context = %p, ip = %p, packet_size = %zu, "
	                "rohc_pkt = %p, rohc_pkt_max_len = %zu, packet_type = %p, "
	                "payload_offset = %p\n", context, ip, packet_size,
	                rohc_pkt, rohc_pkt_max_len, packet_type, payload_offset);

	*packet_type = ROHC_PACKET_UNKNOWN;

	g_context = (struct c_generic_context *) context->specific;
	if(g_context == NULL)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "generic context not valid\n");
		return -1;
	}

	tcp_context = (struct sc_tcp_context *) g_context->specific;
	if(tcp_context == NULL)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "TCP context not valid\n");
		return -1;
	}


	/* STEP 1:
	 *  - check double IP headers
	 *  - find the next header
	 *  - compute the payload offset
	 *  - discard IP fragments
	 */

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *)ip->data;
	ip_context.uint8 = tcp_context->ip_context;
	size = 0;
	ecn_used = 0;
	do
	{
		rohc_comp_debug(context, "base_header %p IP version %d\n",
		                base_header.uint8, base_header.ipvx->version);

		base_header_inner.ipvx = base_header.ipvx;
		ip_inner_context.uint8 = ip_context.uint8;

		switch(base_header.ipvx->version)
		{
			case IPV4:
				/* get the transport protocol */
				protocol = base_header.ipv4->protocol;
				ecn_used |= base_header.ipv4->ip_ecn_flags;
				size += sizeof(base_header_ip_v4_t);
				++base_header.ipv4;
				++ip_context.v4;
				break;
			case IPV6:
				protocol = base_header.ipv6->next_header;
				ecn_used |= base_header.ipv6->ip_ecn_flags;
				size += sizeof(base_header_ip_v6_t);
				++base_header.ipv6;
				++ip_context.v6;
				while(rohc_is_ipv6_opt(protocol))
				{
					switch(protocol)
					{
						case ROHC_IPPROTO_HOPOPTS: // IPv6 Hop-by-Hop options
						case ROHC_IPPROTO_ROUTING: // IPv6 routing header
						case ROHC_IPPROTO_DSTOPTS: // IPv6 destination options
						case ROHC_IPPROTO_AH:
							if(base_header.ipv6_opt->length != ip_context.v6_option->length)
							{
								rohc_comp_debug(context, "IPv6 option %d length "
								                "changed (%d -> %d)\n", protocol,
								                ip_context.v6_option->length,
								                base_header.ipv6_opt->length);
								assert( base_header.ipv6_opt->length < MAX_IPV6_OPTION_LENGTH );
								ip_context.v6_option->option_length =
								   (base_header.ipv6_opt->length + 1) << 3;
								ip_context.v6_option->length = base_header.ipv6_opt->length;
								memcpy(ip_context.v6_option->value,base_header.ipv6_opt->value,
								       ip_context.v6_option->option_length - 2);
#ifdef TODO
								new_context_state = ROHC_COMP_STATE_IR;
#endif
								break;
							}
							if(memcmp(base_header.ipv6_opt->value,ip_context.v6_option->value,
							          ip_context.v6_option->option_length - 2) != 0)
							{
								rohc_comp_debug(context, "IPv6 option %d value "
								                "changed (%d -> %d)\n", protocol,
								                ip_context.v6_option->length,
								                base_header.ipv6_opt->length);
								memcpy(ip_context.v6_option->value,base_header.ipv6_opt->value,
								       ip_context.v6_option->option_length - 2);
#ifdef TODO
								new_context_state = ROHC_COMP_STATE_IR;
#endif
								break;
							}
							break;
						case ROHC_IPPROTO_GRE:
							if(base_header.ip_gre_opt->c_flag != ip_context.v6_gre_option->c_flag)
							{
								rohc_comp_debug(context, "IPv6 option %d c_flag "
								                "changed (%d -> %d)\n", protocol,
								                ip_context.v6_gre_option->c_flag,
								                base_header.ip_gre_opt->c_flag);
#ifdef TODO
								new_context_state = ROHC_COMP_STATE_IR;
#endif
								break;
							}
							break;
						case ROHC_IPPROTO_MINE:
							if(base_header.ip_mime_opt->s_bit != ip_context.v6_mime_option->s_bit)
							{
								rohc_comp_debug(context, "IPv6 option %d s_bit "
								                "changed (0x%x -> 0x%x)\n", protocol,
								                ip_context.v6_mime_option->s_bit,
								                base_header.ip_mime_opt->s_bit);
								ip_context.v6_option->option_length =
								   (2 + base_header.ip_mime_opt->s_bit) << 3;
#ifdef TODO
								new_context_state = ROHC_COMP_STATE_IR;
#endif
								break;
							}
							if(base_header.ip_mime_opt->checksum != ip_context.v6_mime_option->checksum)
							{
								rohc_comp_debug(context, "IPv6 option %d checksum "
								                "changed (0x%x -> 0x%x)\n", protocol,
								                ip_context.v6_mime_option->checksum,
								                base_header.ip_mime_opt->checksum);
#ifdef TODO
								new_context_state = ROHC_COMP_STATE_IR;
#endif
								break;
							}
							break;
					}
					protocol = base_header.ipv6_opt->next_header;
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
				break;
			default:
				return -1;
		}

	}
	while(protocol != ROHC_IPPROTO_TCP && size < ip->size);

	/* find the next header */
	tcp = base_header.tcphdr;
	ecn_used |= tcp->ecn_flags;
	tcp_context->ecn_used = ecn_used;
	rohc_comp_debug(context, "ecn_used %d\n", tcp_context->ecn_used);
	// Reinit source pointer
	base_header.uint8 = (uint8_t*) ip->data;

	/* find the offset of the payload and its size */
	size = packet_size - size - sizeof(tcphdr_t);
	rohc_comp_debug(context, "payload_size = %d\n", size);


	/* STEP 2:
	 *  - check NBO and RND of the IP-ID of the outer and inner IP headers
	 *    (IPv4 only, if the current packet is not the first one)
	 *  - get the next the Sequence Number (SN)
	 *  - find how many static and dynamic IP fields changed
	 */

	/* detect the behaviors of the IP-ID fields for IPv4 headers */
	/* TODO: could be simplified! */
	if(base_header_inner.ipvx->version == IPV4)
	{
		uint16_t swapped_ip_id;
		uint16_t ip_id;

		/* Try to determine the IP_ID behavior of the innermost header */
		ip_id = rohc_ntoh16(base_header_inner.ipv4->ip_id);
		rohc_comp_debug(context, "ip_id_behavior = %d, last_ip_id = 0x%x, "
		                "ip_id = 0x%x\n", ip_inner_context.v4->ip_id_behavior,
		                ip_inner_context.v4->last_ip_id, ip_id);

		switch(ip_inner_context.v4->ip_id_behavior)
		{
			case IP_ID_BEHAVIOR_SEQUENTIAL:
				if((ip_inner_context.v4->last_ip_id + 1) != ip_id)
				{
					// Problem
					rohc_comp_debug(context, "ip_id_behavior not SEQUENTIAL: "
					                "0x%04x + 1 != 0x%04x\n",
					                ip_inner_context.v4->last_ip_id, ip_id);
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
					break;
				}
				break;
			case IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
				swapped_ip_id = swab16(ip_inner_context.v4->last_ip_id);
				rohc_comp_debug(context, " swapped_ip_id = 0x%04x + 1 = 0x%04x, "
				                "ip_id = 0x%04x\n", swapped_ip_id,
				                swapped_ip_id + 1, ip_id);
				swapped_ip_id++;
				if(swapped_ip_id != swab16(ip_id))
				{
					// Problem
					rohc_comp_debug(context, "ip_id_behavior not "
					                "SEQUENTIAL_SWAPPED: 0x%04x + 1 != 0x%04x\n",
					                ip_inner_context.v4->last_ip_id, swapped_ip_id);
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
					break;
				}
				break;
			case IP_ID_BEHAVIOR_RANDOM:
				if((ip_inner_context.v4->last_ip_id + 1) == ip_id)
				{
					rohc_comp_debug(context, "ip_id_behavior SEQUENTIAL\n");
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_SEQUENTIAL;
					break;
				}
				swapped_ip_id = swab16(ip_inner_context.v4->last_ip_id);
				rohc_comp_debug(context, "swapped_ip_id: 0x%04x + 1 = 0x%04x, "
				                "ip_id = 0x%04x\n", swapped_ip_id,
				                swapped_ip_id + 1, ip_id);
				swapped_ip_id++;
				if(swapped_ip_id == swab16(ip_id))
				{
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED;
					rohc_comp_debug(context, "ip_id_behavior SEQUENTIAL SWAPPED\n");
					break;
				}
				if(ip_id == 0)
				{
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_ZERO;
					rohc_comp_debug(context, "ip_id_behavior SEQUENTIAL ZERO\n");
					break;
				}
				break;
			case IP_ID_BEHAVIOR_ZERO:
				if(ip_id != 0)
				{
					if(ip_id == 0x0001)
					{
						rohc_comp_debug(context, "ip_id_behavior SEQUENTIAL\n");
						ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_SEQUENTIAL;
						break;
					}
					if(swab16(ip_id) == 0x0001)
					{
						ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED;
						rohc_comp_debug(context, "ip_id_behavior SEQUENTIAL SWAPPED\n");
						break;
					}
					// Problem
					rohc_comp_debug(context, "ip_id_behavior not ZERO: "
					                "0x%04x != 0\n", ip_id);
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
					break;
				}
				break;
			case IP_ID_BEHAVIOR_UNKNOWN:
				if(ip_id == 0)
				{
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_ZERO;
					rohc_comp_debug(context, "ip_id_behavior ZERO\n");
					break;
				}
				if((ip_inner_context.v4->last_ip_id + 1) == ip_id)
				{
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_SEQUENTIAL;
					rohc_comp_debug(context, "ip_id_behavior SEQUENTIAL\n");
					break;
				}
				if(ip_inner_context.v4->last_ip_id == ip_id)
				{
					break;
				}
				swapped_ip_id = swab16(ip_id);
				if((ip_inner_context.v4->last_ip_id + 1) == swapped_ip_id)
				{
					ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED;
					rohc_comp_debug(context, "ip_id_behavior SEQUENTIAL_SWAPPED\n");
					break;
				}
				if(ip_inner_context.v4->last_ip_id == swapped_ip_id)
				{
					break;
				}
				ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
				rohc_comp_debug(context, "ip_id_behavior RANDOM\n");
				break;
			default:
				assert(0); /* should never happen */
				break;
		}
	}

	/* parse TCP options */
	{
		uint8_t *opts;
		size_t opts_len;
		size_t opt_len;
		size_t opts_offset;

		opts = ((uint8_t *) tcp) + sizeof(tcphdr_t);
		opts_len = (tcp->data_offset << 2) - sizeof(tcphdr_t);

		for(opts_offset = 0; opts_offset < opts_len; opts_offset += opt_len)
		{
			rohc_comp_debug(context, "TCP option %u found\n", opts[opts_offset]);

			if(opts[opts_offset] == 0x00 || opts[opts_offset] == 0x01)
			{
				/* EOL or NOP */
				opt_len = 1;
			}
			else
			{
				if((opts_offset + 1) >= opts_len)
				{
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
					             context->profile->id, "malformed TCP header: not "
					             "enough room for the length field of option %u\n",
					             opts[opts_offset]);
					goto error;
				}
				opt_len = opts[opts_offset + 1];
				if((opts_offset + opt_len) > opts_len)
				{
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
					             context->profile->id, "malformed TCP header: not "
					             "enough room for option %u (%zu bytes required "
					             "but only %zu available)\n", opts[opts_offset],
					             opt_len, opts_len - opts_offset);
					goto error;
				}

				if(opts[opts_offset] == 0x08)
				{
					memcpy(&ts, opts + opts_offset + 2, sizeof(uint32_t));
					memcpy(&ts_reply, opts + opts_offset + 6, sizeof(uint32_t));
					opt_ts_present = true;

					if(tcp_context->tcp_option_timestamp_init &&
					   memcmp(&tcp_context->tcp_option_timestamp,
					          opts + opts_offset + 2,
								 sizeof(struct tcp_option_timestamp)) == 0)
					{
						opt_ts_changed = false;
					}
					else
					{
						opt_ts_changed = true;
					}
				}
			}
		}
	}

	g_context->sn = g_context->get_next_sn(context, ip, NULL);
	rohc_comp_debug(context, "MSN = 0x%x\n", g_context->sn);

	/* how many TCP fields changed? */
#ifdef TODO
	tcp_context->tmp_variables.send_tcp_dynamic = tcp_changed_tcp_dynamic(context, tcp);
#endif


	/*
	 * STEP 3: decide in which state to go
	 */
	rohc_comp_debug(context, "state %d\n", context->state);

#ifdef TODO
	if(tcp_context->tmp_variables.send_tcp_dynamic)
	{
		change_state(context, ROHC_COMP_STATE_IR);
	}
	else
	{
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		decide_state(context);
	}
#endif


	/*
	 * STEP 4: compute how many bits are needed to send header fields
	 */

	rohc_comp_debug(context, "required bits:\n");

	/* how many bits are required to encode the new SN ? */
	if(context->state == ROHC_COMP_STATE_IR)
	{
		/* send all bits in IR state */
		g_context->tmp.nr_sn_bits = 16;
		rohc_comp_debug(context, "IR state: force using %zd bits to encode "
		                "new SN\n", g_context->tmp.nr_sn_bits);
	}
	else
	{
		/* send only required bits in FO or SO states */
		if(!wlsb_get_k_32bits(g_context->sn_window, g_context->sn,
		                      &g_context->tmp.nr_sn_bits))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP,
			             context->profile->id, "failed to find the minimal "
			             "number of bits required for SN\n");
			goto error;
		}
	}
	rohc_comp_debug(context, "%zd bits are required to encode new SN\n",
	                g_context->tmp.nr_sn_bits);
	c_add_wlsb(g_context->sn_window, g_context->sn, g_context->sn);

	/* how many bits are required to encode the new sequence number? */
	if(context->state == ROHC_COMP_STATE_IR)
	{
		/* send all bits in IR state */
		tcp_context->tmp.nr_seq_bits_65535 = 32;
		tcp_context->tmp.nr_seq_bits_32767 = 32;
		tcp_context->tmp.nr_seq_bits_8191 = 32;
		rohc_comp_debug(context, "IR state: force using 32 bits to encode "
		                "new sequence number\n");
	}
	else
	{
		/* send only required bits in FO or SO states */
		if(!wlsb_get_kp_32bits(tcp_context->seq_wlsb,
		                       rohc_ntoh32(tcp->seq_number), 65535,
		                       &tcp_context->tmp.nr_seq_bits_65535))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP,
			             context->profile->id, "failed to find the minimal "
			             "number of bits required for sequence number 0x%08x "
			             "and p = 65535\n", rohc_ntoh32(tcp->seq_number));
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 65535\n",
		                tcp_context->tmp.nr_seq_bits_65535,
		                rohc_ntoh32(tcp->seq_number));
		if(!wlsb_get_kp_32bits(tcp_context->seq_wlsb,
		                       rohc_ntoh32(tcp->seq_number), 32767,
		                       &tcp_context->tmp.nr_seq_bits_32767))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP,
			             context->profile->id, "failed to find the minimal "
			             "number of bits required for sequence number 0x%08x "
			             "and p = 32767\n", rohc_ntoh32(tcp->seq_number));
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 32767\n",
		                tcp_context->tmp.nr_seq_bits_32767,
		                rohc_ntoh32(tcp->seq_number));
		if(!wlsb_get_kp_32bits(tcp_context->seq_wlsb,
		                       rohc_ntoh32(tcp->seq_number), 8191,
		                       &tcp_context->tmp.nr_seq_bits_8191))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP,
			             context->profile->id, "failed to find the minimal "
			             "number of bits required for sequence number 0x%08x"
			             "and p = 8191\n", rohc_ntoh32(tcp->seq_number));
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 8191\n",
		                tcp_context->tmp.nr_seq_bits_8191,
		                rohc_ntoh32(tcp->seq_number));
	}
	c_add_wlsb(tcp_context->seq_wlsb, g_context->sn,
	           rohc_ntoh32(tcp->seq_number));

	/* how many bits are required to encode the new timestamp echo request and
	 * timestamp echo reply? */
	if(!opt_ts_present)
	{
		/* no bit to send */
		tcp_context->tmp.nr_opt_ts_req_bits_minus_1 = 0;
		tcp_context->tmp.nr_opt_ts_req_bits_0x40000 = 0;
		tcp_context->tmp.nr_opt_ts_reply_bits_minus_1 = 0;
		tcp_context->tmp.nr_opt_ts_reply_bits_0x40000 = 0;
		rohc_comp_debug(context, "no TS option: O bit required to encode the "
		                "new timestamp echo request/reply numbers\n");
	}
	else if(context->state == ROHC_COMP_STATE_IR)
	{
		/* send all bits in IR state */
		tcp_context->tmp.nr_opt_ts_req_bits_minus_1 = 32;
		tcp_context->tmp.nr_opt_ts_req_bits_0x40000 = 32;
		tcp_context->tmp.nr_opt_ts_reply_bits_minus_1 = 32;
		tcp_context->tmp.nr_opt_ts_reply_bits_0x40000 = 32;
		rohc_comp_debug(context, "IR state: force using 32 bits to encode "
		                "new timestamp echo request/reply numbers\n");
	}
	else if(!opt_ts_changed)
	{
		/* no bit to send */
		tcp_context->tmp.nr_opt_ts_req_bits_minus_1 = 0;
		tcp_context->tmp.nr_opt_ts_req_bits_0x40000 = 0;
		tcp_context->tmp.nr_opt_ts_reply_bits_minus_1 = 0;
		tcp_context->tmp.nr_opt_ts_reply_bits_0x40000 = 0;
		rohc_comp_debug(context, "TS option unchanged: 0 bit required to "
		                "encode new timestamp echo request/reply numbers\n");
	}
	else
	{
		/* send only required bits in FO or SO states */

		/* how many bits are required to encode the timestamp echo request
		 * with p = -1 ? */
		if(!wlsb_get_kp_32bits(tcp_context->opt_ts_req_wlsb,
		                       rohc_ntoh32(ts), -1,
		                       &tcp_context->tmp.nr_opt_ts_req_bits_minus_1))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to find the minimal number of bits required "
			             "for timestamp echo request 0x%08x and p = -1\n",
			             rohc_ntoh32(ts));
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = -1\n",
		                tcp_context->tmp.nr_opt_ts_req_bits_minus_1,
		                rohc_ntoh32(ts));

		/* how many bits are required to encode the timestamp echo request
		 * with p = 0x40000 ? */
		if(!wlsb_get_kp_32bits(tcp_context->opt_ts_req_wlsb,
		                       rohc_ntoh32(ts), 0x40000,
		                       &tcp_context->tmp.nr_opt_ts_req_bits_0x40000))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to find the minimal number of bits required "
			             "for timestamp echo request 0x%08x and p = 0x40000\n",
			             rohc_ntoh32(ts));
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = 0x40000\n",
		                tcp_context->tmp.nr_opt_ts_req_bits_0x40000,
		                rohc_ntoh32(ts));

		/* how many bits are required to encode the timestamp echo reply
		 * with p = -1 ? */
		if(!wlsb_get_kp_32bits(tcp_context->opt_ts_reply_wlsb,
		                       rohc_ntoh32(ts_reply), -1,
		                       &tcp_context->tmp.nr_opt_ts_reply_bits_minus_1))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to find the minimal number of bits required "
			             "for timestamp echo reply 0x%08x and p = -1\n",
			             rohc_ntoh32(ts_reply));
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = -1\n",
		                tcp_context->tmp.nr_opt_ts_reply_bits_minus_1,
		                rohc_ntoh32(ts_reply));

		/* how many bits are required to encode the timestamp echo reply
		 * with p = 0x40000 ? */
		if(!wlsb_get_kp_32bits(tcp_context->opt_ts_reply_wlsb,
		                       rohc_ntoh32(ts_reply), 0x40000,
		                       &tcp_context->tmp.nr_opt_ts_reply_bits_0x40000))
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to find the minimal number of bits required "
			             "for timestamp echo reply 0x%08x and p = 0x40000\n",
			             rohc_ntoh32(ts_reply));
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = 0x40000\n",
		                tcp_context->tmp.nr_opt_ts_reply_bits_0x40000,
		                rohc_ntoh32(ts_reply));
	}

	// See RFC4996 page 32/33
	c_field_scaling(&(tcp_context->seq_number_scaled),
	                &(tcp_context->seq_number_residue), size, tcp->seq_number);
	rohc_comp_debug(context, "seq_number = 0x%x, scaled = 0x%x, "
	                "residue = 0x%x\n", tcp->seq_number,
	                tcp_context->seq_number_scaled,
	                tcp_context->seq_number_residue);
	c_field_scaling(&(tcp_context->ack_number_scaled),
	                &(tcp_context->ack_number_residue),
	                tcp_context->ack_stride, tcp->ack_number);
	rohc_comp_debug(context, "ack_number = 0x%x, scaled = 0x%x, "
	                "residue = 0x%x\n", tcp->ack_number,
	                tcp_context->ack_number_scaled,
	                tcp_context->ack_number_residue);


	/*
	 * STEP 5: decide which packet to send
	 */

	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			change_state(context, ROHC_COMP_STATE_FO);
			*packet_type = ROHC_PACKET_IR;
			break;
		case ROHC_COMP_STATE_FO: /* The First Order (FO) state */
			change_state(context, ROHC_COMP_STATE_SO);
			*packet_type = ROHC_PACKET_IR_DYN;
			break;
		case ROHC_COMP_STATE_SO: /* The Second Order (SO) state */
		default:
			if(!sdvl_can_length_be_encoded(tcp_context->tmp.nr_opt_ts_req_bits_0x40000) ||
			   !sdvl_can_length_be_encoded(tcp_context->tmp.nr_opt_ts_reply_bits_0x40000))
			{
				rohc_comp_debug(context, "force packet IR-DYN because the TCP "
				                "option changed too much\n");
				*packet_type = ROHC_PACKET_IR_DYN;
			}
			else
			{
				*packet_type = ROHC_PACKET_UNKNOWN;
			}
			break;
	}


	/*
	 * STEP 6: code the packet
	 */

	rohc_comp_debug(context, "state %d\n", context->state);
	if((*packet_type) == ROHC_PACKET_UNKNOWN)
	{
		counter = code_CO_packet(context, ip, packet_size, base_header.uint8,
		                         rohc_pkt, rohc_pkt_max_len, packet_type,
		                         payload_offset);
		if(counter < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to build CO packet\n");
			goto error;
		}
		rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
		                 ROHC_TRACE_DEBUG, "current ROHC packet", rohc_pkt,
		                 counter);
	}
	else /* ROHC_PACKET_IR or ROHC_PACKET_IR_DYN */
	{
		assert((*packet_type) == ROHC_PACKET_IR ||
		       (*packet_type) == ROHC_PACKET_IR_DYN);

		/* parts 1 and 3:
		 *  - part 2 will be placed at 'first_position'
		 *  - part 4 will start at 'counter'
		 */
		counter = code_cid_values(context->compressor->medium.cid_type,
		                          context->cid, rohc_pkt, rohc_pkt_max_len,
		                          &first_position);
		rohc_comp_debug(context, "counter = %d, first_position = %zu, "
		                "rohc_pkt[0] = 0x%02x, rohc_pkt[1] = 0x%02x\n", counter,
		                first_position, rohc_pkt[0], rohc_pkt[1]);

		/* part 2: type of packet */
		if((*packet_type) == ROHC_PACKET_IR)
		{
			rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR;
		}
		else /* ROHC_PACKET_IR_DYN */
		{
			rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR_DYN;
		}
		rohc_comp_debug(context, "packet type = 0x%02x\n",
		                rohc_pkt[first_position]);

		/* part 4 */
		rohc_comp_debug(context, "profile ID = 0x%02x\n", context->profile->id);
		rohc_pkt[counter] = context->profile->id;
		counter++;

		/* part 5: the CRC is computed later since it must be computed
		 * over the whole packet with an empty CRC field */
		rohc_comp_debug(context, "CRC = 0x00 for CRC calculation\n");
		crc_position = counter;
		rohc_pkt[counter] = 0;
		counter++;

		mptr.uint8 = &rohc_pkt[counter];

		if((*packet_type) == ROHC_PACKET_IR)
		{
			/* part 6 : static chain */

			// Init pointer to the initial packet
			base_header.ipvx = (base_header_ip_vx_t *)ip->data;
			ip_context.uint8 = tcp_context->ip_context;

			do
			{
				rohc_comp_debug(context, "base_header = %p, IP version = %d\n",
				                base_header.uint8, base_header.ipvx->version);

				switch(base_header.ipvx->version)
				{
					case IPV4:
						mptr.uint8 =
						   tcp_code_static_ip_part(context, ip_context, base_header,
						                           packet_size, mptr);
						/* get the transport protocol */
						protocol = base_header.ipv4->protocol;
						++base_header.ipv4;
						++ip_context.v4;
						break;
					case IPV6:
						mptr.uint8 =
						   tcp_code_static_ip_part(context, ip_context, base_header,
						                           packet_size, mptr);
						protocol = base_header.ipv6->next_header;
						++base_header.ipv6;
						++ip_context.v6;
						while(rohc_is_ipv6_opt(protocol))
						{
							rohc_comp_debug(context, "IPv6 option %d at %p\n",
							                protocol, base_header.uint8);
							mptr.uint8 =
							   tcp_code_static_ipv6_option_part(context, ip_context,
							                                    mptr, protocol,
							                                    base_header,
							                                    packet_size);
							if(mptr.uint8 == NULL)
							{
								rohc_warning(context->compressor, ROHC_TRACE_COMP,
								             context->profile->id, "failed to code "
								             "the IPv6 extension part of the static "
								             "chain\n");
								goto error;
							}
							protocol = base_header.ipv6_opt->next_header;
							base_header.uint8 += ip_context.v6_option->option_length;
							ip_context.uint8 += ip_context.v6_option->context_length;
						}
						break;
					default:
						rohc_warning(context->compressor, ROHC_TRACE_COMP,
						             context->profile->id, "unexpected IP version "
						             "%u\n", base_header.ipvx->version);
						assert(0);
						goto error;
				}
				rohc_comp_debug(context, "counter = %d, protocol = %d\n",
				                (int)(mptr.uint8 - &rohc_pkt[counter]), protocol);

			}
			while(rohc_is_tunneling(protocol));

			// add TCP static part
			mptr.uint8 = tcp_code_static_tcp_part(context,base_header.tcphdr,mptr);
			rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
			                 ROHC_TRACE_DEBUG, "current ROHC packet",
			                 rohc_pkt, mptr.uint8 - rohc_pkt);
		}

		/* Packet IP or IR-DYN : add dynamic chain */

		// Init pointer to the initial packet
		base_header.ipvx = (base_header_ip_vx_t *)ip->data;
		ip_context.uint8 = tcp_context->ip_context;

		do
		{
			rohc_comp_debug(context, "base_header = %p, IP version = %d\n",
			                base_header.uint8, base_header.ipvx->version);

			mptr.uint8 = tcp_code_dynamic_ip_part(context,ip_context,base_header,packet_size,mptr,
			                                      base_header.uint8 == base_header_inner.uint8);

			switch(base_header.ipvx->version)
			{
				case IPV4:
					/* get the transport protocol */
					protocol = base_header.ipv4->protocol;
					++base_header.ipv4;
					++ip_context.v4;
					break;
				case IPV6:
					protocol = base_header.ipv6->next_header;
					++base_header.ipv6;
					++ip_context.v6;
					while(rohc_is_ipv6_opt(protocol))
					{
						rohc_comp_debug(context, "IPv6 option %d at %p\n",
						                protocol, base_header.uint8);
						mptr.uint8 =
						   tcp_code_dynamic_ipv6_option_part(context, ip_context,
						                                     mptr, protocol,
						                                     base_header,
						                                     packet_size);
						if(mptr.uint8 == NULL)
						{
							rohc_warning(context->compressor, ROHC_TRACE_COMP,
							             context->profile->id, "failed to code the "
							             "IPv6 extension part of the dynamic chain\n");
							goto error;
						}
						protocol = base_header.ipv6_opt->next_header;
						base_header.uint8 += ip_context.v6_option->option_length;
						ip_context.uint8 += ip_context.v6_option->context_length;
					}
					break;
				default:
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
					             context->profile->id, "unexpected IP version "
					             "%u\n", base_header.ipvx->version);
					assert(0);
					goto error;
			}
		}
		while(rohc_is_tunneling(protocol));

		// add TCP dynamic part
		mptr.uint8 = tcp_code_dynamic_tcp_part(context,base_header.uint8,mptr);
		if(mptr.uint8 == NULL)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to code the TCP part of the dynamic chain\n");
			goto error;
		}

		counter = (int) ( mptr.uint8 - rohc_pkt );
		rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
		                 ROHC_TRACE_DEBUG, "current ROHC packet", rohc_pkt, counter);

		rohc_comp_debug(context, "base_header %p\n", base_header.uint8);

		/* last part : payload */
		size = base_header.tcphdr->data_offset << 2;
		// offset payload
		base_header.uint8 += size;
		// payload length
		size = ip->size - ( base_header.uint8 - ip->data );
		rohc_comp_debug(context, "payload size %d\n", size);

		rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
		                 ROHC_TRACE_DEBUG, "current ROHC packet", rohc_pkt, counter);

		/* part 5 */
		rohc_pkt[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt,
		                                       counter, CRC_INIT_8,
		                                       context->compressor->crc_table_8);
		rohc_comp_debug(context, "CRC (header length = %d, crc = 0x%x)\n",
		                counter, rohc_pkt[crc_position]);

		rohc_comp_debug(context, "IR packet, length %d\n",counter);
		rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
		                 ROHC_TRACE_DEBUG, "current ROHC packet", rohc_pkt, counter);

		*packet_type = ROHC_PACKET_IR;
		*payload_offset = base_header.uint8 - (uint8_t*) ip->data;
	}

	rohc_comp_debug(context, "payload_offset = %d\n", *payload_offset);

	/* update the context with the new TCP header */
	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(tcphdr_t));
	tcp_context->seq_number = rohc_ntoh32(tcp->seq_number);
	tcp_context->ack_number = rohc_ntoh32(tcp->ack_number);

	return counter;

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv6 option header.
 *
 * @param context        The compression context
 * @param ip_context     The specific IP compression context
 * @param mptr           The current pointer in the rohc-packet-under-build buffer
 * @param protocol       The IPv6 protocol option
 * @param base_header    The IP header
 * @param packet_size    The size of packet
 * @return               The new pointer in the rohc-packet-under-build buffer,
 *                       NULL if a problem occurs
 */
static uint8_t * tcp_code_static_ipv6_option_part(struct c_context *const context,
																  ip_context_ptr_t ip_context,
																  multi_ptr_t mptr,
																  uint8_t protocol,
																  base_header_ip_t base_header,
																  const int packet_size)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	uint8_t size;
	int ret;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	rohc_comp_debug(context, "tcp_context = %p, ip_context = %p, "
	                "protocol = %d, base_header_ip = %p\n", tcp_context,
	                ip_context.uint8, protocol, base_header.uint8);

	// Common to all options
	mptr.ip_opt_static->next_header = base_header.ipv6_opt->next_header;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
			mptr.ip_hop_opt_static->length = base_header.ipv6_opt->length;
			size = sizeof(ip_hop_opt_static_t);
			break;
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
			mptr.ip_hop_opt_static->length = base_header.ipv6_opt->length;
			size = (base_header.ipv6_opt->length + 1) << 3;
			memcpy(mptr.ip_rout_opt_static->value,base_header.ipv6_opt->value,size - 2);
			break;
		case ROHC_IPPROTO_GRE:
			if(rohc_ntoh16(base_header.ip_gre_opt->protocol) == 0x0800)
			{
				mptr.ip_gre_opt_static->protocol = 0;
			}
			else
			{
				assert(rohc_ntoh16(base_header.ip_gre_opt->protocol) == 0x86DD);
				mptr.ip_gre_opt_static->protocol = 1;
			}
			mptr.ip_gre_opt_static->c_flag = base_header.ip_gre_opt->c_flag;
			mptr.ip_gre_opt_static->s_flag = base_header.ip_gre_opt->s_flag;
			mptr.ip_gre_opt_static->k_flag = base_header.ip_gre_opt->k_flag;
			mptr.ip_gre_opt_static->padding = 0;
			size = sizeof(ip_gre_opt_static_t);

			ret = c_optional32(base_header.ip_gre_opt->k_flag,
			                   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag],
			                   mptr.ip_gre_opt_static->options);
			if(ret < 0)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP,
				             context->profile->id,
				             "failed to encode optional32(key)\n");
				goto error;
			}
			size += sizeof(uint32_t);
			break;
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
			mptr.ip_dest_opt_static->length = base_header.ipv6_opt->length;
			size = sizeof(ip_dest_opt_static_t);
			break;
		case ROHC_IPPROTO_MINE:
			mptr.ip_mime_opt_static->s_bit = base_header.ip_mime_opt->s_bit;
			mptr.ip_mime_opt_static->res_bits = base_header.ip_mime_opt->res_bits;
			mptr.ip_mime_opt_static->orig_dest = base_header.ip_mime_opt->orig_dest;
			if(base_header.ip_mime_opt->s_bit != 0)
			{
				mptr.ip_mime_opt_static->orig_src = base_header.ip_mime_opt->orig_src;
				size = sizeof(ip_mime_opt_static_t);
				break;
			}
			size = sizeof(ip_mime_opt_static_t) - sizeof(uint32_t);
			break;
		case ROHC_IPPROTO_AH:
			mptr.ip_ah_opt_static->length = base_header.ip_ah_opt->length;
			mptr.ip_ah_opt_static->spi = base_header.ip_ah_opt->spi;
			size = sizeof(ip_ah_opt_static_t);
			break;
		default:
			size = 0;
			break;
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "IPv6 option static part",
	                 mptr.uint8, size);
#endif

	return mptr.uint8 + size;

error:
	return NULL;
}


/**
 * @brief Build the dynamic part of the IPv6 option header.
 *
 * @param context        The compression context
 * @param ip_context     The specific IP compression context
 * @param mptr           The current pointer in the rohc-packet-under-build buffer
 * @param protocol       The IPv6 protocol option
 * @param base_header    The IP header
 * @param packet_size    The size of packet
 * @return               The new pointer in the rohc-packet-under-build buffer,
 *                       NULL if a problem occurs
 */
static uint8_t * tcp_code_dynamic_ipv6_option_part(struct c_context *const context,
																	ip_context_ptr_t ip_context,
																	multi_ptr_t mptr,
																	uint8_t protocol,
																	base_header_ip_t base_header,
																	const int packet_size)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	int size;
	int ret;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	rohc_comp_debug(context, "tcp_context = %p, ip_context = %p, "
	                "protocol = %d, base_header = %p\n", tcp_context,
	                ip_context.uint8, protocol, base_header.uint8);

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
		case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
			size = ( (base_header.ipv6_opt->length + 1) << 3 ) - 2;
			memcpy(ip_context.v6_option->value,base_header.ipv6_opt->value,size);
			memcpy(mptr.ip_opt_dynamic->value,base_header.ipv6_opt->value,size);
			break;
		case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
			size = 0;
			break;
		case ROHC_IPPROTO_GRE:
			size = 0;
			// checksum_and_res =:= optional_checksum(c_flag.UVALUE)
			if(base_header.ip_gre_opt->c_flag != 0)
			{
				uint8_t *ptr = (uint8_t*) base_header.ip_gre_opt->datas;
				*(mptr.uint8++) = *ptr++;
				*(mptr.uint8++) = *ptr;
				size += sizeof(uint16_t);
			}
			// sequence_number =:= optional_32(s_flag.UVALUE)
			ret = c_optional32(base_header.ip_gre_opt->s_flag,
			                   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag],
			                   mptr.uint8);
			if(ret < 0)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP,
				             context->profile->id, "failed to encode "
				             "optional32(sequence_number)\n");
				goto error;
			}
			mptr.uint8 += ret;
			size += ret;
			if(base_header.ip_gre_opt->s_flag != 0)
			{
				ip_context.v6_gre_option->sequence_number =
				   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag];
			}
			mptr.uint8 -= size;
			break;
		case ROHC_IPPROTO_MINE:
			size = 0;
			break;
		case ROHC_IPPROTO_AH:
			mptr.ip_ah_opt_dynamic->sequence_number = base_header.ip_ah_opt->sequence_number;
			size = (base_header.ip_ah_opt->length - 1) << 2;
			memcpy(mptr.ip_ah_opt_dynamic->auth_data,base_header.ip_ah_opt->auth_data,
			       (base_header.ip_ah_opt->length - 1) << 2);
			size += sizeof(uint32_t);
			break;
		default:
			size = 0;
			break;
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "IPv6 option dynamic part",
	                 mptr.uint8, size);
#endif

	return mptr.uint8 + size;

error:
	return NULL;
}


/**
 * @brief Build the irregular part of the IPv6 option header.
 *
 * @param context        The compression context
 * @param ip_context     The specific IP compression context
 * @param mptr           The current pointer in the rohc-packet-under-build buffer
 * @param protocol       The IPv6 protocol option
 * @param base_header    The IP header
 * @param packet_size    The size of packet
 * @return               The new pointer in the rohc-packet-under-build buffer,
 *                       NULL if a problem occurs
 */
static uint8_t * tcp_code_irregular_ipv6_option_part(struct c_context *const context,
																	  ip_context_ptr_t ip_context,
																	  multi_ptr_t mptr,
																	  uint8_t protocol,
																	  base_header_ip_t base_header,
																	  const int packet_size)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
#if ROHC_EXTRA_DEBUG == 1
	uint8_t *ptr = mptr.uint8;
#endif
	uint32_t sequence_number;
	int size;
	int ret;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	rohc_comp_debug(context, "tcp_context = %p, ip_context = %p, "
	                "protocol = %d, base_header_ip = %p\n", tcp_context,
	                ip_context.uint8, protocol, base_header.uint8);

	switch(protocol)
	{
		case ROHC_IPPROTO_GRE:
			// checksum_and_res =:= optional_checksum(c_flag.UVALUE)
			if(base_header.ip_gre_opt->c_flag != 0)
			{
				uint8_t *ptr = (uint8_t*) base_header.ip_gre_opt->datas;
				*(mptr.uint8++) = *ptr++;
				*(mptr.uint8++) = *ptr;
			}
			// sequence_number =:= optional_lsb_7_or_31(s_flag.UVALUE)
			if(base_header.ip_gre_opt->s_flag != 0)
			{
				sequence_number = rohc_ntoh32(base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag]);
				ret = c_lsb_7_or_31(ip_context.v6_gre_option->sequence_number,
				                    sequence_number, mptr.uint8);
				if(ret < 0)
				{
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
					             context->profile->id,
					             "failed to code lsb_7_or_31(sequence_number)\n");
					goto error;
				}
				mptr.uint8 += ret;
				ip_context.v6_gre_option->sequence_number =
				   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag];
			}
			break;
		case ROHC_IPPROTO_AH:
			sequence_number = rohc_ntoh32(base_header.ip_ah_opt->sequence_number);
			ret = c_lsb_7_or_31(ip_context.v6_ah_option->sequence_number,
			                    sequence_number, mptr.uint8);
			if(ret < 0)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP,
				             context->profile->id,
				             "failed to code lsb_7_or_31(sequence_number)\n");
				goto error;
			}
			mptr.uint8 += ret;
			ip_context.v6_ah_option->sequence_number = sequence_number;
			size = (base_header.ip_ah_opt->length - 1) << 3;
			memcpy(mptr.uint8,base_header.ip_ah_opt->auth_data,size);
			mptr.uint8 += size;
			break;
		default:
			break;
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "IPv6 option irregular part",
	                 mptr.uint8, mptr.uint8 - ptr);
#endif

	return mptr.uint8;

error:
	return NULL;
}


/**
 * @brief Build the static part of the IP header.
 *
 * @param context        The compression context
 * @param ip_context     The specific IP compression context
 * @param base_header    The IP header
 * @param packet_size    The size of packet
 * @param mptr           The current pointer in the rohc-packet-under-build buffer
 * @return               The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_static_ip_part(struct c_context *const context,
                                         ip_context_ptr_t ip_context,
                                         base_header_ip_t base_header,
                                         const int packet_size,
                                         multi_ptr_t mptr)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	rohc_comp_debug(context, "tcp_context = %p, ip_context = %p, "
	                "base_header_ip = %p\n", tcp_context, ip_context.uint8,
	                base_header.uint8);

	if(base_header.ipvx->version == IPV4)
	{
		mptr.ipv4_static->version_flag = 0;
		mptr.ipv4_static->reserved = 0;
		mptr.ipv4_static->protocol = base_header.ipv4->protocol;
		rohc_comp_debug(context, "protocol = %d\n", mptr.ipv4_static->protocol);
		mptr.ipv4_static->src_addr = base_header.ipv4->src_addr;
		mptr.ipv4_static->dst_addr = base_header.ipv4->dest_addr;
		size = sizeof(ipv4_static_t);
	}
	else
	{
		if(base_header.ipv6->flow_label1 == 0 && base_header.ipv6->flow_label2 == 0)
		{
			mptr.ipv6_static1->version_flag = 1;
			mptr.ipv6_static1->reserved1 = 0;
			mptr.ipv6_static1->flow_label_enc_discriminator = 0;
			mptr.ipv6_static1->reserved2 = 0;
			mptr.ipv6_static1->next_header = base_header.ipv6->next_header;
			memcpy(mptr.ipv6_static1->src_addr,base_header.ipv6->src_addr,sizeof(uint32_t) * 4 * 2);
			size = sizeof(ipv6_static1_t);
		}
		else
		{
			mptr.ipv6_static2->version_flag = 1;
			mptr.ipv6_static2->reserved = 0;
			mptr.ipv6_static2->flow_label_enc_discriminator = 1;
			mptr.ipv6_static2->flow_label1 = base_header.ipv6->flow_label1;
			mptr.ipv6_static2->flow_label2 = base_header.ipv6->flow_label2;
			mptr.ipv6_static2->next_header = base_header.ipv6->next_header;
			memcpy(mptr.ipv6_static2->src_addr,base_header.ipv6->src_addr,sizeof(uint32_t) * 4 * 2);
			size = sizeof(ipv6_static2_t);
		}
		rohc_comp_debug(context, "next_header = %d\n",
		                base_header.ipv6->next_header);
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "IP static part", mptr.uint8, size);
#endif

	return mptr.uint8 + size;
}


/**
 * @brief Build the dynamic part of the IP header.
 *
 * @param context        The compression context
 * @param ip_context     The specific IP compression context
 * @param base_header    The IP header
 * @param packet_size    The size of packet
 * @param mptr           The current pointer in the rohc-packet-under-build buffer
 * @param is_innermost   True if the IP header is the innermost of the packet
 * @return               The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_dynamic_ip_part(const struct c_context *context,
                                           ip_context_ptr_t ip_context,
                                           base_header_ip_t base_header,
                                           const int packet_size,
                                           multi_ptr_t mptr,
                                           int is_innermost)
{
	int size;

	rohc_comp_debug(context, "context = %p, ip_context = %p, "
	                "base_header_ip = %p, is_innermost = %d\n", context,
	                ip_context.uint8, base_header.uint8, is_innermost);

	if(base_header.ipvx->version == IPV4)
	{
		uint16_t ip_id;

		assert( ip_context.v4->version == IPV4 );

		/* Read the IP_ID */
		ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
		rohc_comp_debug(context, "ip_id_behavior = %d, last IP-ID = 0x%04x, "
		                "IP-ID = 0x%04x\n", ip_context.v4->ip_id_behavior,
		                ip_context.v4->last_ip_id, ip_id);

		mptr.ipv4_dynamic1->reserved = 0;
		mptr.ipv4_dynamic1->df = base_header.ipv4->df;
		// cf RFC4996 page 60/61 ip_id_behavior_choice() and ip_id_enc_dyn()
		if(is_innermost != 0)
		{
			// All behavior values possible
			if(base_header.ipv4->ip_id == 0)
			{
				mptr.ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_ZERO;
			}
			else
			{
				if(ip_context.v4->ip_id_behavior == IP_ID_BEHAVIOR_UNKNOWN)
				{
					mptr.ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
				}
				else
				{
					mptr.ipv4_dynamic1->ip_id_behavior = ip_context.v4->ip_id_behavior;
				}
			}
		}
		else
		{
			// Only IP_ID_BEHAVIOR_RANDOM or IP_ID_BEHAVIOR_ZERO
			if(base_header.ipv4->ip_id == 0)
			{
				mptr.ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_ZERO;
			}
			else
			{
				mptr.ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
			}
			ip_context.v4->ip_id_behavior = mptr.ipv4_dynamic1->ip_id_behavior;
		}
		ip_context.v4->last_ip_id_behavior = ip_context.v4->ip_id_behavior;
		mptr.ipv4_dynamic1->dscp = base_header.ipv4->dscp;
		mptr.ipv4_dynamic1->ip_ecn_flags = base_header.ipv4->ip_ecn_flags;
		mptr.ipv4_dynamic1->ttl_hopl = base_header.ipv4->ttl_hopl;
		// cf RFC4996 page 60/61 ip_id_enc_dyn()
		if(mptr.ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
		{
			rohc_comp_debug(context, "ip_id_behavior = %d\n",
			                mptr.ipv4_dynamic1->ip_id_behavior);
			size = sizeof(ipv4_dynamic1_t);
		}
		else
		{
			if(mptr.ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
			{
				mptr.ipv4_dynamic2->ip_id = swab16(base_header.ipv4->ip_id);
			}
			else
			{
				mptr.ipv4_dynamic2->ip_id = base_header.ipv4->ip_id;
			}
			rohc_comp_debug(context, "ip_id_behavior = %d, IP-ID = 0x%04x\n",
			                mptr.ipv4_dynamic1->ip_id_behavior,
			                rohc_ntoh16(base_header.ipv4->ip_id));
			size = sizeof(ipv4_dynamic2_t);
		}

		ip_context.v4->dscp = base_header.ipv4->dscp;
		ip_context.v4->ttl_hopl = base_header.ipv4->ttl_hopl;
		ip_context.v4->df = base_header.ipv4->df;
		ip_context.v4->last_ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
	}
	else
	{
		assert( ip_context.v6->version == IPV6 );

		mptr.ipv6_dynamic->dscp = DSCP_V6(base_header.ipv6);
		mptr.ipv6_dynamic->ip_ecn_flags = base_header.ipv6->ip_ecn_flags;
		mptr.ipv6_dynamic->ttl_hopl = base_header.ipv6->ttl_hopl;

		ip_context.v6->dscp = DSCP_V6(base_header.ipv6);
		ip_context.v6->ttl_hopl = base_header.ipv6->ttl_hopl;

		size = sizeof(ipv6_dynamic_t);
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "IP dynamic part", mptr.uint8, size);
#endif

	return mptr.uint8 + size;
}


/**
 * @brief Build the irregular part of the IP header.
 *
 * See Rfc4996 page 63
 *
 * @param context                   The compression context
 * @param ip_context                The specific IP compression context
 * @param base_header               The IP header
 * @param packet_size               The size of packet
 * @param rohc_data                 The current pointer in the rohc-packet-under-build buffer
 * @param ecn_used                  The indicator of ECN usage
 * @param is_innermost              True if IP header is the innermost of the packet
 * @param ttl_irregular_chain_flag  True if the TTL/Hop Limit of an outer header has changed
 * @param ip_inner_ecn              The ECN flags of the IP innermost header
 * @return                          The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_irregular_ip_part(struct c_context *const context,
                                            ip_context_ptr_t ip_context,
                                            base_header_ip_t base_header,
                                            const int packet_size,
                                            uint8_t *rohc_data,
                                            int ecn_used,
                                            int is_innermost,
                                            int ttl_irregular_chain_flag,
                                            int ip_inner_ecn)
{
#if ROHC_EXTRA_DEBUG == 1
	const uint8_t *const rohc_data_orig = rohc_data;
#endif

	assert(context != NULL);

	rohc_comp_debug(context, "ip_context = %p, base_header_ip = %p\n",
	                ip_context.uint8, base_header.uint8);
	rohc_comp_debug(context, "ecn_used = %d, is_innermost = %d, "
	                "ttl_irregular_chain_flag = %d, ip_inner_ecn = %d\n",
	                ecn_used,is_innermost, ttl_irregular_chain_flag,
	                ip_inner_ecn);
	rohc_comp_debug(context, "IP version = %d, ip_id_behavior = %d\n",
	                base_header.ipvx->version, ip_context.v4->ip_id_behavior);

	if(base_header.ipvx->version == IPV4)
	{

		// ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE )
		if(ip_context.v4->ip_id_behavior == IP_ID_BEHAVIOR_RANDOM)
		{
			memcpy(rohc_data, &base_header.ipv4->ip_id, sizeof(uint16_t));
			rohc_data += sizeof(uint16_t);
			rohc_comp_debug(context, "add ip_id 0x%04x\n",
			                rohc_ntoh16(base_header.ipv4->ip_id));
		}

		if(is_innermost == 0)
		{
			// ipv4_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(ecn_used != 0)
			{
				rohc_data[0] = (base_header.ipv4->dscp << 2) |
				               base_header.ipv4->ip_ecn_flags;
				rohc_comp_debug(context, "add DSCP and ip_ecn_flags = 0x%02x\n",
				                rohc_data[0]);
				rohc_data++;
			}
			if(ttl_irregular_chain_flag != 0)
			{
				// ipv4_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				rohc_data[0] = base_header.ipv4->ttl_hopl;
				rohc_comp_debug(context, "add ttl_hopl = 0x%02x\n", rohc_data[0]);
				rohc_data++;
			}
			/* else: ipv4_outer_without_ttl_irregular */
		}
		/* else ipv4_innermost_irregular */
	}
	else
	{
		// IPv6
		if(is_innermost == 0)
		{
			// ipv6_outer_with/without_ttl_irregular
			// dscp =:= static_or_irreg( ecn_used.UVALUE )
			// ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE )
			if(ecn_used != 0)
			{
				uint8_t dscp = (base_header.ipv6->dscp1 << 2) |
				               base_header.ipv6->dscp2;
				rohc_data[0] = (dscp << 2) | base_header.ipv4->ip_ecn_flags;
				rohc_comp_debug(context, "add DSCP and ip_ecn_flags = 0x%02x\n",
				                rohc_data[0]);
				rohc_data++;
			}
			if(ttl_irregular_chain_flag != 0)
			{
				// ipv6_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				rohc_data[0] = base_header.ipv6->ttl_hopl;
				rohc_comp_debug(context, "add ttl_hopl = 0x%02x\n", rohc_data[0]);
				rohc_data++;
			}
			/* else: ipv6_outer_without_ttl_irregular */
		}
		/* else: ipv6_innermost_irregular */
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "IP irregular part", rohc_data_orig,
	                 rohc_data - rohc_data_orig);
#endif

	return rohc_data;
}


/**
 * @brief Decide the state that should be used for the next packet compressed
 *        with the ROHC TCP profile.
 *
 * The three states are:
 *  - Initialization and Refresh (IR),
 *  - First Order (FO),
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
#ifdef TODO
static void tcp_decide_state(struct c_context *const context)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;

	g_context = (struct c_generic_context *) context->specific;
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	rohc_comp_debug(context, "current state = %d\n", context->state);

	if(tcp_context->tmp_variables.send_tcp_dynamic)
	{
		change_state(context, ROHC_COMP_STATE_IR);
	}
	else
	{
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		decide_state(context);
	}

	rohc_comp_debug(context, "next state = %d\n", context->state);
}
#endif


/**
 * @brief Build the static part of the TCP header.
 *
 * \verbatim

 Static part of TCP header:

    +---+---+---+---+---+---+---+---+
 1  /  Source port                  /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /  Destination port             /   2 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param tcp         The TCP header
 * @param mptr        The current pointer in the rohc-packet-under-build buffer
 * @return            The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_static_tcp_part(const struct c_context *context,
                                           const tcphdr_t *tcp,
                                           multi_ptr_t mptr)
{
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP header", (unsigned char *) tcp,
	                 sizeof(tcphdr_t));

	mptr.tcp_static->src_port = tcp->src_port;
	rohc_comp_debug(context, "TCP source port = %d (0x%04x)\n",
	                rohc_ntoh16(tcp->src_port), rohc_ntoh16(tcp->src_port));

	mptr.tcp_static->dst_port = tcp->dst_port;
	rohc_comp_debug(context, "TCP destination port = %d (0x%04x)\n",
	                rohc_ntoh16(tcp->dst_port), rohc_ntoh16(tcp->dst_port));

	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP static part", mptr.uint8,
	                 sizeof(tcp_static_t));

	return mptr.uint8 + sizeof(tcp_static_t);
}


/**
 * @brief Build the dynamic part of the TCP header.
 *
 * \verbatim

 Dynamic part of TCP header:

TODO
 
\endverbatim
 *
 * @param context     The compression context
 * @param next_header The TCP header
 * @param mptr        The current pointer in the rohc-packet-under-build buffer
 * @return            The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_dynamic_tcp_part(const struct c_context *context,
                                            const unsigned char *next_header,
                                            multi_ptr_t mptr)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	const tcphdr_t *tcp;
	tcp_dynamic_t *tcp_dynamic;
	unsigned char *options;
	int options_length;
	unsigned char *urgent_datas;
#if ROHC_EXTRA_DEBUG == 1
	uint8_t *debug_ptr;
#endif
	int indicator;
	int ret;

	g_context = (struct c_generic_context *) context->specific;
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	rohc_comp_debug(context, "TCP dynamic part (minimal length = %zd)\n",
	                sizeof(tcp_dynamic_t));

	tcp = (tcphdr_t *) next_header;

	rohc_comp_debug(context, "TCP seq = 0x%04x, ack_seq = 0x%04x\n",
	                rohc_ntoh32(tcp->seq_number), rohc_ntoh32(tcp->ack_number));
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d\n",
	                *(uint16_t*)(((unsigned char*)tcp) + 12),
	                tcp->res_flags, tcp->data_offset, tcp->rsf_flags,
	                tcp->ecn_flags, tcp->urg_flag, tcp->ack_flag,
	                tcp->psh_flag);
	rohc_comp_debug(context, "TCP window = 0x%04x, check = 0x%x, "
	                "urg_ptr = %d\n", rohc_ntoh16(tcp->window),
	                rohc_ntoh16(tcp->checksum), rohc_ntoh16(tcp->urg_ptr));

	/* If urgent datas present */
	if(tcp->urg_flag != 0)
	{
		urgent_datas = ((unsigned char *) &tcp->seq_number) +
		               rohc_ntoh16(tcp->urg_ptr);
		rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
		                 ROHC_TRACE_DEBUG, "TCP urgent", urgent_datas, 16);
	}

	tcp_dynamic = mptr.tcp_dynamic;
	++mptr.tcp_dynamic;
	rohc_comp_debug(context, "TCP sizeof(tcp_dynamic_t) = %zd, "
	                "tcp_dynamic = %p, mptr.tcp_dynamic + 1 = %p\n",
	                sizeof(tcp_dynamic_t), tcp_dynamic, mptr.tcp_dynamic);

	tcp_dynamic->ecn_used = tcp_context->ecn_used;
	tcp_dynamic->tcp_res_flags = tcp->res_flags;
	tcp_dynamic->tcp_ecn_flags = tcp->ecn_flags;
	tcp_dynamic->urg_flag = tcp->urg_flag;
	tcp_dynamic->ack_flag = tcp->ack_flag;
	tcp_dynamic->psh_flag = tcp->psh_flag;
	tcp_dynamic->rsf_flags = tcp->rsf_flags;

	tcp_dynamic->msn = rohc_hton16(g_context->sn);
	tcp_dynamic->seq_number = tcp->seq_number;

	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP dynamic part",
	                 (unsigned char *) tcp_dynamic, sizeof(tcp_dynamic_t));

	tcp_context->tcp_last_seq_number = rohc_ntoh32(tcp->seq_number);
	tcp_context->tcp_seq_number_change_count++;

	/* ack_zero flag and ACK number: always check for the ACK number value even
	 * if the ACK flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those bits
	 * will be ignored at reception */
	ret = c_zero_or_irreg32(tcp->ack_number, mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to encode zero_or_irreg(ack_number)\n");
		goto error;
	}
	tcp_dynamic->ack_zero = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "TCP ack_number %spresent\n",
	                tcp_dynamic->ack_zero ? "not " : "");

	/* window */
	memcpy(mptr.uint8, &tcp->window, sizeof(uint16_t));
	mptr.uint8 += sizeof(uint16_t);

	/* checksum */
	memcpy(mptr.uint8, &tcp->checksum, sizeof(uint16_t));
	mptr.uint8 += sizeof(uint16_t);

	/* urp_zero flag and URG pointer: always check for the URG pointer value
	 * even if the URG flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those
	 * bits will be ignored at reception */
	ret = c_zero_or_irreg16(tcp->urg_ptr, mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to encode zero_or_irreg(urg_ptr)\n");
		goto error;
	}
	tcp_dynamic->urp_zero = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "TCP urg_ptr %spresent\n",
	                tcp_dynamic->urp_zero ? "not " : "");

	/* ack_stride */ /* TODO: comparison with new computed ack_stride? */
	ret = c_static_or_irreg16(tcp_context->ack_stride,
	                          rohc_hton16(tcp_context->ack_stride),
	                          mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to encode static_or_irreg(ack_stride)\n");
		goto error;
	}
	tcp_dynamic->ack_stride_flag = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "TCP ack_stride %spresent\n",
	                tcp_dynamic->ack_stride_flag ? "" : "not ");

	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP dynamic part",
	                 (unsigned char *) tcp_dynamic,
	                 mptr.uint8 - ((unsigned char*) tcp_dynamic));

	/* doff is the size of tcp header using 32 bits */
	/* TCP header is at least 20 bytes */
	if(tcp->data_offset > 5)
	{
		uint8_t *pBeginList;
		uint8_t *pValue;
		uint8_t opt_idx;
		int i;

		/* init pointer to TCP options */
		options = ( (unsigned char *) tcp ) + sizeof(tcphdr_t);
		options_length = (tcp->data_offset << 2) - sizeof(tcphdr_t);
		rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
		                 ROHC_TRACE_DEBUG, "TCP options", options,
		                 options_length);
#if ROHC_EXTRA_DEBUG == 1
		debug_ptr = mptr.uint8;
#endif

		/* Save the begin of the list */
		pBeginList = mptr.uint8++;
		/* List is empty */
		*pBeginList = 0;

		for(i = options_length; i > 0; )
		{
			/* determine the index of the TCP option */
			opt_idx = tcp_options_index[*options];

			/* if index never used before */
			if(opt_idx <= TCP_INDEX_SACK /* *options == TCP_OPT_TIMESTAMP*/ ||
			   tcp_context->tcp_options_list[opt_idx] == 0xFF)
			{
				rohc_comp_debug(context, "TCP index = %d never used for option "
				                "%d!\n", opt_idx, *options);

				// Now index used with this option
				tcp_context->tcp_options_list[opt_idx] = *options;

				// Save the value of the TCP option
				switch(*options)
				{
					case TCP_OPT_EOL: // End Of List
						rohc_comp_debug(context, "TCP option EOL\n");
						break;
					case TCP_OPT_NOP: // No Operation
						rohc_comp_debug(context, "TCP option NOP\n");
						break;
					case TCP_OPT_MAXSEG: // Max Segment Size
						memcpy(&tcp_context->tcp_option_maxseg,options + 2,2);
						rohc_comp_debug(context, "TCP option MAXSEG = %d (0x%x)\n",
						                rohc_ntoh16(tcp_context->tcp_option_maxseg),
						                rohc_ntoh16(tcp_context->tcp_option_maxseg));
						break;
					case TCP_OPT_WINDOW: // Window
						rohc_comp_debug(context, "TCP option WINDOW = %d\n",
						                *(options + 2));
						tcp_context->tcp_option_window = *(options + 2);
						break;
					case TCP_OPT_SACK_PERMITTED: // see RFC2018
						rohc_comp_debug(context, "TCP option SACK PERMITTED\n");
						break;
					case TCP_OPT_SACK:
						rohc_comp_debug(context, "TCP option SACK Length = %d\n",
						                *(options + 1));
						tcp_context->tcp_option_sack_length = *(options + 1) - 2;
						assert( tcp_context->tcp_option_sack_length <= (8 * 4) );
						memcpy(tcp_context->tcp_option_sackblocks,options + 1,
						       tcp_context->tcp_option_sack_length);
						break;
					case TCP_OPT_TIMESTAMP:
					{
						uint32_t ts;
						uint32_t ts_reply;

						memcpy(&ts, options + 2, sizeof(uint32_t));
						memcpy(&ts_reply, options + 6, sizeof(uint32_t));
						rohc_comp_debug(context, "TCP option TIMESTAMP = 0x%04x 0x%04x\n",
						                rohc_ntoh32(ts), rohc_ntoh32(ts_reply));
						memcpy(&tcp_context->tcp_option_timestamp, options + 2,
								 sizeof(struct tcp_option_timestamp));
						tcp_context->tcp_option_timestamp_init = true;
						c_add_wlsb(tcp_context->opt_ts_req_wlsb, g_context->sn,
						           rohc_ntoh32(ts));
						c_add_wlsb(tcp_context->opt_ts_reply_wlsb, g_context->sn,
						           rohc_ntoh32(ts_reply));
						break;
					}
					default:
						// Save offset of option value
						tcp_context->tcp_options_offset[opt_idx] =
							tcp_context->tcp_options_free_offset;
						pValue = tcp_context->tcp_options_values + tcp_context->tcp_options_free_offset;
						// Save length
						*pValue = *(options + 1) - 2;
						// Save value
						memcpy(pValue + 1,options + 2,*pValue);
						// Update first free offset
						tcp_context->tcp_options_free_offset += 1 + *pValue;
						assert( tcp_context->tcp_options_free_offset < MAX_TCP_OPT_SIZE );
						break;
				}
			}
			else
			{
				int compare_value;

				// Verify if used with same value
				switch(*options)
				{
					case TCP_OPT_EOL: // End Of List
						rohc_comp_debug(context, "TCP option EOL\n");
						compare_value = 0;
						break;
					case TCP_OPT_NOP: // No Operation
						rohc_comp_debug(context, "TCP option NOP\n");
						compare_value = 0;
						break;
					case TCP_OPT_MAXSEG: // Max Segment Size
						rohc_comp_debug(context, "TCP option MAXSEG = 0x%x\n",
						                (((*(options + 2)) << 8) +
						                 (*(options + 3))));
						compare_value = memcmp(&tcp_context->tcp_option_maxseg,options + 2,2);
						break;
					case TCP_OPT_WINDOW: // Window
						rohc_comp_debug(context, "TCP option WINDOW = %d\n",
						                *(options + 2));
						compare_value = tcp_context->tcp_option_window - *(options + 2);
						break;
					case TCP_OPT_SACK_PERMITTED: // see RFC2018
						rohc_comp_debug(context, "TCP option SACK PERMITTED\n");
						compare_value = 0;
						break;
					case TCP_OPT_SACK:
						rohc_comp_debug(context, "TCP option SACK Length = %d\n",
						                *(options + 1));
						compare_value = tcp_context->tcp_option_sack_length - *(options + 1);
						compare_value += memcmp(tcp_context->tcp_option_sackblocks,options + 2,
						                        tcp_context->tcp_option_sack_length);
						break;
					case TCP_OPT_TIMESTAMP:
						rohc_comp_debug(context, "TCP option TIMESTAMP = 0x%04x 0x%04x\n",
						                rohc_ntoh32(*(uint32_t*)(options + 2)),
						                rohc_ntoh32(*(uint32_t*)(options + 6)));
						compare_value = memcmp(&tcp_context->tcp_option_timestamp,
													  options + 2,
													  sizeof(struct tcp_option_timestamp));
						break;
					default:
						pValue = tcp_context->tcp_options_values +
						         tcp_context->tcp_options_offset[opt_idx];
						if( ( compare_value = ((*pValue) + 2) - *(options + 1) ) == 0)
						{
							compare_value = memcmp(pValue + 1,options + 2,*pValue);
						}
						break;
				}
				// If same value
				if(compare_value == 0)
				{
					// Use same index
					rohc_comp_debug(context, "TCP index = %u already used with "
					                "same value!\n", opt_idx);
				}
				else
				{
					rohc_comp_debug(context, "TCP index = %u already used with "
					                "different value!\n", opt_idx);

					// Try to find a new free index
					for(opt_idx = TCP_INDEX_SACK + 1;
					    opt_idx < MAX_TCP_OPTION_INDEX; opt_idx++)
					{
						if(tcp_context->tcp_options_list[opt_idx] == 0xFF)
						{
							break;
						}
					}
					if(opt_idx == MAX_TCP_OPTION_INDEX)
					{
						// Index not found !
						rohc_comp_debug(context, "cannot find a new free index!\n");
					}
					else
					{
						// Index used now
						tcp_context->tcp_options_list[opt_idx] = *options;
						// Save offset of option value
						tcp_context->tcp_options_offset[opt_idx] =
							tcp_context->tcp_options_free_offset;
						pValue = tcp_context->tcp_options_values +
						         tcp_context->tcp_options_free_offset;
						// Save length
						*pValue = *(options + 1) - 2;
						// Save value
						memcpy(pValue + 1,options + 2,*pValue);
						// Update first free offset
						tcp_context->tcp_options_free_offset += 1 + *pValue;
						assert( tcp_context->tcp_options_free_offset < MAX_TCP_OPT_SIZE );
					}
				}
			}
			// Update length
			switch(*options)
			{
				case TCP_OPT_EOL: // End Of List
					i = 0;
					++options;
					break;
				case TCP_OPT_NOP: // No Operation
					--i;
					++options;
					break;
				case TCP_OPT_MAXSEG: // Max Segment Size
					i -= TCP_OLEN_MAXSEG;
					options += TCP_OLEN_MAXSEG;
					break;
				case TCP_OPT_WINDOW: // Window
					i -= TCP_OLEN_WINDOW;
					options += TCP_OLEN_WINDOW;
					break;
				case TCP_OPT_SACK_PERMITTED: // see RFC2018
					i -= TCP_OLEN_SACK_PERMITTED;
					options += TCP_OLEN_SACK_PERMITTED;
					break;
				case TCP_OPT_SACK:
					i -= *(options + 1);
					options += *(options + 1);
					break;
				case TCP_OPT_TIMESTAMP:
					i -= TCP_OLEN_TIMESTAMP;
					options += TCP_OLEN_TIMESTAMP;
					// TCP_OLEN_TSTAMP_APPA    (TCP_OLEN_TIMESTAMP+2) /* appendix A */
					break;
				/*
				case TCP_OPT_TSTAMP_HDR:
					rohc_comp_debug(context, "TCP option TIMESTAMP HDR\n");
					i = 0;
					break;
				*/
				default:
					rohc_comp_debug(context, "TCP option unknown = 0x%x\n", *options);
					if(*options > 15)
					{
						rohc_comp_debug(context, "TCP invalid option = %d (0x%x)\n",
						                *options, *options);
						break;
					}
					i -= *(options + 1);
					options += *(options + 1);
					break;
			}
			#if MAX_TCP_OPTION_INDEX == 8
			// Use 4-bit XI fields
			// If number of item is odd
			if( (*pBeginList) & 1)
			{
				*mptr.uint8 |= 0x08 | opt_idx;
				++mptr.uint8;
			}
			else
			{
				*mptr.uint8 = (0x08 | opt_idx) << 4;
			}
			#else
			*(mptr.uint8++) = 0x80 | opt_idx;
			#endif
			// One item more
			++(*pBeginList);
		}
		#if MAX_TCP_OPTION_INDEX == 8
		// If number of item is odd
		if( (*pBeginList) & 1)
		{
			// update pointer (padding)
			++mptr.uint8;
		}
		#else
		// 8-bit XI field
		*pBeginList |= 0x10;
		#endif
#if ROHC_EXTRA_DEBUG == 1
		rohc_comp_debug(context, "TCP %d item(s) in list at %p\n",
		                (*pBeginList) & 0x0f, debug_ptr);
#endif
		/* init pointer to the begining of TCP options */
		pBeginList = ( (unsigned char *) tcp ) + sizeof(tcphdr_t);
		/* copy all TCP options */
		memcpy(mptr.uint8,pBeginList,options - pBeginList);
		/* update pointer */
		mptr.uint8 += options - pBeginList;
#if ROHC_EXTRA_DEBUG == 1
		rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
		                 ROHC_TRACE_DEBUG, "debug_ptr", debug_ptr,
		                 mptr.uint8 - debug_ptr);
#endif
	}
	else
	{
		rohc_comp_debug(context, "TCP no options!\n");
		// See RFC4996, 6.3.3 : no XI items
		// PS=0 m=0
		*(mptr.uint8++) = 0;
	}

	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP dynamic part",
	                 (unsigned char *) tcp_dynamic,
	                 mptr.uint8 - (uint8_t *) tcp_dynamic);

	return mptr.uint8;

error:
	return NULL;
}


/**
 * @brief Build the irregular part of the TCP header.
 *
 * @param context       The compression context
 * @param tcp           The TCP header
 * @param rohc_data     The current pointer in the rohc-packet-under-build buffer
 * @param ip_inner_ecn  The ecn flags of the ip inner
 * @return              The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_irregular_tcp_part(struct c_context *const context,
                                             tcphdr_t *tcp,
                                             uint8_t *const rohc_data,
                                             int ip_inner_ecn)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	uint8_t *remain_data = rohc_data;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	// ip_ecn_flags = := tcp_irreg_ip_ecn(ip_inner_ecn)
	// tcp_res_flags =:= static_or_irreg(ecn_used.CVALUE,4)
	// tcp_ecn_flags =:= static_or_irreg(ecn_used.CVALUE,2)
	if(tcp_context->ecn_used != 0)
	{
		remain_data[0] =
			(((ip_inner_ecn << 2) | tcp->ecn_flags) << 4) | tcp->res_flags;
		rohc_comp_debug(context, "add TCP ecn_flags res_flags = 0x%02x\n",
		                remain_data[0]);
		remain_data++;
	}

	// checksum =:= irregular(16)
	memcpy(remain_data, &tcp->checksum, sizeof(uint16_t));
	remain_data += sizeof(uint16_t);
	rohc_comp_debug(context, "add TCP checksum = 0x%04x\n",
	                rohc_ntoh16(tcp->checksum));

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP irregular part", rohc_data,
	                 remain_data - rohc_data);
#endif

	return remain_data;
}


/**
 * @brief Compress the TimeStamp option value.
 *
 * See RFC4996 page 65
 *
 * @param context          The compression context
 * @param[out] dest        Pointer to the compressed value
 * @param timestamp        The timestamp value to compress
 * @param nr_bits_minus_1  The minimal number of required bits for p = -1
 * @param nr_bits_0x40000  The minimal number of required bits for p = 0x40000
 * @return                 true if compression was successful, false otherwise
 */
static bool c_ts_lsb(const struct c_context *const context,
                     uint8_t **dest,
                     const uint32_t timestamp,
                     const size_t nr_bits_minus_1,
                     const size_t nr_bits_0x40000)
{
	uint8_t *ptr = *dest;

	assert(context != NULL);
	assert(ptr != NULL);

	rohc_comp_debug(context, "encode timestamp = 0x%x\n", timestamp);

	if(nr_bits_minus_1 <= 7)
	{
		/* discriminator '0' */
		*(ptr++) = timestamp & 0x7F;
	}
	else if(nr_bits_minus_1 <= 14)
	{
		/* discriminator '10' */
		*(ptr++) = 0x80 | ((timestamp >> 8) & 0x3F);
		*(ptr++) = timestamp;
	}
	else if(nr_bits_0x40000 <= 21)
	{
		/* discriminator '110' */
		*(ptr++) = 0xC0 | ((timestamp >> 16) & 0x1F);
		*(ptr++) = timestamp >> 8;
		*(ptr++) = timestamp;
	}
	else if(nr_bits_0x40000 <= 29)
	{
		/* discriminator '111' */
		*(ptr++) = 0xE0 | ((timestamp >> 24) & 0x1F);
		*(ptr++) = timestamp >> 16;
		*(ptr++) = timestamp >> 8;
		*(ptr++) = timestamp;
	}
	else
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to compress timestamp 0x%08x: more than 29 bits "
		             "required\n", timestamp);
		goto error;
	}

	*dest = ptr;

	return true;

error:
	return false;
}


/**
 * @brief Compress the SACK field value.
 *
 * See RFC6846 page 67
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context   The compression context
 * @param ptr       Pointer to the compressed value
 * @param base      The base value
 * @param field     The value to compress
 * @return          Pointer after the compressed value
 */
static uint8_t * c_sack_pure_lsb(const struct c_context *const context,
                                 uint8_t *ptr,
                                 uint32_t base,
                                 uint32_t field)
{
	uint32_t sack_field;
	size_t len;

	assert(context != NULL);

	/* if base can be >= field, overflow is expected */
	sack_field = field - base;

	if(sack_field < 0x8000)
	{
		/* discriminator '0' */
		*ptr = 0;
		*(ptr++) = ( sack_field >> 8 ) & 0x7F;
		*(ptr++) = sack_field & 0xff;
		len = 2;
	}
	else if(sack_field < 0x400000)
	{
		/* discriminator '10' */
		*(ptr++) = 0x80 | ( ( sack_field >> 16 ) & 0x3F );
		*(ptr++) = (sack_field >> 8) & 0xff;
		*(ptr++) = sack_field & 0xff;
		len = 3;
	}
	else if(sack_field < 0x40000000)
	{
		/* discriminator '110' */
		*(ptr++) = 0xC0 | ( ( sack_field >> 24 ) & 0x3F );
		*(ptr++) = (sack_field >> 16) & 0xff;
		*(ptr++) = (sack_field >> 8) & 0xff;
		*(ptr++) = sack_field & 0xff;
		len = 4;
	}
	else
	{
		/* discriminator '11111111' */
		*(ptr++) = 0xff;
		*(ptr++) = (sack_field >> 24) & 0xff;
		*(ptr++) = (sack_field >> 16) & 0xff;
		*(ptr++) = (sack_field >> 8) & 0xff;
		*(ptr++) = sack_field & 0xff;
		len = 5;
	}

	rohc_comp_debug(context, "sack_field = 0x%x (0x%x - 0x%x) encoded on %zd "
	                "bytes (discriminator included)\n", sack_field, field,
	                base, len);

	return ptr;
}


/**
 * @brief Compress a SACK block.
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context     The compression context
 * @param ptr         Pointer to the compressed value
 * @param reference   The reference value
 * @param sack_block  Pointer to the SACK block to compress
 * @return            Pointer after the compressed value
 */
static uint8_t * c_sack_block(const struct c_context *const context,
                              uint8_t *ptr,
                              uint32_t reference,
                              sack_block_t *sack_block)
{
	assert(context != NULL);

	rohc_comp_debug(context, "reference = 0x%x, block_start = 0x%x, "
	                "block_end = 0x%x\n", reference,
	                rohc_ntoh32(sack_block->block_start),
	                rohc_ntoh32(sack_block->block_end));

	// block_start =:= sack_var_length_enc(reference)
	ptr = c_sack_pure_lsb(context, ptr, reference,
	                      rohc_ntoh32(sack_block->block_start));
	// block_end =:= sack_var_length_enc(block_start)
	ptr = c_sack_pure_lsb(context, ptr, rohc_ntoh32(sack_block->block_start),
	                      rohc_ntoh32(sack_block->block_end));

	return ptr;
}


/**
 * @brief Compress the SACK TCP option.
 *
 * See RFC6846 page 68
 * (and RFC2018 for Selective Acknowledgement option)
 *
 * @param context     The compression context
 * @param ptr         Pointer to the compressed value
 * @param ack_value   The ack value
 * @param length      The length of the sack block
 * @param sack_block  Pointer to the first SACK block to compress
 * @return            Pointer after the compressed value
 */
static uint8_t * c_tcp_opt_sack(const struct c_context *const context,
                                uint8_t *ptr,
                                uint32_t ack_value,
                                uint8_t length,
                                sack_block_t *sack_block)
{
	int i;

	assert(context != NULL);

	rohc_comp_debug(context, "TCP option SACK (reference ACK = 0x%08x)\n",
	                ack_value);
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP option SACK",
	                 (unsigned char *) sack_block, length - 2);

	// Calculate number of sack_block
	i = (length - 2) >> 3;
	*(ptr++) = i;
	// Compress each sack_block
	while(i-- != 0)
	{
		rohc_comp_debug(context, "block of SACK option: start = 0x%08x, "
		                "end = 0x%08x\n", rohc_ntoh32(sack_block->block_start),
		                rohc_ntoh32(sack_block->block_end));
		ptr = c_sack_block(context, ptr, ack_value, sack_block);
		++sack_block;
	}

	return ptr;
}


/**
 * @brief Compress a generic TCP option
 *
 * See RFC4996 page 67
 *
 * @param tcp_context  The specific TCP context
 * @param ptr          Pointer where to compress the option
 * @param options      Pointer to the TCP option to compress
 * @return             Pointer after the compressed value
 */
static uint8_t * c_tcp_opt_generic(struct sc_tcp_context *tcp_context,
                                   uint8_t *ptr,
                                   uint8_t *options)
{
	// generic_static_irregular

	// generic_stable_irregular
	*(ptr++) = 0xFF;
	// generic_full_irregular
	*(ptr++) = 0x00;

	return ptr;
}


/**
 * @brief Compress the TCP options
 *
 * @param context        The compression context
 * @param tcp            The TCP header
 * @param comp_opts      IN/OUT: The compressed TCP options
 * @param comp_opts_len  OUT: The length (in bytes) of the compressed TCP options
 * @return               true if the TCP options were successfully compressed,
 *                       false otherwise
 */
static bool tcp_compress_tcp_options(struct c_context *const context,
												 const tcphdr_t *const tcp,
												 uint8_t *const comp_opts,
												 size_t *const comp_opts_len)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	uint8_t compressed_options[40];
	uint8_t *ptr_compressed_options;
	uint8_t *options;
	int options_length;
	uint8_t *pValue;
	uint8_t opt_idx;
	uint8_t m;
	bool is_ok;
	int i;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	tcp_context = (struct sc_tcp_context *) g_context->specific;
	assert(tcp != NULL);
	assert(comp_opts != NULL);
	assert(comp_opts_len != NULL);

	/* retrieve TCP options */
	options = ((uint8_t *) tcp) + sizeof(tcphdr_t);
	options_length = (tcp->data_offset << 2) - sizeof(tcphdr_t);
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP options", options, options_length);

	/* List is empty */
	*comp_opts_len = 0;
	comp_opts[*comp_opts_len] = 0;
	(*comp_opts_len)++;

	ptr_compressed_options = compressed_options;

	// see RFC4996 page 25-26
	for(m = 0, i = options_length; i > 0; )
	{
		/* determine the index of the TCP option */
		opt_idx = tcp_options_index[*options];
		rohc_comp_debug(context, "i = %d, options = %p, id = %d, opt_idx = %u, "
		                "length = %d, tcp_options_list[%d] = %d\n",
		                i, options, *options, opt_idx, *(options + 1), opt_idx,
		                tcp_context->tcp_options_list[opt_idx]);

		// If option already used
		if(tcp_context->tcp_options_list[opt_idx] == *options)
		{
			rohc_comp_debug(context, "TCP option of type %d at index %u was "
			                "already used\n", *options, opt_idx);

			// Verify if used with same value
			switch(opt_idx)
			{
				case TCP_INDEX_NOP: // No Operation
					rohc_comp_debug(context, "TCP option NOP\n");
					--i;
					++options;
					goto same_index_without_value;
				case TCP_INDEX_EOL: // End Of List
					rohc_comp_debug(context, "TCP option EOL\n");
					i = 0;
					goto same_index_without_value;
				case TCP_INDEX_MAXSEG: // Max Segment Size
					                    // If same value that in the context
					if(memcmp(&tcp_context->tcp_option_maxseg,options + 2,2) == 0)
					{
						rohc_comp_debug(context, "TCP option MAXSEG same value\n");
						i -= TCP_OLEN_MAXSEG;
						options += TCP_OLEN_MAXSEG;
						goto same_index_without_value;
					}
					rohc_comp_debug(context, "TCP option MAXSEG different value\n");
					break;
				case TCP_INDEX_WINDOW: // Window
					                    // If same value that in the context
					if(tcp_context->tcp_option_window == *(options + 2) )
					{
						rohc_comp_debug(context, "TCP option WINDOW same value\n");
						i -= TCP_OLEN_WINDOW;
						options += TCP_OLEN_WINDOW;
						goto same_index_without_value;
					}
					rohc_comp_debug(context, "TCP option WINDOW different value\n");
					break;
				case TCP_INDEX_TIMESTAMP:
				{
					uint32_t ts;
					uint32_t ts_reply;

					memcpy(&ts, options + 2, sizeof(uint32_t));
					memcpy(&ts_reply, options + 6, sizeof(uint32_t));

					if(memcmp(&tcp_context->tcp_option_timestamp, options + 2,
								 sizeof(struct tcp_option_timestamp)) == 0)
					{
						rohc_comp_debug(context, "TCP option TIMESTAMP same value "
						                "(0x%04x 0x%04x)\n",
						                rohc_ntoh32(ts), rohc_ntoh32(ts_reply));
						i -= TCP_OLEN_TIMESTAMP;
						options += TCP_OLEN_TIMESTAMP;
						goto same_index_without_value;
					}
					rohc_comp_debug(context, "TCP option TIMESTAMP not same value "
					                "(0x%04x 0x%04x)\n",
					                rohc_ntoh32(ts), rohc_ntoh32(ts_reply));
					// Use same index because time always change!
					// memcpy(&tcp_context->tcp_option_timestamp, options + 2,
					//        sizeof(struct tcp_option_timestamp));
					// i -= TCP_OLEN_TIMESTAMP;
					// options += TCP_OLEN_TIMESTAMP;
					goto new_index_with_compressed_value;
					break;
				}
				case TCP_INDEX_SACK_PERMITTED: // see RFC2018
					rohc_comp_debug(context, "TCP option SACK PERMITTED\n");
					i -= TCP_OLEN_SACK_PERMITTED;
					options += TCP_OLEN_SACK_PERMITTED;
					goto same_index_without_value;
				case TCP_INDEX_SACK: // see RFC2018
					if(tcp_context->tcp_option_sack_length == *(options + 1) &&
					   memcmp(tcp_context->tcp_option_sackblocks,options + 2,*(options + 1)) == 0)
					{
						rohc_comp_debug(context, "TCP option SACK same value\n");
						i -= *(options + 1);
						options += *(options + 1);
						goto same_index_without_value;
					}
					rohc_comp_debug(context, "TCP option SACK different value\n");
					// Use same index because acknowledge always change!
					// memcpy(tcp_context->tcp_option_sackblocks,options+2,*(options+1))
					// i -= *(options+1);
					// options += *(options+1);
					goto new_index_with_compressed_value;
					break;
				default:
					rohc_comp_debug(context, "TCP option of type %d at index %u\n",
					                *options, opt_idx);
					// Init pointer where is the value
					pValue = tcp_context->tcp_options_values +
					         tcp_context->tcp_options_offset[opt_idx];
					// If same length
					if( ((*pValue) + 2) == *(options + 1) )
					{
						// If same value
						if(memcmp(pValue + 1,options + 2,*pValue) == 0)
						{
							rohc_comp_debug(context, "TCP option of type %d: same "
							                "value\n", *options);
							// Use same index
							goto same_index_without_value;
						}
					}
					rohc_comp_debug(context, "TCP option of type %d: different "
					                "value\n", *options);
					break;
			}
		}
		else
		{
			rohc_comp_debug(context, "TCP option of type %d was never used "
			                "before with index %u\n", *options, opt_idx);

			// Some TCP option are compressed without item
			switch(opt_idx)
			{
				case TCP_INDEX_NOP: // No Operation
					rohc_comp_debug(context, "TCP option NOP\n");
					--i;
					++options;
					tcp_context->tcp_options_list[opt_idx] = *options;
					// tcp_opt_nop page 64
					goto same_index_without_value;
				case TCP_INDEX_EOL: // End Of List
					rohc_comp_debug(context, "TCP option EOL\n");
					i = 0;
					tcp_context->tcp_options_list[opt_idx] = *options;
					// tcp_opt_eol page 63
					goto same_index_without_value;
				case TCP_INDEX_SACK_PERMITTED: // see RFC2018
					rohc_comp_debug(context, "TCP option SACK PERMITTED\n");
					i -= TCP_OLEN_SACK_PERMITTED;
					options += TCP_OLEN_SACK_PERMITTED;
					tcp_context->tcp_options_list[opt_idx] = *options;
					// tcp_opt_sack_permitted page 69
					goto same_index_without_value;
				case TCP_INDEX_SACK:
					goto new_index_with_compressed_value;
				default:
					rohc_comp_debug(context, "TCP option of type %d at index %u\n",
					                *options, opt_idx);
					break;
			}

			// Verify if TCP option not used before with another index
			for(opt_idx = TCP_INDEX_SACK + 1;
			    opt_idx < MAX_TCP_OPTION_INDEX &&
			    tcp_context->tcp_options_list[opt_idx] != 0xFF; opt_idx++)
			{
				if(tcp_context->tcp_options_list[opt_idx] == *options)
				{
					// Init pointer where is the value
					pValue = tcp_context->tcp_options_values +
					         tcp_context->tcp_options_offset[opt_idx];
					// If same length
					if( ((*pValue) + 2) == *(options + 1) )
					{
						// If same value
						if(memcmp(pValue + 1,options + 2,*pValue) == 0)
						{
							// Use same index
							goto same_index_without_value;
						}
					}
				}
			}

			rohc_comp_debug(context, "TCP option of type %d was never used "
			                "before with same value\n", *options);

			if(opt_idx == MAX_TCP_OPTION_INDEX)
			{
				rohc_comp_debug(context, "warning: TCP option list is full!\n");
				i -= TCP_OLEN_SACK_PERMITTED;
				options += TCP_OLEN_SACK_PERMITTED;
				continue;
			}

		}

		rohc_comp_debug(context, "try to find a new free index\n");

		// Try to find a new free index
		for(opt_idx = TCP_INDEX_SACK + 1; opt_idx < MAX_TCP_OPTION_INDEX; opt_idx++)
		{
			rohc_comp_debug(context, "tcp_options_list[%u] = %d\n", opt_idx,
			                tcp_context->tcp_options_list[opt_idx]);

			// If other index already used for this option
			if(tcp_context->tcp_options_list[opt_idx] == *options)
			{
				// Verify if same value
				// Init pointer where is the value
				pValue = tcp_context->tcp_options_values +
				         tcp_context->tcp_options_offset[opt_idx];
				// If same length
				if( ((*pValue) + 2) == *(options + 1) )
				{
					// If same value
					if(memcmp(pValue + 1,options + 2,*pValue) == 0)
					{
						rohc_comp_debug(context, "index %u for options %d used "
						                "with same value\n", opt_idx, *options);

						i -= *(options + 1);
						options += *(options + 1);

						// Use same index
						goto same_index_without_value;
					}
				}
				continue;
			}
			// If free index
			if(tcp_context->tcp_options_list[opt_idx] == 0xFF)
			{
				// Save option for this index
				tcp_context->tcp_options_list[opt_idx] = *options;
				// Save offset of the TCP option value
				tcp_context->tcp_options_offset[opt_idx] =
					tcp_context->tcp_options_free_offset;
				// Init pointer where to store
				pValue = tcp_context->tcp_options_values + tcp_context->tcp_options_free_offset;
				// Save length
				*pValue = *(options + 1) - 2;
				// Save value
				memcpy(pValue + 1,options + 2,*pValue);
				// Update first free offset
				tcp_context->tcp_options_free_offset += 1 + *pValue;
				assert( tcp_context->tcp_options_free_offset < MAX_TCP_OPT_SIZE );
				goto new_index_with_compressed_value;
			}

		}
		if(opt_idx == MAX_TCP_OPTION_INDEX)
		{
			// PROBLEM !!!
			rohc_comp_debug(context, "max index used for TCP options, TCP "
			                "option full!\n");
			i -= *(options + 1);
			options += *(options + 1);
			continue;
		}

new_index_with_compressed_value:

		switch(*options)
		{
			case TCP_OPT_MAXSEG: // Max Segment Size
				rohc_comp_debug(context, "TCP option MAXSEG\n");
				// see RFC4996 page 64
				options += 2;
				*(ptr_compressed_options++) = *(options++);
				*(ptr_compressed_options++) = *(options++);
				i -= TCP_OLEN_MAXSEG;
				break;
			case TCP_OPT_WINDOW: // Window
				rohc_comp_debug(context, "TCP option WINDOW\n");
				// see RFC4996 page 65
				options += 2;
				*(ptr_compressed_options++) = *(options++);
				i -= TCP_OLEN_WINDOW;
				break;
			case TCP_OPT_SACK: // see RFC2018
				rohc_comp_debug(context, "TCP option SACK\n");
				// see RFC4996 page 67
				ptr_compressed_options =
				   c_tcp_opt_sack(context, ptr_compressed_options,
				                  rohc_ntoh32(tcp->ack_number), *(options + 1),
				                  (sack_block_t *) (options + 2));
				i -= *(options + 1);
				options += *(options + 1);
				break;
			case TCP_OPT_TIMESTAMP:
			{
				uint32_t ts;
				uint32_t ts_reply;

				memcpy(&ts, options + 2, sizeof(uint32_t));
				memcpy(&ts_reply, options + 6, sizeof(uint32_t));

				rohc_comp_debug(context, "TCP option TIMESTAMP = 0x%04x 0x%04x\n",
				                rohc_ntoh32(ts), rohc_ntoh32(ts_reply));
				// see RFC4996 page65
				// ptr_compressed_options = c_tcp_opt_ts(ptr_compressed_options,options+2);
				is_ok = c_ts_lsb(context, &ptr_compressed_options,
				                 rohc_ntoh32(ts),
				                 tcp_context->tmp.nr_opt_ts_req_bits_minus_1,
				                 tcp_context->tmp.nr_opt_ts_req_bits_0x40000);
				if(!is_ok)
				{
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
									 context->profile->id,
									 "failed to compress the timestamp value of the TCP "
									 "Timestamp option\n");
					goto error;
				}
				is_ok = c_ts_lsb(context, &ptr_compressed_options,
									  rohc_ntoh32(ts_reply),
				                 tcp_context->tmp.nr_opt_ts_reply_bits_minus_1,
				                 tcp_context->tmp.nr_opt_ts_reply_bits_0x40000);
				if(!is_ok)
				{
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
									 context->profile->id,
									 "failed to compress the timestamp echo reply of "
									 "the TCP Timestamp option\n");
					goto error;
				}

				/* save value after compression */
				memcpy(&tcp_context->tcp_option_timestamp, options + 2,
				       sizeof(struct tcp_option_timestamp));
				tcp_context->tcp_option_timestamp_init = true;
				c_add_wlsb(tcp_context->opt_ts_req_wlsb, g_context->sn,
				           rohc_ntoh32(ts));
				c_add_wlsb(tcp_context->opt_ts_reply_wlsb, g_context->sn,
				           rohc_ntoh32(ts_reply));

				i -= TCP_OLEN_TIMESTAMP;
				options += TCP_OLEN_TIMESTAMP;
				break;
			}
			/*
			case TCP_OPT_TSTAMP_HDR:
				rohc_comp_debug(context, "TCP option TIMESTAMP HDR\n");
				i = 0;
				break;
			*/
			default:
				rohc_comp_debug(context, "TCP option unknown 0x%x\n", *options);
				assert( tcp_options_index[*options] > TCP_INDEX_SACK );
				if(*options > 15)
				{
					rohc_comp_debug(context, "TCP invalid option %d (0x%x)\n",
					                *options, *options);
					break;
				}
				// see RFC4996 page 69
				ptr_compressed_options = c_tcp_opt_generic(tcp_context,ptr_compressed_options,options);
				i -= *(options + 1);
				options += *(options + 1);
				break;
		}

#if MAX_TCP_OPTION_INDEX == 8
		if(m & 1)
		{
			comp_opts[*comp_opts_len] |= opt_idx | 0x08;
			(*comp_opts_len)++;
		}
		else
		{
			comp_opts[(*comp_opts_len)] = (opt_idx | 0x08) << 4;
		}
#else
		comp_opts[(*comp_opts_len)] = opt_idx | 0x80;
		(*comp_opts_len)++;
#endif
		++m;
		continue;

same_index_without_value:

#if MAX_TCP_OPTION_INDEX == 8
		if(m & 1)
		{
			comp_opts[(*comp_opts_len)] |= opt_idx;
			(*comp_opts_len)++;
		}
		else
		{
			comp_opts[(*comp_opts_len)] = opt_idx << 4;
		}
#else
		comp_opts[(*comp_opts_len)] = opt_idx;
		(*comp_opts_len)++;
#endif
		++m;
		continue;
	}

#if MAX_TCP_OPTION_INDEX == 8
	// 4-bit XI field
	comp_opts[0] = m;
	// If odd number of TCP options
	(*comp_opts_len) += m & 1;
#else
	// 8-bit XI field
	comp_opts[0] = m | 0x10;
#endif

	// If compressed value present
	if(ptr_compressed_options > compressed_options)
	{
		// Add them
		memcpy(comp_opts + (*comp_opts_len), compressed_options,
				 ptr_compressed_options - compressed_options);
		(*comp_opts_len) += (ptr_compressed_options - compressed_options);
	}

	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "TCP compressed options",
						  comp_opts, *comp_opts_len);

	return true;

error:
	return false;
}


/**
 * @brief Build the CO packet.
 *
 * See RFC4996 page 46
 *
 * \verbatim

 CO packet (RFC4996 §7.3 page 41):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  |   First octet of base header  |  (with type indication)
    +---+---+---+---+---+---+---+---+
    |                               |
 3  /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
 4  /   Remainder of base header    /  variable number of octets
    +---+---+---+---+---+---+---+---+
    :        Irregular chain        :
 5  /   (including irregular chain  /  variable
    :    items for TCP options)     :
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /           Payload             /  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param packet_size       The length of the uncompressed packet (in bytes)
 * @param next_header       The next header data used to code the static and
 *                          dynamic parts of the next header for some profiles
 *                          such as UDP, UDP-Lite, and so on.
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_CO_packet(struct c_context *const context,
                          const struct ip_packet *ip,
                          const int packet_size,
                          const unsigned char *next_header,
                          unsigned char *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          rohc_packet_t *const packet_type,
                          int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	ip_context_ptr_t ip_inner_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header_inner;
	base_header_ip_t base_header;
	tcphdr_t *tcp;
	uint8_t ttl_hopl;
	int ttl_irregular_chain_flag;
	int remain_data_len;
	int counter;
	size_t first_position;
	multi_ptr_t mptr;
	uint8_t save_first_byte;
	uint16_t payload_size;
	int ip_inner_ecn;
#if ROHC_EXTRA_DEBUG == 1
	uint8_t *puchar;
#endif
	uint8_t protocol;
	int i;

	assert(context != NULL);
	assert(context->specific != NULL);
	assert(packet_type != NULL);

	g_context = (struct c_generic_context *) context->specific;
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	*packet_type = ROHC_PACKET_UNKNOWN;

	rohc_comp_debug(context, "code CO packet (CID = %zu)\n", context->cid);

	rohc_comp_debug(context, "context = %p, ip = %p, packet_size = %d, "
	                "next_header = %p, rohc_pkt = %p\n", context, ip,
	                packet_size, next_header, rohc_pkt);

	rohc_comp_debug(context, "parse the %u-byte IP packet\n", ip->size);
	base_header.ipvx = (base_header_ip_vx_t*) ip->data;
	remain_data_len = ip->size;

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *)ip->data;
	ip_context.uint8 = tcp_context->ip_context;
	ttl_irregular_chain_flag = 0;

	do
	{
		rohc_comp_debug(context, "base_header_ip = %p, IP version = %d\n",
		                base_header.uint8, base_header.ipvx->version);

		base_header_inner.ipvx = base_header.ipvx;
		ip_inner_context.uint8 = ip_context.uint8;

		switch(base_header.ipvx->version)
		{
			case IPV4:
				if(remain_data_len < sizeof(base_header_ip_v4_t) )
				{
					return -1;
				}
				ttl_hopl = base_header.ipv4->ttl_hopl;
				/* get the transport protocol */
				protocol = base_header.ipv4->protocol;
				ip_inner_ecn = base_header.ipv4->ip_ecn_flags;
				payload_size = rohc_ntoh16(base_header.ipv4->length) -
				               (base_header.ipv4->header_length << 2);

				/* irregular chain? */
				if(ttl_hopl != ip_context.v4->ttl_hopl)
				{
					ttl_irregular_chain_flag |= 1;
					rohc_comp_debug(context, "last ttl_hopl = 0x%02x, "
					                "ttl_hopl = 0x%02x, "
					                "ttl_irregular_chain_flag = %d\n",
					                ip_context.v4->ttl_hopl, ttl_hopl,
					                ttl_irregular_chain_flag);
				}

				/* skip IPv4 header */
				rohc_comp_debug(context, "skip %d-byte IPv4 header with Protocol "
				                "0x%02x\n", base_header.ipv4->header_length << 2,
				                protocol);
				remain_data_len -= base_header.ipv4->header_length << 2;
				base_header.uint8 += base_header.ipv4->header_length << 2;
				++ip_context.v4;
				break;
			case IPV6:
				if(remain_data_len < sizeof(base_header_ip_v6_t) )
				{
					return -1;
				}
				ttl_hopl = base_header.ipv6->ttl_hopl;
				/* get the transport protocol */
				protocol = base_header.ipv6->next_header;
				ip_inner_ecn = base_header.ipv6->ip_ecn_flags;
				payload_size = rohc_ntoh16(base_header.ipv6->payload_length);

				/* irregular chain? */
				if(ttl_hopl != ip_context.v6->ttl_hopl)
				{
					ttl_irregular_chain_flag |= 1;
					rohc_comp_debug(context, "last ttl_hopl = 0x%02x, "
					                "ttl_hopl = 0x%02x, "
					                "ttl_irregular_chain_flag = %d\n",
					                ip_context.v6->ttl_hopl, ttl_hopl,
					                ttl_irregular_chain_flag);
				}

				/* skip IPv6 header */
				rohc_comp_debug(context, "skip %zd-byte IPv6 header with Next "
				                "Header 0x%02x\n", sizeof(base_header_ip_v6_t),
				                protocol);
				remain_data_len -= sizeof(base_header_ip_v6_t);
				++base_header.ipv6;
				++ip_context.v6;

				/* parse IPv6 extension headers */
				while(rohc_is_ipv6_opt(protocol))
				{
					rohc_comp_debug(context, "skip %d-byte IPv6 extension header "
					                "with Next Header 0x%02x\n",
					                ip_context.v6_option->option_length,
					                protocol);
					protocol = base_header.ipv6_opt->next_header;
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
				break;
			default:
				return -1;
		}
	}
	while(rohc_is_tunneling(protocol));

	rohc_comp_debug(context, "payload_size = %d\n", payload_size);

	if(remain_data_len < sizeof(tcphdr_t) )
	{
		rohc_comp_debug(context, "insufficient size for TCP header\n");
		return -1;
	}

	tcp = base_header.tcphdr;

	*payload_offset = ( (uint8_t*) tcp ) + ( tcp->data_offset << 2 ) - ip->data;
	rohc_comp_debug(context, "payload_offset = %d\n", *payload_offset);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context->compressor->medium.cid_type,
	                          context->cid, rohc_pkt, rohc_pkt_max_len,
	                          &first_position);
	rohc_comp_debug(context, "rohc_pkt = %p, counter = %d, "
	                "first_position = %zu, rohc_pkt[0] = 0x%02x, "
	                "rohc_pkt[1] = 0x%02x\n", rohc_pkt, counter,
	                first_position, rohc_pkt[0], rohc_pkt[1]);

	/* part 4: dynamic part of outer and inner IP header and dynamic part
	 * of next header */
#if ROHC_EXTRA_DEBUG == 1
	puchar = &rohc_pkt[counter];
	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "puchar", puchar,
	                 counter + (puchar - rohc_pkt));
#endif

	// If SMALL_CID
	// If CID = 0         counter = 1   first_position = 0  no ADD-CID
	// If CID = 1-15      counter = 2   first_position = 1  0xEx
	// else
	//               1 <= counter <= 5  first_position = 0

	/* save the last CID octet */
	save_first_byte = rohc_pkt[counter - 1];

	i = co_baseheader(context, tcp_context, ip_inner_context,
	                  base_header_inner,
	                  &rohc_pkt[counter - 1], rohc_pkt_max_len,
	                  packet_type, payload_size, ttl_irregular_chain_flag);
	if(i < 0)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to build co_baseheader\n");
		goto error;
	}

	// Now add irregular chain

	mptr.uint8 = &rohc_pkt[counter - 1] + i;

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *)ip->data;
	ip_context.uint8 = tcp_context->ip_context;

	do
	{

		rohc_comp_debug(context, "base_header_ip = %p, IP version = %d\n",
		                base_header.uint8, base_header.ipvx->version);

		mptr.uint8 = tcp_code_irregular_ip_part(context, ip_context,
		                                        base_header, payload_size,
		                                        mptr.uint8,
		                                        tcp_context->ecn_used,
		                                        base_header.ipvx == base_header_inner.ipvx ? 1 : 0, // int is_innermost,
		                                        ttl_irregular_chain_flag,
		                                        ip_inner_ecn);

		switch(base_header.ipvx->version)
		{
			case IPV4:
				/* get the transport protocol */
				protocol = base_header.ipv4->protocol;
				base_header.uint8 += base_header.ipv4->header_length << 2;
				++ip_context.v4;
				break;
			case IPV6:
				/* get the transport protocol */
				protocol = base_header.ipv6->next_header;
				++base_header.ipv6;
				++ip_context.v6;
				while(rohc_is_ipv6_opt(protocol))
				{
					mptr.uint8 =
					   tcp_code_irregular_ipv6_option_part(context, ip_context,
					                                       mptr, protocol,
					                                       base_header,
					                                       packet_size);
					if(mptr.uint8 == NULL)
					{
						rohc_warning(context->compressor, ROHC_TRACE_COMP,
						             context->profile->id, "failed to encode the "
						             "IPv6 extension part of the irregular chain\n");
						goto error;
					}
					protocol = base_header.ipv6_opt->next_header;
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
				break;
			default:
				goto error;
		}

	}
	while(rohc_is_tunneling(protocol));

	mptr.uint8 = tcp_code_irregular_tcp_part(context, tcp, mptr.uint8,
	                                         ip_inner_ecn);

	if(context->compressor->medium.cid_type != ROHC_SMALL_CID)
	{
		rohc_comp_debug(context, "counter = %d, rohc_pkt[counter-1] = 0x%02x, "
		                "save_first_byte = 0x%02x\n", counter,
		                rohc_pkt[counter - 1], save_first_byte);
		// Restore byte saved
		rohc_pkt[first_position] = rohc_pkt[counter - 1];
		rohc_pkt[counter - 1] = save_first_byte;
	}

	counter = mptr.uint8 - rohc_pkt;

	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "CO packet", rohc_pkt, counter);

	return counter;

error:
	return -1;
}


/**
 * @brief Compress the innermost IP header AND the TCP header
 *
 * See RFC4996 page 77
 *
 * @param context                   The compression context
 * @param tcp_context               The specific TCP context
 * @param ip_context                The specific IP innermost context
 * @param base_header               The innermost IP header
 * @param rohc_pkt                  OUT: The ROHC packet
 * @param rohc_pkt_max_len          The maximum length of the ROHC packet
 * @param packet_type               OUT: The type of ROHC packet that is created
 * @param payload_size              The size of the payload
 * @param ttl_irregular_chain_flag  Set if the TTL/Hop Limit of an outer header has changed
 * @return                          The position in the rohc-packet-under-build buffer
 *                                  -1 in case of problem
 */
static int co_baseheader(struct c_context *const context,
								 struct sc_tcp_context *const tcp_context,
								 ip_context_ptr_t ip_context,
								 base_header_ip_t base_header,
								 unsigned char *const rohc_pkt,
								 const size_t rohc_pkt_max_len,
                         rohc_packet_t *const packet_type,
								 int payload_size,
								 int ttl_irregular_chain_flag)
{
	struct c_generic_context *g_context = context->specific;
	tcphdr_t *tcp;
	multi_ptr_t c_base_header; // compressed
	uint8_t ttl_hopl;
	int counter;
	multi_ptr_t mptr;
	uint16_t ip_id;
	uint8_t *puchar;
	int version;
	bool ip_id_behavior_changed;
	bool ip_id_hi9_changed; /* TODO: replace by the number of required bits */
	bool ip_id_hi11_changed; /* TODO: replace by the number of required bits */
	bool ip_id_hi12_changed; /* TODO: replace by the number of required bits */
	bool ip_id_hi13_changed; /* TODO: replace by the number of required bits */
	bool ip_ttl_changed;
	bool ip_df_changed;
	bool dscp_changed;
	bool tcp_ack_flag_changed;
	bool tcp_urg_flag_present;
	bool tcp_urg_flag_changed;
	bool tcp_ecn_flag_changed;
	bool tcp_rsf_flag_changed;
	bool tcp_ack_number_changed;
	bool tcp_ack_number_hi16_changed; /* TODO: replace by number of required bits */
	bool tcp_ack_number_hi17_changed; /* TODO: replace by number of required bits */
	bool tcp_ack_number_hi28_changed; /* TODO: replace by number of required bits */
	bool tcp_window_changed;
	bool ecn_used;
	bool is_ok;

	assert(packet_type != NULL);
	*packet_type = ROHC_PACKET_UNKNOWN;

	rohc_comp_debug(context, "tcp_context = %p, ip_context = %p, "
	                "base_header_ip = %p, rohc_pkt = %p, payload_size = %d, "
	                "ttl_irregular_chain_flag = %d\n",
	                tcp_context, ip_context.uint8, base_header.uint8, rohc_pkt,
	                payload_size, ttl_irregular_chain_flag);

	// Init pointer on rohc compressed buffer
	c_base_header.uint8 = rohc_pkt;

	if(base_header.ipvx->version == IPV4)
	{
		version = IPV4;
		assert( ip_context.v4->version == IPV4 );
		ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
		rohc_comp_debug(context, "payload_size = %d\n", payload_size);
		ttl_hopl = base_header.ipv4->ttl_hopl;
		tcp = (tcphdr_t*) ( base_header.ipv4 + 1 );
	}
	else
	{
		version = IPV6;
		assert( ip_context.v6->version == IPV6 );
		ip_id = 0; /* TODO: added to avoid warning, not the best way to handle the warning however */
		rohc_comp_debug(context, "payload_size = %d\n", payload_size);
		ttl_hopl = base_header.ipv6->ttl_hopl;
		tcp = (tcphdr_t*) ( base_header.ipv6 + 1 );
	}

	rohc_comp_debug(context, "new TCP seq = 0x%04x, ack_seq = 0x%04x\n",
	                rohc_ntoh32(tcp->seq_number), rohc_ntoh32(tcp->ack_number));
	rohc_comp_debug(context, "old TCP seq = 0x%04x, ack_seq = 0x%04x\n",
	                rohc_ntoh32(tcp_context->old_tcphdr.seq_number),
						 rohc_ntoh32(tcp_context->old_tcphdr.ack_number));
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d\n",
	                *(uint16_t *)(((unsigned char *) tcp) + 12),
	                tcp->res_flags, tcp->data_offset, tcp->rsf_flags,
	                tcp->ecn_flags, tcp->urg_flag, tcp->ack_flag,
	                tcp->psh_flag);
	rohc_comp_debug(context, "TCP window = %d (0x%04x), check = 0x%x, "
	                "urg_ptr = %d\n", rohc_ntoh16(tcp->window),
	                rohc_ntoh16(tcp->window), rohc_ntoh16(tcp->checksum),
	                rohc_ntoh16(tcp->urg_ptr));

	payload_size -= tcp->data_offset << 2;
	rohc_comp_debug(context, "payload_size = %d\n", payload_size);

/*
                               IP_ID_BEHAVIOR_RANDOM       |     IP_ID_BEHAVIOR_SEQUENTIAL
                               IP_ID_BEHAVIOR_ZERO         c  IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED
                                                           o
                         | r | r | r | r | r | r | r | r | m | s | s | s | s | s | s | s | s |
                         | n | n | n | n | n | n | n | n | m | e | e | e | e | e | e | e | e |
                         | d | d | d | d | d | d | d | d | o | q | q | q | q | q | q | q | q |
                         | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | n | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
                   +-----+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
     ip_id         | 16  |   |   |   |   |   |   |   |   |  x|  4|  7|  4|  3|  4|  7|  5|  4|
     dscp          |  6  |   |   |   |   |   |   |   |   |  x|   |   |   |   |   |   |   |   |
     ttl_hopl      |  8  |   |   |   |   |   |   |   |  3|  x|   |   |   |   |   |   |   |  3|
     ecn_used      |     |   |   |   |   |   |   |   |  1|  1|   |   |   |   |   |   |   |  1|
     msn           | 16  |  4|  4|  4|  4|  4|  4|  4|  4|  4|  4|  4|  4|  4|  4|  4|  4|  4|
     seq_number    | 32  | 18|  4|   |   | 14|  4|   | 16|  x| 16|  4|   |   | 16|  4|   | 14|
     ack_number    | 32  |   |   | 15|  4| 15| 16| 18| 16|  x|   |   | 16|  4| 16| 16| 16| 15|
     tcp_res_flags |  4  |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
     tcp_ecn_flags |  2  |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
     urg_flag      |  1  |   |   |   |   |   |   |   |   |  1|   |   |   |   |   |   |   |   |
     df            |     |   |   |   |   |   |   |   |   |  1|   |   |   |   |   |   |   |   |
     ack_flag      |  1  |   |   |   |   |   |   |   |   |  1|   |   |   |   |   |   |   |   |
     psh_flag      |  1  |  1|  1|  1|  1|  1|  1|  1|  1|  1|  1|  1|  1|  1|  1|  1|  1|  1|
     rsf_flags     |  3  |   |   |   |   |   |   |   |  2|  2|   |   |   |   |   |   |   |  2|
     window        | 16  |   |   |   |   |   |   | 16|   |  x|   |   |   |   |   |   | 16|   |
     urg_ptr       | 16  |   |   |   |   |   |   |   |   |  x|   |   |   |   |   |   |   |   |
     options       |  n  |   |   |   |   |   |   |   |YES|  x|   |   |   |   |   |   |   |YES|
     payload       |  n  |   |!=0|   |   |   |!=0|   |   |  x|   |!=0|   |   |   |!=0|   |   |
     ack_stride    |     |   |   |   |!=0|   |   |   |   |  x|   |   |   |!=0|   |   |   |   |
     header_crc    |     |  3|  3|  3|  3|  3|  3|  3|  7|  7|  3|  3|  3|  3|  3|  3|  3|  7|
                   +-----+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
     size in bits  |     | 32| 16| 24| 16| 40| 32| 48|>56|   | 32| 24| 32| 16| 48| 40| 48|>56|
                   +-----+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

*/

	/* Try to determine the best base compressed header */

	ecn_used = ( tcp_context->ecn_used == 0 ) ? 0 : 1;

	ip_ttl_changed = (ttl_irregular_chain_flag != 0);
	if(base_header.ipvx->version == IPV4)
	{
		ip_id_behavior_changed =
			(ip_context.v4->last_ip_id_behavior != ip_context.v4->ip_id_behavior);
		if(ip_context.vx->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL)
		{
			ip_id_hi9_changed =
				((ip_context.v4->last_ip_id & 0xFF80) != (ip_id & 0xFF80));
			ip_id_hi11_changed =
				((ip_context.v4->last_ip_id & 0xFFE0) != (ip_id & 0xFFE0));
			ip_id_hi12_changed =
				((ip_context.v4->last_ip_id & 0xFFF0) != (ip_id & 0xFFF0));
			ip_id_hi13_changed =
				((ip_context.v4->last_ip_id & 0xFFF8) != (ip_id & 0xFFF8));
		}
		else if(ip_context.vx->ip_id_behavior == IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
		{
			ip_id_hi9_changed =
				((ip_context.v4->last_ip_id & 0x80FF) != (ip_id & 0x80FF));
			ip_id_hi11_changed =
				((ip_context.v4->last_ip_id & 0xE0FF) != (ip_id & 0xE0FF));
			ip_id_hi12_changed =
				((ip_context.v4->last_ip_id & 0xF0FF) != (ip_id & 0xF0FF));
			ip_id_hi13_changed =
				((ip_context.v4->last_ip_id & 0xF8FF) != (ip_id & 0xF8FF));
		}
		else
		{
			ip_id_hi9_changed = false; /* TODO: true or false ? */
			ip_id_hi11_changed = false; /* TODO: true or false ? */
			ip_id_hi12_changed = false; /* TODO: true or false ? */
			ip_id_hi13_changed = false; /* TODO: true or false ? */
		}

		ip_df_changed = (base_header.ipv4->df != ip_context.v4->df);
		dscp_changed = (base_header.ipv4->dscp != ip_context.v4->dscp);
	}
	else
	{
		ip_id_behavior_changed = false;
		ip_id_hi9_changed = false;
		ip_id_hi11_changed = false;
		ip_id_hi12_changed = false;
		ip_id_hi13_changed = false;
		ip_df_changed = false;
		dscp_changed = (DSCP_V6(base_header.ipv6) != ip_context.v6->dscp);
	}
	tcp_ack_flag_changed = (tcp->ack_flag != tcp_context->old_tcphdr.ack_flag);
	tcp_urg_flag_present = (tcp->urg_flag != 0);
	tcp_urg_flag_changed = (tcp->urg_flag != tcp_context->old_tcphdr.urg_flag);
	tcp_ecn_flag_changed = (tcp->ecn_flags != tcp_context->old_tcphdr.ecn_flags);
	tcp_rsf_flag_changed = (tcp->rsf_flags != tcp_context->old_tcphdr.rsf_flags);
	if(tcp->ack_flag != 0)
	{
		tcp_ack_number_changed =
			(tcp->ack_number != tcp_context->old_tcphdr.ack_number);
		tcp_ack_number_hi16_changed =
			((rohc_ntoh32(tcp->ack_number) & 0xffff0000) !=
			 (rohc_ntoh32(tcp_context->old_tcphdr.ack_number) & 0xffff0000));
		tcp_ack_number_hi17_changed =
			((rohc_ntoh32(tcp->ack_number) & 0xffff8000) !=
			 (rohc_ntoh32(tcp_context->old_tcphdr.ack_number) & 0xffff8000));
		tcp_ack_number_hi28_changed =
			((rohc_ntoh32(tcp->ack_number) & 0xfffffff0) !=
			 (rohc_ntoh32(tcp_context->old_tcphdr.ack_number) & 0xfffffff0));
	}
	else
	{
		tcp_ack_number_changed = false;
		tcp_ack_number_hi16_changed = false;
		tcp_ack_number_hi17_changed = false;
		tcp_ack_number_hi28_changed = false;
	}
	rohc_comp_debug(context, "ACK number: hi16_changed = %d, "
						 "hi17_changed = %d, hi28_changed = %d, changed = %d\n",
						 tcp_ack_number_hi16_changed, tcp_ack_number_hi17_changed,
						 tcp_ack_number_hi28_changed, tcp_ack_number_changed);
	rohc_comp_debug(context, "sequence number requires %zu bits for p = "
	                "65535, %zu bits for p = 32767, %zu bits for p = 8191\n",
	                tcp_context->tmp.nr_seq_bits_65535,
	                tcp_context->tmp.nr_seq_bits_32767,
	                tcp_context->tmp.nr_seq_bits_8191);
	tcp_window_changed = (tcp->window != tcp_context->old_tcphdr.window);
	rohc_comp_debug(context, "TCP window changed = %d\n", tcp_window_changed);
	ecn_used = (tcp_context->ecn_used != 0);

	if(ip_ttl_changed || ip_id_behavior_changed || ip_df_changed || dscp_changed ||
	   tcp_ack_flag_changed || tcp_urg_flag_present || tcp_urg_flag_changed ||
	   tcp_ecn_flag_changed || tcp_ack_number_hi16_changed)
	{
		TRACE_GOTO_CHOICE;
		*packet_type = ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(ecn_used != 0) /* ecn used change */
	{
		/* use compressed header with a 7-bit CRC (rnd_8, seq_8 or common):
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if window changed */
		if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED &&
		   tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
		   !tcp_window_changed)
		{
			/* IP_ID_BEHAVIOR_SEQUENTIAL or IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED */
			TRACE_GOTO_CHOICE;
			*packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else if(tcp_context->tmp.nr_seq_bits_65535 <= 16 &&
		        !tcp_window_changed)
		{
			TRACE_GOTO_CHOICE;
			*packet_type = ROHC_PACKET_TCP_RND_8;
		}
		else
		{
			TRACE_GOTO_CHOICE;
			*packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED)
	{
		/* IP_ID_BEHAVIOR_SEQUENTIAL or IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED:
		 * co_common or seq_X packet types */

		if(tcp->data_offset > 5)
		{
			/* seq_8 can be used if:
			 *  - TCP window didn't change,
			 *  - at most 14 LSB of the TCP sequence number are required,
			 *  - the 17 MSBs of ACK number didn't change,
			 *  - at most 4 LSBs of IP-ID must be transmitted
			 * otherwise use co_common packet */
			if(!tcp_window_changed &&
			   tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
			   !tcp_ack_number_hi17_changed &&
			   ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED &&
			   !ip_id_hi12_changed)
			{
				/* seq_8 is possible */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_SEQ_8;
			}
			else
			{
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else /* no TCP option */
		{
			if(tcp_rsf_flag_changed)
			{
				/* seq_8 can be used if:
				 *  - TCP window didn't change,
				 *  - at most 14 LSB of the TCP sequence number are required,
				 *  - the 17 MSBs of ACK number didn't change,
				 *  - at most 4 LSBs of IP-ID must be transmitted
				 * otherwise use seq_8 packet */
				if(!tcp_window_changed &&
				   tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
				   !tcp_ack_number_hi17_changed &&
				   ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED &&
				   !ip_id_hi12_changed)
				{
					/* seq_8 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_SEQ_8;
				}
				else
				{
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
			}
			else if(tcp_context->tmp.nr_seq_bits_65535 > 0)
			{
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
			else if(tcp_window_changed)
			{
				if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL &&
					ip_id_hi11_changed)
				{
					/* more than 5 LSBs required for IP-ID => co_common */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
				else
				{
					/* seq_7 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_SEQ_7;
				}
			}
			else if(tcp->ack_flag != 0 && !tcp_ack_number_changed)
			{
				TRACE_GOTO_CHOICE;

				/* ACK number present */
				if(payload_size == 0)
				{
					/* seq_1 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_SEQ_1;
				}
				else if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL &&
						  ip_id_hi13_changed)
				{
					/* more than 3 LSBs required for IP-ID => co_common */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
				else if(tcp_context->ack_stride != 0)
				{
					/* seq_4 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_SEQ_4;
				}
				else
				{
					/* seq_1 and seq_4 not possible => co_common */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
			}
			else if(tcp->ack_flag != 0 &&
			        tcp_context->tmp.nr_seq_bits_65535 == 0)
			{
				TRACE_GOTO_CHOICE;

				/* ACK number present */
				if(!tcp_ack_number_hi28_changed && tcp_context->ack_stride != 0)
				{
					if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL &&
						ip_id_hi13_changed)
					{
						/* more than 3 LSBs required for IP-ID => co_common */
						TRACE_GOTO_CHOICE;
						*packet_type = ROHC_PACKET_TCP_CO_COMMON;
					}
					else
					{
						/* seq_4 is possible */
						TRACE_GOTO_CHOICE;
						*packet_type = ROHC_PACKET_TCP_SEQ_4;
					}
				}
				else if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL &&
						  ip_id_hi12_changed)
				{
					/* more than 4 LSBs required for IP-ID => co_common */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
				else
				{
					/* seq_3 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_SEQ_3;
				}
			}
			else if(tcp->ack_flag != 0 &&
			        tcp_context->tmp.nr_seq_bits_65535 == 0 &&
			        payload_size > 0)
			{
				/* ACK number present */
				if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED &&
					ip_id_hi9_changed)
				{
					/* more than 7 LSBs required for IP-ID => co_common */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
				else
				{
					/* seq_6 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_SEQ_6;
				}
			}
			else if(tcp->ack_flag != 0)
			{
				/* ACK number present */
				/* seq_5 is possible */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_SEQ_5;
			}
			else if(tcp->ack_flag == 0 &&
			        tcp_context->tmp.nr_seq_bits_32767 <= 16)
			{
				/* ACK number absent */
				if(payload_size > 0)
				{
					if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL_SWAPPED &&
						ip_id_hi9_changed &&
						tcp_context->tmp.nr_seq_bits_65535 > 0)
					{
						/* more than 7 LSBs required for IP-ID => co_common */
						TRACE_GOTO_CHOICE;
						*packet_type = ROHC_PACKET_TCP_CO_COMMON;
					}
					else
					{
						/* seq_2 is possible */
						TRACE_GOTO_CHOICE;
						*packet_type = ROHC_PACKET_TCP_SEQ_2;
					}
				}
				else if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL &&
				        ip_id_hi12_changed)
				{
					/* more than 4 LSBs required for IP-ID => co_common */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
				else
				{
					/* seq_1 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_SEQ_1;
				}
			}
			else if(tcp->ack_flag == 0)
			{
				/* ACK number absent */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
			else if(ip_context.vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQUENTIAL &&
				     ip_id_hi11_changed)
			{
				/* more than 5 LSBs required for IP-ID => co_common */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
			else
			{
				/* seq_7 is possible */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_SEQ_7;
			}
		} /* no TCP option */

		/* IP-ID is sequential, so only co_common and seq_X packets are allowed */
		assert((*packet_type) == ROHC_PACKET_TCP_CO_COMMON ||
		       ((*packet_type) >= ROHC_PACKET_TCP_SEQ_1 &&
		        (*packet_type) <= ROHC_PACKET_TCP_SEQ_8));
	}
	else if(ip_context.vx->ip_id_behavior == IP_ID_BEHAVIOR_RANDOM ||
	        ip_context.vx->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
	{
		/* IP_ID_BEHAVIOR_RANDOM or IP_ID_BEHAVIOR_ZERO:
		 * co_common or rnd_X packet types */

		if(tcp->data_offset > 5)
		{
			if(!tcp_window_changed && tcp_context->tmp.nr_seq_bits_65535 <= 16)
			{
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_RND_8;
			}
			else
			{
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else /* no TCP option */
		{
			if(tcp_rsf_flag_changed)
			{
				if(!tcp_window_changed && tcp_context->tmp.nr_seq_bits_65535 <= 16)
				{
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_RND_8;
				}
				else
				{
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
			}
			else if((rohc_ntoh32(tcp->seq_number) & 0xFFFF) !=
				     (rohc_ntoh32(tcp_context->old_tcphdr.seq_number) & 0xFFFF))
			{
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
			else if(tcp_window_changed)
			{
				/* rnd_7 is possible */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_RND_7;
			}
			else if(tcp->ack_flag != 0 && !tcp_ack_number_changed)
			{
				/* ACK number present */
				if(payload_size > 0 && tcp_context->ack_stride != 0)
				{
					/* rnd_4 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_RND_4;
				}
				else
				{
					/* rnd_1 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_RND_1;
				}
			}
			else if(tcp->ack_flag != 0 &&
			        tcp_context->tmp.nr_seq_bits_65535 == 0)
			{
				/* ACK number present */
				if(!tcp_ack_number_hi28_changed && tcp_context->ack_stride != 0)
				{
					/* rnd_4 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_RND_4;
				}
				else
				{
					/* rnd_3 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_RND_3;
				}
			}
			else if(tcp->ack_flag != 0 &&
			        tcp_context->tmp.nr_seq_bits_65535 == 0 &&
			        payload_size > 0)
			{
				/* ACK number present */
				/* rnd_6 is possible */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_RND_6;
			}
			else if(tcp->ack_flag != 0)
			{
				/* ACK number present */
				/* rnd_5 is possible */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_RND_5;
			}
			else if(tcp->ack_flag == 0 &&
			        tcp_context->tmp.nr_seq_bits_65535 <= 18)
			{
				/* ACK number absent */
				if(payload_size > 0 &&
				   tcp_context->tmp.nr_seq_bits_65535 == 0)
				{
					/* rnd_2 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_RND_2;
				}
				else
				{
					/* rnd_1 is possible */
					TRACE_GOTO_CHOICE;
					*packet_type = ROHC_PACKET_TCP_RND_1;
				}
			}
			else
			{
				/* ACK number absent */
				TRACE_GOTO_CHOICE;
				*packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		} /* no TCP option */

		/* IP-ID is NOT sequential, so only co_common and rnd_X packets are allowed */
		assert((*packet_type) == ROHC_PACKET_TCP_CO_COMMON ||
		       ((*packet_type) >= ROHC_PACKET_TCP_RND_1 &&
		        (*packet_type) <= ROHC_PACKET_TCP_RND_8));
	}
	else
	{
		rohc_comp_debug(context, "unexpected unknown IP-ID behavior\n");
		assert(0);
		goto error;
	}

	mptr.uint8 = c_base_header.uint8;

	switch(*packet_type)
	{
		case ROHC_PACKET_TCP_RND_1:
			mptr.uint8 += c_tcp_build_rnd_1(context, tcp_context, tcp,
													  c_base_header.rnd1);
			break;
		case ROHC_PACKET_TCP_RND_2:
			mptr.uint8 += c_tcp_build_rnd_2(context, tcp_context, tcp,
													  c_base_header.rnd2);
			break;
		case ROHC_PACKET_TCP_RND_3:
			mptr.uint8 += c_tcp_build_rnd_3(context, tcp_context, tcp,
													  c_base_header.rnd3);
			break;
		case ROHC_PACKET_TCP_RND_4:
			mptr.uint8 += c_tcp_build_rnd_4(context, tcp_context, tcp,
													  c_base_header.rnd4);
			break;
		case ROHC_PACKET_TCP_RND_5:
			mptr.uint8 += c_tcp_build_rnd_5(context, tcp_context, tcp,
													  c_base_header.rnd5);
			break;
		case ROHC_PACKET_TCP_RND_6:
			mptr.uint8 += c_tcp_build_rnd_6(context, tcp_context, tcp,
													  c_base_header.rnd6);
			break;
		case ROHC_PACKET_TCP_RND_7:
			mptr.uint8 += c_tcp_build_rnd_7(context, tcp_context, tcp,
													  c_base_header.rnd7);
			break;
		case ROHC_PACKET_TCP_RND_8:
		{
			size_t rnd8_len;

			is_ok = c_tcp_build_rnd_8(context, ip_context, tcp_context,
											  base_header, tcp, c_base_header.rnd8,
											  &rnd8_len);
			if(!is_ok)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP,
								 context->profile->id,
								 "failed to build seq_8 packet\n");
				goto error;
			}
			mptr.uint8 += rnd8_len;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_1:
			mptr.uint8 += c_tcp_build_seq_1(context, ip_context, tcp_context,
													  base_header, tcp, c_base_header.seq1);
			break;
		case ROHC_PACKET_TCP_SEQ_2:
			mptr.uint8 += c_tcp_build_seq_2(context, ip_context, tcp_context,
													  base_header, tcp, c_base_header.seq2);
			break;
		case ROHC_PACKET_TCP_SEQ_3:
			mptr.uint8 += c_tcp_build_seq_3(context, ip_context, tcp_context,
													  base_header, tcp, c_base_header.seq3);
			break;
		case ROHC_PACKET_TCP_SEQ_4:
			mptr.uint8 += c_tcp_build_seq_4(context, ip_context, tcp_context,
													  base_header, tcp, c_base_header.seq4);
			break;
		case ROHC_PACKET_TCP_SEQ_5:
			mptr.uint8 += c_tcp_build_seq_5(context, ip_context, tcp_context,
													  base_header, tcp, c_base_header.seq5);
			break;
		case ROHC_PACKET_TCP_SEQ_6:
			mptr.uint8 += c_tcp_build_seq_6(context, ip_context, tcp_context,
													  base_header, tcp, c_base_header.seq6);
			break;
		case ROHC_PACKET_TCP_SEQ_7:
			mptr.uint8 += c_tcp_build_seq_7(context, ip_context, tcp_context,
													  base_header, tcp, c_base_header.seq7);
			break;
		case ROHC_PACKET_TCP_SEQ_8:
		{
			size_t seq8_len;

			is_ok = c_tcp_build_seq_8(context, ip_context, tcp_context,
											  base_header, tcp, c_base_header.seq8,
											  &seq8_len);
			if(!is_ok)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP,
								 context->profile->id,
								 "failed to build seq_8 packet\n");
				goto error;
			}
			mptr.uint8 += seq8_len;
			break;
		}
		case ROHC_PACKET_TCP_CO_COMMON:
		{
	int ret;
	int indicator;

	rohc_comp_debug(context, "code common\n");
	// See RFC4996 page 80:
	rohc_comp_debug(context, "ttl_irregular_chain_flag = %d\n",
	                ttl_irregular_chain_flag);
	mptr.uint8 = (uint8_t*)(c_base_header.co_common + 1);
	rohc_comp_debug(context, "rohc_pkt = %p, co_common = %p, seq_number = %p\n",
	                rohc_pkt, c_base_header.co_common, mptr.uint8);

	c_base_header.co_common->discriminator = 0x7D; // '1111101'
	c_base_header.co_common->ttl_hopl_outer_flag = ttl_irregular_chain_flag;

	rohc_comp_debug(context, "TCP ack_flag = %d, psh_flag = %d, rsf_flags = %d\n",
	                tcp->ack_flag, tcp->psh_flag, tcp->rsf_flags);
	// =:= irregular(1) [ 1 ];
	c_base_header.co_common->ack_flag = tcp->ack_flag;
	// =:= irregular(1) [ 1 ];
	c_base_header.co_common->psh_flag = tcp->psh_flag;
	// =:= rsf_index_enc [ 2 ];
	c_base_header.co_common->rsf_flags = rsf_index_enc(context, tcp->rsf_flags);
	// =:= lsb(4, 4) [ 4 ];
	c_base_header.co_common->msn = g_context->sn & 0xf;
	puchar = mptr.uint8;
	// =:= irregular(2) [ 2 ];
	c_base_header.co_common->seq_indicator =
		variable_length_32_enc(&mptr, tcp->seq_number);
	rohc_comp_debug(context, "size = %d, seq_indicator = %d, seq_number = 0x%x\n",
	                (unsigned)(mptr.uint8 - puchar),
	                c_base_header.co_common->seq_indicator,
	                rohc_ntoh32(tcp->seq_number));
	// =:= irregular(2) [ 2 ];
	c_base_header.co_common->ack_indicator =
		variable_length_32_enc(&mptr, tcp->ack_number);
	rohc_comp_debug(context, "size = %d, ack_indicator = %d, ack_number = 0x%x\n",
	                (unsigned)(mptr.uint8 - puchar),
	                c_base_header.co_common->seq_indicator,
	                rohc_ntoh32(tcp->ack_number));

	/* ack_stride */ /* TODO: comparison with new computed ack_stride? */
	ret = c_static_or_irreg16(tcp_context->ack_stride,
	                          rohc_hton16(tcp_context->ack_stride),
	                          mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to encode static_or_irreg(ack_stride)\n");
		goto error;
	}
	c_base_header.co_common->ack_stride_indicator = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "size = %d, ack_stride_indicator = %d, "
	                "ack_stride 0x%x\n", (unsigned)(mptr.uint8 - puchar),
	                c_base_header.co_common->ack_stride_indicator,
	                tcp_context->ack_stride);

	/* window */
	ret = c_static_or_irreg16(tcp_context->old_tcphdr.window, tcp->window,
	                          mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to encode static_or_irreg(window)\n");
		goto error;
	}
	c_base_header.co_common->window_indicator = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "size = %d, window_indicator = %d, "
	                "old_window = 0x%x, window = 0x%x\n",
	                (unsigned)(mptr.uint8 - puchar),
	                c_base_header.co_common->window_indicator,
	                rohc_ntoh16(tcp_context->old_tcphdr.window),
	                rohc_ntoh16(tcp->window));
	if(version == IPV4)
	{
		// =:= irregular(1) [ 1 ];
		ret = c_optional_ip_id_lsb(context, ip_context.v4->ip_id_behavior,
		                           ip_context.v4->last_ip_id, ip_id,
		                           g_context->sn, mptr.uint8, &indicator);
		if(ret < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to encode optional_ip_id_lsb(ip_id)\n");
			goto error;
		}
		c_base_header.co_common->ip_id_indicator = indicator;
		mptr.uint8 += ret;
		ip_context.v4->last_ip_id = ip_id;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		c_base_header.co_common->ip_id_behavior = ip_context.v4->ip_id_behavior;
		rohc_comp_debug(context, "size = %u, ip_id_indicator = %d, "
		                "ip_id_behavior = %d\n",
		                (unsigned int) (mptr.uint8 - puchar),
		                c_base_header.co_common->ip_id_indicator,
		                c_base_header.co_common->ip_id_behavior);

		/* dscp_present =:= irregular(1) [ 1 ] */
		c_base_header.co_common->dscp_present =
			dscp_encode(&mptr, ip_context.vx->dscp, base_header.ipv4->dscp);
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %u bytes\n",
		                c_base_header.co_common->dscp_present,
		                ip_context.vx->dscp, base_header.ipv4->dscp,
		                (unsigned int) (mptr.uint8 - puchar));
		ip_context.vx->dscp = base_header.ipv4->dscp;

		/* ttl_hopl */
		ret = c_static_or_irreg8(ip_context.vx->ttl_hopl, ttl_hopl, mptr.uint8,
		                         &indicator);
		if(ret < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to encode static_or_irreg(ttl_hopl)\n");
			goto error;
		}
		c_base_header.co_common->ttl_hopl_present = indicator;
		mptr.uint8 += ret;

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		c_base_header.co_common->df = base_header.ipv4->df;
		ip_context.v4->df = base_header.ipv4->df;
		rohc_comp_debug(context, "size = %u, dscp_present = %d, "
		                "ttl_hopl_present = %d\n",
		                (unsigned int) (mptr.uint8 - puchar),
		                c_base_header.co_common->dscp_present,
		                c_base_header.co_common->ttl_hopl_present);
	}
	else
	{
		// =:= irregular(1) [ 1 ];
		c_base_header.co_common->ip_id_indicator = 0;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		c_base_header.co_common->ip_id_behavior = IP_ID_BEHAVIOR_RANDOM;
		rohc_comp_debug(context, "size = %u, ip_id_indicator = %d, "
		                "ip_id_behavior = %d\n",
		                (unsigned int) (mptr.uint8 - puchar),
		                c_base_header.co_common->ip_id_indicator,
		                c_base_header.co_common->ip_id_behavior);

		/* dscp_present =:= irregular(1) [ 1 ] */
		c_base_header.co_common->dscp_present =
			dscp_encode(&mptr, ip_context.vx->dscp, DSCP_V6(base_header.ipv6));
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %u bytes\n",
		                c_base_header.co_common->dscp_present,
		                ip_context.vx->dscp, DSCP_V6(base_header.ipv6),
		                (unsigned int) (mptr.uint8 - puchar));
		ip_context.vx->dscp = DSCP_V6(base_header.ipv6);

		/* ttl_hopl */
		ret = c_static_or_irreg8(ip_context.vx->ttl_hopl, ttl_hopl, mptr.uint8,
		                         &indicator);
		if(ret < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to encode static_or_irreg(ttl_hopl)\n");
			goto error;
		}
		c_base_header.co_common->ttl_hopl_present = indicator;
		mptr.uint8 += ret;

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		c_base_header.co_common->df = 0;
		rohc_comp_debug(context, "size = %u, dscp_present = %d, "
		                "ttl_hopl_present %d\n",
		                (unsigned int) (mptr.uint8 - puchar),
		                c_base_header.co_common->dscp_present,
		                c_base_header.co_common->ttl_hopl_present);
	}
	// cf RFC3168 and RFC4996 page 20 :
	if(tcp_context->ecn_used == 0)
	{
		// =:= one_bit_choice [ 1 ];
		c_base_header.co_common->ecn_used = 0;
	}
	else
	{
		// =:= one_bit_choice [ 1 ];
		c_base_header.co_common->ecn_used = 1;
	}
	rohc_comp_debug(context, "ecn_used = %d\n",
	                c_base_header.co_common->ecn_used);
	// =:= irregular(1) [ 1 ];
	if( (c_base_header.co_common->urg_flag = tcp->urg_flag) != 0) // TODO: check that!
	{
		/* urg_ptr */
		ret = c_static_or_irreg16(tcp_context->old_tcphdr.urg_ptr, tcp->urg_ptr,
		                          mptr.uint8, &indicator);
		if(ret < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to encode static_or_irreg(urg_ptr)\n");
			goto error;
		}
		c_base_header.co_common->urg_ptr_present = indicator;
		mptr.uint8 += ret;
		rohc_comp_debug(context, "urg_flag = %d, urg_ptr_present = %d\n",
		                c_base_header.co_common->urg_flag,
		                c_base_header.co_common->urg_ptr_present);
	}
	else
	{
		// =:= irregular(1) [ 1 ];
		c_base_header.co_common->urg_ptr_present = 0;
	}
	// =:= compressed_value(1, 0) [ 1 ];
	c_base_header.co_common->reserved = 0;
	// If TCP options
	if(tcp->data_offset > 5)
	{
		size_t comp_opts_len;

		// =:= irregular(1) [ 1 ];
		c_base_header.co_common->list_present = 1;
		// compress the TCP options
		is_ok = tcp_compress_tcp_options(context, tcp, mptr.uint8, &comp_opts_len);
		if(!is_ok)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
							 "failed to compress TCP options\n");
			goto error;
		}
		mptr.uint8 += comp_opts_len;
	}
	else
	{
		// =:= irregular(1) [ 1 ];
		c_base_header.co_common->list_present = 0;
	}
	rohc_comp_debug(context, "size = %u, list_present = %d, DF = %d\n",
	                (unsigned int) (mptr.uint8 - puchar),
	                c_base_header.co_common->list_present,
	                c_base_header.co_common->df);
	// =:= crc7(THIS.UVALUE,THIS.ULENGTH) [ 7 ];
	c_base_header.co_common->header_crc = 0;
	c_base_header.co_common->header_crc =
	   crc_calculate(ROHC_CRC_TYPE_7,  c_base_header.uint8,
	                 mptr.uint8 - c_base_header.uint8, CRC_INIT_7,
	                 context->compressor->crc_table_7);
	rohc_comp_debug(context, "CRC (header length = %d, CRC = 0x%x)\n",
	                (int) (mptr.uint8 - c_base_header.uint8),
	                c_base_header.co_common->header_crc);
			break;
		}
		default:
			rohc_comp_debug(context, "unexpected packet type %d\n",
								 *packet_type);
			assert(0);
			break;
	}

	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "compressed header",
	                 c_base_header.uint8, mptr.uint8 - c_base_header.uint8);

	counter = mptr.uint8 - rohc_pkt;

	rohc_dump_packet(context->compressor->trace_callback, ROHC_TRACE_COMP,
	                 ROHC_TRACE_DEBUG, "co_header", rohc_pkt, counter);

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	ip_context.v4->last_ip_id_behavior = ip_context.v4->ip_id_behavior;
	ip_context.v4->last_ip_id = ip_id;
	ip_context.vx->ttl_hopl = ttl_hopl;

	return counter;

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_1 packet
 *
 * Send LSBs of sequence number
 * See RFC4996 page 81
 *
 * @param context       The compression context
 * @param tcp_context   The specific TCP context
 * @param tcp           The TCP header to compress
 * @param rnd1          IN/OUT: The rnd_1 packet to build
 * @return              The length (in bytes) of the rnd_1 packet
 */
static size_t c_tcp_build_rnd_1(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_1_t *const rnd1)
{
	struct c_generic_context *g_context;
	uint32_t seq_number;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd1 != NULL);

	rohc_comp_debug(context, "code rnd_1\n");

	rnd1->discriminator = 0x2e; /* '101110' */
	seq_number = rohc_ntoh32(tcp->seq_number) & 0x3ffff;
	rnd1->seq_number1 = (seq_number >> 16) & 0x3;
	rnd1->seq_number2 = rohc_hton16(seq_number & 0xffff);
	rnd1->msn = g_context->sn & 0xf;
	rnd1->psh_flag = tcp->psh_flag;
	rnd1->header_crc = 0; /* for CRC computation */
	rnd1->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) rnd1,
	                                 sizeof(rnd_1_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(rnd_1_t);
}


/**
 * @brief Build a TCP rnd_2 packet
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 81
 *
 * @param context       The compression context
 * @param tcp_context   The specific TCP context
 * @param tcp           The TCP header to compress
 * @param rnd2          IN/OUT: The rnd_2 packet to build
 * @return              The length (in bytes) of the rnd_2 packet
 */
static size_t c_tcp_build_rnd_2(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_2_t *const rnd2)
{
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd2 != NULL);

	rohc_comp_debug(context, "code rnd_2\n");

	rnd2->discriminator = 0x0c; /* '1100' */
	rnd2->seq_number_scaled = c_lsb(context, 4, 7, tcp_context->seq_number,
	                                tcp_context->seq_number_scaled);
	rnd2->msn = g_context->sn & 0xf;
	rnd2->header_crc = 0; /* for CRC computation */
	rnd2->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) rnd2,
	                                 sizeof(rnd_2_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(rnd_2_t);
}


/**
 * @brief Build a TCP rnd_3 packet
 *
 * Send acknowlegment number LSBs
 * See RFC4996 page 81
 *
 * @param context       The compression context
 * @param tcp_context   The specific TCP context
 * @param tcp           The TCP header to compress
 * @param rnd3          IN/OUT: The rnd_3 packet to build
 * @return              The length (in bytes) of the rnd_3 packet
 */
static size_t c_tcp_build_rnd_3(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_3_t *const rnd3)
{
	struct c_generic_context *g_context;
	uint16_t ack_number;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd3 != NULL);

	rohc_comp_debug(context, "code rnd_3\n");

	rnd3->discriminator = 0x0; /* '0' */
	ack_number = c_lsb(context, 15, 8191, tcp_context->ack_number,
	                   rohc_ntoh32(tcp->ack_number));
	rnd3->ack_number1 = (ack_number >> 8) & 0x7f;
	rnd3->ack_number2 = ack_number & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)\n",
	                ack_number, rnd3->ack_number1, rnd3->ack_number2);
	rnd3->msn = g_context->sn & 0xf;
	rnd3->psh_flag = tcp->psh_flag;
	rnd3->header_crc = 0; /* for CRC computation */
	rnd3->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) rnd3,
	                                 sizeof(rnd_3_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(rnd_3_t);
}


/**
 * @brief Build a TCP rnd_4 packet
 *
 * Send acknowlegment number scaled
 * See RFC4996 page 81
 *
 * @param context       The compression context
 * @param tcp_context   The specific TCP context
 * @param tcp           The TCP header to compress
 * @param rnd4          IN/OUT: The rnd_4 packet to build
 * @return              The length (in bytes) of the rnd_4 packet
 */
static size_t c_tcp_build_rnd_4(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_4_t *const rnd4)
{
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp_context->ack_stride != 0);
	assert(tcp != NULL);
	assert(rnd4 != NULL);

	rohc_comp_debug(context, "code rnd_4\n");

	rnd4->discriminator = 0x0d; /* '1101' */
	rnd4->ack_number_scaled = c_lsb(context, 4, 3,
	                                /*tcp_context->ack_number*/ 0,
	                                tcp_context->ack_number_scaled);
	rnd4->msn = g_context->sn & 0xf;
	rnd4->psh_flag = tcp->psh_flag;
	rnd4->header_crc = 0; /* for CRC computation */
	rnd4->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) rnd4,
	                                 sizeof(rnd_4_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(rnd_4_t);
}


/**
 * @brief Build a TCP rnd_5 packet
 *
 * Send ACK and sequence number
 * See RFC4996 page 82
 *
 * @param context       The compression context
 * @param tcp_context   The specific TCP context
 * @param tcp           The TCP header to compress
 * @param rnd5          IN/OUT: The rnd_5 packet to build
 * @return              The length (in bytes) of the rnd_5 packet
 */
static size_t c_tcp_build_rnd_5(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_5_t *const rnd5)
{
	struct c_generic_context *g_context;
	uint16_t seq_number;
	uint16_t ack_number;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd5 != NULL);

	rohc_comp_debug(context, "code rnd_5\n");

	rnd5->discriminator = 0x04; /* '100' */
	rnd5->psh_flag = tcp->psh_flag;
	rnd5->msn = g_context->sn & 0xf;

	/* sequence number */
	seq_number = rohc_ntoh32(tcp->seq_number) & 0x3fff;
	rnd5->seq_number1 = (seq_number >> 9) & 0x1f;
	rnd5->seq_number2 = (seq_number >> 1) & 0xff;
	rnd5->seq_number3 = seq_number & 0x01;
	rohc_comp_debug(context, "seq_number = 0x%04x (0x%02x 0x%02x 0x%02x)\n",
	                seq_number, rnd5->seq_number1, rnd5->seq_number2,
	                rnd5->seq_number3);

	/* ACK number */
	ack_number = c_lsb(context, 15, 8191, tcp_context->ack_number,
	                   rohc_ntoh32(tcp->ack_number));
	rnd5->ack_number1 = (ack_number >> 8) & 0x7f;
	rnd5->ack_number2 = ack_number & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)\n",
	                ack_number, rnd5->ack_number1, rnd5->ack_number2);
	rnd5->header_crc = 0; /* for CRC computation */
	rnd5->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) rnd5,
	                                 sizeof(rnd_5_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(rnd_5_t);
}


/**
 * @brief Build a TCP rnd_6 packet
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 82
 *
 * @param context       The compression context
 * @param tcp_context   The specific TCP context
 * @param tcp           The TCP header to compress
 * @param rnd6          IN/OUT: The rnd_6 packet to build
 * @return              The length (in bytes) of the rnd_6 packet
 */
static size_t c_tcp_build_rnd_6(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_6_t *const rnd6)
{
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd6 != NULL);

	rohc_comp_debug(context, "code rnd_6\n");

	rnd6->discriminator = 0x0a; /* '1010' */
	rnd6->header_crc = 0; /* for CRC computation */
	rnd6->psh_flag = tcp->psh_flag;
	rnd6->ack_number = rohc_hton16(c_lsb(context, 16, 16383, tcp_context->ack_number,
	                               rohc_ntoh32(tcp->ack_number)));
	rnd6->msn = g_context->sn & 0xf;
	rnd6->seq_number_scaled = c_lsb(context, 4, 7, tcp_context->seq_number,
	                                tcp_context->seq_number_scaled);
	rnd6->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) rnd6,
	                                 sizeof(rnd_6_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(rnd_6_t);
}


/**
 * @brief Build a TCP rnd_7 packet
 *
 * Send ACK and window
 * See RFC4996 page 82
 *
 * @param context       The compression context
 * @param tcp_context   The specific TCP context
 * @param tcp           The TCP header to compress
 * @param rnd7          IN/OUT: The rnd_7 packet to build
 * @return              The length (in bytes) of the rnd_7 packet
 */
static size_t c_tcp_build_rnd_7(struct c_context *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                rnd_7_t *const rnd7)
{
	struct c_generic_context *g_context;
	uint32_t ack_number;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd7 != NULL);

	rohc_comp_debug(context, "code rnd_7\n");

	rnd7->discriminator = 0x2f; /* '101111' */
	ack_number = c_lsb(context, 18, 65535, tcp_context->ack_number,
	                   rohc_ntoh32(tcp->ack_number));
	rnd7->ack_number1 = (ack_number >> 16) & 0x03;
	rnd7->ack_number2 = rohc_hton16(ack_number & 0xffff);
	rnd7->window = tcp->window;
	rnd7->msn = g_context->sn & 0xf;
	rnd7->psh_flag = tcp->psh_flag;
	rnd7->header_crc = 0; /* for CRC computation */
	rnd7->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) rnd7,
	                                 sizeof(rnd_7_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(rnd_7_t);
}


/**
 * @brief Build a TCP rnd_8 packet
 *
 * Send LSBs of TTL, RSF flags, change ECN behavior and options list
 * See RFC4996 page 82
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param rnd8          IN/OUT: The rnd_8 packet to build
 * @param rnd8_len      OUT: The length (in bytes) of the rnd_8 packet
 * @return              true if the packet is successfully built, false otherwise
 */
static bool c_tcp_build_rnd_8(struct c_context *const context,
										const ip_context_ptr_t ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										rnd_8_t *const rnd8,
										size_t *const rnd8_len)
{
	struct c_generic_context *g_context;
	uint32_t seq_number;
	size_t comp_opts_len;
	uint8_t ttl_hl;
	uint8_t msn;
	bool is_ok;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd8 != NULL);
	assert(rnd8_len != NULL);

	rohc_comp_debug(context, "code rnd_8\n");

	rnd8->discriminator = 0x16; /* '10110' */
	rnd8->rsf_flags = rsf_index_enc(context, tcp->rsf_flags);
	rnd8->list_present = 0; /* options are set later */
	rnd8->header_crc = 0; /* for CRC computation */

	/* MSN */
	msn = g_context->sn & 0xf;
	rnd8->msn1 = (msn >> 3) & 0x01;
	rnd8->msn2 = msn & 0x07;

	rnd8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	if(ip.ipvx->version == IPV4)
	{
		assert(ip_context.vx->version == IPV4);
		ttl_hl = ip.ipv4->ttl_hopl;
	}
	else
	{
		assert(ip.ipvx->version == IPV6);
		assert(ip_context.vx->version == IPV6);
		ttl_hl = ip.ipv6->ttl_hopl;
	}
	rnd8->ttl_hopl = c_lsb(context, 3, 3, ip_context.vx->ttl_hopl, ttl_hl);
	rnd8->ecn_used = (tcp_context->ecn_used != 0);

	/* sequence number */
	seq_number = rohc_ntoh32(tcp->seq_number) & 0xffff;
	rnd8->seq_number = rohc_hton16(seq_number);
	rohc_comp_debug(context, "16 bits of sequence number = 0x%04x\n",
	                seq_number);

	/* ACK number */
	rnd8->ack_number = rohc_hton16(c_lsb(context, 16, 65535, tcp_context->ack_number,
	                               rohc_ntoh32(tcp->ack_number)));

	/* TCP options */
	if(tcp->data_offset > 5)
	{
		/* TCP options are present, compress them */
		rnd8->list_present = 1;
		is_ok = tcp_compress_tcp_options(context, tcp, rnd8->options,
													&comp_opts_len);
		if(!is_ok)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
							 "failed to compress TCP options\n");
			goto error;
		}
	}
	else
	{
		/* no TCP option */
		rnd8->list_present = 0;
		comp_opts_len = 0;
	}

	/* CRC */
	rnd8->header_crc = crc_calculate(ROHC_CRC_TYPE_7, (unsigned char *) rnd8,
	                                 sizeof(rnd_8_t) + comp_opts_len, CRC_INIT_7,
	                                 context->compressor->crc_table_7);
	rohc_comp_debug(context, "CRC (header length = %zd, CRC = 0x%x)\n",
	                sizeof(rnd_8_t) + comp_opts_len, rnd8->header_crc);

	*rnd8_len = sizeof(rnd_8_t) + comp_opts_len;

	return true;

error:
	return false;
}


/**
 * @brief Build a TCP seq_1 packet
 *
 * Send LSBs of sequence number
 * See RFC4996 page 83
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param seq1          IN/OUT: The seq_1 packet to build
 * @return              The length (in bytes) of the seq_1 packet
 */
static size_t c_tcp_build_seq_1(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_1_t *const seq1)
{
	struct c_generic_context *g_context;
	uint32_t seq_number;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq1 != NULL);

	rohc_comp_debug(context, "code seq_1\n");

	seq1->discriminator = 0x0a; /* '1010' */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq1->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 4, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq_number = rohc_ntoh32(tcp->seq_number) & 0xffff;
	seq1->seq_number = rohc_hton16(seq_number);
	seq1->msn = g_context->sn & 0xf;
	seq1->psh_flag = tcp->psh_flag;
	seq1->header_crc = 0; /* for CRC computation */
	seq1->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) seq1,
	                                 sizeof(seq_1_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(seq_1_t);
}


/**
 * @brief Build a TCP seq_2 packet
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 83
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param seq2          IN/OUT: The seq_2 packet to build
 * @return              The length (in bytes) of the seq_2 packet
 */
static size_t c_tcp_build_seq_2(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_2_t *const seq2)
{
	struct c_generic_context *g_context;
	uint16_t ip_id;
	uint8_t ip_id_lsb;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq2 != NULL);

	rohc_comp_debug(context, "code seq_2\n");

	seq2->discriminator = 0x1a; /* '11010' */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	ip_id_lsb = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 7, 3,
	                        ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq2->ip_id1 = (ip_id_lsb >> 4) & 0x7;
	seq2->ip_id2 = ip_id_lsb & 0x0f;
	seq2->seq_number_scaled = c_lsb(context, 4, 7, tcp_context->seq_number,
	                                tcp_context->seq_number_scaled);
	seq2->msn = g_context->sn & 0xf;
	seq2->psh_flag = tcp->psh_flag;
	seq2->header_crc = 0; /* for CRC computation */
	seq2->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) seq2,
	                                 sizeof(seq_2_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(seq_2_t);
}


/**
 * @brief Build a TCP seq_3 packet
 *
 * Send acknowledgment number LSBs
 * See RFC4996 page 83
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param seq3          IN/OUT: The seq_3 packet to build
 * @return              The length (in bytes) of the seq_3 packet
 */
static size_t c_tcp_build_seq_3(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_3_t *const seq3)
{
	struct c_generic_context *g_context;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq3 != NULL);

	rohc_comp_debug(context, "code seq_3\n");

	seq3->discriminator = 0x09; /* '1001' */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq3->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 4, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq3->ack_number = rohc_hton16(c_lsb(context, 16, 16383, tcp_context->ack_number,
	                               rohc_ntoh32(tcp->ack_number)));
	seq3->msn = g_context->sn & 0xf;
	seq3->psh_flag = tcp->psh_flag;
	seq3->header_crc = 0; /* for CRC computation */
	seq3->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) seq3,
	                                 sizeof(seq_3_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(seq_3_t);
}


/**
 * @brief Build a TCP seq_4 packet
 *
 * Send scaled acknowledgment number scaled
 * See RFC4996 page 84
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param seq4          IN/OUT: The seq_4 packet to build
 * @return              The length (in bytes) of the seq_4 packet
 */
static size_t c_tcp_build_seq_4(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_4_t *const seq4)
{
	struct c_generic_context *g_context;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(tcp_context->ack_stride != 0);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq4 != NULL);

	rohc_comp_debug(context, "code seq_4\n");

	seq4->discriminator = 0x00; /* '0' */
	seq4->ack_number_scaled = c_lsb(context, 4, 3,
	                                /*tcp_context->ack_number*/ 0,
	                                tcp_context->ack_number_scaled);
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq4->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 3, 1,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq4->msn = g_context->sn & 0xf;
	seq4->psh_flag = tcp->psh_flag;
	seq4->header_crc = 0; /* for CRC computation */
	seq4->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) seq4,
	                                 sizeof(seq_4_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(seq_4_t);
}


/**
 * @brief Build a TCP seq_5 packet
 *
 * Send ACK and sequence number
 * See RFC4996 page 84
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param seq5          IN/OUT: The seq_5 packet to build
 * @return              The length (in bytes) of the seq_5 packet
 */
static size_t c_tcp_build_seq_5(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_5_t *const seq5)
{
	struct c_generic_context *g_context;
	uint32_t seq_number;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq5 != NULL);

	rohc_comp_debug(context, "code seq_5\n");

	seq5->discriminator = 0x08; /* '1000' */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq5->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 4, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq5->ack_number = rohc_hton16(c_lsb(context, 16, 16383, tcp_context->ack_number,
	                               rohc_ntoh32(tcp->ack_number)));
	seq_number = rohc_ntoh32(tcp->seq_number) & 0xffff;
	seq5->seq_number = rohc_hton16(seq_number);
	seq5->msn = g_context->sn & 0xf;
	seq5->psh_flag = tcp->psh_flag;
	seq5->header_crc = 0; /* for CRC computation */
	seq5->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) seq5,
	                                 sizeof(seq_5_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(seq_5_t);
}


/**
 * @brief Build a TCP seq_6 packet
 *
 * See RFC4996 page 84
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param seq6          IN/OUT: The seq_6 packet to build
 * @return              The length (in bytes) of the seq_6 packet
 */
static size_t c_tcp_build_seq_6(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_6_t *const seq6)
{
	struct c_generic_context *g_context;
	uint8_t seq_number_scaled;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq6 != NULL);

	rohc_comp_debug(context, "code seq_6\n");

	seq6->discriminator = 0x1b; /* '11011' */

	/* scaled sequence number */
	seq_number_scaled = c_lsb(context, 4, 7, tcp_context->seq_number,
	                          tcp_context->seq_number_scaled);
	seq6->seq_number_scaled1 = (seq_number_scaled >> 1) & 0x07;
	seq6->seq_number_scaled2 = seq_number_scaled & 0x01;

	/* IP-ID */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq6->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 7, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq6->ack_number = rohc_hton16(c_lsb(context, 16, 16383, tcp_context->ack_number,
	                               rohc_ntoh32(tcp->ack_number)));
	seq6->msn = g_context->sn & 0xf;
	seq6->psh_flag = tcp->psh_flag;
	seq6->header_crc = 0; /* for CRC computation */
	seq6->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) seq6,
	                                 sizeof(seq_6_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(seq_6_t);
}


/**
 * @brief Build a TCP seq_7 packet
 *
 * Send ACK and window
 * See RFC4996 page 85
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param seq7          IN/OUT: The seq_7 packet to build
 * @return              The length (in bytes) of the seq_7 packet
 */
static size_t c_tcp_build_seq_7(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_7_t *const seq7)
{
	struct c_generic_context *g_context;
	uint16_t window;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq7 != NULL);

	rohc_comp_debug(context, "code seq_7\n");

	seq7->discriminator = 0x0c; /* '1100' */

	/* window */
	window = c_lsb(context, 15, 16383, rohc_ntoh16(tcp_context->old_tcphdr.window),
	               rohc_ntoh16(tcp->window));
	seq7->window1 = (window >> 11) & 0x0f;
	seq7->window2 = (window >> 3) & 0xff;
	seq7->window3 = window & 0x07;

	/* IP-ID */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq7->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 5, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq7->ack_number = rohc_hton16(c_lsb(context, 16, 32767, tcp_context->ack_number,
	                               rohc_ntoh32(tcp->ack_number)));
	seq7->msn = g_context->sn & 0xf;
	seq7->psh_flag = tcp->psh_flag;
	seq7->header_crc = 0; /* for CRC computation */
	seq7->header_crc = crc_calculate(ROHC_CRC_TYPE_3, (unsigned char *) seq7,
	                                 sizeof(seq_7_t), CRC_INIT_3,
	                                 context->compressor->crc_table_3);

	return sizeof(seq_7_t);
}


/**
 * @brief Build a TCP seq_8 packet
 *
 * Send LSBs of TTL, RSF flags, change ECN behavior, and options list
 * See RFC4996 page 85
 *
 * @param context       The compression context
 * @param ip_context    The specific IP innermost context
 * @param tcp_context   The specific TCP context
 * @param ip            The IPv4 or IPv6 header to compress
 * @param tcp           The TCP header to compress
 * @param seq8          IN/OUT: The seq_8 packet to build
 * @param seq8_len      OUT: The length (in bytes) of the seq_8 packet
 * @return              true if the packet is successfully built, false otherwise
 */
static bool c_tcp_build_seq_8(struct c_context *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                seq_8_t *const seq8,
										  size_t *const seq8_len)
{
	struct c_generic_context *g_context;
	size_t comp_opts_len;
	uint16_t ack_number;
	uint16_t seq_number;
	uint16_t ip_id;
	bool is_ok;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq8 != NULL);
	assert(seq8_len != NULL);

	rohc_comp_debug(context, "code seq_8\n");

	seq8->discriminator = 0x0b; /* '1011' */

	/* IP-ID */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq8->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 4, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);

	seq8->list_present = 0; /* options are set later */
	seq8->header_crc = 0; /* for CRC computation */
	seq8->msn = g_context->sn & 0xf;
	seq8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	seq8->ttl_hopl = c_lsb(context, 3, 3, ip_context.vx->ttl_hopl,
	                       ip.ipv4->ttl_hopl);

	seq8->ecn_used = (tcp_context->ecn_used != 0);

	/* ACK number */
	ack_number = c_lsb(context, 15, 8191, tcp_context->ack_number,
	                   rohc_ntoh32(tcp->ack_number));
	seq8->ack_number1 = (ack_number >> 8) & 0x7f;
	seq8->ack_number2 = ack_number & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)\n",
	                ack_number, seq8->ack_number1, seq8->ack_number2);

	seq8->rsf_flags = rsf_index_enc(context, tcp->rsf_flags);

	/* sequence number */
	seq_number = rohc_ntoh32(tcp->seq_number) & 0x3fff;
	seq8->seq_number1 = (seq_number >> 8) & 0x3f;
	seq8->seq_number2 = seq_number & 0xff;
	rohc_comp_debug(context, "seq_number = 0x%04x (0x%02x 0x%02x)\n",
	                seq_number, seq8->seq_number1, seq8->seq_number2);

	/* TCP options */
	if(tcp->data_offset > 5)
	{
		/* TCP options are present, compress them */
		seq8->list_present = 1;
		is_ok = tcp_compress_tcp_options(context, tcp, seq8->options,
													&comp_opts_len);
		if(!is_ok)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
							 "failed to compress TCP options\n");
			goto error;
		}
	}
	else
	{
		/* no TCP option */
		seq8->list_present = 0;
		comp_opts_len = 0;
	}

	/* CRC */
	seq8->header_crc = crc_calculate(ROHC_CRC_TYPE_7, (unsigned char *) seq8,
	                                 sizeof(seq_8_t) + comp_opts_len, CRC_INIT_7,
	                                 context->compressor->crc_table_7);
	rohc_comp_debug(context, "CRC (header length = %zd, CRC = 0x%x)\n",
	                sizeof(seq_8_t) + comp_opts_len, seq8->header_crc);

	*seq8_len = sizeof(seq_8_t) + comp_opts_len;

	return true;

error:
	return false;
}


/**
 * @brief Define the compression part of the TCP profile as described
 *        in the RFC 3095.
 */
struct c_profile c_tcp_profile =
{
	ROHC_IPPROTO_TCP,    /* IP protocol */
	ROHC_PROFILE_TCP,    /* profile ID (see 8 in RFC 3095) */
	c_tcp_create,        /* profile handlers */
	c_tcp_destroy,
	c_tcp_check_profile,
	c_tcp_check_context,
	c_tcp_encode,
	c_generic_reinit_context,
	c_generic_feedback,
	c_generic_use_udp_port,
};

