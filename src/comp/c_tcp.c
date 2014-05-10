/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013,2014 Viveris Technologies
 * Copyright 2012 WBX
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


#define TRACE_GOTO_CHOICE \
	rohc_comp_debug(context, "Compressed format choice LINE %d", __LINE__ )


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

	/* the length of the TCP payload (headers and options excluded) */
	size_t payload_len;

	/** The minimal number of bits required to encode the TCP sequence number
	 *  with p = 65535 */
	size_t nr_seq_bits_65535;
	/** The minimal number of bits required to encode the TCP sequence number
	 *  with p = 32767 */
	size_t nr_seq_bits_32767;
	/** The minimal number of bits required to encode the TCP sequence number
	 *  with p = 16383 */
	size_t nr_seq_bits_16383;
	/** The minimal number of bits required to encode the TCP sequence number
	 *  with p = 8191 */
	size_t nr_seq_bits_8191;
	/** The minimal number of bits required to encode the TCP sequence number
	 *  with p = 63 */
	size_t nr_seq_bits_63;
	/** The minimal number of bits required to encode the TCP scaled sequence
	 *  number */
	size_t nr_seq_scaled_bits;

	/** Whether the ACK number changed or not */
	bool tcp_ack_num_changed;
	/** The minimal number of bits required to encode the TCP ACK number
	 *  with p = 65535 */
	size_t nr_ack_bits_65535;
	/** The minimal number of bits required to encode the TCP ACK number
	 *  with p = 32767 */
	size_t nr_ack_bits_32767;
	/** The minimal number of bits required to encode the TCP ACK number
	 *  with p = 16383 */
	size_t nr_ack_bits_16383;
	/** The minimal number of bits required to encode the TCP ACK number
	 *  with p = 8191 */
	size_t nr_ack_bits_8191;
	/** The minimal number of bits required to encode the TCP ACK number
	 *  with p = 63 */
	size_t nr_ack_bits_63;
	/** The minimal number of bits required to encode the TCP scaled ACK
	 * number */
	size_t nr_ack_scaled_bits;

	/** Whether the structure of the list of TCP options changed in the
	 * current packet */
	bool is_tcp_opts_list_struct_changed;
	/** Whether the content of every TCP options was transmitted or not */
	bool is_tcp_opts_list_item_present[ROHC_TCP_OPTS_MAX];

	/** Whether the TCP option timestamp echo request is present in packet */
	bool opt_ts_present;
	/** The value of the TCP option timestamp echo request (in HBO) */
	uint32_t ts_req;
	/** The value of the TCP option timestamp echo reply (in HBO) */
	uint32_t ts_reply;
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

	uint16_t ip_id;
	bool ip_id_behavior_changed;
	bool ip_id_hi9_changed; /* TODO: replace by the number of required bits */
	bool ip_id_hi11_changed; /* TODO: replace by the number of required bits */
	bool ip_id_hi12_changed; /* TODO: replace by the number of required bits */
	bool ip_id_hi13_changed; /* TODO: replace by the number of required bits */

	uint8_t ttl_hopl;
	int ttl_irregular_chain_flag;
	bool ip_ttl_changed;

	bool ip_df_changed;
	bool dscp_changed;

	bool tcp_ack_flag_changed;
	bool tcp_urg_flag_present;
	bool tcp_urg_flag_changed;
	bool tcp_ecn_flag_changed;
	bool tcp_rsf_flag_changed;

	bool tcp_window_changed;

	bool ecn_used;

	uint8_t tcp_opts_list_indexes[ROHC_TCP_OPTS_MAX];
	uint8_t tcp_opts_idx_max;
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
 * @brief The compression context for one TCP option
 */
struct tcp_opt_context
{
	/** The type of the TCP option */
	uint8_t type;
	/** The number of times the TCP option was transmitted */
	size_t nr_trans;
/** The maximum size (in bytes) of one TCP option */
#define MAX_TCP_OPT_SIZE 40U
	/** The value of the TCP option */
	uint8_t value[MAX_TCP_OPT_SIZE];
};


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
	int tcp_seq_num_change_count;

	// Explicit Congestion Notification used
	uint8_t ecn_used;

	uint32_t tcp_last_seq_num;

	uint16_t window;

	uint32_t seq_num;
	struct c_wlsb *seq_wlsb;
	struct c_wlsb *seq_scaled_wlsb;

	uint32_t seq_num_scaled;
	uint32_t seq_num_residue;
	size_t seq_num_factor;
	size_t seq_num_scaling_nr;

	uint32_t ack_num;
	struct c_wlsb *ack_wlsb;
	struct c_wlsb *ack_scaled_wlsb;

	uint16_t ack_stride;
	uint32_t ack_num_scaled;
	uint32_t ack_num_residue;

	/** The number of times the structure of the list of TCP options was
	 * transmitted since it last changed */
	size_t tcp_opts_list_struct_nr_trans;
	uint8_t tcp_opts_list_struct[ROHC_TCP_OPTS_MAX];
	struct tcp_opt_context tcp_options_list[ROHC_TCP_OPTS_MAX];
	uint16_t tcp_option_maxseg;
	uint8_t tcp_option_window;

	struct tcp_option_timestamp tcp_option_timestamp;
	bool tcp_option_timestamp_init;
	struct c_wlsb *opt_ts_req_wlsb;
	struct c_wlsb *opt_ts_reply_wlsb;

	uint8_t tcp_option_sack_length;
	sack_block_t tcp_option_sackblocks[4];
	uint8_t tcp_options_free_offset;

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


/** The length of the table mapping for TCP options */
#define TCP_LIST_ITEM_MAP_LEN  16U

/**
 * @brief Table of TCP option index, from option Id
 *
 * See RFC4996 6.3.4
 * Return item index of TCP option
 */
static int tcp_options_index[TCP_LIST_ITEM_MAP_LEN] =
{
	TCP_INDEX_EOL,             // TCP_OPT_EOL             0
	TCP_INDEX_NOP,             // TCP_OPT_NOP             1
	TCP_INDEX_MAXSEG,          // TCP_OPT_MAXSEG          2
	TCP_INDEX_WINDOW,          // TCP_OPT_WINDOW          3
	TCP_INDEX_SACK_PERMITTED,  // TCP_OPT_SACK_PERMITTED  4  (experimental)
	TCP_INDEX_SACK,            // TCP_OPT_SACK            5  (experimental)
	-1,                        // TODO ?                  6
	-1,                        // TODO ?                  7
	TCP_INDEX_TIMESTAMP,       // TCP_OPT_TIMESTAMP       8
	-1,                        // TODO ?                  9
	-1,                        // TODO ?                 10
	-1,                        // TODO ?                 11
	-1,                        // TODO ?                 12
	-1,                        // TODO ?                 13
	-1,                        // TODO ?                 14
	-1                         // TODO ?                 15
};


/*
 * Private function prototypes.
 */

static bool c_tcp_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void c_tcp_destroy(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

static bool c_tcp_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool c_tcp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int c_tcp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        unsigned char *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void tcp_decide_state(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

static bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static rohc_packet_t tcp_decide_packet(const struct rohc_comp_ctxt *const context,
                                       const ip_context_ptr_t *const ip_inner_context,
                                       const tcphdr_t *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_ptr_t *const ip_inner_context,
                                          const tcphdr_t *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static uint8_t * tcp_code_static_ipv6_option_part(struct rohc_comp_ctxt *const context,
																  multi_ptr_t mptr,
																  uint8_t protocol,
																  base_header_ip_t base_header);
static uint8_t * tcp_code_dynamic_ipv6_option_part(struct rohc_comp_ctxt *const context,
																	ip_context_ptr_t ip_context,
																	multi_ptr_t mptr,
																	uint8_t protocol,
																	base_header_ip_t base_header);
static uint8_t * tcp_code_irregular_ipv6_option_part(struct rohc_comp_ctxt *const context,
																	  ip_context_ptr_t ip_context,
																	  multi_ptr_t mptr,
																	  uint8_t protocol,
																	  base_header_ip_t base_header);
static uint8_t * tcp_code_static_ip_part(struct rohc_comp_ctxt *const context,
                                         base_header_ip_t base_header,
                                         multi_ptr_t mptr);
static uint8_t * tcp_code_dynamic_ip_part(const struct rohc_comp_ctxt *context,
                                          ip_context_ptr_t ip_context,
                                          base_header_ip_t base_header,
                                          multi_ptr_t mptr,
                                          int is_innermost);
static uint8_t * tcp_code_irregular_ip_part(struct rohc_comp_ctxt *const context,
                                            ip_context_ptr_t ip_context,
                                            base_header_ip_t base_header,
                                            uint8_t *rohc_data,
                                            int ecn_used,
                                            int is_innermost,
                                            int ttl_irregular_chain_flag,
                                            int ip_inner_ecn);

static uint8_t * tcp_code_static_tcp_part(const struct rohc_comp_ctxt *context,
                                           const tcphdr_t *tcp,
                                           multi_ptr_t mptr);
static uint8_t * tcp_code_dynamic_tcp_part(const struct rohc_comp_ctxt *context,
                                            const unsigned char *next_header,
                                            multi_ptr_t mptr);
static uint8_t * tcp_code_irregular_tcp_part(struct rohc_comp_ctxt *const context,
                                             tcphdr_t *tcp,
                                             uint8_t *const rohc_data,
                                             int ip_inner_ecn);

static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *ip,
                          const int packet_size,
                          const unsigned char *next_header,
                          unsigned char *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset);
static int co_baseheader(struct rohc_comp_ctxt *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_ptr_t ip_inner_context,
                         base_header_ip_t base_header,
                         unsigned char *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         const rohc_packet_t packet_type,
                         const tcphdr_t *const tcp,
								 const uint8_t crc)
	__attribute__((nonnull(1, 2, 5, 8), warn_unused_result));


/*
 * Functions that build the rnd_X packets
 */

static size_t c_tcp_build_rnd_1(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_1_t *const rnd1)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static size_t c_tcp_build_rnd_2(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_2_t *const rnd2)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static size_t c_tcp_build_rnd_3(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_3_t *const rnd3)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static size_t c_tcp_build_rnd_4(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_4_t *const rnd4)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static size_t c_tcp_build_rnd_5(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_5_t *const rnd5)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static size_t c_tcp_build_rnd_6(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_6_t *const rnd6)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static size_t c_tcp_build_rnd_7(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_7_t *const rnd7)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static bool c_tcp_build_rnd_8(struct rohc_comp_ctxt *const context,
										const ip_context_ptr_t ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										const uint8_t crc,
										rnd_8_t *const rnd8,
										size_t *const rnd8_len)
	__attribute__((nonnull(1, 3, 5, 7, 8), warn_unused_result));


/*
 * Functions that build the seq_X packets
 */

static size_t c_tcp_build_seq_1(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_1_t *const seq1)
	__attribute__((nonnull(1, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_2(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_2_t *const seq2)
	__attribute__((nonnull(1, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_3(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_3_t *const seq3)
	__attribute__((nonnull(1, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_4(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_4_t *const seq4)
	__attribute__((nonnull(1, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_5(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_5_t *const seq5)
	__attribute__((nonnull(1, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_6(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_6_t *const seq6)
	__attribute__((nonnull(1, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_7(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_7_t *const seq7)
	__attribute__((nonnull(1, 3, 5, 7), warn_unused_result));

static bool c_tcp_build_seq_8(struct rohc_comp_ctxt *const context,
										const ip_context_ptr_t ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										const uint8_t crc,
										seq_8_t *const seq8,
										size_t *const seq8_len)
	__attribute__((nonnull(1, 3, 5, 7, 8), warn_unused_result));


/*
 * Misc functions
 */

static bool tcp_compress_tcp_options(struct rohc_comp_ctxt *const context,
												 const tcphdr_t *const tcp,
												 uint8_t *const comp_opts,
												 size_t *const comp_opts_len)
	__attribute__((nonnull(1, 2, 3, 4), warn_unused_result));

static bool c_ts_lsb(const struct rohc_comp_ctxt *const context,
                     uint8_t **dest,
                     const uint32_t timestamp,
                     const size_t nr_bits_minus_1,
                     const size_t nr_bits_0x40000)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static uint8_t * c_tcp_opt_sack(const struct rohc_comp_ctxt *const context,
                                uint8_t *ptr,
                                uint32_t ack_value,
                                uint8_t length,
                                const sack_block_t *const sack_block)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));

static tcp_ip_id_behavior_t tcp_detect_ip_id_behavior(const uint16_t last_ip_id,
																		const uint16_t new_ip_id)
	__attribute__((warn_unused_result, const));

static void tcp_field_descr_change(const struct rohc_comp_ctxt *const context,
                                   const char *const name,
                                   const bool changed)
	__attribute__((nonnull(1, 2)));

static void tcp_field_descr_present(const struct rohc_comp_ctxt *const context,
                                    const char *const name,
                                    const bool present)
	__attribute__((nonnull(1, 2)));

static char * tcp_ip_id_behavior_get_descr(const tcp_ip_id_behavior_t ip_id_behavior)
	__attribute__((warn_unused_result, const));

static char * tcp_opt_get_descr(const uint8_t opt_type)
	__attribute__((warn_unused_result, const));



/**
 * @brief Create a new TCP context and initialize it thanks to the given IP/TCP
 *        packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP/TCP packet given to initialize the new context
 * @return         true if successful, false otherwise
 */
static bool c_tcp_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
{
	const struct rohc_comp *const comp = context->compressor;
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header;   // Source
	const tcphdr_t *tcp;
	uint8_t proto;
	int size_context;
	size_t size_option;
	size_t i;
	size_t size;

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_VAR, packet))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto error;
	}
	g_context = (struct c_generic_context *) context->specific;

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *) packet->outer_ip.data;

	size = 0;
	size_context = 0;

	do
	{
		rohc_comp_debug(context, "found IPv%d header", base_header.ipvx->version);

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
				proto = base_header.ipv4->protocol;
				size += sizeof(base_header_ip_v4_t);
				size_context += sizeof(ipv4_context_t);
				++base_header.ipv4;
				break;
			case IPV6:
				proto = base_header.ipv6->next_header;
				size += sizeof(base_header_ip_v6_t);
				size_context += sizeof(ipv6_context_t);
				++base_header.ipv6;
				while(rohc_is_ipv6_opt(proto))
				{
					switch(proto)
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
					proto = base_header.ipv6_opt->next_header;
					size += size_option;
					base_header.uint8 += size_option;
				}
				break;
			default:
				goto free_context;
		}

	}
	while(rohc_is_tunneling(proto) && size < packet->outer_ip.size);

	if(size >= packet->outer_ip.size)
	{
		goto free_context;
	}

	tcp = base_header.tcphdr;

	/* create the TCP part of the profile context */
	tcp_context = malloc(sizeof(struct sc_tcp_context) + size_context + 1);
	if(tcp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the TCP part of the profile context");
		goto free_context;
	}
	g_context->specific = tcp_context;

	/* initialize the specific context of the profile context */
	memset(tcp_context->ip_context,0,size_context);

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *) packet->outer_ip.data;
	ip_context.uint8 = tcp_context->ip_context;

	do
	{
		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);
		ip_context.vx->version = base_header.ipvx->version;

		switch(base_header.ipvx->version)
		{
			case IPV4:
				ip_context.v4->last_ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
				rohc_comp_debug(context, "IP-ID 0x%04x", ip_context.v4->last_ip_id);
				ip_context.v4->last_ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
				ip_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
				/* get the transport protocol */
				proto = base_header.ipv4->protocol;
				ip_context.v4->protocol = proto;
				ip_context.v4->dscp = base_header.ipv4->dscp;
				ip_context.v4->df = base_header.ipv4->df;
				ip_context.v4->ttl_hopl = base_header.ipv4->ttl_hopl;
				ip_context.v4->src_addr = base_header.ipv4->src_addr;
				ip_context.v4->dst_addr = base_header.ipv4->dest_addr;
				++base_header.ipv4;
				++ip_context.v4;
				break;
			case IPV6:
				ip_context.v6->ip_id_behavior = IP_ID_BEHAVIOR_RAND;
				/* get the transport protocol */
				proto = base_header.ipv6->next_header;
				ip_context.v6->next_header = proto;
				ip_context.v6->dscp = DSCP_V6(base_header.ipv6);
				ip_context.v6->ttl_hopl = base_header.ipv6->ttl_hopl;
				ip_context.v6->flow_label1 = base_header.ipv6->flow_label1;
				ip_context.v6->flow_label2 = base_header.ipv6->flow_label2;
				memcpy(ip_context.v6->src_addr,base_header.ipv6->src_addr,sizeof(uint32_t) * 4 * 2);
				++base_header.ipv6;
				++ip_context.v6;
				while(rohc_is_ipv6_opt(proto))
				{
					switch(proto)
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
	while(rohc_is_tunneling(proto));

	// Last in chain
	ip_context.vx->version = 0;

	tcp_context->tcp_seq_num_change_count = 0;
	tcp_context->tcp_last_seq_num = -1;

	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(tcphdr_t));

	/* TCP sequence number */
	tcp_context->seq_num = rohc_ntoh32(tcp->seq_num);
	tcp_context->seq_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->seq_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP sequence number");
		goto free_context;
	}
	tcp_context->seq_scaled_wlsb = c_create_wlsb(32, 4, 7);
	if(tcp_context->seq_scaled_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP scaled sequence "
		           "number");
		goto free_wlsb_seq;
	}

	/* TCP acknowledgment (ACK) number */
	tcp_context->ack_num = rohc_ntoh32(tcp->ack_num);
	tcp_context->ack_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->ack_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP ACK number");
		goto free_wlsb_seq_scaled;
	}
	tcp_context->ack_scaled_wlsb = c_create_wlsb(32, 4, 3);
	if(tcp_context->ack_scaled_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP scaled ACK number");
		goto free_wlsb_ack;
	}

	/* init the TCP-specific temporary variables DBX */
#ifdef TODO
	tcp_context->tmp_variables.send_tcp_dynamic = -1;
#endif

	/* init the Master Sequence Number to a random value */
	g_context->sn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "MSN = 0x%04x", g_context->sn);

	tcp_context->ack_stride = 0;

	/* init the last list of TCP options */
	tcp_context->tcp_opts_list_struct_nr_trans = 0;
	memset(tcp_context->tcp_opts_list_struct, 0xff, ROHC_TCP_OPTS_MAX);
	// Initialize TCP options list index used
	for(i = 0; i < ROHC_TCP_OPTS_MAX; i++)
	{
		tcp_context->tcp_options_list[i].type = 0xff;
		tcp_context->tcp_options_list[i].nr_trans = 0;
	}

	/* no TCP option Timestamp received yet */
	tcp_context->tcp_option_timestamp_init = false;
	/* TCP option Timestamp (request) */
	tcp_context->opt_ts_req_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->opt_ts_req_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "request");
		goto free_wlsb_ack_scaled;
	}
	/* TCP option Timestamp (reply) */
	tcp_context->opt_ts_reply_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->opt_ts_reply_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "reply");
		goto free_wlsb_opt_ts_req;
	}

	/* init the TCP-specific variables and functions */
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
free_wlsb_ack_scaled:
	c_destroy_wlsb(tcp_context->ack_scaled_wlsb);
free_wlsb_ack:
	c_destroy_wlsb(tcp_context->ack_wlsb);
free_wlsb_seq_scaled:
	c_destroy_wlsb(tcp_context->seq_scaled_wlsb);
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
static void c_tcp_destroy(struct rohc_comp_ctxt *const context)
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
	c_destroy_wlsb(tcp_context->ack_scaled_wlsb);
	c_destroy_wlsb(tcp_context->ack_wlsb);
	c_destroy_wlsb(tcp_context->seq_scaled_wlsb);
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
 * @param comp    The ROHC compressor
 * @param packet  The packet to check
 * @return        Whether the IP packet corresponds to the profile:
 *                  \li true if the IP packet corresponds to the profile,
 *                  \li false if the IP packet does not correspond to
 *                      the profile
 */
static bool c_tcp_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
{
	const struct tcphdr *tcp_header;
	bool ip_check;

	assert(comp != NULL);
	assert(packet != NULL);

	/* check that the the versions of outer and inner IP headers are 4 or 6
	   and that outer and inner IP headers are not IP fragments */
	ip_check = c_generic_check_profile(comp, packet);
	if(!ip_check)
	{
		goto bad_profile;
	}

	/* IP payload shall be large enough for TCP header */
	if(packet->transport->len < sizeof(struct tcphdr))
	{
		goto bad_profile;
	}

	/* check that the transport protocol is TCP */
	if(packet->transport->data == NULL ||
	   packet->transport->proto != ROHC_IPPROTO_TCP)
	{
		goto bad_profile;
	}

	/* retrieve the TCP header */
	tcp_header = (const struct tcphdr *) packet->transport->data;
	if(packet->transport->len < (tcp_header->data_offset * 4U))
	{
		goto bad_profile;
	}

	/* the TCP profile doesn't handle TCP packets with more than 15 options */
	{
		const size_t opts_len =
			tcp_header->data_offset * 4U - sizeof(struct tcphdr);
		size_t opts_offset;
		size_t opt_pos;
		size_t opt_len;

		for(opt_pos = 0, opts_offset = 0;
		    opt_pos < ROHC_TCP_OPTS_MAX && opts_offset < opts_len;
		    opt_pos++, opts_offset += opt_len)
		{
			const uint8_t opt_type = tcp_header->options[opts_offset];

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "TCP option %u found", opt_type);

			if(opt_type == TCP_OPT_EOL || opt_type == TCP_OPT_NOP)
			{
				/* 1-byte TCP options: EOL or NOP */
				opt_len = 1;
			}
			else
			{
				/* multi-byte TCP options */
				if((opts_offset + 1) >= opts_len)
				{
					rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					             "malformed TCP header: not enough room for the "
					             "length field of option %u", opt_type);
					goto bad_profile;
				}
				opt_len = tcp_header->options[opts_offset + 1];
				if(opt_len < 2)
				{
					rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					             "malformed TCP header: option %u got length "
					             "field %zu", opt_type, opt_len);
					goto bad_profile;
				}
				if((opts_offset + opt_len) > opts_len)
				{
					rohc_warning(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					             "malformed TCP header: not enough room for "
					             "option %u (%zu bytes required but only %zu "
					             "available)", opt_type, opt_len,
					             opts_len - opts_offset);
					goto bad_profile;
				}
			}
		}
		if(opt_pos >= ROHC_TCP_OPTS_MAX && opts_offset != opts_len)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unexpected TCP header: too many TCP options: %zu "
			           "options found in packet but only %u options possible",
			           opt_pos, ROHC_TCP_OPTS_MAX);
			goto bad_profile;
		}
	}

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
 * @param context  The compression context
 * @param packet   The IP/TCP packet to check
 * @return         true if the IP/TCP packet belongs to the context
 *                 false if it does not belong to the context
 */
static bool c_tcp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header;   // Source
	uint8_t proto;
	tcphdr_t *tcp;
	bool is_tcp_same;
	size_t size;

	g_context = (struct c_generic_context *) context->specific;
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *) packet->outer_ip.data;
	ip_context.uint8 = tcp_context->ip_context;
	size = packet->outer_ip.size;

	do
	{
		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

		if(base_header.ipvx->version != ip_context.vx->version)
		{
			rohc_comp_debug(context, "  not same IP version");
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
					rohc_comp_debug(context, "  not same IPv4 addresses");
					goto bad_context;
				}
				rohc_comp_debug(context, "  same IPv4 addresses");
				/* get the transport protocol */
				proto = base_header.ipv4->protocol;
				if(base_header.ipv4->protocol != ip_context.v4->protocol)
				{
					rohc_comp_debug(context, "  IPv4 not same protocol");
					goto bad_context;
				}
				rohc_comp_debug(context, "  IPv4 same protocol %d", proto);
				++base_header.ipv4;
				++ip_context.v4;
				assert(size >= sizeof(base_header_ip_v4_t));
				size -= sizeof(base_header_ip_v4_t);
				break;
			case IPV6:
				if(memcmp(base_header.ipv6->src_addr, ip_context.v6->src_addr, sizeof(uint32_t) * 4) != 0 ||
				   memcmp(base_header.ipv6->dest_addr, ip_context.v6->dest_addr, sizeof(uint32_t) * 4) != 0)
				{
					rohc_comp_debug(context, "  not same IPv6 addresses");
					goto bad_context;
				}
				rohc_comp_debug(context, "  same IPv6 addresses");
				if(base_header.ipv6->flow_label1 != ip_context.v6->flow_label1 ||
				   base_header.ipv6->flow_label2 != ip_context.v6->flow_label2)
				{
					rohc_comp_debug(context, "  not same IPv6 flow label");
					goto bad_context;
				}
				proto = base_header.ipv6->next_header;
				if(proto != ip_context.v6->next_header)
				{
					rohc_comp_debug(context, "  IPv6 not same protocol %d", proto);
					goto bad_context;
				}
				++base_header.ipv6;
				++ip_context.v6;
				assert(size >= sizeof(base_header_ip_v6_t));
				size -= sizeof(base_header_ip_v6_t);
				while(rohc_is_ipv6_opt(proto) && size < packet->outer_ip.size)
				{
					proto = base_header.ipv6_opt->next_header;
					if(proto != ip_context.v6_option->next_header)
					{
						rohc_comp_debug(context, "  not same IPv6 option (%d != %d)",
						                proto, ip_context.v6_option->next_header);
						goto bad_context;
					}
					rohc_comp_debug(context, "  same IPv6 option %d", proto);
					base_header.uint8 += ip_context.v6_option->option_length;
					ip_context.uint8 += ip_context.v6_option->context_length;
				}
				break;
			default:
				assert(0);
				goto bad_context;
		}

	}
	while(rohc_is_tunneling(proto) && size >= sizeof(tcphdr_t));

	tcp = base_header.tcphdr;
	is_tcp_same = tcp_context->old_tcphdr.src_port == tcp->src_port &&
	              tcp_context->old_tcphdr.dst_port == tcp->dst_port;
	rohc_comp_debug(context, "  TCP %ssame Source and Destination ports",
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
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int c_tcp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        unsigned char *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	ip_context_ptr_t ip_inner_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header_inner;   // Source innermost
	base_header_ip_t base_header;   // Source
	multi_ptr_t mptr;
	const tcphdr_t *tcp;
	size_t first_position;
	int crc_position;
	int counter;
	uint8_t protocol;
	int ecn_used;
	size_t size;
#ifdef TODO
	uint8_t new_context_state;
#endif
	size_t i;
	int ret;

	assert(context != NULL);
	assert(rohc_pkt != NULL);
	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	*packet_type = ROHC_PACKET_UNKNOWN;

	/* at the beginning, no item transmitted for the compressed list of TCP options */
	for(i = 0; i < ROHC_TCP_OPTS_MAX; i++)
	{
		tcp_context->tmp.is_tcp_opts_list_item_present[i] = false;
	}


	/* STEP 1:
	 *  - check double IP headers
	 *  - find the next header
	 *  - compute the payload offset
	 *  - discard IP fragments
	 */

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *) uncomp_pkt->outer_ip.data;
	ip_context.uint8 = tcp_context->ip_context;
	size = 0;
	ecn_used = 0;
	do
	{
		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

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
								                "changed (%d -> %d)", protocol,
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
								                "changed (%d -> %d)", protocol,
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
								                "changed (%d -> %d)", protocol,
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
								                "changed (0x%x -> 0x%x)", protocol,
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
								                "changed (0x%x -> 0x%x)", protocol,
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
	while(protocol != ROHC_IPPROTO_TCP && size < uncomp_pkt->outer_ip.size);

	/* find the next header */
	tcp = base_header.tcphdr;
	ecn_used |= tcp->ecn_flags;
	tcp_context->ecn_used = ecn_used;
	rohc_comp_debug(context, "ecn_used %d", tcp_context->ecn_used);
	// Reinit source pointer
	base_header.uint8 = (uint8_t *) uncomp_pkt->outer_ip.data;


	/* determine the IP-ID behavior of the innermost IPv4 header */
	if(base_header_inner.ipvx->version == IPV4)
	{
		const uint16_t ip_id = rohc_ntoh16(base_header_inner.ipv4->ip_id);

		rohc_comp_debug(context, "IP-ID behaved as %s",
		                tcp_ip_id_behavior_get_descr(ip_inner_context.v4->ip_id_behavior));
		rohc_comp_debug(context, "IP-ID = 0x%04x -> 0x%04x",
		                ip_inner_context.v4->last_ip_id, ip_id);

		if(context->num_sent_packets == 0)
		{
			/* first packet, be optimistic: choose sequential behavior */
			ip_inner_context.v4->ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
		}
		else
		{
			ip_inner_context.v4->ip_id_behavior =
				tcp_detect_ip_id_behavior(ip_inner_context.v4->last_ip_id, ip_id);
		}
		rohc_comp_debug(context, "IP-ID now behaves as %s",
		                tcp_ip_id_behavior_get_descr(ip_inner_context.v4->ip_id_behavior));
	}

	/* parse TCP options */
	{
		uint8_t *opts;
		size_t opts_len;
		size_t opt_pos;
		size_t opt_len;
		size_t opts_offset;

		tcp_context->tmp.is_tcp_opts_list_struct_changed = false;
		tcp_context->tmp.opt_ts_present = false;
		memset(tcp_context->tmp.tcp_opts_list_indexes, 0xff, ROHC_TCP_OPTS_MAX);
		tcp_context->tmp.tcp_opts_idx_max = 0;

		opts = ((uint8_t *) tcp) + sizeof(tcphdr_t);
		opts_len = (tcp->data_offset << 2) - sizeof(tcphdr_t);

		rohc_comp_debug(context, "parse %zu-byte TCP options", opts_len);

		for(opt_pos = 0, opts_offset = 0;
		    opt_pos < ROHC_TCP_OPTS_MAX && opts_offset < opts_len;
		    opt_pos++, opts_offset += opt_len)
		{
			const uint8_t opt_type = opts[opts_offset];
			uint8_t opt_idx;

			rohc_comp_debug(context, "  TCP option %u found", opt_type);

			if(opt_type == TCP_OPT_EOL || opt_type == TCP_OPT_NOP)
			{
				/* EOL or NOP */
				opt_len = 1;
			}
			else
			{
				if((opts_offset + 1) >= opts_len)
				{
					rohc_comp_warn(context, "malformed TCP header: not enough "
					               "room for length field of option %u", opt_type);
					goto error;
				}
				opt_len = opts[opts_offset + 1];
				if(opt_len < 2)
				{
					rohc_comp_warn(context, "malformed TCP header: option %u got "
					               "length field %zu", opt_type, opt_len);
					goto error;
				}
				if((opts_offset + opt_len) > opts_len)
				{
					rohc_comp_warn(context, "malformed TCP header: not enough "
					               "room for option %u (%zu bytes required but "
					               "only %zu available)", opt_type, opt_len,
					               opts_len - opts_offset);
					goto error;
				}

				if(opt_type == TCP_OPT_TIMESTAMP)
				{
					memcpy(&tcp_context->tmp.ts_req, opts + opts_offset + 2,
					       sizeof(uint32_t));
					tcp_context->tmp.ts_req = rohc_ntoh32(tcp_context->tmp.ts_req);
					memcpy(&tcp_context->tmp.ts_reply, opts + opts_offset + 6,
					       sizeof(uint32_t));
					tcp_context->tmp.ts_reply = rohc_ntoh32(tcp_context->tmp.ts_reply);
					tcp_context->tmp.opt_ts_present = true;
				}
			}

			/* determine the index of the TCP option */
			if(opt_type < TCP_LIST_ITEM_MAP_LEN &&
			   tcp_options_index[opt_type] >= 0)
			{
				/* TCP option got a reserved index */
				opt_idx = tcp_options_index[opt_type];
				rohc_comp_debug(context, "    option '%s' (%u) will use reserved "
				                "index %u", tcp_opt_get_descr(opt_type),
				                opt_type, opt_idx);
			}
			else /* TCP option doesn't have a reserved index */
			{
				bool opt_idx_found = false;
				int opt_idx_free = -1;

				/* find the index that was used for the same option in previous
				 * packets, or the first unused one */
				for(opt_idx = TCP_INDEX_SACK + 1;
				    !opt_idx_found && opt_idx_free < 0 &&
				    opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
				{
					if(tcp_context->tcp_options_list[opt_idx].type == opt_type)
					{
						opt_idx_found = true;
					}
					else if(tcp_context->tcp_options_list[opt_idx].type == 0xff)
					{
						opt_idx_free = opt_idx;
					}
				}
				if(opt_idx_found)
				{
					rohc_comp_debug(context, "    option '%s' (%u) will use same "
					                "index %u as in previous packet",
					                tcp_opt_get_descr(opt_type), opt_type, opt_idx);
				}
				else if(opt_idx_free < 0)
				{
					rohc_comp_warn(context, "no free index found for option '%s' "
					               "(%u)", tcp_opt_get_descr(opt_type), opt_type);
					goto error;
				}
				else
				{
					/* now index used by this option */
					opt_idx = opt_idx_free;
					tcp_context->tcp_options_list[opt_idx].type = opt_type;
					tcp_context->tcp_options_list[opt_idx].nr_trans++;
					rohc_comp_debug(context, "    option '%s' (%u) will use new "
					                "index %u", tcp_opt_get_descr(opt_type),
					                opt_type, opt_idx);
				}
			}
			tcp_context->tmp.tcp_opts_list_indexes[opt_pos] = opt_idx;
			if(opt_idx > tcp_context->tmp.tcp_opts_idx_max)
			{
				tcp_context->tmp.tcp_opts_idx_max = opt_idx;
			}

			/* was the TCP option present at the very same location in previous
			 * packet? */
			if(tcp_context->tcp_opts_list_struct[opt_pos] != opt_type)
			{
				rohc_comp_debug(context, "    option was not present at the very "
				                "same location in previous packet");
				tcp_context->tmp.is_tcp_opts_list_struct_changed = true;
			}
			else
			{
				rohc_comp_debug(context, "    option was at the very same "
				                "location in previous packet");
			}

			/* record the structure of the current list TCP options in context */
			tcp_context->tcp_opts_list_struct[opt_pos] = opt_type;
		}
		if(opt_pos >= ROHC_TCP_OPTS_MAX && opts_offset != opts_len)
		{
			rohc_comp_warn(context, "unexpected TCP header: too many TCP "
			               "options: %zu options found in packet but only %u "
			               "options possible", opt_pos, ROHC_TCP_OPTS_MAX);
			goto error;
		}

		/* fewer options than in previous packet? */
		while(opt_pos < ROHC_TCP_OPTS_MAX &&
		      tcp_context->tcp_opts_list_struct[opt_pos] != 0xff)
		{
			rohc_comp_debug(context, "  TCP option %d is not present anymore",
			                tcp_context->tcp_opts_list_struct[opt_pos]);
			tcp_context->tmp.is_tcp_opts_list_struct_changed = true;
			tcp_context->tcp_opts_list_struct[opt_pos] = 0xff;
			opt_pos++;
		}

		if(tcp_context->tmp.is_tcp_opts_list_struct_changed)
		{
			/* the new structure has never been transmitted yet */
			rohc_comp_debug(context, "structure of TCP options list changed, "
			                "compressed list must be transmitted in the compressed "
			                "base header");
			tcp_context->tcp_opts_list_struct_nr_trans = 0;
		}
		else if(tcp_context->tcp_opts_list_struct_nr_trans <
		        context->compressor->list_trans_nr)
		{
			/* the structure was transmitted but not enough times */
			rohc_comp_debug(context, "structure of TCP options list changed in "
			                "the last few packets, compressed list must be "
			                "transmitted in the compressed base header");
			tcp_context->tmp.is_tcp_opts_list_struct_changed = true;
			tcp_context->tcp_opts_list_struct_nr_trans++;
		}
		else
		{
			rohc_comp_debug(context, "structure of TCP options list is unchanged, "
			                "compressed list may be omitted from the compressed "
			                "base header, any content changes may be transmitted "
			                "in the irregular chain");
		}

		/* use 4-bit XI or 8-bit XI ? */
		if(tcp_context->tmp.tcp_opts_idx_max <= 7)
		{
			rohc_comp_debug(context, "compressed TCP options list will be able "
			                "to use 4-bit XI since the largest index is %u",
			                tcp_context->tmp.tcp_opts_idx_max);
		}
		else
		{
			assert(tcp_context->tmp.tcp_opts_idx_max <= MAX_TCP_OPTION_INDEX);
			rohc_comp_debug(context, "compressed TCP options list will use "
			                "8-bit XI since the largest index is %u",
			                tcp_context->tmp.tcp_opts_idx_max);
		}

		/* find the offset of the payload and its size */
		assert(uncomp_pkt->len >= (size + sizeof(tcphdr_t) + opts_len));
		tcp_context->tmp.payload_len =
			uncomp_pkt->len - size - sizeof(tcphdr_t) - opts_len;
		rohc_comp_debug(context, "payload length = %zu bytes",
		                tcp_context->tmp.payload_len);
	}

	/* detect changes between new uncompressed packet and context */
	if(!tcp_detect_changes(context, uncomp_pkt))
	{
		rohc_comp_warn(context, "failed to detect changes in uncompressed "
		               "packet");
		goto error;
	}

	/* decide in which state to go */
	tcp_decide_state(context);

	/* compute how many bits are needed to send header fields */
	if(!tcp_encode_uncomp_fields(context, uncomp_pkt))
	{
		rohc_comp_warn(context, "failed to compute how many bits are needed to "
		               "transmit all changes in header fields");
		goto error;
	}

	/* decide which packet to send */
	*packet_type = tcp_decide_packet(context, &ip_inner_context, tcp);

	/* code the chosen packet */
	if((*packet_type) == ROHC_PACKET_UNKNOWN)
	{
		rohc_comp_warn(context, "failed to find the packet type to encode");
		goto error;
	}
	else if((*packet_type) != ROHC_PACKET_IR &&
	        (*packet_type) != ROHC_PACKET_IR_DYN)
	{
		/* co_common, seq_X, or rnd_X */
		counter = code_CO_packet(context, &uncomp_pkt->outer_ip, uncomp_pkt->len,
		                         base_header.uint8, rohc_pkt, rohc_pkt_max_len,
		                         *packet_type, payload_offset);
		if(counter < 0)
		{
			rohc_comp_warn(context, "failed to build CO packet");
			goto error;
		}
		rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
		              ROHC_TRACE_DEBUG, "current ROHC packet", rohc_pkt, counter);
	}
	else /* ROHC_PACKET_IR or ROHC_PACKET_IR_DYN */
	{
		assert((*packet_type) == ROHC_PACKET_IR ||
		       (*packet_type) == ROHC_PACKET_IR_DYN);

		/* parts 1 and 3:
		 *  - part 2 will be placed at 'first_position'
		 *  - part 4 will start at 'counter'
		 */
		ret = code_cid_values(context->compressor->medium.cid_type,
		                      context->cid, rohc_pkt, rohc_pkt_max_len,
		                      &first_position);
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

		/* part 2: type of packet */
		if((*packet_type) == ROHC_PACKET_IR)
		{
			rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR;
		}
		else /* ROHC_PACKET_IR_DYN */
		{
			rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR_DYN;
		}
		rohc_comp_debug(context, "packet type = 0x%02x", rohc_pkt[first_position]);

		/* part 4 */
		rohc_comp_debug(context, "profile ID = 0x%02x", context->profile->id);
		rohc_pkt[counter] = context->profile->id;
		counter++;

		/* part 5: the CRC is computed later since it must be computed
		 * over the whole packet with an empty CRC field */
		rohc_comp_debug(context, "CRC = 0x00 for CRC calculation");
		crc_position = counter;
		rohc_pkt[counter] = 0;
		counter++;

		mptr.uint8 = &rohc_pkt[counter];

		if((*packet_type) == ROHC_PACKET_IR)
		{
			/* part 6 : static chain */

			// Init pointer to the initial packet
			base_header.ipvx = (base_header_ip_vx_t *) uncomp_pkt->outer_ip.data;
			ip_context.uint8 = tcp_context->ip_context;

			do
			{
				rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

				switch(base_header.ipvx->version)
				{
					case IPV4:
						mptr.uint8 =
						   tcp_code_static_ip_part(context, base_header, mptr);
						/* get the transport protocol */
						protocol = base_header.ipv4->protocol;
						++base_header.ipv4;
						++ip_context.v4;
						break;
					case IPV6:
						mptr.uint8 =
						   tcp_code_static_ip_part(context, base_header, mptr);
						protocol = base_header.ipv6->next_header;
						++base_header.ipv6;
						++ip_context.v6;
						while(rohc_is_ipv6_opt(protocol))
						{
							rohc_comp_debug(context, "IPv6 option %u", protocol);
							mptr.uint8 =
							   tcp_code_static_ipv6_option_part(context, mptr,
							                                    protocol, base_header);
							if(mptr.uint8 == NULL)
							{
								rohc_comp_warn(context, "failed to code the IPv6 "
								               "extension part of the static chain");
								goto error;
							}
							protocol = base_header.ipv6_opt->next_header;
							base_header.uint8 += ip_context.v6_option->option_length;
							ip_context.uint8 += ip_context.v6_option->context_length;
						}
						break;
					default:
						rohc_comp_warn(context, "unexpected IP version %u",
						               base_header.ipvx->version);
						assert(0);
						goto error;
				}
				rohc_comp_debug(context, "counter = %d, protocol = %d",
				                (int)(mptr.uint8 - &rohc_pkt[counter]), protocol);

			}
			while(rohc_is_tunneling(protocol));

			// add TCP static part
			mptr.uint8 = tcp_code_static_tcp_part(context,base_header.tcphdr,mptr);
			rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
			              ROHC_TRACE_DEBUG, "current ROHC packet",
			              rohc_pkt, mptr.uint8 - rohc_pkt);
		}

		/* Packet IP or IR-DYN : add dynamic chain */

		// Init pointer to the initial packet
		base_header.ipvx = (base_header_ip_vx_t *) uncomp_pkt->outer_ip.data;
		ip_context.uint8 = tcp_context->ip_context;

		do
		{
			rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

			mptr.uint8 = tcp_code_dynamic_ip_part(context, ip_context, base_header,
			                                      mptr,
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
						rohc_comp_debug(context, "IPv6 option %u", protocol);
						mptr.uint8 =
						   tcp_code_dynamic_ipv6_option_part(context, ip_context,
						                                     mptr, protocol,
						                                     base_header);
						if(mptr.uint8 == NULL)
						{
							rohc_comp_warn(context, "failed to code the IPv6 "
							               "extension part of the dynamic chain");
							goto error;
						}
						protocol = base_header.ipv6_opt->next_header;
						base_header.uint8 += ip_context.v6_option->option_length;
						ip_context.uint8 += ip_context.v6_option->context_length;
					}
					break;
				default:
					rohc_comp_warn(context, "unexpected IP version %u",
					               base_header.ipvx->version);
					assert(0);
					goto error;
			}
		}
		while(rohc_is_tunneling(protocol));

		// add TCP dynamic part
		mptr.uint8 = tcp_code_dynamic_tcp_part(context,base_header.uint8,mptr);
		if(mptr.uint8 == NULL)
		{
			rohc_comp_warn(context, "failed to code the TCP part of the dynamic "
			               "chain");
			goto error;
		}

		counter = (int) ( mptr.uint8 - rohc_pkt );
		rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
		              ROHC_TRACE_DEBUG, "current ROHC packet", rohc_pkt, counter);

		/* last part : payload */
		base_header.uint8 += (base_header.tcphdr->data_offset << 2);

		rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
		              ROHC_TRACE_DEBUG, "current ROHC packet", rohc_pkt, counter);

		/* part 5 */
		rohc_pkt[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt,
		                                       counter, CRC_INIT_8,
		                                       context->compressor->crc_table_8);
		rohc_comp_debug(context, "CRC (header length = %d, crc = 0x%x)",
		                counter, rohc_pkt[crc_position]);

		rohc_comp_debug(context, "IR packet, length %d",counter);
		rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
		              ROHC_TRACE_DEBUG, "current ROHC packet", rohc_pkt, counter);

		*packet_type = ROHC_PACKET_IR;
		*payload_offset = base_header.uint8 - (uint8_t *) uncomp_pkt->outer_ip.data;
	}

	rohc_comp_debug(context, "payload_offset = %zu", *payload_offset);

	/* update the context with the new TCP header */
	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(tcphdr_t));
	tcp_context->seq_num = rohc_ntoh32(tcp->seq_num);
	tcp_context->ack_num = rohc_ntoh32(tcp->ack_num);

	/* sequence number sent once more, count the number of transmissions to
	 * know when scaled sequence number is possible */
	if(tcp_context->seq_num_factor != 0 &&
	   tcp_context->seq_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
	{
		tcp_context->seq_num_scaling_nr++;
		rohc_comp_debug(context, "unscaled sequence number was transmitted "
		                "%zu / %u times since the scaling factor or residue "
		                "changed", tcp_context->seq_num_scaling_nr,
		                ROHC_INIT_TS_STRIDE_MIN);
	}

	return counter;

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv6 option header.
 *
 * @param context        The compression context
 * @param mptr           The current pointer in the rohc-packet-under-build buffer
 * @param protocol       The IPv6 protocol option
 * @param base_header    The IP header
 * @return               The new pointer in the rohc-packet-under-build buffer,
 *                       NULL if a problem occurs
 */
static uint8_t * tcp_code_static_ipv6_option_part(struct rohc_comp_ctxt *const context,
																  multi_ptr_t mptr,
																  uint8_t protocol,
																  base_header_ip_t base_header)
{
	uint8_t size;
	int ret;

	assert(context != NULL);

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
				rohc_comp_warn(context, "failed to encode optional32(key)");
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
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "IPv6 option static part", mptr.uint8, size);
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
 * @return               The new pointer in the rohc-packet-under-build buffer,
 *                       NULL if a problem occurs
 */
static uint8_t * tcp_code_dynamic_ipv6_option_part(struct rohc_comp_ctxt *const context,
																	ip_context_ptr_t ip_context,
																	multi_ptr_t mptr,
																	uint8_t protocol,
																	base_header_ip_t base_header)
{
	int size;
	int ret;

	assert(context != NULL);

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
				rohc_comp_warn(context, "optional32(seq_number) failed");
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
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "IPv6 option dynamic part", mptr.uint8, size);
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
 * @return               The new pointer in the rohc-packet-under-build buffer,
 *                       NULL if a problem occurs
 */
static uint8_t * tcp_code_irregular_ipv6_option_part(struct rohc_comp_ctxt *const context,
																	  ip_context_ptr_t ip_context,
																	  multi_ptr_t mptr,
																	  uint8_t protocol,
																	  base_header_ip_t base_header)
{
#if ROHC_EXTRA_DEBUG == 1
	uint8_t *ptr = mptr.uint8;
#endif
	uint32_t sequence_number;
	int size;
	int ret;

	assert(context != NULL);

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
					rohc_comp_warn(context, "lsb_7_or_31(seq_number)");
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
				rohc_comp_warn(context, "lsb_7_or_31(seq_number) failed");
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
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
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
 * @param base_header    The IP header
 * @param mptr           The current pointer in the rohc-packet-under-build buffer
 * @return               The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_static_ip_part(struct rohc_comp_ctxt *const context,
                                         base_header_ip_t base_header,
                                         multi_ptr_t mptr)
{
	int size;

	assert(context != NULL);

	if(base_header.ipvx->version == IPV4)
	{
		mptr.ipv4_static->version_flag = 0;
		mptr.ipv4_static->reserved = 0;
		mptr.ipv4_static->protocol = base_header.ipv4->protocol;
		rohc_comp_debug(context, "protocol = %d", mptr.ipv4_static->protocol);
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
		rohc_comp_debug(context, "next_header = %d",
		                base_header.ipv6->next_header);
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
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
 * @param mptr           The current pointer in the rohc-packet-under-build buffer
 * @param is_innermost   True if the IP header is the innermost of the packet
 * @return               The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_dynamic_ip_part(const struct rohc_comp_ctxt *context,
                                           ip_context_ptr_t ip_context,
                                           base_header_ip_t base_header,
                                           multi_ptr_t mptr,
                                           int is_innermost)
{
	int size;

	if(base_header.ipvx->version == IPV4)
	{
		uint16_t ip_id;

		assert( ip_context.v4->version == IPV4 );

		/* Read the IP_ID */
		ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
		rohc_comp_debug(context, "ip_id_behavior = %d, last IP-ID = 0x%04x, "
		                "IP-ID = 0x%04x", ip_context.v4->ip_id_behavior,
		                ip_context.v4->last_ip_id, ip_id);

		mptr.ipv4_dynamic1->reserved = 0;
		mptr.ipv4_dynamic1->df = base_header.ipv4->df;
		// cf RFC4996 page 60/61 ip_id_behavior_choice() and ip_id_enc_dyn()
		if(is_innermost)
		{
			// All behavior values possible
			mptr.ipv4_dynamic1->ip_id_behavior = ip_context.v4->ip_id_behavior;
		}
		else
		{
			// Only IP_ID_BEHAVIOR_RAND or IP_ID_BEHAVIOR_ZERO
			if(base_header.ipv4->ip_id == 0)
			{
				mptr.ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_ZERO;
			}
			else
			{
				mptr.ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_RAND;
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
			rohc_comp_debug(context, "ip_id_behavior = %d",
			                mptr.ipv4_dynamic1->ip_id_behavior);
			size = sizeof(ipv4_dynamic1_t);
		}
		else
		{
			if(mptr.ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
			{
				mptr.ipv4_dynamic2->ip_id = swab16(base_header.ipv4->ip_id);
			}
			else
			{
				mptr.ipv4_dynamic2->ip_id = base_header.ipv4->ip_id;
			}
			rohc_comp_debug(context, "ip_id_behavior = %d, IP-ID = 0x%04x",
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
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
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
 * @param rohc_data                 The current pointer in the rohc-packet-under-build buffer
 * @param ecn_used                  The indicator of ECN usage
 * @param is_innermost              True if IP header is the innermost of the packet
 * @param ttl_irregular_chain_flag  Whether he TTL/Hop Limit of an outer header changed
 * @param ip_inner_ecn              The ECN flags of the IP innermost header
 * @return                          The new pointer in the rohc-packet-under-build buffer
 */
static uint8_t * tcp_code_irregular_ip_part(struct rohc_comp_ctxt *const context,
                                            ip_context_ptr_t ip_context,
                                            base_header_ip_t base_header,
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

	rohc_comp_debug(context, "ecn_used = %d, is_innermost = %d, "
	                "ttl_irregular_chain_flag = %d, ip_inner_ecn = %d",
	                ecn_used,is_innermost, ttl_irregular_chain_flag,
	                ip_inner_ecn);
	rohc_comp_debug(context, "IP version = %d, ip_id_behavior = %d",
	                base_header.ipvx->version, ip_context.v4->ip_id_behavior);

	if(base_header.ipvx->version == IPV4)
	{

		// ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE )
		if(ip_context.v4->ip_id_behavior == IP_ID_BEHAVIOR_RAND)
		{
			memcpy(rohc_data, &base_header.ipv4->ip_id, sizeof(uint16_t));
			rohc_data += sizeof(uint16_t);
			rohc_comp_debug(context, "add ip_id 0x%04x",
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
				rohc_comp_debug(context, "add DSCP and ip_ecn_flags = 0x%02x",
				                rohc_data[0]);
				rohc_data++;
			}
			if(ttl_irregular_chain_flag != 0)
			{
				// ipv4_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				rohc_data[0] = base_header.ipv4->ttl_hopl;
				rohc_comp_debug(context, "add ttl_hopl = 0x%02x", rohc_data[0]);
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
				rohc_comp_debug(context, "add DSCP and ip_ecn_flags = 0x%02x",
				                rohc_data[0]);
				rohc_data++;
			}
			if(ttl_irregular_chain_flag != 0)
			{
				// ipv6_outer_with_ttl_irregular
				// ttl_hopl =:= irregular(8)
				rohc_data[0] = base_header.ipv6->ttl_hopl;
				rohc_comp_debug(context, "add ttl_hopl = 0x%02x", rohc_data[0]);
				rohc_data++;
			}
			/* else: ipv6_outer_without_ttl_irregular */
		}
		/* else: ipv6_innermost_irregular */
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "IP irregular part", rohc_data_orig,
	              rohc_data - rohc_data_orig);
#endif

	return rohc_data;
}


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
static uint8_t * tcp_code_static_tcp_part(const struct rohc_comp_ctxt *context,
                                           const tcphdr_t *tcp,
                                           multi_ptr_t mptr)
{
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "TCP header", (unsigned char *) tcp,
	              sizeof(tcphdr_t));

	mptr.tcp_static->src_port = tcp->src_port;
	rohc_comp_debug(context, "TCP source port = %d (0x%04x)",
	                rohc_ntoh16(tcp->src_port), rohc_ntoh16(tcp->src_port));

	mptr.tcp_static->dst_port = tcp->dst_port;
	rohc_comp_debug(context, "TCP destination port = %d (0x%04x)",
	                rohc_ntoh16(tcp->dst_port), rohc_ntoh16(tcp->dst_port));

	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
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
static uint8_t * tcp_code_dynamic_tcp_part(const struct rohc_comp_ctxt *context,
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
	int indicator;
	int ret;

	g_context = (struct c_generic_context *) context->specific;
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	rohc_comp_debug(context, "TCP dynamic part (minimal length = %zd)",
	                sizeof(tcp_dynamic_t));

	tcp = (tcphdr_t *) next_header;

	rohc_comp_debug(context, "TCP seq = 0x%04x, ack_seq = 0x%04x",
	                rohc_ntoh32(tcp->seq_num), rohc_ntoh32(tcp->ack_num));
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d",
	                *(uint16_t*)(((unsigned char*)tcp) + 12),
	                tcp->res_flags, tcp->data_offset, tcp->rsf_flags,
	                tcp->ecn_flags, tcp->urg_flag, tcp->ack_flag,
	                tcp->psh_flag);
	rohc_comp_debug(context, "TCP window = 0x%04x, check = 0x%x, "
	                "urg_ptr = %d", rohc_ntoh16(tcp->window),
	                rohc_ntoh16(tcp->checksum), rohc_ntoh16(tcp->urg_ptr));

	/* If urgent datas present */
	if(tcp->urg_flag != 0)
	{
		urgent_datas = ((unsigned char *) &tcp->seq_num) +
		               rohc_ntoh16(tcp->urg_ptr);
		rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
		              ROHC_TRACE_DEBUG, "TCP urgent", urgent_datas, 16);
	}

	tcp_dynamic = mptr.tcp_dynamic;
	++mptr.tcp_dynamic;
	rohc_comp_debug(context, "TCP sizeof(tcp_dynamic_t) = %zu", sizeof(tcp_dynamic_t));

	tcp_dynamic->ecn_used = tcp_context->ecn_used;
	tcp_dynamic->tcp_res_flags = tcp->res_flags;
	tcp_dynamic->tcp_ecn_flags = tcp->ecn_flags;
	tcp_dynamic->urg_flag = tcp->urg_flag;
	tcp_dynamic->ack_flag = tcp->ack_flag;
	tcp_dynamic->psh_flag = tcp->psh_flag;
	tcp_dynamic->rsf_flags = tcp->rsf_flags;

	tcp_dynamic->msn = rohc_hton16(g_context->sn);
	tcp_dynamic->seq_num = tcp->seq_num;

	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "TCP dynamic part",
	              (unsigned char *) tcp_dynamic, sizeof(tcp_dynamic_t));

	tcp_context->tcp_last_seq_num = rohc_ntoh32(tcp->seq_num);
	tcp_context->tcp_seq_num_change_count++;

	/* ack_zero flag and ACK number: always check for the ACK number value even
	 * if the ACK flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those bits
	 * will be ignored at reception */
	ret = c_zero_or_irreg32(tcp->ack_num, mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode zero_or_irreg(ack_number)");
		goto error;
	}
	tcp_dynamic->ack_zero = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "TCP ack_number %spresent",
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
		rohc_comp_warn(context, "failed to encode zero_or_irreg(urg_ptr)");
		goto error;
	}
	tcp_dynamic->urp_zero = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "TCP urg_ptr %spresent",
	                tcp_dynamic->urp_zero ? "not " : "");

	/* ack_stride */ /* TODO: comparison with new computed ack_stride? */
	ret = c_static_or_irreg16(tcp_context->ack_stride,
	                          rohc_hton16(tcp_context->ack_stride),
	                          mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(ack_stride)");
		goto error;
	}
	tcp_dynamic->ack_stride_flag = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "TCP ack_stride %spresent",
	                tcp_dynamic->ack_stride_flag ? "" : "not ");

	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "TCP dynamic part",
	              (unsigned char *) tcp_dynamic,
	              mptr.uint8 - ((unsigned char*) tcp_dynamic));

	/* doff is the size of tcp header using 32 bits */
	/* TCP header is at least 20 bytes */
	if(tcp->data_offset > 5) // TODO: put else before if
		                      // TODO: put if/else in a function
	{
		uint8_t *pBeginList;
		size_t opt_pos;
		int i;

		/* init pointer to TCP options */
		options = ( (unsigned char *) tcp ) + sizeof(tcphdr_t);
		options_length = (tcp->data_offset << 2) - sizeof(tcphdr_t);
		rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
		              ROHC_TRACE_DEBUG, "TCP options", options, options_length);

		/* Save the begin of the list */
		pBeginList = mptr.uint8++;
		/* List is empty */
		*pBeginList = 0;

		for(i = options_length, opt_pos = 0;
		    i > 0 && opt_pos < ROHC_TCP_OPTS_MAX;
		    opt_pos++)
		{
			uint8_t opt_type;
			uint8_t opt_len;
			uint8_t opt_idx;

			/* option type */
			if(i < 1)
			{
				rohc_comp_warn(context, "malformed TCP option #%zu: not enough "
				               "remaining bytes for option type", opt_pos + 1);
				goto error;
			}
			opt_type = options[0];

			/* determine the index of the TCP option */
			opt_idx = tcp_context->tmp.tcp_opts_list_indexes[opt_pos];

			/* option length */
			if(opt_type == TCP_OPT_EOL || opt_type == TCP_OPT_NOP)
			{
				opt_len = 1;
			}
			else if(i < 2)
			{
				rohc_comp_warn(context, "malformed TCP option #%zu: not enough "
				               "remaining bytes for option length", opt_pos + 1);
				goto error;
			}
			else
			{
				opt_len = options[1];
				if(opt_len < 2)
				{
					rohc_comp_warn(context, "malformed TCP option #%zu: option "
					               "should be at least 2 bytes but length field "
					               "is %u", opt_pos + 1, opt_len);
					goto error;
				}
			}

			/* save the value of the TCP option in context */
			switch(opt_type)
			{
				case TCP_OPT_EOL: // End Of List
					rohc_comp_debug(context, "TCP option EOL");
					break;
				case TCP_OPT_NOP: // No Operation
					rohc_comp_debug(context, "TCP option NOP");
					break;
				case TCP_OPT_MAXSEG: // Max Segment Size
					memcpy(&tcp_context->tcp_option_maxseg,options + 2,2);
					rohc_comp_debug(context, "TCP option MAXSEG = %d (0x%x)",
					                rohc_ntoh16(tcp_context->tcp_option_maxseg),
					                rohc_ntoh16(tcp_context->tcp_option_maxseg));
					break;
				case TCP_OPT_WINDOW: // Window
					rohc_comp_debug(context, "TCP option WINDOW = %d",
					                *(options + 2));
					tcp_context->tcp_option_window = *(options + 2);
					break;
				case TCP_OPT_SACK_PERMITTED: // see RFC2018
					rohc_comp_debug(context, "TCP option SACK PERMITTED");
					break;
				case TCP_OPT_SACK:
					rohc_comp_debug(context, "TCP option SACK Length = %d", opt_len);
					assert(opt_len >= 2);
					tcp_context->tcp_option_sack_length = opt_len - 2;
					if(tcp_context->tcp_option_sack_length > (sizeof(sack_block_t) * 4))
					{
						rohc_comp_warn(context, "malformed TCP option #%zu: SACK "
						               "option too long: %u bytes while less than "
						               "%zu bytes expected", opt_pos + 1,
						               tcp_context->tcp_option_sack_length,
						               sizeof(sack_block_t) * 4);
						goto error;
					}
					memcpy(tcp_context->tcp_option_sackblocks,options + 1,
					       tcp_context->tcp_option_sack_length);
					break;
				case TCP_OPT_TIMESTAMP:
				{
					const struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (options + 2);

					rohc_comp_debug(context, "TCP option TIMESTAMP = 0x%04x 0x%04x",
					                rohc_ntoh32(opt_ts->ts), rohc_ntoh32(opt_ts->ts_reply));

					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;
					tcp_context->tcp_option_timestamp_init = true;
					c_add_wlsb(tcp_context->opt_ts_req_wlsb, g_context->sn,
					           rohc_ntoh32(opt_ts->ts));
					c_add_wlsb(tcp_context->opt_ts_reply_wlsb, g_context->sn,
					           rohc_ntoh32(opt_ts->ts_reply));
					break;
				}
				default:
				{
					/* TODO: check max length */
					// Save length
					assert(opt_len >= 2);
					tcp_context->tcp_options_list[opt_idx].value[0] = opt_len - 2;
					// Save value
					memcpy(tcp_context->tcp_options_list[opt_idx].value + 1, options + 2,
					       tcp_context->tcp_options_list[opt_idx].value[0]);
					break;
				}
			}
			tcp_context->tcp_options_list[opt_idx].nr_trans++;

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
					i -= opt_len;
					options += opt_len;
					break;
				case TCP_OPT_TIMESTAMP:
					i -= TCP_OLEN_TIMESTAMP;
					options += TCP_OLEN_TIMESTAMP;
					// TCP_OLEN_TSTAMP_APPA    (TCP_OLEN_TIMESTAMP+2) /* appendix A */
					break;
				/*
				case TCP_OPT_TSTAMP_HDR:
					rohc_comp_debug(context, "TCP option TIMESTAMP HDR");
					i = 0;
					break;
				*/
				default:
					rohc_comp_debug(context, "TCP option unknown = 0x%x", *options);
					i -= opt_len;
					options += opt_len;
					break;
			}

			/* TODO: do not include item if value is unchanged for more
			 * than N packets */
			if(tcp_context->tmp.tcp_opts_idx_max <= 7)
			{
				/* use 4-bit XI fields */
				assert(opt_idx <= 7);
				if((*pBeginList) & 1) /* number is odd */
				{
					*mptr.uint8 |= 0x08 | opt_idx;
					rohc_comp_debug(context, "  add 4-bit  odd XI field 0x%x",
					                (*mptr.uint8) & 0xf);
					mptr.uint8++;
				}
				else
				{
					*mptr.uint8 = (0x08 | opt_idx) << 4;
					rohc_comp_debug(context, "  add 4-bit even XI field 0x%x",
					                ((*mptr.uint8) >> 4) & 0xf);
				}
			}
			else
			{
				/* 8-bit XI field */
				assert(tcp_context->tmp.tcp_opts_idx_max <= MAX_TCP_OPTION_INDEX);
				assert(opt_idx <= MAX_TCP_OPTION_INDEX);
				*mptr.uint8 = 0x80 | opt_idx;
				rohc_comp_debug(context, "  add 8-bit XI field 0x%02x",
				                *mptr.uint8);
				mptr.uint8++;
			}
			// One item more
			++(*pBeginList);
		}
		if(opt_pos >= ROHC_TCP_OPTS_MAX && i != 0)
		{
			rohc_comp_warn(context, "unexpected TCP header: too many TCP "
			               "options: %zu options found in packet but only %u "
			               "options possible", opt_pos, ROHC_TCP_OPTS_MAX);
			goto error;
		}

		if(tcp_context->tmp.tcp_opts_idx_max <= 7)
		{
			/* 4-bit XI field */
			if((*pBeginList) & 1) /* number of items is odd */
			{
				/* update pointer (padding) */
				++mptr.uint8;
			}
		}
		else
		{
			/* 8-bit XI field */
			*pBeginList |= 0x10;
		}
		rohc_comp_debug(context, "TCP %d item(s) in list", (*pBeginList) & 0x0f);

		/* encode items */
		rohc_comp_debug(context, "list items:");
		options = ( (unsigned char *) tcp ) + sizeof(tcphdr_t);
		options_length = (tcp->data_offset << 2) - sizeof(tcphdr_t);
		for(i = options_length; i > 0; )
		{
			uint8_t opt_type;
			uint8_t opt_len;

			/* option type */
			if(i < 1)
			{
				rohc_comp_warn(context, "malformed TCP options: not enough "
				               "remaining bytes for option type");
				goto error;
			}
			opt_type = options[0];

			/* option length */
			if(opt_type == TCP_OPT_EOL || opt_type == TCP_OPT_NOP)
			{
				opt_len = 1;
			}
			else if(i < 2)
			{
				rohc_comp_warn(context, "malformed TCP options: not enough "
				               "remaining bytes for option length");
				goto error;
			}
			else
			{
				opt_len = options[1];
				if(opt_len < 2)
				{
					rohc_comp_warn(context, "malformed TCP options: option should "
					               "be at least 2 bytes but length field is %u",
					               opt_len);
					goto error;
				}
			}

			switch(opt_type)
			{
				case TCP_OPT_EOL:
					/* COMPRESSED eol_list_item {
					 *   pad_len =:= compressed_value(8, nbits-8) [ 8 ];
					 * }
					 */
					rohc_comp_debug(context, "  item EOL: %d padding bytes", i - 1);
					*(mptr.uint8) = i - 1;
					mptr.uint8++;
					/* skip option */
					i = 0;
					options++;
					break;
				case TCP_OPT_NOP:
					/* COMPRESSED nop_list_item {
					 * }
					 */
					rohc_comp_debug(context, "  item NOP: empty");
					/* skip option */
					--i;
					++options;
					break;
				case TCP_OPT_MAXSEG:
					/* COMPRESSED mss_list_item {
					 *   mss =:= irregular(16) [ 16 ];
					 * }
					 */
					rohc_comp_debug(context, "  item MSS");
					memcpy(mptr.uint8, options + 2, sizeof(uint16_t));
					mptr.uint8 += sizeof(uint16_t);
					/* skip option */
					i -= TCP_OLEN_MAXSEG;
					options += TCP_OLEN_MAXSEG;
					break;
				case TCP_OPT_WINDOW:
					/* COMPRESSED wscale_list_item {
					 *   wscale =:= irregular(8) [ 8 ];
					 * }
					 */
					rohc_comp_debug(context, "  item WSCALE");
					*(mptr.uint8) = options[2];
					mptr.uint8++;
					/* skip option */
					i -= TCP_OLEN_WINDOW;
					options += TCP_OLEN_WINDOW;
					break;
				case TCP_OPT_TIMESTAMP:
					/* COMPRESSED tsopt_list_item {
					 *   tsval  =:= irregular(32) [ 32 ];
					 *   tsecho =:= irregular(32) [ 32 ];
					 * }
					 */
					rohc_comp_debug(context, "  item Timestamp");
					memcpy(mptr.uint8, options + 2, sizeof(uint32_t) * 2);
					mptr.uint8 += sizeof(uint32_t) * 2;
					/* skip option */
					i -= TCP_OLEN_TIMESTAMP;
					options += TCP_OLEN_TIMESTAMP;
					break;
				case TCP_OPT_SACK:
					rohc_comp_debug(context, "  item SACK");
					mptr.uint8 = c_tcp_opt_sack(context, mptr.uint8,
					                            rohc_ntoh32(tcp->ack_num), opt_len,
					                            (sack_block_t *) (options + 2));
					/* skip option */
					i -= opt_len;
					options += opt_len;
					break;
				case TCP_OPT_SACK_PERMITTED:
					/* COMPRESSED sack_permitted_list_item {
					 * }
					 */
					rohc_comp_debug(context, "  item SACK permitted: empty");
					/* skip option */
					i -= TCP_OLEN_SACK_PERMITTED;
					options += TCP_OLEN_SACK_PERMITTED;
					break;
				default:
					rohc_comp_debug(context, "  item option 0x%x", opt_type);
					/* COMPRESSED generic_list_item {
					 *   type          =:= irregular(8)      [ 8 ];
					 *   option_static =:= one_bit_choice    [ 1 ];
					 *   length_lsb    =:= irregular(7)      [ 7 ];
					 *   contents      =:=
					 *     irregular(length_lsb.UVALUE*8-16) [ length_lsb.UVALUE*8-16 ];
					 * }
					 */
					memcpy(mptr.uint8, options, opt_len);
					mptr.uint8[1] &= 0x7f; /* option_static = 0 */
					mptr.uint8 += opt_len;
					/* skip option */
					i -= opt_len;
					options += opt_len;
					break;
			}
		}
	}
	else
	{
		rohc_comp_debug(context, "TCP no options!");
		// See RFC4996, 6.3.3 : no XI items
		// PS=0 m=0
		*(mptr.uint8++) = 0;
	}

	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
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
 * @return              The new pointer in the rohc-packet-under-build buffer,
 *                      NULL in case of problem
 */
static uint8_t * tcp_code_irregular_tcp_part(struct rohc_comp_ctxt *const context,
                                             tcphdr_t *tcp,
                                             uint8_t *const rohc_data,
                                             int ip_inner_ecn)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	uint8_t *remain_data = rohc_data;
	bool is_ok;

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
		rohc_comp_debug(context, "add TCP ecn_flags res_flags = 0x%02x",
		                remain_data[0]);
		remain_data++;
	}

	// checksum =:= irregular(16)
	memcpy(remain_data, &tcp->checksum, sizeof(uint16_t));
	remain_data += sizeof(uint16_t);
	rohc_comp_debug(context, "add TCP checksum = 0x%04x",
	                rohc_ntoh16(tcp->checksum));

	/* irregular parts for TCP options */
	{
		uint8_t *opts;
		size_t opts_len;
		size_t opt_len;
		size_t opts_offset;
		size_t opt_idx;

		rohc_comp_debug(context, "irregular chain: encode irregular content "
		                "for all TCP options");

		opts = ((uint8_t *) tcp) + sizeof(tcphdr_t);
		opts_len = (tcp->data_offset << 2) - sizeof(tcphdr_t);

		for(opt_idx = 0, opts_offset = 0;
		    opt_idx < ROHC_TCP_OPTS_MAX && opts_offset < opts_len;
		    opt_idx++, opts_offset += opt_len)
		{
			const uint8_t opt_type = opts[opts_offset];

			/* put option in irregular chain or not? */
			if(tcp_context->tmp.is_tcp_opts_list_item_present[opt_idx])
			{
				rohc_comp_debug(context, "irregular chain: do not encode irregular "
				                "content for TCP option %u because it is already "
				                "transmitted in the compressed list of TCP options",
				                opt_type);
			}
			else
			{
				rohc_comp_debug(context, "irregular chain: encode irregular content "
				                "for TCP option %u", opt_type);
			}

			if(opt_type == TCP_OPT_EOL || opt_type == TCP_OPT_NOP)
			{
				/* EOL or NOP: nothing in irregular chain */
				opt_len = 1;
			}
			else
			{
				assert((opts_offset + 1) < opts_len); /* length already checked */
				opt_len = opts[opts_offset + 1];
				assert((opts_offset + opt_len) <= opts_len);

				/* don't put this option in the irregular chain in already present
				 * in dynamic chain */
				if(tcp_context->tmp.is_tcp_opts_list_item_present[opt_idx])
				{
					continue;
				}

				if(opt_type == TCP_OPT_TIMESTAMP)
				{
					const struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (opts + opts_offset + 2);

					/* encode TS with ts_lsb() */
					is_ok = c_ts_lsb(context, &remain_data,
					                 rohc_ntoh32(opt_ts->ts),
					                 tcp_context->tmp.nr_opt_ts_req_bits_minus_1,
					                 tcp_context->tmp.nr_opt_ts_req_bits_0x40000);
					if(!is_ok)
					{
						rohc_comp_warn(context, "irregular chain: failed to encode "
						               "echo request of TCP Timestamp option");
						goto error;
					}

					/* encode TS reply with ts_lsb()*/
					is_ok = c_ts_lsb(context, &remain_data,
					                 rohc_ntoh32(opt_ts->ts_reply),
					                 tcp_context->tmp.nr_opt_ts_reply_bits_minus_1,
					                 tcp_context->tmp.nr_opt_ts_reply_bits_0x40000);
					if(!is_ok)
					{
						rohc_comp_warn(context, "irregular chain: failed to encode "
						               "echo reply of TCP Timestamp option");
						goto error;
					}

					tcp_context->tcp_option_timestamp_init = true;
					c_add_wlsb(tcp_context->opt_ts_req_wlsb, g_context->sn,
					           rohc_ntoh32(opt_ts->ts));
					c_add_wlsb(tcp_context->opt_ts_reply_wlsb, g_context->sn,
					           rohc_ntoh32(opt_ts->ts_reply));
				}
				else if(opt_type == TCP_OPT_SACK)
				{
					const sack_block_t *const sack_block =
						(sack_block_t *) (opts + opts_offset + 2);

					remain_data = c_tcp_opt_sack(context, remain_data,
					                             rohc_ntoh32(tcp->ack_num),
					                             opt_len, sack_block);
				}
			}
		}
		assert(opt_idx <= ROHC_TCP_OPTS_MAX);
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "TCP irregular part", rohc_data,
	              remain_data - rohc_data);
#endif

	return remain_data;

error:
	return NULL;
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
static bool c_ts_lsb(const struct rohc_comp_ctxt *const context,
                     uint8_t **dest,
                     const uint32_t timestamp,
                     const size_t nr_bits_minus_1,
                     const size_t nr_bits_0x40000)
{
	uint8_t *ptr = *dest;

	assert(context != NULL);
	assert(ptr != NULL);

	if(nr_bits_minus_1 <= 7)
	{
		/* discriminator '0' */
		ptr[0] = timestamp & 0x7F;
		rohc_comp_debug(context, "encode timestamp = 0x%04x on 1 byte: 0x%02x",
		                timestamp, ptr[0]);
		ptr++;
	}
	else if(nr_bits_minus_1 <= 14)
	{
		/* discriminator '10' */
		ptr[0] = 0x80 | ((timestamp >> 8) & 0x3F);
		ptr[1] = timestamp;
		rohc_comp_debug(context, "encode timestamp = 0x%04x on 2 bytes: 0x%02x "
		                "0x%02x", timestamp, ptr[0], ptr[1]);
		ptr += 2;
	}
	else if(nr_bits_0x40000 <= 21)
	{
		/* discriminator '110' */
		ptr[0] = 0xC0 | ((timestamp >> 16) & 0x1F);
		ptr[1] = timestamp >> 8;
		ptr[2] = timestamp;
		rohc_comp_debug(context, "encode timestamp = 0x%04x on 3 bytes: 0x%02x "
		                "0x%02x 0x%02x", timestamp, ptr[0], ptr[1], ptr[2]);
		ptr += 3;
	}
	else if(nr_bits_0x40000 <= 29)
	{
		/* discriminator '111' */
		ptr[0] = 0xE0 | ((timestamp >> 24) & 0x1F);
		ptr[1] = timestamp >> 16;
		ptr[2] = timestamp >> 8;
		ptr[3] = timestamp;
		rohc_comp_debug(context, "encode timestamp = 0x%04x on 4 bytes: 0x%02x "
		                "0x%02x 0x%02x 0x%02x", timestamp, ptr[0], ptr[1],
		                ptr[2], ptr[3]);
		ptr += 4;
	}
	else
	{
		rohc_comp_warn(context, "failed to compress timestamp 0x%08x: more "
		               "than 29 bits required", timestamp);
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
static uint8_t * c_sack_pure_lsb(const struct rohc_comp_ctxt *const context,
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
	                "bytes (discriminator included)", sack_field, field,
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
static uint8_t * c_sack_block(const struct rohc_comp_ctxt *const context,
                              uint8_t *ptr,
                              uint32_t reference,
                              const sack_block_t *const sack_block)
{
	assert(context != NULL);

	rohc_comp_debug(context, "reference = 0x%x, block_start = 0x%x, block_end "
	                "= 0x%x", reference, rohc_ntoh32(sack_block->block_start),
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
static uint8_t * c_tcp_opt_sack(const struct rohc_comp_ctxt *const context,
                                uint8_t *ptr,
                                uint32_t ack_value,
                                uint8_t length,
                                const sack_block_t *const sack_block)
{
	const sack_block_t *block;
	int i;

	assert(context != NULL);

	rohc_comp_debug(context, "TCP option SACK (reference ACK = 0x%08x)", ack_value);
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "TCP option SACK",
	              (unsigned char *) sack_block, length - 2);

	// Calculate number of sack_block
	i = (length - 2) >> 3;
	*(ptr++) = i;

	// Compress each sack_block
	block = sack_block;
	while(i-- != 0)
	{
		rohc_comp_debug(context, "block of SACK option: start = 0x%08x, "
		                "end = 0x%08x", rohc_ntoh32(block->block_start),
		                rohc_ntoh32(block->block_end));
		ptr = c_sack_block(context, ptr, ack_value, block);
		block++;
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
static uint8_t * c_tcp_opt_generic(struct sc_tcp_context *tcp_context __attribute__((unused)),
                                   uint8_t *ptr,
                                   uint8_t *options __attribute__((unused)))
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
static bool tcp_compress_tcp_options(struct rohc_comp_ctxt *const context,
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
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "TCP options", options, options_length);

	/* number and type of XI fields: will be set after list processing */
	*comp_opts_len = 0;
	comp_opts[*comp_opts_len] = 0;
	(*comp_opts_len)++;

	ptr_compressed_options = compressed_options;

	// see RFC4996 page 25-26
	for(m = 0, i = options_length; m < ROHC_TCP_OPTS_MAX && i > 0; m++)
	{
		bool item_needed;
		uint8_t opt_type;
		uint8_t opt_len;
		uint8_t opt_idx;

		/* option type */
		if(i < 1)
		{
			rohc_comp_warn(context, "malformed TCP option #%u: not enough "
			               "remaining bytes for option type", m + 1);
			goto error;
		}
		opt_type = options[0];

		/* determine the index of the TCP option */
		opt_idx = tcp_context->tmp.tcp_opts_list_indexes[m];

		/* option length */
		if(opt_type == TCP_OPT_EOL || opt_type == TCP_OPT_NOP)
		{
			opt_len = 1;
		}
		else if(i < 2)
		{
			rohc_comp_warn(context, "malformed TCP option #%u: not enough "
			               "remaining bytes for option length", m + 1);
			goto error;
		}
		else
		{
			opt_len = options[1];
			if(opt_len < 2)
			{
				rohc_comp_warn(context, "malformed TCP option #%u: option should "
				               "be at least 2 bytes but length field is %u",
				               m + 1, opt_len);
				goto error;
			}
		}
		rohc_comp_debug(context, "TCP options list: compress option '%s' (%u)",
		                tcp_opt_get_descr(opt_type), opt_type);

		// If option already used
		if(tcp_context->tcp_options_list[opt_idx].type == opt_type &&
		   tcp_context->tcp_options_list[opt_idx].nr_trans > 0)
		{
			rohc_comp_debug(context, "TCP options list: option '%s' (%u) was "
			                "already used with index %u in previous packets",
			                tcp_opt_get_descr(opt_type), opt_type, opt_idx);

			// Verify if used with same value
			switch(opt_idx)
			{
				case TCP_INDEX_NOP: // No Operation
					--i;
					++options;
					item_needed = false;
					break;
				case TCP_INDEX_EOL: // End Of List
					i = 0;
					item_needed = false;
					break;
				case TCP_INDEX_MAXSEG: // Max Segment Size
					                    // If same value that in the context
					if(memcmp(&tcp_context->tcp_option_maxseg,options + 2,2) == 0)
					{
						i -= TCP_OLEN_MAXSEG;
						options += TCP_OLEN_MAXSEG;
						item_needed = false;
					}
					else
					{
						item_needed = true;
					}
					break;
				case TCP_INDEX_WINDOW: // Window
					                    // If same value that in the context
					if(tcp_context->tcp_option_window == *(options + 2) )
					{
						i -= TCP_OLEN_WINDOW;
						options += TCP_OLEN_WINDOW;
						item_needed = false;
					}
					else
					{
						item_needed = true;
					}
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
						i -= TCP_OLEN_TIMESTAMP;
						options += TCP_OLEN_TIMESTAMP;
						item_needed = false;
					}
					else
					{
						item_needed = true;
					}
					break;
				}
				case TCP_INDEX_SACK_PERMITTED: // see RFC2018
					i -= TCP_OLEN_SACK_PERMITTED;
					options += TCP_OLEN_SACK_PERMITTED;
					item_needed = false;
					break;
				case TCP_INDEX_SACK: // see RFC2018
					if(tcp_context->tcp_option_sack_length == *(options + 1) &&
					   memcmp(tcp_context->tcp_option_sackblocks,options + 2,*(options + 1)) == 0)
					{
						i -= *(options + 1);
						options += *(options + 1);
						item_needed = false;
					}
					else
					{
						item_needed = true;
					}
					break;
				default:
				{
					// If same length/value
					if((tcp_context->tcp_options_list[opt_idx].value[0] + 2) == opt_len &&
					   memcmp(tcp_context->tcp_options_list[opt_idx].value + 1, options + 2,
					          tcp_context->tcp_options_list[opt_idx].value[0]) == 0)
					{
						item_needed = false;
					}
					else
					{
						item_needed = true;
					}
					break;
				}
			}
		}
		else
		{
			rohc_comp_debug(context, "TCP options list: option '%s' (%u) was "
			                "never used with index %u in previous packets",
			                tcp_opt_get_descr(opt_type), opt_type, opt_idx);

			// Some TCP option are compressed without item
			switch(opt_idx)
			{
				case TCP_INDEX_NOP: // No Operation
					--i;
					++options;
					item_needed = false;
					break;
				case TCP_INDEX_EOL: // End Of List
					i = 0;
					item_needed = false;
					break;
				case TCP_INDEX_SACK_PERMITTED: // see RFC2018
					i -= TCP_OLEN_SACK_PERMITTED;
					options += TCP_OLEN_SACK_PERMITTED;
					item_needed = false;
					break;
				case TCP_INDEX_MAXSEG: // Max Segment Size
				case TCP_INDEX_WINDOW:
				case TCP_INDEX_TIMESTAMP:
				case TCP_INDEX_SACK:
				default:
				{
					item_needed = true;
					// Save length
					assert(opt_type >= 2);
					tcp_context->tcp_options_list[opt_idx].value[0] = opt_type - 2;
					// Save value
					memcpy(tcp_context->tcp_options_list[opt_idx].value + 1, options + 2,
					       tcp_context->tcp_options_list[opt_idx].value[0]);
					break;
				}
			}
		}
		tcp_context->tcp_options_list[opt_idx].nr_trans++;

		/* write index */
		if(tcp_context->tmp.tcp_opts_idx_max <= 7)
		{
			/* use 4-bit XI fields */
			assert(opt_idx <= 7);
			rohc_comp_debug(context, "TCP options list: 4-bit XI field #%u: "
			                "item with index %u is present", m, opt_idx);
			if(m & 1)
			{
				comp_opts[*comp_opts_len] |= opt_idx;
				if(item_needed)
				{
					comp_opts[*comp_opts_len] |= 0x08;
				}
				(*comp_opts_len)++;
			}
			else
			{
				comp_opts[(*comp_opts_len)] = opt_idx << 4;
				if(item_needed)
				{
					comp_opts[(*comp_opts_len)] |= 0x08 << 4;
				}
			}
		}
		else
		{
			/* use 8-bit XI fields */
			assert(tcp_context->tmp.tcp_opts_idx_max <= MAX_TCP_OPTION_INDEX);
			assert(opt_idx <= MAX_TCP_OPTION_INDEX);
			rohc_comp_debug(context, "TCP options list: 8-bit XI field #%u: "
			                "item with index %u is present", m, opt_idx);
			comp_opts[(*comp_opts_len)] = opt_idx;
			if(item_needed)
			{
				comp_opts[(*comp_opts_len)] |= 0x80;
			}
			(*comp_opts_len)++;
		}

		if(item_needed)
		{
			size_t comp_opt_len = 0;

			switch(opt_type)
			{
				case TCP_OPT_MAXSEG: // Max Segment Size
					// see RFC4996 page 64
					options += 2;
					*(ptr_compressed_options++) = *(options++);
					comp_opt_len++;
					*(ptr_compressed_options++) = *(options++);
					comp_opt_len++;
					i -= TCP_OLEN_MAXSEG;
					tcp_context->tmp.is_tcp_opts_list_item_present[m] = true;
					break;
				case TCP_OPT_WINDOW: // Window
					// see RFC4996 page 65
					options += 2;
					*(ptr_compressed_options++) = *(options++);
					comp_opt_len++;
					i -= TCP_OLEN_WINDOW;
					tcp_context->tmp.is_tcp_opts_list_item_present[m] = true;
					break;
				case TCP_OPT_SACK: // see RFC2018
				{
					uint8_t *const opt_start = ptr_compressed_options;
					// see RFC4996 page 67
					ptr_compressed_options =
					   c_tcp_opt_sack(context, ptr_compressed_options,
					                  rohc_ntoh32(tcp->ack_num), opt_len,
					                  (sack_block_t *) (options + 2));
					comp_opt_len += ptr_compressed_options - opt_start;
					i -= opt_len;
					options += opt_len;
					tcp_context->tmp.is_tcp_opts_list_item_present[m] = true;
					break;
				}
				case TCP_OPT_TIMESTAMP:
				{
					const struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (options + 2);
					uint8_t *opt_start;

					rohc_comp_debug(context, "TCP option TIMESTAMP = 0x%04x 0x%04x",
					                rohc_ntoh32(opt_ts->ts), rohc_ntoh32(opt_ts->ts_reply));

					// see RFC4996 page65
					opt_start = ptr_compressed_options;
					is_ok = c_ts_lsb(context, &ptr_compressed_options,
					                 rohc_ntoh32(opt_ts->ts),
					                 tcp_context->tmp.nr_opt_ts_req_bits_minus_1,
					                 tcp_context->tmp.nr_opt_ts_req_bits_0x40000);
					if(!is_ok)
					{
						rohc_comp_warn(context, "failed to encode echo request of "
						               "TCP Timestamp option");
						goto error;
					}
					comp_opt_len += ptr_compressed_options - opt_start;

					opt_start = ptr_compressed_options;
					is_ok = c_ts_lsb(context, &ptr_compressed_options,
					                 rohc_ntoh32(opt_ts->ts_reply),
					                 tcp_context->tmp.nr_opt_ts_reply_bits_minus_1,
					                 tcp_context->tmp.nr_opt_ts_reply_bits_0x40000);
					if(!is_ok)
					{
						rohc_comp_warn(context, "failed to encode echo reply of "
						               "TCP Timestamp option");
						goto error;
					}
					comp_opt_len += ptr_compressed_options - opt_start;

					/* save value after compression */
					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;
					c_add_wlsb(tcp_context->opt_ts_req_wlsb, g_context->sn,
					           rohc_ntoh32(opt_ts->ts));
					c_add_wlsb(tcp_context->opt_ts_reply_wlsb, g_context->sn,
					           rohc_ntoh32(opt_ts->ts_reply));

					i -= TCP_OLEN_TIMESTAMP;
					options += TCP_OLEN_TIMESTAMP;
					tcp_context->tmp.is_tcp_opts_list_item_present[m] = true;
					break;
				}
				default:
				{
					uint8_t *const opt_start = ptr_compressed_options;
					// see RFC4996 page 69
					ptr_compressed_options =
						c_tcp_opt_generic(tcp_context, ptr_compressed_options, options);
					comp_opt_len += ptr_compressed_options - opt_start;
					i -= opt_len;
					options += opt_len;
					tcp_context->tmp.is_tcp_opts_list_item_present[m] = true;
					break;
				}
			}
			rohc_comp_debug(context, "TCP options list: option '%s' (%u) added "
			                "%zu bytes of item", tcp_opt_get_descr(opt_type),
			                opt_type, comp_opt_len);
		}
	}
	if(m >= ROHC_TCP_OPTS_MAX && i != 0)
	{
		rohc_comp_warn(context, "compressed list of TCP options: too many "
		               "options");
		goto error;
	}

	/* set the number of XI fields in the 1st byte */
	comp_opts[0] |= m & 0x0f;

	/* add padding if odd number 4-bit XI fields */
	if(tcp_context->tmp.tcp_opts_idx_max <= 7)
	{
		/* 4-bit XI field: add padding if odd number of items */
		(*comp_opts_len) += m & 1;
	}
	else
	{
		/* 8-bit XI field: set the length of XI fields to 8 bits */
		comp_opts[0] |= 0x10;
	}

	// If compressed value present
	if(ptr_compressed_options > compressed_options)
	{
		// Add them
		memcpy(comp_opts + (*comp_opts_len), compressed_options,
				 ptr_compressed_options - compressed_options);
		(*comp_opts_len) += (ptr_compressed_options - compressed_options);
	}

	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
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
 * @param packet_type       The type of ROHC packet to create
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *ip,
                          const int packet_size __attribute__((unused)),
                          const unsigned char *next_header __attribute__((unused)),
                          unsigned char *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_tcp_context *tcp_context;
	ip_context_ptr_t ip_inner_context;
	ip_context_ptr_t ip_context;
	base_header_ip_t base_header_inner;
	base_header_ip_t base_header;
	tcphdr_t *tcp;
	size_t remain_data_len;
	int counter;
	size_t first_position;
	multi_ptr_t mptr;
	uint8_t save_first_byte;
	size_t payload_size;
	int ip_inner_ecn;
#if ROHC_EXTRA_DEBUG == 1
	uint8_t *puchar;
#endif
	uint8_t protocol;
	uint8_t crc_computed;
	int i;
	int ret;

	assert(context != NULL);
	assert(context->specific != NULL);

	g_context = (struct c_generic_context *) context->specific;
	tcp_context = (struct sc_tcp_context *) g_context->specific;

	rohc_comp_debug(context, "code CO packet (CID = %zu)", context->cid);

	rohc_comp_debug(context, "parse the %zu-byte IP packet", ip->size);
	base_header.ipvx = (base_header_ip_vx_t *) ip->data;
	remain_data_len = ip->size;
	ip_context.uint8 = tcp_context->ip_context;
	do
	{
		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

		base_header_inner.ipvx = base_header.ipvx;
		ip_inner_context.uint8 = ip_context.uint8;

		switch(base_header.ipvx->version)
		{
			case IPV4:
			{
				size_t ipv4_hdr_len;
				if(remain_data_len < sizeof(base_header_ip_v4_t))
				{
					return -1;
				}
				ipv4_hdr_len = base_header.ipv4->header_length * sizeof(uint32_t);
				if(remain_data_len < ipv4_hdr_len)
				{
					return -1;
				}
				/* get the transport protocol */
				protocol = base_header.ipv4->protocol;
				ip_inner_ecn = base_header.ipv4->ip_ecn_flags;
				payload_size = rohc_ntoh16(base_header.ipv4->length) - ipv4_hdr_len;

				/* skip IPv4 header */
				rohc_comp_debug(context, "skip %zu-byte IPv4 header with "
				                "Protocol 0x%02x", ipv4_hdr_len, protocol);
				remain_data_len -= ipv4_hdr_len;
				base_header.uint8 += ipv4_hdr_len;
				++ip_context.v4;
				break;
			}
			case IPV6:
				if(remain_data_len < sizeof(base_header_ip_v6_t) )
				{
					return -1;
				}
				/* get the transport protocol */
				protocol = base_header.ipv6->next_header;
				ip_inner_ecn = base_header.ipv6->ip_ecn_flags;
				payload_size = rohc_ntoh16(base_header.ipv6->payload_length);

				/* skip IPv6 header */
				rohc_comp_debug(context, "skip %zd-byte IPv6 header with Next "
				                "Header 0x%02x", sizeof(base_header_ip_v6_t),
				                protocol);
				remain_data_len -= sizeof(base_header_ip_v6_t);
				++base_header.ipv6;
				++ip_context.v6;

				/* parse IPv6 extension headers */
				while(rohc_is_ipv6_opt(protocol))
				{
					rohc_comp_debug(context, "skip %d-byte IPv6 extension header "
					                "with Next Header 0x%02x",
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

	if(remain_data_len < sizeof(tcphdr_t) )
	{
		rohc_comp_debug(context, "insufficient size for TCP header");
		return -1;
	}
	tcp = base_header.tcphdr;
	{
		const size_t tcp_data_offset = tcp->data_offset << 2;

		assert(payload_size >= tcp_data_offset);
		payload_size -= tcp_data_offset;

		assert(((uint8_t *) tcp) >= ip->data);
		*payload_offset = ((uint8_t *) tcp) + tcp_data_offset - ip->data;
		rohc_comp_debug(context, "payload offset = %zu", *payload_offset);
		rohc_comp_debug(context, "payload size = %zu", payload_size);
	}

	/* we have just identified the IP and TCP headers (options included), so
	 * let's compute the CRC on uncompressed headers */
	if(packet_type == ROHC_PACKET_TCP_SEQ_8 ||
	   packet_type == ROHC_PACKET_TCP_RND_8 ||
	   packet_type == ROHC_PACKET_TCP_CO_COMMON)
	{
		crc_computed = crc_calculate(ROHC_CRC_TYPE_7, ip->data, *payload_offset,
		                             CRC_INIT_7, context->compressor->crc_table_7);
		rohc_comp_debug(context, "CRC-7 on %zu-byte uncompressed header = 0x%x",
		                *payload_offset, crc_computed);
	}
	else
	{
		crc_computed = crc_calculate(ROHC_CRC_TYPE_3, ip->data, *payload_offset,
		                             CRC_INIT_3, context->compressor->crc_table_3);
		rohc_comp_debug(context, "CRC-3 on %zu-byte uncompressed header = 0x%x",
		                *payload_offset, crc_computed);
	}

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

	/* part 4: dynamic part of outer and inner IP header and dynamic part
	 * of next header */
#if ROHC_EXTRA_DEBUG == 1
	puchar = &rohc_pkt[counter];
	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
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
	                  packet_type, tcp, crc_computed);
	if(i < 0)
	{
		rohc_comp_warn(context, "failed to build co_baseheader");
		goto error;
	}

	// Now add irregular chain

	mptr.uint8 = &rohc_pkt[counter - 1] + i;

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *)ip->data;
	ip_context.uint8 = tcp_context->ip_context;

	do
	{

		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

		mptr.uint8 = tcp_code_irregular_ip_part(context, ip_context,
		                                        base_header, mptr.uint8,
		                                        tcp_context->ecn_used,
		                                        base_header.ipvx == base_header_inner.ipvx ? 1 : 0, // int is_innermost,
		                                        tcp_context->tmp.ttl_irregular_chain_flag,
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
					                                       base_header);
					if(mptr.uint8 == NULL)
					{
						rohc_comp_warn(context, "failed to encode the IPv6 "
						               "extension part of the irregular chain");
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

	/* TCP part (base header + options) of the irregular chain */
	mptr.uint8 = tcp_code_irregular_tcp_part(context, tcp, mptr.uint8,
	                                         ip_inner_ecn);
	if(mptr.uint8 == NULL)
	{
		rohc_comp_warn(context, "failed to encode the TCP part of the "
		               "irregular chain");
		goto error;
	}

	if(context->compressor->medium.cid_type != ROHC_SMALL_CID)
	{
		rohc_comp_debug(context, "counter = %d, rohc_pkt[counter-1] = 0x%02x, "
		                "save_first_byte = 0x%02x", counter,
		                rohc_pkt[counter - 1], save_first_byte);
		// Restore byte saved
		rohc_pkt[first_position] = rohc_pkt[counter - 1];
		rohc_pkt[counter - 1] = save_first_byte;
	}

	counter = mptr.uint8 - rohc_pkt;

	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
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
 * @param tcp                       The TCP header to compress
 * @param crc                       The CRC on the uncompressed headers
 * @return                          The position in the rohc-packet-under-build buffer
 *                                  -1 in case of problem
 */
static int co_baseheader(struct rohc_comp_ctxt *const context,
								 struct sc_tcp_context *const tcp_context,
								 ip_context_ptr_t ip_context,
								 base_header_ip_t base_header,
								 unsigned char *const rohc_pkt,
								 const size_t rohc_pkt_max_len __attribute__((unused)), /* TODO */
                         const rohc_packet_t packet_type,
                         const tcphdr_t *const tcp,
								 const uint8_t crc)
{
	struct c_generic_context *g_context = context->specific;
	multi_ptr_t c_base_header; // compressed
	int counter;
	multi_ptr_t mptr;
	uint8_t *puchar;
	bool is_ok;

	// Init pointer on rohc compressed buffer
	c_base_header.uint8 = rohc_pkt;
	mptr.uint8 = c_base_header.uint8;

	switch(packet_type)
	{
		case ROHC_PACKET_TCP_RND_1:
			mptr.uint8 += c_tcp_build_rnd_1(context, tcp_context, tcp, crc,
													  c_base_header.rnd1);
			break;
		case ROHC_PACKET_TCP_RND_2:
			mptr.uint8 += c_tcp_build_rnd_2(context, tcp_context, tcp, crc,
													  c_base_header.rnd2);
			break;
		case ROHC_PACKET_TCP_RND_3:
			mptr.uint8 += c_tcp_build_rnd_3(context, tcp_context, tcp, crc,
													  c_base_header.rnd3);
			break;
		case ROHC_PACKET_TCP_RND_4:
			mptr.uint8 += c_tcp_build_rnd_4(context, tcp_context, tcp, crc,
													  c_base_header.rnd4);
			break;
		case ROHC_PACKET_TCP_RND_5:
			mptr.uint8 += c_tcp_build_rnd_5(context, tcp_context, tcp, crc,
													  c_base_header.rnd5);
			break;
		case ROHC_PACKET_TCP_RND_6:
			mptr.uint8 += c_tcp_build_rnd_6(context, tcp_context, tcp, crc,
													  c_base_header.rnd6);
			break;
		case ROHC_PACKET_TCP_RND_7:
			mptr.uint8 += c_tcp_build_rnd_7(context, tcp_context, tcp, crc,
													  c_base_header.rnd7);
			break;
		case ROHC_PACKET_TCP_RND_8:
		{
			size_t rnd8_len;

			is_ok = c_tcp_build_rnd_8(context, ip_context, tcp_context,
											  base_header, tcp, crc, c_base_header.rnd8,
											  &rnd8_len);
			if(!is_ok)
			{
				rohc_comp_warn(context, "failed to build rnd_8 packet");
				goto error;
			}
			mptr.uint8 += rnd8_len;
			break;
		}
		case ROHC_PACKET_TCP_SEQ_1:
			mptr.uint8 += c_tcp_build_seq_1(context, ip_context, tcp_context,
													  base_header, tcp, crc,
													  c_base_header.seq1);
			break;
		case ROHC_PACKET_TCP_SEQ_2:
			mptr.uint8 += c_tcp_build_seq_2(context, ip_context, tcp_context,
													  base_header, tcp, crc,
													  c_base_header.seq2);
			break;
		case ROHC_PACKET_TCP_SEQ_3:
			mptr.uint8 += c_tcp_build_seq_3(context, ip_context, tcp_context,
													  base_header, tcp, crc,
													  c_base_header.seq3);
			break;
		case ROHC_PACKET_TCP_SEQ_4:
			mptr.uint8 += c_tcp_build_seq_4(context, ip_context, tcp_context,
													  base_header, tcp, crc,
													  c_base_header.seq4);
			break;
		case ROHC_PACKET_TCP_SEQ_5:
			mptr.uint8 += c_tcp_build_seq_5(context, ip_context, tcp_context,
													  base_header, tcp, crc,
													  c_base_header.seq5);
			break;
		case ROHC_PACKET_TCP_SEQ_6:
			mptr.uint8 += c_tcp_build_seq_6(context, ip_context, tcp_context,
													  base_header, tcp, crc,
													  c_base_header.seq6);
			break;
		case ROHC_PACKET_TCP_SEQ_7:
			mptr.uint8 += c_tcp_build_seq_7(context, ip_context, tcp_context,
													  base_header, tcp, crc,
													  c_base_header.seq7);
			break;
		case ROHC_PACKET_TCP_SEQ_8:
		{
			size_t seq8_len;

			is_ok = c_tcp_build_seq_8(context, ip_context, tcp_context,
											  base_header, tcp, crc, c_base_header.seq8,
											  &seq8_len);
			if(!is_ok)
			{
				rohc_comp_warn(context, "failed to build seq_8 packet");
				goto error;
			}
			mptr.uint8 += seq8_len;
			break;
		}
		case ROHC_PACKET_TCP_CO_COMMON:
		{
	size_t encoded_seq_len;
	size_t encoded_ack_len;
	int ret;
	int indicator;

	rohc_comp_debug(context, "code common packet");
	// See RFC4996 page 80:
	rohc_comp_debug(context, "ttl_irregular_chain_flag = %d",
	                tcp_context->tmp.ttl_irregular_chain_flag);
	mptr.uint8 = (uint8_t*)(c_base_header.co_common + 1);

	c_base_header.co_common->discriminator = 0x7D; // '1111101'
	c_base_header.co_common->ttl_hopl_outer_flag =
		tcp_context->tmp.ttl_irregular_chain_flag;

	rohc_comp_debug(context, "TCP ack_flag = %d, psh_flag = %d, rsf_flags = %d",
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

	/* seq_number */
	encoded_seq_len =
		variable_length_32_enc(rohc_ntoh32(tcp_context->old_tcphdr.seq_num),
		                       rohc_ntoh32(tcp->seq_num),
		                       tcp_context->tmp.nr_seq_bits_63,
		                       tcp_context->tmp.nr_seq_bits_16383,
		                       mptr.uint8, &indicator);
	c_base_header.co_common->seq_indicator = indicator;
	mptr.uint8 += encoded_seq_len;
	rohc_comp_debug(context, "encode sequence number 0x%08x on %zu bytes with "
	                "indicator %d", rohc_ntoh32(tcp->seq_num),
	                encoded_seq_len, c_base_header.co_common->seq_indicator);

	/* ack_number */
	if(tcp->ack_flag == 0 && tcp->ack_num == 0)
	{
		encoded_ack_len = 0;
		indicator = 0;
	}
	else
	{
		encoded_ack_len =
			variable_length_32_enc(rohc_ntoh32(tcp_context->old_tcphdr.ack_num),
			                       rohc_ntoh32(tcp->ack_num),
			                       tcp_context->tmp.nr_ack_bits_63,
			                       tcp_context->tmp.nr_ack_bits_16383,
			                       mptr.uint8, &indicator);
	}
	c_base_header.co_common->ack_indicator = indicator;
	mptr.uint8 += encoded_ack_len;
	rohc_comp_debug(context, "encode ACK number 0x%08x on %zu bytes with "
	                "indicator %d", rohc_ntoh32(tcp->ack_num),
	                encoded_ack_len, c_base_header.co_common->ack_indicator);

	/* ack_stride */ /* TODO: comparison with new computed ack_stride? */
	ret = c_static_or_irreg16(tcp_context->ack_stride,
	                          rohc_hton16(tcp_context->ack_stride),
	                          mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(ack_stride)");
		goto error;
	}
	c_base_header.co_common->ack_stride_indicator = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "size = %d, ack_stride_indicator = %d, "
	                "ack_stride 0x%x", (unsigned)(mptr.uint8 - puchar),
	                c_base_header.co_common->ack_stride_indicator,
	                tcp_context->ack_stride);

	/* window */
	ret = c_static_or_irreg16(tcp_context->old_tcphdr.window, tcp->window,
	                          mptr.uint8, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(window)");
		goto error;
	}
	c_base_header.co_common->window_indicator = indicator;
	mptr.uint8 += ret;
	rohc_comp_debug(context, "size = %d, window_indicator = %d, "
	                "old_window = 0x%x, window = 0x%x",
	                (unsigned)(mptr.uint8 - puchar),
	                c_base_header.co_common->window_indicator,
	                rohc_ntoh16(tcp_context->old_tcphdr.window),
	                rohc_ntoh16(tcp->window));
	if(base_header.ipvx->version == IPV4)
	{
		// =:= irregular(1) [ 1 ];
		ret = c_optional_ip_id_lsb(context, ip_context.v4->ip_id_behavior,
		                           ip_context.v4->last_ip_id,
		                           tcp_context->tmp.ip_id,
		                           g_context->sn, mptr.uint8, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode optional_ip_id_lsb(ip_id)");
			goto error;
		}
		c_base_header.co_common->ip_id_indicator = indicator;
		mptr.uint8 += ret;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		c_base_header.co_common->ip_id_behavior = ip_context.v4->ip_id_behavior;
		rohc_comp_debug(context, "size = %u, ip_id_indicator = %d, "
		                "ip_id_behavior = %d",
		                (unsigned int) (mptr.uint8 - puchar),
		                c_base_header.co_common->ip_id_indicator,
		                c_base_header.co_common->ip_id_behavior);

		/* dscp_present =:= irregular(1) [ 1 ] */
		c_base_header.co_common->dscp_present =
			dscp_encode(&mptr, ip_context.vx->dscp, base_header.ipv4->dscp);
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %u bytes",
		                c_base_header.co_common->dscp_present,
		                ip_context.vx->dscp, base_header.ipv4->dscp,
		                (unsigned int) (mptr.uint8 - puchar));
		ip_context.vx->dscp = base_header.ipv4->dscp;

		/* ttl_hopl */
		ret = c_static_or_irreg8(ip_context.vx->ttl_hopl,
		                         tcp_context->tmp.ttl_hopl, mptr.uint8,
		                         &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ttl_hopl)");
			goto error;
		}
		c_base_header.co_common->ttl_hopl_present = indicator;
		mptr.uint8 += ret;

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		c_base_header.co_common->df = base_header.ipv4->df;
		ip_context.v4->df = base_header.ipv4->df;
		rohc_comp_debug(context, "size = %u, dscp_present = %d, "
		                "ttl_hopl_present = %d",
		                (unsigned int) (mptr.uint8 - puchar),
		                c_base_header.co_common->dscp_present,
		                c_base_header.co_common->ttl_hopl_present);
	}
	else
	{
		// =:= irregular(1) [ 1 ];
		c_base_header.co_common->ip_id_indicator = 0;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		c_base_header.co_common->ip_id_behavior = IP_ID_BEHAVIOR_RAND;
		rohc_comp_debug(context, "size = %u, ip_id_indicator = %d, "
		                "ip_id_behavior = %d",
		                (unsigned int) (mptr.uint8 - puchar),
		                c_base_header.co_common->ip_id_indicator,
		                c_base_header.co_common->ip_id_behavior);

		/* dscp_present =:= irregular(1) [ 1 ] */
		c_base_header.co_common->dscp_present =
			dscp_encode(&mptr, ip_context.vx->dscp, DSCP_V6(base_header.ipv6));
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %u bytes",
		                c_base_header.co_common->dscp_present,
		                ip_context.vx->dscp, DSCP_V6(base_header.ipv6),
		                (unsigned int) (mptr.uint8 - puchar));
		ip_context.vx->dscp = DSCP_V6(base_header.ipv6);

		/* ttl_hopl */
		ret = c_static_or_irreg8(ip_context.vx->ttl_hopl,
		                         tcp_context->tmp.ttl_hopl, mptr.uint8,
		                         &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ttl_hopl)");
			goto error;
		}
		c_base_header.co_common->ttl_hopl_present = indicator;
		mptr.uint8 += ret;

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		c_base_header.co_common->df = 0;
		rohc_comp_debug(context, "size = %u, dscp_present = %d, "
		                "ttl_hopl_present %d",
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
	rohc_comp_debug(context, "ecn_used = %d", c_base_header.co_common->ecn_used);
	// =:= irregular(1) [ 1 ];
	if( (c_base_header.co_common->urg_flag = tcp->urg_flag) != 0) // TODO: check that!
	{
		/* urg_ptr */
		ret = c_static_or_irreg16(tcp_context->old_tcphdr.urg_ptr, tcp->urg_ptr,
		                          mptr.uint8, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(urg_ptr)");
			goto error;
		}
		c_base_header.co_common->urg_ptr_present = indicator;
		mptr.uint8 += ret;
		rohc_comp_debug(context, "urg_flag = %d, urg_ptr_present = %d",
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

	/* include the list of TCP options if the structure of the list changed */
	if(tcp_context->tmp.is_tcp_opts_list_struct_changed)
	{
		size_t comp_opts_len;

		/* the structure of the list of TCP options changed, compress them */
		c_base_header.co_common->list_present = 1;
		is_ok = tcp_compress_tcp_options(context, tcp, mptr.uint8, &comp_opts_len);
		if(!is_ok)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
		mptr.uint8 += comp_opts_len;
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		c_base_header.co_common->list_present = 0;
	}
	rohc_comp_debug(context, "size = %u, list_present = %d, DF = %d",
	                (unsigned int) (mptr.uint8 - puchar),
	                c_base_header.co_common->list_present,
	                c_base_header.co_common->df);
	// =:= crc7(THIS.UVALUE,THIS.ULENGTH) [ 7 ];
	c_base_header.co_common->header_crc = crc;
	rohc_comp_debug(context, "CRC = 0x%x",
	                c_base_header.co_common->header_crc);
			break;
		}
		default:
			rohc_comp_debug(context, "unexpected packet type %d", packet_type);
			assert(0);
			break;
	}

	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "compressed header",
	              c_base_header.uint8, mptr.uint8 - c_base_header.uint8);

	counter = mptr.uint8 - rohc_pkt;

	rohc_dump_buf(context->compressor->trace_callback, ROHC_TRACE_COMP,
	              ROHC_TRACE_DEBUG, "co_header", rohc_pkt, counter);

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	ip_context.v4->last_ip_id_behavior = ip_context.v4->ip_id_behavior;
	ip_context.v4->last_ip_id = tcp_context->tmp.ip_id;
	ip_context.vx->ttl_hopl = tcp_context->tmp.ttl_hopl;

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
 * @param crc           The CRC on the uncompressed headers
 * @param rnd1          IN/OUT: The rnd_1 packet to build
 * @return              The length (in bytes) of the rnd_1 packet
 */
static size_t c_tcp_build_rnd_1(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_1_t *const rnd1)
{
	struct c_generic_context *g_context;
	uint32_t seq_num;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd1 != NULL);

	rohc_comp_debug(context, "code rnd_1 packet");

	rnd1->discriminator = 0x2e; /* '101110' */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3ffff;
	rnd1->seq_num1 = (seq_num >> 16) & 0x3;
	rnd1->seq_num2 = rohc_hton16(seq_num & 0xffff);
	rnd1->msn = g_context->sn & 0xf;
	rnd1->psh_flag = tcp->psh_flag;
	rnd1->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param rnd2          IN/OUT: The rnd_2 packet to build
 * @return              The length (in bytes) of the rnd_2 packet
 */
static size_t c_tcp_build_rnd_2(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_2_t *const rnd2)
{
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd2 != NULL);

	rohc_comp_debug(context, "code rnd_2 packet");

	rnd2->discriminator = 0x0c; /* '1100' */
	rnd2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	rnd2->msn = g_context->sn & 0xf;
	rnd2->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param rnd3          IN/OUT: The rnd_3 packet to build
 * @return              The length (in bytes) of the rnd_3 packet
 */
static size_t c_tcp_build_rnd_3(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_3_t *const rnd3)
{
	struct c_generic_context *g_context;
	uint16_t ack_num;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd3 != NULL);

	rohc_comp_debug(context, "code rnd_3 packet");

	rnd3->discriminator = 0x0; /* '0' */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x7fff;
	rnd3->ack_num1 = (ack_num >> 8) & 0x7f;
	rnd3->ack_num2 = ack_num & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)",
	                ack_num, rnd3->ack_num1, rnd3->ack_num2);
	rnd3->msn = g_context->sn & 0xf;
	rnd3->psh_flag = tcp->psh_flag;
	rnd3->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param rnd4          IN/OUT: The rnd_4 packet to build
 * @return              The length (in bytes) of the rnd_4 packet
 */
static size_t c_tcp_build_rnd_4(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
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

	rohc_comp_debug(context, "code rnd_4 packet");

	rnd4->discriminator = 0x0d; /* '1101' */
	rnd4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	rnd4->msn = g_context->sn & 0xf;
	rnd4->psh_flag = tcp->psh_flag;
	rnd4->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param rnd5          IN/OUT: The rnd_5 packet to build
 * @return              The length (in bytes) of the rnd_5 packet
 */
static size_t c_tcp_build_rnd_5(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_5_t *const rnd5)
{
	struct c_generic_context *g_context;
	uint16_t seq_num;
	uint16_t ack_num;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd5 != NULL);

	rohc_comp_debug(context, "code rnd_5 packet");

	rnd5->discriminator = 0x04; /* '100' */
	rnd5->psh_flag = tcp->psh_flag;
	rnd5->msn = g_context->sn & 0xf;

	/* sequence number */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3fff;
	rnd5->seq_num1 = (seq_num >> 9) & 0x1f;
	rnd5->seq_num2 = (seq_num >> 1) & 0xff;
	rnd5->seq_num3 = seq_num & 0x01;
	rohc_comp_debug(context, "seq_number = 0x%04x (0x%02x 0x%02x 0x%02x)",
	                seq_num, rnd5->seq_num1, rnd5->seq_num2, rnd5->seq_num3);

	/* ACK number */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x7fff;
	rnd5->ack_num1 = (ack_num >> 8) & 0x7f;
	rnd5->ack_num2 = ack_num & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)",
	                ack_num, rnd5->ack_num1, rnd5->ack_num2);
	rnd5->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param rnd6          IN/OUT: The rnd_6 packet to build
 * @return              The length (in bytes) of the rnd_6 packet
 */
static size_t c_tcp_build_rnd_6(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_6_t *const rnd6)
{
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd6 != NULL);

	rohc_comp_debug(context, "code rnd_6 packet");

	rnd6->discriminator = 0x0a; /* '1010' */
	rnd6->header_crc = 0; /* for CRC computation */
	rnd6->psh_flag = tcp->psh_flag;
	rnd6->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	rnd6->msn = g_context->sn & 0xf;
	rnd6->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	rnd6->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param rnd7          IN/OUT: The rnd_7 packet to build
 * @return              The length (in bytes) of the rnd_7 packet
 */
static size_t c_tcp_build_rnd_7(struct rohc_comp_ctxt *const context,
                                struct sc_tcp_context *const tcp_context,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                rnd_7_t *const rnd7)
{
	struct c_generic_context *g_context;
	uint32_t ack_num;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd7 != NULL);

	rohc_comp_debug(context, "code rnd_7 packet");

	rnd7->discriminator = 0x2f; /* '101111' */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x3ffff;
	rnd7->ack_num1 = (ack_num >> 16) & 0x03;
	rnd7->ack_num2 = rohc_hton16(ack_num & 0xffff);
	rnd7->window = tcp->window;
	rnd7->msn = g_context->sn & 0xf;
	rnd7->psh_flag = tcp->psh_flag;
	rnd7->header_crc = 0; /* for CRC computation */
	rnd7->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param rnd8          IN/OUT: The rnd_8 packet to build
 * @param rnd8_len      OUT: The length (in bytes) of the rnd_8 packet
 * @return              true if the packet is successfully built, false otherwise
 */
static bool c_tcp_build_rnd_8(struct rohc_comp_ctxt *const context,
										const ip_context_ptr_t ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										const uint8_t crc,
										rnd_8_t *const rnd8,
										size_t *const rnd8_len)
{
	struct c_generic_context *g_context;
	uint32_t seq_num;
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

	rohc_comp_debug(context, "code rnd_8 packet");

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
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	rnd8->seq_num = rohc_hton16(seq_num);
	rohc_comp_debug(context, "16 bits of sequence number = 0x%04x", seq_num);

	/* ACK number */
	rnd8->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);

	/* include the list of TCP options if the structure of the list changed */
	if(tcp_context->tmp.is_tcp_opts_list_struct_changed)
	{
		/* the structure of the list of TCP options changed, compress them */
		rnd8->list_present = 1;
		is_ok = tcp_compress_tcp_options(context, tcp, rnd8->options,
													&comp_opts_len);
		if(!is_ok)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		rnd8->list_present = 0;
		comp_opts_len = 0;
	}

	/* CRC */
	rnd8->header_crc = crc;
	rohc_comp_debug(context, "CRC 0x%x", rnd8->header_crc);

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
 * @param crc           The CRC on the uncompressed headers
 * @param seq1          IN/OUT: The seq_1 packet to build
 * @return              The length (in bytes) of the seq_1 packet
 */
static size_t c_tcp_build_seq_1(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_1_t *const seq1)
{
	struct c_generic_context *g_context;
	uint32_t seq_num;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq1 != NULL);

	rohc_comp_debug(context, "code seq_1 packet");

	seq1->discriminator = 0x0a; /* '1010' */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq1->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 4, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	seq1->seq_num = rohc_hton16(seq_num);
	seq1->msn = g_context->sn & 0xf;
	seq1->psh_flag = tcp->psh_flag;
	seq1->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param seq2          IN/OUT: The seq_2 packet to build
 * @return              The length (in bytes) of the seq_2 packet
 */
static size_t c_tcp_build_seq_2(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
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

	rohc_comp_debug(context, "code seq_2 packet");

	seq2->discriminator = 0x1a; /* '11010' */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	ip_id_lsb = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 7, 3,
	                        ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq2->ip_id1 = (ip_id_lsb >> 4) & 0x7;
	seq2->ip_id2 = ip_id_lsb & 0x0f;
	seq2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	seq2->msn = g_context->sn & 0xf;
	seq2->psh_flag = tcp->psh_flag;
	seq2->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param seq3          IN/OUT: The seq_3 packet to build
 * @return              The length (in bytes) of the seq_3 packet
 */
static size_t c_tcp_build_seq_3(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
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

	rohc_comp_debug(context, "code seq_3 packet");

	seq3->discriminator = 0x09; /* '1001' */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq3->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 4, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq3->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq3->msn = g_context->sn & 0xf;
	seq3->psh_flag = tcp->psh_flag;
	seq3->header_crc = 0; /* for CRC computation */
	seq3->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param seq4          IN/OUT: The seq_4 packet to build
 * @return              The length (in bytes) of the seq_4 packet
 */
static size_t c_tcp_build_seq_4(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
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

	rohc_comp_debug(context, "code seq_4 packet");

	seq4->discriminator = 0x00; /* '0' */
	seq4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq4->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 3, 1,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq4->msn = g_context->sn & 0xf;
	seq4->psh_flag = tcp->psh_flag;
	seq4->header_crc = 0; /* for CRC computation */
	seq4->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param seq5          IN/OUT: The seq_5 packet to build
 * @return              The length (in bytes) of the seq_5 packet
 */
static size_t c_tcp_build_seq_5(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_5_t *const seq5)
{
	struct c_generic_context *g_context;
	uint32_t seq_num;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq5 != NULL);

	rohc_comp_debug(context, "code seq_5 packet");

	seq5->discriminator = 0x08; /* '1000' */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq5->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 4, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq5->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	seq5->seq_num = rohc_hton16(seq_num);
	seq5->msn = g_context->sn & 0xf;
	seq5->psh_flag = tcp->psh_flag;
	seq5->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param seq6          IN/OUT: The seq_6 packet to build
 * @return              The length (in bytes) of the seq_6 packet
 */
static size_t c_tcp_build_seq_6(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_6_t *const seq6)
{
	struct c_generic_context *g_context;
	uint8_t seq_num_scaled;
	uint16_t ip_id;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(ip_context.vx->version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq6 != NULL);

	rohc_comp_debug(context, "code seq_6 packet");

	seq6->discriminator = 0x1b; /* '11011' */

	/* scaled sequence number */
	seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	seq6->seq_num_scaled1 = (seq_num_scaled >> 1) & 0x07;
	seq6->seq_num_scaled2 = seq_num_scaled & 0x01;

	/* IP-ID */
	ip_id = rohc_ntoh16(ip.ipv4->ip_id);
	seq6->ip_id = c_ip_id_lsb(context, ip_context.v4->ip_id_behavior, 7, 3,
	                          ip_context.v4->last_ip_id, ip_id, g_context->sn);
	seq6->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq6->msn = g_context->sn & 0xf;
	seq6->psh_flag = tcp->psh_flag;
	seq6->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param seq7          IN/OUT: The seq_7 packet to build
 * @return              The length (in bytes) of the seq_7 packet
 */
static size_t c_tcp_build_seq_7(struct rohc_comp_ctxt *const context,
                                const ip_context_ptr_t ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
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

	rohc_comp_debug(context, "code seq_7 packet");

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
	seq7->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq7->msn = g_context->sn & 0xf;
	seq7->psh_flag = tcp->psh_flag;
	seq7->header_crc = crc;

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
 * @param crc           The CRC on the uncompressed headers
 * @param seq8          IN/OUT: The seq_8 packet to build
 * @param seq8_len      OUT: The length (in bytes) of the seq_8 packet
 * @return              true if the packet is successfully built, false otherwise
 */
static bool c_tcp_build_seq_8(struct rohc_comp_ctxt *const context,
                              const ip_context_ptr_t ip_context,
                              struct sc_tcp_context *const tcp_context,
                              const base_header_ip_t ip,
                              const tcphdr_t *const tcp,
                              const uint8_t crc,
                              seq_8_t *const seq8,
                              size_t *const seq8_len)
{
	struct c_generic_context *g_context;
	size_t comp_opts_len;
	uint16_t ack_num;
	uint16_t seq_num;
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

	rohc_comp_debug(context, "code seq_8 packet");

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
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x7fff;
	seq8->ack_num1 = (ack_num >> 8) & 0x7f;
	seq8->ack_num2 = ack_num & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)",
	                ack_num, seq8->ack_num1, seq8->ack_num2);

	seq8->rsf_flags = rsf_index_enc(context, tcp->rsf_flags);

	/* sequence number */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3fff;
	seq8->seq_num1 = (seq_num >> 8) & 0x3f;
	seq8->seq_num2 = seq_num & 0xff;
	rohc_comp_debug(context, "seq_number = 0x%04x (0x%02x 0x%02x)",
	                seq_num, seq8->seq_num1, seq8->seq_num2);

	/* include the list of TCP options if the structure of the list changed */
	if(tcp_context->tmp.is_tcp_opts_list_struct_changed)
	{
		/* the structure of the list of TCP options changed, compress them */
		seq8->list_present = 1;
		is_ok = tcp_compress_tcp_options(context, tcp, seq8->options,
													&comp_opts_len);
		if(!is_ok)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		seq8->list_present = 0;
		comp_opts_len = 0;
	}

	/* CRC */
	seq8->header_crc = crc;
	rohc_comp_debug(context, "CRC = 0x%x", seq8->header_crc);

	*seq8_len = sizeof(seq_8_t) + comp_opts_len;

	return true;

error:
	return false;
}


/**
 * @brief Detect changes between packet and context
 *
 * @param context     The compression context to compare
 * @param uncomp_pkt  The uncompressed packet to compare
 * @return            true if changes were successfully detected,
 *                    false if a problem occurred
 */
static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               const struct net_pkt *const uncomp_pkt)
{
	struct c_generic_context *g_context =
		(struct c_generic_context *) context->specific;

	/* compute or find the new SN */
	assert(g_context->get_next_sn != NULL);
	g_context->sn = g_context->get_next_sn(context, uncomp_pkt);
	rohc_comp_debug(context, "SN = %u", g_context->sn);

	return true;
}


/**
 * @brief Decide the state that should be used for the next packet.
 *
 * The three states are:\n
 *  - Initialization and Refresh (IR),\n
 *  - First Order (FO),\n
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
static void tcp_decide_state(struct rohc_comp_ctxt *const context)
{
	struct c_generic_context *g_context =
		(struct c_generic_context *) context->specific;

	/* TODO: be conform with RFC */
	/* TODO: use generic function? */
	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			if(g_context->ir_count < MAX_IR_COUNT)
			{
				rohc_comp_debug(context, "no enough packets transmitted in IR "
				                "state for the moment (%d/%d), so stay in IR "
				                "state", g_context->ir_count, MAX_IR_COUNT);
			}
			else
			{
				change_state(context, ROHC_COMP_STATE_FO);
			}
			break;
		case ROHC_COMP_STATE_FO: /* The First Order (FO) state */
			if(g_context->fo_count < MAX_FO_COUNT)
			{
				rohc_comp_debug(context, "no enough packets transmitted in FO "
				                "state for the moment (%d/%d), so stay in FO "
				                "state", g_context->fo_count, MAX_FO_COUNT);
			}
			else
			{
				change_state(context, ROHC_COMP_STATE_SO);
			}
			break;
		case ROHC_COMP_STATE_SO: /* The Second Order (SO) state */
			/* do not change state */
			break;
		default:
			assert(0); /* should never happen */
			break;
	}
}


/**
 * @brief Encode uncompressed fields with the corresponding encoding scheme
 *
 * @param context      The compression context
 * @param uncomp_pkt   The uncompressed packet to encode
 * @return             true in case of success,
 *                     false otherwise
 */
static bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt)
{
	struct c_generic_context *g_context =
		(struct c_generic_context *) context->specific;
	struct sc_tcp_context *const tcp_context =
		(struct sc_tcp_context *) g_context->specific;

	base_header_ip_t base_header;
	base_header_ip_t inner_ip_hdr;
	size_t remain_data_len;
	ip_context_ptr_t ip_context;
	ip_context_ptr_t inner_ip_ctxt;
	uint8_t protocol;
	tcphdr_t *tcp;
	uint32_t seq_num_hbo;
	uint32_t ack_num_hbo;

	/* how many bits are required to encode the new SN ? */
	if(context->state == ROHC_COMP_STATE_IR)
	{
		/* send all bits in IR state */
		g_context->tmp.nr_sn_bits = 16;
		rohc_comp_debug(context, "IR state: force using %zd bits to encode "
		                "new SN", g_context->tmp.nr_sn_bits);
	}
	else
	{
		/* send only required bits in FO or SO states */
		if(!wlsb_get_k_32bits(g_context->sn_window, g_context->sn,
		                      &g_context->tmp.nr_sn_bits))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for SN");
			goto error;
		}
	}
	rohc_comp_debug(context, "%zd bits are required to encode new SN",
	                g_context->tmp.nr_sn_bits);
	c_add_wlsb(g_context->sn_window, g_context->sn, g_context->sn);

	/* parse IP headers */
	base_header.ipvx = (base_header_ip_vx_t *) uncomp_pkt->data;
	remain_data_len = uncomp_pkt->len;
	ip_context.uint8 = tcp_context->ip_context;
	tcp_context->tmp.ttl_irregular_chain_flag = 0;
	do
	{
		uint8_t ttl_hopl;

		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

		switch(base_header.ipvx->version)
		{
			case IPV4:
			{
				size_t ipv4_hdr_len;
				if(remain_data_len < sizeof(base_header_ip_v4_t))
				{
					goto error;
				}
				ipv4_hdr_len = base_header.ipv4->header_length * sizeof(uint32_t);
				if(remain_data_len < ipv4_hdr_len)
				{
					goto error;
				}

				/* get the transport protocol */
				protocol = base_header.ipv4->protocol;

				/* irregular chain? */
				ttl_hopl = base_header.ipv4->ttl_hopl;
				if(ttl_hopl != ip_context.v4->ttl_hopl)
				{
					tcp_context->tmp.ttl_irregular_chain_flag |= 1;
					rohc_comp_debug(context, "last ttl_hopl = 0x%02x, ttl_hopl = "
					                "0x%02x, ttl_irregular_chain_flag = %d",
					                ip_context.v4->ttl_hopl, ttl_hopl,
					                tcp_context->tmp.ttl_irregular_chain_flag);
				}

				/* skip IPv4 header */
				rohc_comp_debug(context, "skip %zu-byte IPv4 header with "
				                "Protocol 0x%02x", ipv4_hdr_len, protocol);
				inner_ip_hdr.uint8 = base_header.uint8;
				remain_data_len -= ipv4_hdr_len;
				base_header.uint8 += ipv4_hdr_len;
				inner_ip_ctxt.v4 = ip_context.v4;
				ip_context.v4++;
				break;
			}
			case IPV6:
				if(remain_data_len < sizeof(base_header_ip_v6_t) )
				{
					goto error;
				}
				/* get the transport protocol */
				protocol = base_header.ipv6->next_header;

				/* irregular chain? */
				ttl_hopl = base_header.ipv6->ttl_hopl;
				if(ttl_hopl != ip_context.v6->ttl_hopl)
				{
					tcp_context->tmp.ttl_irregular_chain_flag |= 1;
					rohc_comp_debug(context, "last ttl_hopl = 0x%02x, ttl_hopl = "
					                "0x%02x, ttl_irregular_chain_flag = %d",
					                ip_context.v6->ttl_hopl, ttl_hopl,
					                tcp_context->tmp.ttl_irregular_chain_flag);
				}

				/* skip IPv6 header */
				rohc_comp_debug(context, "skip %zd-byte IPv6 header with Next "
				                "Header 0x%02x", sizeof(base_header_ip_v6_t),
				                protocol);
				inner_ip_hdr.uint8 = base_header.uint8;
				remain_data_len -= sizeof(base_header_ip_v6_t);
				++base_header.ipv6;
				inner_ip_ctxt.v6 = ip_context.v6;
				ip_context.v6++;

				/* parse IPv6 extension headers */
				while(rohc_is_ipv6_opt(protocol))
				{
					rohc_comp_debug(context, "skip %d-byte IPv6 extension header "
					                "with Next Header 0x%02x",
					                ip_context.v6_option->option_length,
					                protocol);
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

	tcp_context->tmp.ip_ttl_changed =
		(tcp_context->tmp.ttl_irregular_chain_flag != 0);
	tcp_field_descr_change(context, "TTL", tcp_context->tmp.ip_ttl_changed);

	if(inner_ip_hdr.ipvx->version == IPV4)
	{
		tcp_context->tmp.ip_id = rohc_ntoh16(inner_ip_hdr.ipv4->ip_id);
		tcp_context->tmp.ttl_hopl = inner_ip_hdr.ipv4->ttl_hopl;

		tcp_context->tmp.ip_id_behavior_changed =
			(inner_ip_ctxt.v4->last_ip_id_behavior != inner_ip_ctxt.v4->ip_id_behavior);
		tcp_field_descr_change(context, "IP-ID behavior",
		                       tcp_context->tmp.ip_id_behavior_changed);
		if(inner_ip_ctxt.vx->ip_id_behavior == IP_ID_BEHAVIOR_SEQ)
		{
			tcp_context->tmp.ip_id_hi9_changed =
				((inner_ip_ctxt.v4->last_ip_id & 0xFF80) != (tcp_context->tmp.ip_id & 0xFF80));
			tcp_context->tmp.ip_id_hi11_changed =
				((inner_ip_ctxt.v4->last_ip_id & 0xFFE0) != (tcp_context->tmp.ip_id & 0xFFE0));
			tcp_context->tmp.ip_id_hi12_changed =
				((inner_ip_ctxt.v4->last_ip_id & 0xFFF0) != (tcp_context->tmp.ip_id & 0xFFF0));
			tcp_context->tmp.ip_id_hi13_changed =
				((inner_ip_ctxt.v4->last_ip_id & 0xFFF8) != (tcp_context->tmp.ip_id & 0xFFF8));
		}
		else if(inner_ip_ctxt.vx->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
		{
			tcp_context->tmp.ip_id_hi9_changed =
				((inner_ip_ctxt.v4->last_ip_id & 0x80FF) != (tcp_context->tmp.ip_id & 0x80FF));
			tcp_context->tmp.ip_id_hi11_changed =
				((inner_ip_ctxt.v4->last_ip_id & 0xE0FF) != (tcp_context->tmp.ip_id & 0xE0FF));
			tcp_context->tmp.ip_id_hi12_changed =
				((inner_ip_ctxt.v4->last_ip_id & 0xF0FF) != (tcp_context->tmp.ip_id & 0xF0FF));
			tcp_context->tmp.ip_id_hi13_changed =
				((inner_ip_ctxt.v4->last_ip_id & 0xF8FF) != (tcp_context->tmp.ip_id & 0xF8FF));
		}
		else
		{
			tcp_context->tmp.ip_id_hi9_changed = false; /* TODO: true/false ? */
			tcp_context->tmp.ip_id_hi11_changed = false; /* TODO: true/false ? */
			tcp_context->tmp.ip_id_hi12_changed = false; /* TODO: true/false ? */
			tcp_context->tmp.ip_id_hi13_changed = false; /* TODO: true/false ? */
		}

		tcp_context->tmp.ip_df_changed =
			(inner_ip_hdr.ipv4->df != inner_ip_ctxt.v4->df);
		tcp_field_descr_change(context, "DF", tcp_context->tmp.ip_df_changed);

		tcp_context->tmp.dscp_changed =
			(inner_ip_hdr.ipv4->dscp != inner_ip_ctxt.v4->dscp);
		tcp_field_descr_change(context, "DSCP", tcp_context->tmp.dscp_changed);

		tcp = (tcphdr_t *) (inner_ip_hdr.ipv4 + 1);
	}
	else
	{
		tcp_context->tmp.ip_id = 0;
		tcp_context->tmp.ip_id_behavior_changed = false;
		tcp_context->tmp.ip_id_hi9_changed = false;
		tcp_context->tmp.ip_id_hi11_changed = false;
		tcp_context->tmp.ip_id_hi12_changed = false;
		tcp_context->tmp.ip_id_hi13_changed = false;
		tcp_context->tmp.ip_df_changed = false;

		tcp_context->tmp.dscp_changed =
			(DSCP_V6(inner_ip_hdr.ipv6) != inner_ip_ctxt.v6->dscp);
		tcp_field_descr_change(context, "DSCP", tcp_context->tmp.dscp_changed);

		tcp_context->tmp.ttl_hopl = inner_ip_hdr.ipv6->ttl_hopl;

		tcp = (tcphdr_t *) (inner_ip_hdr.ipv6 + 1);
	}
	rohc_comp_debug(context, "IP-ID: high 9 = %u, high 11 = %u, high 12 = %u, "
	                "high 13 = %u", tcp_context->tmp.ip_id_hi9_changed,
	                tcp_context->tmp.ip_id_hi11_changed,
	                tcp_context->tmp.ip_id_hi12_changed,
	                tcp_context->tmp.ip_id_hi13_changed);

	seq_num_hbo = rohc_ntoh32(tcp->seq_num);
	ack_num_hbo = rohc_ntoh32(tcp->ack_num);
	rohc_comp_debug(context, "new TCP seq = 0x%08x, ack_seq = 0x%08x",
	                seq_num_hbo, ack_num_hbo);
	rohc_comp_debug(context, "old TCP seq = 0x%08x, ack_seq = 0x%08x",
	                rohc_ntoh32(tcp_context->old_tcphdr.seq_num),
						 rohc_ntoh32(tcp_context->old_tcphdr.ack_num));
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d",
	                *(uint16_t *)(((unsigned char *) tcp) + 12),
	                tcp->res_flags, tcp->data_offset, tcp->rsf_flags,
	                tcp->ecn_flags, tcp->urg_flag, tcp->ack_flag,
	                tcp->psh_flag);
	rohc_comp_debug(context, "TCP window = %d (0x%04x), check = 0x%x, "
	                "urg_ptr = %d", rohc_ntoh16(tcp->window),
	                rohc_ntoh16(tcp->window), rohc_ntoh16(tcp->checksum),
	                rohc_ntoh16(tcp->urg_ptr));

	tcp_context->tmp.tcp_ack_flag_changed =
		(tcp->ack_flag != tcp_context->old_tcphdr.ack_flag);
	tcp_field_descr_change(context, "ACK flag",
	                       tcp_context->tmp.tcp_ack_flag_changed);
	tcp_context->tmp.tcp_urg_flag_present = (tcp->urg_flag != 0);
	tcp_field_descr_present(context, "URG flag",
	                        tcp_context->tmp.tcp_urg_flag_present);
	tcp_context->tmp.tcp_urg_flag_changed =
		(tcp->urg_flag != tcp_context->old_tcphdr.urg_flag);
	tcp_field_descr_change(context, "URG flag",
	                       tcp_context->tmp.tcp_urg_flag_changed);
	tcp_context->tmp.ecn_used = (tcp_context->ecn_used != 0);
	tcp_field_descr_present(context, "ECN flag", tcp_context->tmp.ecn_used);
	tcp_context->tmp.tcp_ecn_flag_changed =
		(tcp->ecn_flags != tcp_context->old_tcphdr.ecn_flags);
	tcp_field_descr_change(context, "ECN flag",
	                       tcp_context->tmp.tcp_ecn_flag_changed);
	tcp_context->tmp.tcp_rsf_flag_changed =
		(tcp->rsf_flags != tcp_context->old_tcphdr.rsf_flags);
	tcp_field_descr_change(context, "RSF flag",
	                       tcp_context->tmp.tcp_rsf_flag_changed);

	tcp_context->tmp.tcp_window_changed =
		(tcp->window != tcp_context->old_tcphdr.window);
	tcp_field_descr_change(context, "window",
	                       tcp_context->tmp.tcp_window_changed);

	/* compute new scaled TCP sequence number */
	{
		const size_t seq_num_factor = tcp_context->tmp.payload_len;
		uint32_t seq_num_scaled;
		uint32_t seq_num_residue;

		c_field_scaling(&seq_num_scaled, &seq_num_residue, seq_num_factor,
		                seq_num_hbo);
		rohc_comp_debug(context, "seq_num = 0x%x, scaled = 0x%x, factor = %zu, "
		                "residue = 0x%x", seq_num_hbo, seq_num_scaled,
		                seq_num_factor, seq_num_residue);

		if(context->num_sent_packets == 0 ||
		   seq_num_factor == 0 ||
		   seq_num_factor != tcp_context->seq_num_factor ||
		   seq_num_residue != tcp_context->seq_num_residue)
		{
			/* sequence number is not scalable with same parameters any more */
			tcp_context->seq_num_scaling_nr = 0;
		}
		rohc_comp_debug(context, "unscaled sequence number was transmitted at "
		                "least %zu / %u times since the scaling factor or "
		                "residue changed", tcp_context->seq_num_scaling_nr,
		                ROHC_INIT_TS_STRIDE_MIN);

		/* TODO: should update context at the very end only */
		tcp_context->seq_num_scaled = seq_num_scaled;
		tcp_context->seq_num_residue = seq_num_residue;
		tcp_context->seq_num_factor = seq_num_factor;
	}

	/* compute new scaled TCP acknowledgment number */
	/* TODO: handle transmission count the same way as sequence number */
	c_field_scaling(&(tcp_context->ack_num_scaled),
	                &(tcp_context->ack_num_residue),
	                tcp_context->ack_stride, ack_num_hbo);
	rohc_comp_debug(context, "ack_number = 0x%x, scaled = 0x%x, factor = %zu, "
	                "residue = 0x%x", ack_num_hbo, tcp_context->ack_num_scaled,
	                tcp_context->tmp.payload_len, tcp_context->ack_num_residue);

	/* how many bits are required to encode the new sequence number? */
	if(context->state == ROHC_COMP_STATE_IR)
	{
		/* send all bits in IR state */
		tcp_context->tmp.nr_seq_bits_65535 = 32;
		tcp_context->tmp.nr_seq_bits_32767 = 32;
		tcp_context->tmp.nr_seq_bits_16383 = 32;
		tcp_context->tmp.nr_seq_bits_8191 = 32;
		tcp_context->tmp.nr_seq_bits_63 = 32;
		tcp_context->tmp.nr_seq_scaled_bits = 32;
		rohc_comp_debug(context, "IR state: force using 32 bits to encode "
		                "new sequence number");
	}
	else
	{
		/* send only required bits in FO or SO states */
		if(!wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 65535,
		                       &tcp_context->tmp.nr_seq_bits_65535))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for sequence number 0x%08x and p = 65535",
			               seq_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 65535",
		                tcp_context->tmp.nr_seq_bits_65535, seq_num_hbo);
		if(!wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 32767,
		                       &tcp_context->tmp.nr_seq_bits_32767))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for sequence number 0x%08x and p = 32767",
			               seq_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 32767",
		                tcp_context->tmp.nr_seq_bits_32767, seq_num_hbo);
		if(!wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 16383,
		                       &tcp_context->tmp.nr_seq_bits_16383))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for sequence number 0x%08x and p = 16383",
			               seq_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 16383",
		                tcp_context->tmp.nr_seq_bits_16383, seq_num_hbo);
		if(!wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 8191,
		                       &tcp_context->tmp.nr_seq_bits_8191))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for sequence number 0x%08x and p = 8191",
			               seq_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 8191",
		                tcp_context->tmp.nr_seq_bits_8191, seq_num_hbo);
		if(!wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 63,
		                       &tcp_context->tmp.nr_seq_bits_63))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for sequence number 0x%08x and p = 63",
			               seq_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new sequence "
		                "number 0x%08x with p = 63",
		                tcp_context->tmp.nr_seq_bits_63, seq_num_hbo);

		if(tcp_context->seq_num_factor == 0 ||
		   tcp_context->seq_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
		{
			tcp_context->tmp.nr_seq_scaled_bits = 32;
		}
		else
		{
			if(!wlsb_get_k_32bits(tcp_context->seq_scaled_wlsb,
			                      tcp_context->seq_num_scaled,
			                      &tcp_context->tmp.nr_seq_scaled_bits))
			{
				rohc_comp_warn(context, "failed to find the minimal number of "
				               "bits required for scaled sequence number 0x%08x",
				               tcp_context->seq_num_scaled);
				goto error;
			}
			rohc_comp_debug(context, "%zu bits are required to encode new "
			                "scaled sequence number 0x%08x",
			                tcp_context->tmp.nr_seq_scaled_bits,
			                tcp_context->seq_num_scaled);
		}
	}
	c_add_wlsb(tcp_context->seq_wlsb, g_context->sn, seq_num_hbo);
	if(tcp_context->seq_num_factor != 0)
	{
		c_add_wlsb(tcp_context->seq_scaled_wlsb, g_context->sn,
		           tcp_context->seq_num_scaled);
	}

	/* how many bits are required to encode the new ACK number? */
	if(tcp->ack_flag == 0 && tcp->ack_num == 0)
	{
		/* send no bit if ACK flag is not set */
		tcp_context->tmp.tcp_ack_num_changed = false;
		tcp_context->tmp.nr_ack_bits_65535 = 0;
		tcp_context->tmp.nr_ack_bits_32767 = 0;
		tcp_context->tmp.nr_ack_bits_16383 = 0;
		tcp_context->tmp.nr_ack_bits_8191 = 0;
		tcp_context->tmp.nr_ack_bits_63 = 0;
		tcp_context->tmp.nr_ack_scaled_bits = 0;
		rohc_comp_debug(context, "no bit required to encode new ACK number "
		                "since the ACK flag is not set");
	}
	else
	{
		tcp_context->tmp.tcp_ack_num_changed =
			(tcp->ack_num != tcp_context->old_tcphdr.ack_num);

		if(context->state == ROHC_COMP_STATE_IR)
		{
			/* send all bits in IR state */
			tcp_context->tmp.nr_ack_bits_65535 = 32;
			tcp_context->tmp.nr_ack_bits_32767 = 32;
			tcp_context->tmp.nr_ack_bits_16383 = 32;
			tcp_context->tmp.nr_ack_bits_8191 = 32;
			tcp_context->tmp.nr_ack_bits_63 = 32;
			tcp_context->tmp.nr_ack_scaled_bits = 32;
			rohc_comp_debug(context, "IR state: force using 32 bits to encode "
			                "new ACK number");
		}
		else
		{
			/* send only required bits in FO or SO states */
			if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 65535,
			                       &tcp_context->tmp.nr_ack_bits_65535))
			{
				rohc_comp_warn(context, "failed to find the minimal number of "
				               "bits required for ACK number 0x%08x and p = 65535",
				               ack_num_hbo);
				goto error;
			}
			rohc_comp_debug(context, "%zd bits are required to encode new ACK "
			                "number 0x%08x with p = 65535",
			                tcp_context->tmp.nr_ack_bits_65535, ack_num_hbo);
			if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 32767,
			                       &tcp_context->tmp.nr_ack_bits_32767))
			{
				rohc_comp_warn(context, "failed to find the minimal number of "
				               "bits required for ACK number 0x%08x and p = 32767",
				               ack_num_hbo);
				goto error;
			}
			rohc_comp_debug(context, "%zd bits are required to encode new ACK "
			                "number 0x%08x with p = 32767",
			                tcp_context->tmp.nr_ack_bits_32767, ack_num_hbo);
			if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 16383,
			                       &tcp_context->tmp.nr_ack_bits_16383))
			{
				rohc_comp_warn(context, "failed to find the minimal number of "
				               "bits required for ACK number 0x%08x and p = 16383",
				               ack_num_hbo);
				goto error;
			}
			rohc_comp_debug(context, "%zd bits are required to encode new ACK "
			                "number 0x%08x with p = 16383",
			                tcp_context->tmp.nr_ack_bits_16383, ack_num_hbo);
			if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 8191,
			                       &tcp_context->tmp.nr_ack_bits_8191))
			{
				rohc_comp_warn(context, "failed to find the minimal number of "
				               "bits required for ACK number 0x%08x and p = 8191",
				               ack_num_hbo);
				goto error;
			}
			rohc_comp_debug(context, "%zd bits are required to encode new ACK "
			                "number 0x%08x with p = 8191",
			                tcp_context->tmp.nr_ack_bits_8191, ack_num_hbo);
			if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 63,
			                       &tcp_context->tmp.nr_ack_bits_63))
			{
				rohc_comp_warn(context, "failed to find the minimal number of "
				               "bits required for ACK number 0x%08x and p = 63",
				               ack_num_hbo);
				goto error;
			}
			rohc_comp_debug(context, "%zd bits are required to encode new ACK "
			                "number 0x%08x with p = 63",
			                tcp_context->tmp.nr_ack_bits_63, ack_num_hbo);
			if(!wlsb_get_k_32bits(tcp_context->ack_scaled_wlsb,
			                      tcp_context->ack_num_scaled,
			                      &tcp_context->tmp.nr_ack_scaled_bits))
			{
				rohc_comp_warn(context, "failed to find the minimal number of "
				               "bits required for scaled ACK number 0x%08x",
				               tcp_context->ack_num_scaled);
				goto error;
			}
			rohc_comp_debug(context, "%zu bits are required to encode new scaled "
			                "ACK number 0x%08x",
			                tcp_context->tmp.nr_ack_scaled_bits,
			                tcp_context->ack_num_scaled);
		}
		c_add_wlsb(tcp_context->ack_wlsb, g_context->sn, ack_num_hbo);
		c_add_wlsb(tcp_context->ack_scaled_wlsb, g_context->sn,
		           tcp_context->ack_num_scaled);
	}

	/* how many bits are required to encode the new timestamp echo request and
	 * timestamp echo reply? */
	if(!tcp_context->tmp.opt_ts_present)
	{
		/* no bit to send */
		tcp_context->tmp.nr_opt_ts_req_bits_minus_1 = 0;
		tcp_context->tmp.nr_opt_ts_req_bits_0x40000 = 0;
		tcp_context->tmp.nr_opt_ts_reply_bits_minus_1 = 0;
		tcp_context->tmp.nr_opt_ts_reply_bits_0x40000 = 0;
		rohc_comp_debug(context, "no TS option: O bit required to encode the "
		                "new timestamp echo request/reply numbers");
	}
	else if(context->state == ROHC_COMP_STATE_IR)
	{
		/* send all bits in IR state */
		tcp_context->tmp.nr_opt_ts_req_bits_minus_1 = 32;
		tcp_context->tmp.nr_opt_ts_req_bits_0x40000 = 32;
		tcp_context->tmp.nr_opt_ts_reply_bits_minus_1 = 32;
		tcp_context->tmp.nr_opt_ts_reply_bits_0x40000 = 32;
		rohc_comp_debug(context, "IR state: force using 32 bits to encode "
		                "new timestamp echo request/reply numbers");
	}
	else if(!tcp_context->tcp_option_timestamp_init)
	{
		/* send all bits for the first occurrence of the TCP TS option */
		tcp_context->tmp.nr_opt_ts_req_bits_minus_1 = 32;
		tcp_context->tmp.nr_opt_ts_req_bits_0x40000 = 32;
		tcp_context->tmp.nr_opt_ts_reply_bits_minus_1 = 32;
		tcp_context->tmp.nr_opt_ts_reply_bits_0x40000 = 32;
		rohc_comp_debug(context, "first occurrence of TCP TS option: force "
							 "using 32 bits to encode new timestamp echo "
							 "request/reply numbers");
	}
	else
	{
		/* send only required bits in FO or SO states */

		/* how many bits are required to encode the timestamp echo request
		 * with p = -1 ? */
		if(!wlsb_get_kp_32bits(tcp_context->opt_ts_req_wlsb,
		                       tcp_context->tmp.ts_req, -1,
		                       &tcp_context->tmp.nr_opt_ts_req_bits_minus_1))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for timestamp echo request 0x%08x and "
			               "p = -1", tcp_context->tmp.ts_req);
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = -1",
		                tcp_context->tmp.nr_opt_ts_req_bits_minus_1,
		                tcp_context->tmp.ts_req);

		/* how many bits are required to encode the timestamp echo request
		 * with p = 0x40000 ? */
		if(!wlsb_get_kp_32bits(tcp_context->opt_ts_req_wlsb,
		                       tcp_context->tmp.ts_req, 0x40000,
		                       &tcp_context->tmp.nr_opt_ts_req_bits_0x40000))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for timestamp echo request 0x%08x and "
			               "p = 0x40000", tcp_context->tmp.ts_req);
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = 0x40000",
		                tcp_context->tmp.nr_opt_ts_req_bits_0x40000,
		                tcp_context->tmp.ts_req);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = -1 ? */
		if(!wlsb_get_kp_32bits(tcp_context->opt_ts_reply_wlsb,
		                       tcp_context->tmp.ts_reply, -1,
		                       &tcp_context->tmp.nr_opt_ts_reply_bits_minus_1))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for timestamp echo reply 0x%08x and p = -1",
			               tcp_context->tmp.ts_reply);
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = -1",
		                tcp_context->tmp.nr_opt_ts_reply_bits_minus_1,
		                tcp_context->tmp.ts_reply);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = 0x40000 ? */
		if(!wlsb_get_kp_32bits(tcp_context->opt_ts_reply_wlsb,
		                       tcp_context->tmp.ts_reply, 0x40000,
		                       &tcp_context->tmp.nr_opt_ts_reply_bits_0x40000))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for timestamp echo reply 0x%08x and "
			               "p = 0x40000", tcp_context->tmp.ts_reply);
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = 0x40000",
		                tcp_context->tmp.nr_opt_ts_reply_bits_0x40000,
		                tcp_context->tmp.ts_reply);
	}

	return true;

error:
	return false;
}


/**
 * @brief Decide which packet to send when in the different states.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param tcp               The TCP header to compress
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_[1-8],
 *                              ROHC_PACKET_TCP_SEQ_[1-8] and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_packet(const struct rohc_comp_ctxt *const context,
                                       const ip_context_ptr_t *const ip_inner_context,
                                       const tcphdr_t *const tcp)
{
	struct c_generic_context *g_context =
		(struct c_generic_context *) context->specific;

	rohc_packet_t packet_type;

	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			rohc_comp_debug(context, "code IR packet");
			packet_type = ROHC_PACKET_IR;
			g_context->ir_count++;
			break;
		case ROHC_COMP_STATE_FO: /* The First Order (FO) state */
			rohc_comp_debug(context, "code IR-DYN packet");
			packet_type = ROHC_PACKET_IR_DYN;
			g_context->fo_count++;
			break;
		case ROHC_COMP_STATE_SO: /* The Second Order (SO) state */
			g_context->so_count++;
			packet_type = tcp_decide_SO_packet(context, ip_inner_context, tcp);
			break;
		default:
#if defined(NDEBUG) || defined(__KERNEL__)
			packet_type = ROHC_PACKET_UNKNOWN;
#endif
			assert(0); /* should not happen */
			break;
	}

	return packet_type;
}


/**
 * @brief Decide which packet to send when in SO state.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param tcp               The TCP header to compress
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_[1-8],
 *                              ROHC_PACKET_TCP_SEQ_[1-8] and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_ptr_t *const ip_inner_context,
                                          const tcphdr_t *const tcp)
{
	struct c_generic_context *const g_context =
		(struct c_generic_context *) context->specific;
	struct sc_tcp_context *const tcp_context =
		(struct sc_tcp_context *) g_context->specific;

	rohc_packet_t packet_type;

	if(!sdvl_can_length_be_encoded(tcp_context->tmp.nr_opt_ts_req_bits_0x40000) ||
	   !sdvl_can_length_be_encoded(tcp_context->tmp.nr_opt_ts_reply_bits_0x40000))
	{
		rohc_comp_debug(context, "force packet IR-DYN because the TCP "
		                "option changed too much");
		rohc_comp_debug(context, "code IR-DYN packet");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(tcp_context->tmp.ip_ttl_changed ||
	        tcp_context->tmp.ip_id_behavior_changed ||
	        tcp_context->tmp.ip_df_changed ||
	        tcp_context->tmp.dscp_changed ||
	        tcp_context->tmp.tcp_ack_flag_changed ||
	        tcp_context->tmp.tcp_urg_flag_present ||
	        tcp_context->tmp.tcp_urg_flag_changed ||
	        tcp_context->tmp.tcp_ecn_flag_changed)
	{
		TRACE_GOTO_CHOICE;
		packet_type = ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(tcp_context->tmp.ecn_used != 0) /* ecn used change */
	{
		/* use compressed header with a 7-bit CRC (rnd_8, seq_8 or common):
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if window changed */
		if(ip_inner_context->vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP &&
		   tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
		   tcp_context->tmp.nr_ack_bits_8191 <= 15 &&
		   !tcp_context->tmp.tcp_window_changed)
		{
			/* IP_ID_BEHAVIOR_SEQ or IP_ID_BEHAVIOR_SEQ_SWAP */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else if(tcp_context->tmp.nr_seq_bits_65535 <= 16 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        !tcp_context->tmp.tcp_window_changed)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_8;
		}
		else
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(ip_inner_context->vx->ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* IP_ID_BEHAVIOR_SEQ or IP_ID_BEHAVIOR_SEQ_SWAP:
		 * co_common or seq_X packet types */

		if(tcp_context->tmp.tcp_rsf_flag_changed ||
		   tcp_context->tmp.is_tcp_opts_list_struct_changed)
		{
			/* seq_8 or co_common
			 *
			 * seq_8 can be used if:
			 *  - TCP window didn't change,
			 *  - at most 14 LSB of the TCP sequence number are required,
			 *  - at most 15 LSB of the TCP ACK number are required,
			 *  - at most 4 LSBs of IP-ID must be transmitted
			 * otherwise use co_common packet */
			if(!tcp_context->tmp.tcp_window_changed &&
			   !tcp_context->tmp.ip_id_hi12_changed && /* TODO: WLSB */
			   true /* TODO: list changed */ &&
			   true /* TODO: no more than 4 bits of SN */ &&
			   true /* TODO: no more than 3 bits of TTL */ &&
			   tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
			   tcp_context->tmp.nr_ack_bits_8191 <= 15)
			{
				/* seq_8 is possible */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_8;
			}
			else
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else if(tcp_context->tmp.tcp_window_changed)
		{
			/* seq_7 or co_common */
			if(/* TODO: no more than 15 bits of TCP window */
			   !tcp_context->tmp.ip_id_hi11_changed && /* TODO: WLSB */
			   tcp_context->tmp.nr_ack_bits_32767 <= 16 &&
			   true /* TODO: no more than 4 bits of SN */ &&
			   tcp_context->tmp.tcp_rsf_flag_changed)
			{
				/* seq_7 is possible */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_7;
			}
			else
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else if(tcp->ack_flag == 0 ||
		        (tcp->ack_flag != 0 && !tcp_context->tmp.tcp_ack_num_changed))
		{
			/* seq_1, seq_2 or co_common */
			if(!tcp_context->tmp.ip_id_hi11_changed && /* TODO: WLSB */
			   tcp_context->tmp.nr_seq_bits_32767 <= 16 &&
			   true /* TODO: no more than 4 bits of SN */)
			{
				/* seq_1 is possible */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_1;
			}
			else if(!tcp_context->tmp.ip_id_hi9_changed && /* TODO: WLSB */
			        tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
			        tcp_context->tmp.nr_seq_scaled_bits <= 4 &&
			        true /* TODO: no more than 4 bits of SN */)
			{
				/* seq_2 is possible */
				TRACE_GOTO_CHOICE;
				assert(tcp_context->tmp.payload_len > 0);
				packet_type = ROHC_PACKET_TCP_SEQ_2;
			}
			else
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else if(tcp_context->tmp.nr_seq_bits_65535 == 0 &&
		        tcp_context->tmp.nr_seq_bits_32767 == 0 &&
		        tcp_context->tmp.nr_seq_bits_8191 == 0)
		{
			/* seq_3, seq_4, or co_common */
			if(!tcp_context->tmp.ip_id_hi12_changed && /* TODO: WLSB */
			   tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
			   true /* TODO: no more than 4 bits of SN */)
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_3;
			}
			else if(!tcp_context->tmp.ip_id_hi13_changed && /* TODO: WLSB */
			        tcp_context->ack_stride != 0 &&
			        tcp_context->tmp.nr_ack_scaled_bits <= 4 &&
			        true /* TODO: no more than 4 bits of SN */)
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_4;
			}
			else
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else
		{
			/* sequence and acknowledgment numbers changed:
			 * seq_5, seq_6, seq_8 or co_common */
			if(!tcp_context->tmp.ip_id_hi12_changed && /* TODO: WLSB */
			   tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
			   tcp_context->tmp.nr_seq_bits_32767 <= 16 &&
			   true /* TODO: no more than 4 bits of SN */)
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_5;
			}
			else if(!tcp_context->tmp.ip_id_hi9_changed && /* TODO: WLSB */
			        tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
			        tcp_context->tmp.nr_seq_scaled_bits <= 4 &&
			        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
			        true /* TODO: no more than 4 bits of SN */)
			{
				TRACE_GOTO_CHOICE;
				assert(tcp_context->tmp.payload_len > 0);
				packet_type = ROHC_PACKET_TCP_SEQ_6;
			}
			else if(!tcp_context->tmp.ip_id_hi12_changed && /* TODO: WLSB */
			        true /* TODO: list changed */ &&
			        true /* TODO: no more than 4 bits of SN */ &&
			        true /* TODO: no more than 3 bits of TTL */ &&
			        tcp_context->tmp.nr_ack_bits_8191 <= 15 &&
			        tcp_context->tmp.nr_seq_bits_8191 <= 14)
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_8;
			}
			else
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}

		/* IP-ID is sequential, so only co_common and seq_X packets are allowed */
		assert(packet_type == ROHC_PACKET_TCP_CO_COMMON ||
		       (packet_type >= ROHC_PACKET_TCP_SEQ_1 &&
		        packet_type <= ROHC_PACKET_TCP_SEQ_8));
	}
	else if(ip_inner_context->vx->ip_id_behavior == IP_ID_BEHAVIOR_RAND ||
	        ip_inner_context->vx->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
	{
		/* IP_ID_BEHAVIOR_RAND or IP_ID_BEHAVIOR_ZERO:
		 * co_common or rnd_X packet types */

		if(tcp_context->tmp.is_tcp_opts_list_struct_changed)
		{
			if(!tcp_context->tmp.tcp_window_changed &&
			   tcp_context->tmp.nr_seq_bits_65535 <= 16 &&
			   tcp_context->tmp.nr_ack_bits_16383 <= 16)
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_RND_8;
			}
			else
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else /* unchanged structure of the list of TCP options */
		{
			if(tcp_context->tmp.tcp_rsf_flag_changed)
			{
				if(!tcp_context->tmp.tcp_window_changed &&
				   tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
				   tcp_context->tmp.nr_seq_bits_65535 <= 16)
				{
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_RND_8;
				}
				else
				{
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
			}
			else if((rohc_ntoh32(tcp->seq_num) & 0xFFFF) !=
				     (rohc_ntoh32(tcp_context->old_tcphdr.seq_num) & 0xFFFF))
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
			else if(tcp_context->tmp.tcp_window_changed)
			{
				if(tcp_context->tmp.nr_ack_bits_65535 <= 18 &&
				   true /* TODO: no more than 4 bits of SN */)
				{
					/* rnd_7 is possible */
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_RND_7;
				}
				else
				{
					/* rnd_7 is not possible, fallback on co_common */
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
			}
			else if(tcp->ack_flag != 0 && !tcp_context->tmp.tcp_ack_num_changed)
			{
				/* ACK number not present */
				if(tcp_context->tmp.payload_len > 0 &&
				   tcp_context->ack_stride != 0)
				{
					/* rnd_4 is possible */
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_RND_4;
				}
				else
				{
					/* rnd_1 is possible */
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_RND_1;
				}
			}
			else if(tcp->ack_flag != 0 &&
			        tcp_context->tmp.nr_seq_bits_65535 == 0)
			{
				/* ACK number present */
				if(tcp_context->tmp.nr_ack_scaled_bits <= 4 &&
				   tcp_context->ack_stride != 0)
				{
					/* rnd_4 is possible */
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_RND_4;
				}
				else if(tcp_context->tmp.nr_ack_bits_8191 <= 15)
				{
					/* rnd_3 is possible */
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_RND_3;
				}
				else
				{
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_CO_COMMON;
				}
			}
			else if(tcp->ack_flag != 0 &&
			        tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
			        tcp_context->tmp.nr_seq_scaled_bits <= 4 &&
			        tcp_context->tmp.nr_ack_bits_16383 <= 16)
			{
				/* ACK number present */
				/* rnd_6 is possible */
				assert(tcp_context->tmp.payload_len > 0);
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_RND_6;
			}
			else if(tcp->ack_flag != 0 &&
			        tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
			        tcp_context->tmp.nr_ack_bits_8191 <= 15)
			{
				/* ACK number present */
				/* rnd_5 is possible */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_RND_5;
			}
			else if(tcp->ack_flag == 0 &&
			        tcp_context->tmp.nr_seq_bits_65535 <= 18)
			{
				/* ACK number absent */
				if(tcp_context->tmp.payload_len > 0 &&
				   tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
				   tcp_context->tmp.nr_seq_scaled_bits <= 4)
				{
					/* rnd_2 is possible */
					assert(tcp_context->tmp.payload_len > 0);
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_RND_2;
				}
				else
				{
					/* rnd_1 is possible */
					TRACE_GOTO_CHOICE;
					packet_type = ROHC_PACKET_TCP_RND_1;
				}
			}
			else
			{
				/* ACK number absent */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		} /* end of case 'unchanged structure of the list of TCP options' */

		/* IP-ID is NOT sequential, so only co_common and rnd_X packets are
		 * allowed */
		assert(packet_type == ROHC_PACKET_TCP_CO_COMMON ||
		       (packet_type >= ROHC_PACKET_TCP_RND_1 &&
		        packet_type <= ROHC_PACKET_TCP_RND_8));
	}
	else
	{
		rohc_comp_warn(context, "unexpected IP-ID behavior (%d)",
		               ip_inner_context->vx->ip_id_behavior);
		assert(0);
		goto error;
	}

	rohc_comp_debug(context, "code %s packet",
	                rohc_get_packet_descr(packet_type));

	return packet_type;

error:
	return ROHC_PACKET_UNKNOWN;
}


/**
 * @brief Detect the behavior of the IPv4 Identification field
 *
 * @param last_ip_id  The IP-ID value of the previous packet (in HBO)
 * @param new_ip_id   The IP-ID value of the current packet (in HBO)
 * @return            The IP-ID behavior among: IP_ID_BEHAVIOR_SEQ,
 *                    IP_ID_BEHAVIOR_SEQ_SWAP, IP_ID_BEHAVIOR_ZERO, or
 *                    IP_ID_BEHAVIOR_RAND
 */
static tcp_ip_id_behavior_t tcp_detect_ip_id_behavior(const uint16_t last_ip_id,
																		const uint16_t new_ip_id)
{
	tcp_ip_id_behavior_t behavior;

	if((last_ip_id + 1) == new_ip_id)
	{
		behavior = IP_ID_BEHAVIOR_SEQ;
	}
	else
	{
		const uint16_t swapped_ip_id = swab16(last_ip_id);

		if((swapped_ip_id + 1) == swab16(new_ip_id))
		{
			behavior = IP_ID_BEHAVIOR_SEQ_SWAP;
		}
		else if(new_ip_id == 0)
		{
			behavior = IP_ID_BEHAVIOR_ZERO;
		}
		else
		{
			behavior = IP_ID_BEHAVIOR_RAND;
		}
	}

	return behavior;
}


/**
 * @brief Print a debug trace for the field change
 *
 * @param context  The compression context
 * @param name     The name of the field
 * @param changed  Whether the field changed or not
 */
static void tcp_field_descr_change(const struct rohc_comp_ctxt *const context,
                                   const char *const name,
                                   const bool changed)
{
	rohc_comp_debug(context, "%s did%s change", name, changed ? "" : " not");
}


/**
 * @brief Print a debug trace for the field presence
 *
 * @param context  The compression context
 * @param name     The name of the field
 * @param present  Whether the field is present or not
 */
static void tcp_field_descr_present(const struct rohc_comp_ctxt *const context,
                                    const char *const name,
                                    const bool present)
{
	rohc_comp_debug(context, "%s is%s present", name, present ? "" : " not");
}


/**
 * @brief Get a string that describes the given IP-ID behavior
 *
 * @param behavior  The type of the option to get a description for
 * @return          The description of the option
 */
static char * tcp_ip_id_behavior_get_descr(const tcp_ip_id_behavior_t behavior)
{
	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ:
			return "sequential";
		case IP_ID_BEHAVIOR_SEQ_SWAP:
			return "sequential swapped";
		case IP_ID_BEHAVIOR_RAND:
			return "random";
		case IP_ID_BEHAVIOR_ZERO:
			return "constant zero";
		default:
			assert(0);
#if defined(NDEBUG) || defined(__KERNEL__)
			return "unknown";
#endif
	}
}


/**
 * @brief Get a string that describes the given option type
 *
 * @param opt_type  The type of the option to get a description for
 * @return          The description of the option
 */
static char * tcp_opt_get_descr(const uint8_t opt_type)
{
	switch(opt_type)
	{
		case TCP_OPT_EOL:
			return "EOL";
		case TCP_OPT_NOP:
			return "NOP";
		case TCP_OPT_MAXSEG:
			return "MSS";
		case TCP_OPT_WINDOW:
			return "Window Scale";
		case TCP_OPT_SACK_PERMITTED:
			return "SACK permitted";
		case TCP_OPT_SACK:
			return "SACK";
		case TCP_OPT_TIMESTAMP:
			return "Timestamp";
		default:
			return "generic";
	}
}


/**
 * @brief Define the compression part of the TCP profile as described
 *        in the RFC 3095.
 */
const struct rohc_comp_profile c_tcp_profile =
{
	.id             = ROHC_PROFILE_TCP, /* profile ID (see 8 in RFC 3095) */
	.protocol       = ROHC_IPPROTO_TCP, /* IP protocol */
	.create         = c_tcp_create,     /* profile handlers */
	.destroy        = c_tcp_destroy,
	.check_profile  = c_tcp_check_profile,
	.check_context  = c_tcp_check_context,
	.encode         = c_tcp_encode,
	.reinit_context = c_generic_reinit_context,
	.feedback       = c_generic_feedback,
	.use_udp_port   = c_generic_use_udp_port,
};

