/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013,2014 Viveris Technologies
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
 * @file   c_tcp.c
 * @brief  ROHC compression context for the TCP profile.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "rohc_comp_internals.h"
#include "rohc_traces_internal.h"
#include "rohc_utils.h"
#include "rohc_packets.h"
#include "net_pkt.h"
#include "protocols/ip_numbers.h"
#include "protocols/tcp.h"
#include "schemes/cid.h"
#include "schemes/rfc4996.h"
#include "sdvl.h"
#include "crc.h"

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
	/* the length of the TCP payload (headers and options excluded) */
	size_t payload_len;

	/** The minimal number of bits required to encode the MSN value */
	size_t nr_msn_bits;

	/** The minimal number of bits required to encode the TCP window */
	size_t nr_window_bits;

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
	bool is_tcp_opts_list_item_present[MAX_TCP_OPTION_INDEX + 1];

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

	/** The current IP-ID value (if IPv4) */
	uint16_t ip_id;
	/** The IP-ID / SN delta (with bits swapped if necessary) */
	uint16_t ip_id_delta;
	/** Whether the behavior of the IP-ID field changed with current packet */
	bool ip_id_behavior_changed;
	/** The minimal number of bits required to encode the innermost IP-ID value
	 *  with p = 3 */
	size_t nr_ip_id_bits_3;
	/** The minimal number of bits required to encode the innermost IP-ID value
	 *  with p = 1 */
	size_t nr_ip_id_bits_1;

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

	bool ecn_used;

	uint8_t tcp_opts_nr;
	uint8_t tcp_opts_list_indexes[ROHC_TCP_OPTS_MAX];
	uint8_t tcp_opts_idx_max;
};

#define MAX_IPV6_OPTION_LENGTH        0xffU
#define MAX_IPV6_CONTEXT_OPTION_SIZE  (2 + ((MAX_IPV6_OPTION_LENGTH + 1) << 3))


/**
 * @brief Define the IPv6 generic option context.
 */
typedef struct __attribute__((packed)) ipv6_generic_option_context
{
	size_t option_length;
	uint8_t next_header;
	uint8_t length;
	uint8_t data[(255 + 1) * 8 - 2];

} ipv6_generic_option_context_t;


/**
 * @brief Define the IPv6 GRE option context.
 */
typedef struct __attribute__((packed)) ipv6_gre_option_context
{
	size_t option_length;

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
	size_t option_length;

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
	size_t option_length;

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


/** The compression context for one IPv6 extension header */
typedef union
{
	ipv6_generic_option_context_t generic; /**< IPv6 generic extension header */
	ipv6_gre_option_context_t gre;         /**< IPv6 GRE extension header */
	ipv6_mime_option_context_t mime;       /**< IPv6 MIME extension header */
	ipv6_ah_option_context_t ah;           /**< IPv6 AH extension header */
} ipv6_option_context_t;


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

	size_t opts_nr;
	size_t opts_len;
	ipv6_option_context_t opts[ROHC_TCP_MAX_IPV6_EXT_HDRS];

} ipv6_context_t;


/**
 * @brief Define union of IP contexts
 */
typedef struct
{
	ip_version version;
	union
	{
		ipvx_context_t vx;
		ipv4_context_t v4;
		ipv6_context_t v6;
	} ctxt;

} ip_context_t;


/**
 * @brief The compression context for one TCP option
 */
struct tcp_opt_context
{
	/** Whether the option context is in use or not */
	bool used;
	/** The type of the TCP option */
	uint8_t type;
	/** The number of times the TCP option was transmitted */
	size_t nr_trans;
	size_t age;
/** The maximum size (in bytes) of one TCP option */
#define MAX_TCP_OPT_SIZE 40U
	/** The value of the TCP option */
	uint8_t value[MAX_TCP_OPT_SIZE];
};


/** Define the TCP part of the profile decompression context */
struct sc_tcp_context
{
	/// The number of times the sequence number field was added to the compressed header
	int tcp_seq_num_change_count;

	// Explicit Congestion Notification used
	uint8_t ecn_used;

	uint32_t tcp_last_seq_num;

	uint16_t msn;               /**< The Master Sequence Number (MSN) */
	struct c_wlsb *msn_wlsb;    /**< The W-LSB decoding context for MSN */

	struct c_wlsb *ip_id_wlsb;

// lsb(15, 16383)
	struct c_wlsb *window_wlsb; /**< The W-LSB decoding context for TCP window */

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
	size_t tcp_opts_list_struct_nr;
	uint8_t tcp_opts_list_struct[ROHC_TCP_OPTS_MAX];
	struct tcp_opt_context tcp_options_list[MAX_TCP_OPTION_INDEX + 1];
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

	size_t ip_contexts_nr;
	ip_context_t ip_contexts[ROHC_TCP_MAX_IP_HDRS];
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
	TCP_INDEX_MSS,             // TCP_OPT_MAXSEG          2
	TCP_INDEX_WS,              // TCP_OPT_WINDOW          3
	TCP_INDEX_SACK_PERM,       // TCP_OPT_SACK_PERMITTED  4
	TCP_INDEX_SACK,            // TCP_OPT_SACK            5
	-1,                        // TODO ?                  6
	-1,                        // TODO ?                  7
	TCP_INDEX_TS,              // TCP_OPT_TIMESTAMP       8
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

static uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));

static bool tcp_detect_options_changes(struct rohc_comp_ctxt *const context,
                                       const tcphdr_t *const tcp,
                                       size_t *const opts_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               const struct net_pkt *const uncomp_pkt,
                               ip_context_t **const ip_inner_context,
                               const tcphdr_t **const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

static void tcp_decide_state(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

static bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static rohc_packet_t tcp_decide_packet(struct rohc_comp_ctxt *const context,
                                       const ip_context_t *const ip_inner_context,
                                       const tcphdr_t *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const tcphdr_t *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int tcp_code_static_part(struct rohc_comp_ctxt *const context,
                                const struct ip_packet *const ip,
                                const int packet_size __attribute__((unused)),
                                unsigned char *const rohc_pkt,
                                const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int tcp_code_dyn_part(struct rohc_comp_ctxt *const context,
                             const struct ip_packet *const ip,
                             const int packet_size __attribute__((unused)),
                             unsigned char *const rohc_pkt,
                             const size_t rohc_pkt_max_len __attribute__((unused)),
                             size_t *const parsed_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 6)));

static uint8_t * tcp_code_static_ipv6_option_part(struct rohc_comp_ctxt *const context,
																  multi_ptr_t mptr,
																  uint8_t protocol,
																  base_header_ip_t base_header);
static uint8_t * tcp_code_dynamic_ipv6_option_part(struct rohc_comp_ctxt *const context,
																	ipv6_option_context_t *const opt_ctxt,
																	multi_ptr_t mptr,
																	uint8_t protocol,
																	base_header_ip_t base_header);
static uint8_t * tcp_code_irregular_ipv6_option_part(struct rohc_comp_ctxt *const context,
																	  ipv6_option_context_t *const opt_ctxt,
																	  multi_ptr_t mptr,
																	  uint8_t protocol,
																	  base_header_ip_t base_header);
static uint8_t * tcp_code_static_ip_part(struct rohc_comp_ctxt *const context,
                                         base_header_ip_t base_header,
                                         multi_ptr_t mptr);
static uint8_t * tcp_code_dynamic_ip_part(const struct rohc_comp_ctxt *context,
                                          ip_context_t *const ip_context,
                                          base_header_ip_t base_header,
                                          multi_ptr_t mptr,
                                          int is_innermost);
static uint8_t * tcp_code_irregular_ip_part(struct rohc_comp_ctxt *const context,
                                            const ip_context_t *const ip_context,
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

static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *const ip,
                          const int packet_size,
                          unsigned char *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 7)));

static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *ip,
                          const int packet_size,
                          unsigned char *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset);
static int co_baseheader(struct rohc_comp_ctxt *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_t *const ip_inner_context,
                         base_header_ip_t base_header,
                         unsigned char *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         const rohc_packet_t packet_type,
                         const tcphdr_t *const tcp,
								 const uint8_t crc)
	__attribute__((nonnull(1, 2, 3, 5, 8), warn_unused_result));


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
	__attribute__((nonnull(1, 2, 2, 3, 5), warn_unused_result));

static bool c_tcp_build_rnd_8(struct rohc_comp_ctxt *const context,
										const ip_context_t *const ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										const uint8_t crc,
										rnd_8_t *const rnd8,
										size_t *const rnd8_len)
	__attribute__((nonnull(1, 2, 3, 5, 7, 8), warn_unused_result));


/*
 * Functions that build the seq_X packets
 */

static size_t c_tcp_build_seq_1(struct rohc_comp_ctxt *const context,
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_1_t *const seq1)
	__attribute__((nonnull(1, 2, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_2(struct rohc_comp_ctxt *const context,
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_2_t *const seq2)
	__attribute__((nonnull(1, 2, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_3(struct rohc_comp_ctxt *const context,
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_3_t *const seq3)
	__attribute__((nonnull(1, 2, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_4(struct rohc_comp_ctxt *const context,
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_4_t *const seq4)
	__attribute__((nonnull(1, 2, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_5(struct rohc_comp_ctxt *const context,
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_5_t *const seq5)
	__attribute__((nonnull(1, 2, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_6(struct rohc_comp_ctxt *const context,
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_6_t *const seq6)
	__attribute__((nonnull(1, 2, 3, 5, 7), warn_unused_result));

static size_t c_tcp_build_seq_7(struct rohc_comp_ctxt *const context,
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_7_t *const seq7)
	__attribute__((nonnull(1, 2, 3, 5, 7), warn_unused_result));

static bool c_tcp_build_seq_8(struct rohc_comp_ctxt *const context,
										const ip_context_t *const ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										const uint8_t crc,
										seq_8_t *const seq8,
										size_t *const seq8_len)
	__attribute__((nonnull(1, 2, 3, 5, 7, 8), warn_unused_result));


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

static bool c_tcp_feedback(struct rohc_comp_ctxt *const context,
                           const struct c_feedback *const feedback)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static bool c_tcp_feedback_2(struct rohc_comp_ctxt *const context,
                             const struct c_feedback *const feedback)
	__attribute__((warn_unused_result, nonnull(1, 2)));


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
	struct sc_tcp_context *tcp_context;
	base_header_ip_t base_header;   // Source
	const tcphdr_t *tcp;
	uint8_t proto;
	size_t size_option;
	size_t i;

	/* create the TCP part of the profile context */
	tcp_context = malloc(sizeof(struct sc_tcp_context));
	if(tcp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the TCP part of the profile context");
		goto error;
	}
	memset(tcp_context, 0, sizeof(struct sc_tcp_context));
	context->specific = tcp_context;

	// Init pointer to the initial packet
	base_header.ipvx = (base_header_ip_vx_t *) packet->outer_ip.data;
	tcp_context->ip_contexts_nr = 0;
	do
	{
		ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[tcp_context->ip_contexts_nr]);

		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);
		ip_context->version = base_header.ipvx->version;
		ip_context->ctxt.vx.version = base_header.ipvx->version;

		switch(base_header.ipvx->version)
		{
			case IPV4:
				ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
				rohc_comp_debug(context, "IP-ID 0x%04x", ip_context->ctxt.v4.last_ip_id);
				ip_context->ctxt.v4.last_ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
				ip_context->ctxt.v4.ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
				/* get the transport protocol */
				proto = base_header.ipv4->protocol;
				ip_context->ctxt.v4.protocol = proto;
				ip_context->ctxt.v4.dscp = base_header.ipv4->dscp;
				ip_context->ctxt.v4.df = base_header.ipv4->df;
				ip_context->ctxt.v4.ttl_hopl = base_header.ipv4->ttl_hopl;
				ip_context->ctxt.v4.src_addr = base_header.ipv4->src_addr;
				ip_context->ctxt.v4.dst_addr = base_header.ipv4->dest_addr;
				++base_header.ipv4;
				break;
			case IPV6:
				ip_context->ctxt.v6.ip_id_behavior = IP_ID_BEHAVIOR_RAND;
				/* get the transport protocol */
				proto = base_header.ipv6->next_header;
				ip_context->ctxt.v6.next_header = proto;
				ip_context->ctxt.v6.dscp = DSCP_V6(base_header.ipv6);
				ip_context->ctxt.v6.ttl_hopl = base_header.ipv6->ttl_hopl;
				ip_context->ctxt.v6.flow_label1 = base_header.ipv6->flow_label1;
				ip_context->ctxt.v6.flow_label2 = base_header.ipv6->flow_label2;
				memcpy(ip_context->ctxt.v6.src_addr,base_header.ipv6->src_addr,sizeof(uint32_t) * 4 * 2);
				++base_header.ipv6;
				rohc_comp_debug(context, "parse IPv6 extension headers");
				ip_context->ctxt.v6.opts_nr = 0;
				while(rohc_is_ipv6_opt(proto))
				{
					ipv6_option_context_t *const ipv6_opt =
						&(ip_context->ctxt.v6.opts[ip_context->ctxt.v6.opts_nr]);

					switch(proto)
					{
						case ROHC_IPPROTO_HOPOPTS:  // IPv6 Hop-by-Hop options
						case ROHC_IPPROTO_ROUTING:  // IPv6 routing header
						case ROHC_IPPROTO_DSTOPTS:  // IPv6 destination options
							size_option = ( base_header.ipv6_opt->length + 1 ) << 3;
							rohc_comp_debug(context, "  IPv6 extension header is %zu-byte long",
							                size_option);
							ipv6_opt->generic.option_length = size_option;
							memcpy(&ipv6_opt->generic.data, &base_header.ipv6_opt->value,
							       size_option - 2);
							break;
						case ROHC_IPPROTO_GRE:
							size_option = base_header.ip_gre_opt->c_flag +
							              base_header.ip_gre_opt->k_flag +
							              base_header.ip_gre_opt->s_flag + 1;
							size_option <<= 3;
							ipv6_opt->gre.c_flag = base_header.ip_gre_opt->c_flag;
							ipv6_opt->gre.k_flag = base_header.ip_gre_opt->k_flag;
							ipv6_opt->gre.s_flag = base_header.ip_gre_opt->s_flag;
							ipv6_opt->gre.protocol = base_header.ip_gre_opt->protocol;
							ipv6_opt->gre.key =
							   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag];
							ipv6_opt->gre.sequence_number =
							   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag +
							                                 base_header.ip_gre_opt->k_flag];
							break;
						case ROHC_IPPROTO_MINE:
							size_option = ( 2 + base_header.ip_mime_opt->s_bit ) << 3;
							ipv6_opt->mime.next_header = base_header.ipv6_opt->next_header;
							ipv6_opt->mime.s_bit = base_header.ip_mime_opt->s_bit;
							ipv6_opt->mime.res_bits = base_header.ip_mime_opt->res_bits;
							ipv6_opt->mime.checksum = base_header.ip_mime_opt->checksum;
							ipv6_opt->mime.orig_dest = base_header.ip_mime_opt->orig_dest;
							ipv6_opt->mime.orig_src = base_header.ip_mime_opt->orig_src;
							break;
						case ROHC_IPPROTO_AH:
							size_option = sizeof(ip_ah_opt_t) - sizeof(uint32_t) +
							              ( base_header.ip_ah_opt->length << 4 ) - sizeof(int32_t);
							ipv6_opt->ah.option_length = size_option;
							ipv6_opt->ah.next_header = base_header.ipv6_opt->next_header;
							ipv6_opt->ah.length = base_header.ip_ah_opt->length;
							ipv6_opt->ah.spi = base_header.ip_ah_opt->spi;
							ipv6_opt->ah.sequence_number =
							   base_header.ip_ah_opt->sequence_number;
							break;
						// case ROHC_IPPROTO_ESP : ???
						default:
							goto free_context;
					}
					proto = base_header.ipv6_opt->next_header;
					base_header.uint8 += size_option;
					ip_context->ctxt.v6.opts_nr++;
				}
				break;
			default:
				goto free_context;
		}

		tcp_context->ip_contexts_nr++;
	}
	while(rohc_is_tunneling(proto) && tcp_context->ip_contexts_nr < ROHC_TCP_MAX_IP_HDRS);

	/* profile cannot handle the packet if it bypasses internal limit of IP headers */
	if(tcp_context->ip_contexts_nr > ROHC_TCP_MAX_IP_HDRS)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "too many IP headers for TCP profile (%u headers max)",
		           ROHC_TCP_MAX_IP_HDRS);
		goto free_context;
	}

	tcp_context->tcp_seq_num_change_count = 0;
	tcp_context->tcp_last_seq_num = -1;

	/* TCP header begins just after the IP headers */
	tcp = (tcphdr_t *) base_header.uint8;
	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(tcphdr_t));

	/* MSN */
	tcp_context->msn_wlsb =
		c_create_wlsb(16, comp->wlsb_window_width, ROHC_LSB_SHIFT_TCP_SN);
	if(tcp_context->msn_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for MSN");
		goto free_context;
	}

	/* IP-ID offset */
	tcp_context->ip_id_wlsb =
		c_create_wlsb(16, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->ip_id_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for IP-ID offset");
		goto free_wlsb_msn;
	}

	/* TCP window offset */
	tcp_context->window_wlsb =
		c_create_wlsb(16, comp->wlsb_window_width, ROHC_LSB_SHIFT_TCP_WINDOW);
	if(tcp_context->window_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP window");
		goto free_wlsb_ip_id;
	}

	/* TCP sequence number */
	tcp_context->seq_num = rohc_ntoh32(tcp->seq_num);
	tcp_context->seq_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->seq_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP sequence number");
		goto free_wlsb_window;
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

	/* init the Master Sequence Number to a random value */
	tcp_context->msn = comp->random_cb(comp, comp->random_cb_ctxt) & 0xffff;
	rohc_comp_debug(context, "MSN = 0x%04x / %u", tcp_context->msn, tcp_context->msn);

	tcp_context->ack_stride = 0;

	/* init the last list of TCP options */
	tcp_context->tcp_opts_list_struct_nr_trans = 0;
	tcp_context->tcp_opts_list_struct_nr = 0;
	// Initialize TCP options list index used
	for(i = 0; i <= MAX_TCP_OPTION_INDEX; i++)
	{
		tcp_context->tcp_options_list[i].used = false;
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
free_wlsb_ip_id:
	c_destroy_wlsb(tcp_context->ip_id_wlsb);
free_wlsb_window:
	c_destroy_wlsb(tcp_context->window_wlsb);
free_wlsb_msn:
	c_destroy_wlsb(tcp_context->msn_wlsb);
free_context:
	free(tcp_context);
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
	struct sc_tcp_context *const tcp_context = context->specific;

	c_destroy_wlsb(tcp_context->opt_ts_reply_wlsb);
	c_destroy_wlsb(tcp_context->opt_ts_req_wlsb);
	c_destroy_wlsb(tcp_context->ack_scaled_wlsb);
	c_destroy_wlsb(tcp_context->ack_wlsb);
	c_destroy_wlsb(tcp_context->seq_scaled_wlsb);
	c_destroy_wlsb(tcp_context->seq_wlsb);
	c_destroy_wlsb(tcp_context->ip_id_wlsb);
	c_destroy_wlsb(tcp_context->window_wlsb);
	c_destroy_wlsb(tcp_context->msn_wlsb);
	free(tcp_context);
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
	const uint8_t *remain_data;
	size_t remain_len;
	size_t ip_hdrs_nr;
	uint8_t next_proto;
	const struct tcphdr *tcp_header;

	assert(comp != NULL);
	assert(packet != NULL);

	remain_data = packet->outer_ip.data;
	remain_len = packet->outer_ip.size;

	/* check that the the versions of IP headers are 4 or 6 and that IP headers
	 * are not IP fragments */
	ip_hdrs_nr = 0;
	do
	{
		ip_version ip_ver;

		/* get IP version */
		if(remain_len < 1)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "uncompressed packet too short for version field of IP "
			           "header #%zu", ip_hdrs_nr + 1);
			goto bad_profile;
		}
		if(!get_ip_version(remain_data, remain_len, &ip_ver))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "failed to determine the version of IP header #%zu",
			           ip_hdrs_nr + 1);
			goto bad_profile;
		}

		if(ip_ver == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;
			const size_t ipv4_min_words_nr = sizeof(struct ipv4_hdr) / sizeof(uint32_t);

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "found IPv4");
			if(remain_len < sizeof(struct ipv4_hdr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "uncompressed packet too short for IP header #%zu",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}

			/* IPv4 options are not supported by the TCP profile */
			if(ipv4->ihl != ipv4_min_words_nr)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: "
				           "IP options are not accepted", ip_hdrs_nr + 1);
				goto bad_profile;
			}

			/* IPv4 total length shall be correct */
			if(rohc_ntoh16(ipv4->tot_len) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: total "
				           "length is %u while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv4->tot_len), remain_len);
				goto bad_profile;
			}

			/* check if the IPv4 header is a fragment */
			if((rohc_ntoh16(ipv4->frag_off) & (~IP_DF)) != 0)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is fragmented", ip_hdrs_nr + 1);
				goto bad_profile;
			}

			/* check if the checksum of the IPv4 header is correct */
			if((comp->features & ROHC_COMP_FEATURE_NO_IP_CHECKSUMS) == 0 &&
			   ip_fast_csum(remain_data, ipv4_min_words_nr) != 0)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not correct (bad checksum)",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}

			next_proto = ipv4->protocol;
			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip_ver == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			size_t ipv6_ext_nr;
			size_t size_option;

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "found IPv6");
			if(remain_len < sizeof(struct ipv6_hdr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "uncompressed packet too short for IP header #%zu",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}
			next_proto = ipv6->ip6_nxt;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* payload length shall be correct */
			if(rohc_ntoh16(ipv6->ip6_plen) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: payload "
				           "length is %u while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv6->ip6_plen), remain_len);
				goto bad_profile;
			}

			ipv6_ext_nr = 0;
			while(rohc_is_ipv6_opt(next_proto) && ipv6_ext_nr < ROHC_TCP_MAX_IPV6_EXT_HDRS)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "  found extension header #%zu of type %u",
				           ipv6_ext_nr + 1, next_proto);
				switch(next_proto)
				{
					case ROHC_IPPROTO_HOPOPTS: // IPv6 Hop-by-Hop options
					case ROHC_IPPROTO_ROUTING: // IPv6 routing header
					case ROHC_IPPROTO_DSTOPTS: // IPv6 destination options
					{
						const struct ipv6_opt *const ipv6_opt =
							(struct ipv6_opt *) remain_data;
						if(remain_len < (sizeof(ipv6_opt) - 1))
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "packet too short for IPv6 extension header");
							goto bad_profile;
						}
						size_option = (ipv6_opt->length + 1) << 3;
						if(remain_len < size_option)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "packet too short for IPv6 extension header");
							goto bad_profile;
						}
						next_proto = ipv6_opt->next_header;
						break;
					}
					case ROHC_IPPROTO_GRE:
					{
						const struct ip_gre_opt *const gre_opt =
							(struct ip_gre_opt *) remain_data;
						if(remain_len < (sizeof(struct ip_gre_opt) - sizeof(uint32_t)))
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "packet too short for GRE header");
							goto bad_profile;
						}
						size_option =
							(gre_opt->c_flag + gre_opt->k_flag + gre_opt->s_flag + 1) << 3;
						if(remain_len < size_option)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "packet too short for GRE header");
							goto bad_profile;
						}
						next_proto = gre_opt->protocol;
						break;
					}
					case ROHC_IPPROTO_MINE:
					{
						const struct ip_mime_opt *const mime_opt =
							(struct ip_mime_opt *) remain_data;
						if(remain_len < sizeof(struct ip_mime_opt))
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "packet too short for MIME header");
							goto bad_profile;
						}
						size_option = (2 + mime_opt->s_bit) << 3;
						if(remain_len < size_option)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "packet too short for MIME header");
							goto bad_profile;
						}
						break;
					}
					case ROHC_IPPROTO_AH:
					{
						const struct ip_ah_opt *const ah_opt =
							(struct ip_ah_opt *) remain_data;
						if(remain_len < (sizeof(struct ip_ah_opt) - sizeof(uint32_t)))
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "packet too short for AH header");
							goto bad_profile;
						}
						size_option = sizeof(ip_ah_opt_t) - sizeof(uint32_t) +
						              (ah_opt->length << 4) - sizeof(int32_t);
						if(remain_len < size_option)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "packet too short for AH header");
							goto bad_profile;
						}
						break;
					}
					// case ROHC_IPPROTO_ESP : ???
					default:
						goto bad_profile;
				}
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "  extension header %zu-byte long", size_option);
				remain_data += size_option;
				remain_len -= size_option;

				ipv6_ext_nr++;
			}

			/* profile cannot handle the packet if it bypasses internal limit of
			 * IPv6 extension headers */
			if(ipv6_ext_nr > ROHC_TCP_MAX_IPV6_EXT_HDRS)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP header #%zu got too many IPv6 extension headers for "
				           "TCP profile (%u headers max)", ip_hdrs_nr + 1,
				           ROHC_TCP_MAX_IPV6_EXT_HDRS);
				goto bad_profile;
			}
		}
		else
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported version %d for header #%zu", ip_ver, ip_hdrs_nr);
			goto bad_profile;
		}
		ip_hdrs_nr++;
	}
	while(rohc_is_tunneling(next_proto) && ip_hdrs_nr < ROHC_TCP_MAX_IP_HDRS);

	/* profile cannot handle the packet if it bypasses internal limit of IP headers */
	if(ip_hdrs_nr > ROHC_TCP_MAX_IP_HDRS)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "too many IP headers for TCP profile (%u headers max)",
		           ROHC_TCP_MAX_IP_HDRS);
		goto bad_profile;
	}

	/* check that the transport protocol is TCP */
	if(next_proto != ROHC_IPPROTO_TCP)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "transport protocol is not TCP");
		goto bad_profile;
	}

	/* innermost IP payload shall be large enough for TCP header */
	if(remain_len < sizeof(struct tcphdr))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "innermost IP payload too small for minimal TCP header");
		goto bad_profile;
	}

	/* retrieve the TCP header */
	tcp_header = (const struct tcphdr *) remain_data;
	if(tcp_header->data_offset < 5)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "TCP data offset too small for minimal TCP header");
		goto bad_profile;
	}
	if(remain_len < (tcp_header->data_offset * sizeof(uint32_t)))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "TCP data too small for full TCP header with options");
		goto bad_profile;
	}

	/* the TCP profile doesn't handle TCP packets with more than 15 options */
	{
		const size_t opts_len =
			tcp_header->data_offset * sizeof(uint32_t) - sizeof(struct tcphdr);
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

			if(opt_type == TCP_OPT_NOP)
			{
				/* 1-byte TCP option NOP */
				opt_len = 1;
			}
			else if(opt_type == TCP_OPT_EOL)
			{
				size_t i;

				/* TCP option EOL consumes all the remaining bytes of options */
				opt_len = opts_len - opts_offset;
				for(i = 0; i < opt_len; i++)
				{
					if(tcp_header->options[opts_offset + i] != TCP_OPT_EOL)
					{
						rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
						           "malformed TCP header: malformed option padding: "
						           "padding byte #%zu is 0x%02x while it should be 0x00",
						           i + 1, tcp_header->options[opts_offset + i]);
						goto bad_profile;
					}
				}
			}
			else
			{
				/* multi-byte TCP options */
				if((opts_offset + 1) >= opts_len)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed TCP header: not enough room for the "
					           "length field of option %u", opt_type);
					goto bad_profile;
				}
				opt_len = tcp_header->options[opts_offset + 1];
				if(opt_len < 2)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed TCP header: option %u got length "
					           "field %zu", opt_type, opt_len);
					goto bad_profile;
				}
				if((opts_offset + opt_len) > opts_len)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed TCP header: not enough room for option %u "
					           "(%zu bytes required but only %zu available)",
					           opt_type, opt_len, opts_len - opts_offset);
					goto bad_profile;
				}

				/* check the length of well-known options in order to avoid using
				 * the TCP profile with malformed TCP packets */
				switch(opt_type)
				{
					case TCP_OPT_EOL:
						assert(opt_len >= 1); /* by definition */
						break;
					case TCP_OPT_NOP:
						assert(opt_len == 1); /* by definition */
						break;
					case TCP_OPT_MSS:
						if(opt_len != TCP_OLEN_MSS)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "malformed TCP option #%zu: unexpected length "
							           "for MSS option: %zu found in packet while %u "
							           "expected", opt_pos + 1, opt_len, TCP_OLEN_MSS);
							goto bad_profile;
						}
						break;
					case TCP_OPT_WS:
						if(opt_len != TCP_OLEN_WS)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "malformed TCP option #%zu: unexpected length "
							           "for WS option: %zu found in packet while %u "
							           "expected", opt_pos + 1, opt_len, TCP_OLEN_WS);
							goto bad_profile;
						}
						break;
					case TCP_OPT_SACK_PERM:
						if(opt_len != TCP_OLEN_SACK_PERM)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "malformed TCP option #%zu: unexpected length "
							           "for SACK Permitted option: %zu found in packet "
							           "while %u expected", opt_pos + 1, opt_len,
							           TCP_OLEN_SACK_PERM);
							goto bad_profile;
						}
						break;
					case TCP_OPT_SACK:
					{
						size_t sack_blocks_remain = (opt_len - 2) % sizeof(sack_block_t);
						size_t sack_blocks_nr = (opt_len - 2) / sizeof(sack_block_t);
						if(sack_blocks_remain != 0 || sack_blocks_nr == 0 || sack_blocks_nr > 4)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "malformed TCP option #%zu: unexpected length "
							           "for SACK option: %zu found in packet while 2 + "
							           "[1-4] * %zu expected", opt_pos + 1, opt_len,
							           sizeof(sack_block_t));
							goto bad_profile;
						}
						break;
					}
					case TCP_OPT_TS:
						if(opt_len != TCP_OLEN_TS)
						{
							rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
							           "malformed TCP option #%zu: unexpected length "
							           "for TS option: %zu found in packet while %u "
							           "expected", opt_pos + 1, opt_len, TCP_OLEN_TS);
							goto bad_profile;
						}
						break;
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
	struct sc_tcp_context *const tcp_context = context->specific;
	base_header_ip_t base_header;   // Source
	size_t ip_hdr_pos;
	uint8_t next_proto = ROHC_IPPROTO_IPIP;
	tcphdr_t *tcp;
	bool is_tcp_same;

	/* parse the IP headers (lengths already checked while checking profile) */
	base_header.ipvx = (base_header_ip_vx_t *) packet->outer_ip.data;
	for(ip_hdr_pos = 0;
	    ip_hdr_pos < tcp_context->ip_contexts_nr && rohc_is_tunneling(next_proto);
	    ip_hdr_pos++)
	{
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		size_t ip_ext_pos;

		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);
		if(base_header.ipvx->version != ip_context->version)
		{
			rohc_comp_debug(context, "  not same IP version");
			goto bad_context;
		}

		switch(base_header.ipvx->version)
		{
			case IPV4:
				if(base_header.ipv4->src_addr != ip_context->ctxt.v4.src_addr ||
				   base_header.ipv4->dest_addr != ip_context->ctxt.v4.dst_addr)
				{
					rohc_comp_debug(context, "  not same IPv4 addresses");
					goto bad_context;
				}
				rohc_comp_debug(context, "  same IPv4 addresses");
				/* get the transport protocol */
				next_proto = base_header.ipv4->protocol;
				if(next_proto != ip_context->ctxt.v4.protocol)
				{
					rohc_comp_debug(context, "  IPv4 not same protocol");
					goto bad_context;
				}
				rohc_comp_debug(context, "  IPv4 same protocol %d", next_proto);
				++base_header.ipv4;
				break;
			case IPV6:
				if(memcmp(base_header.ipv6->src_addr, ip_context->ctxt.v6.src_addr, sizeof(uint32_t) * 4) != 0 ||
				   memcmp(base_header.ipv6->dest_addr, ip_context->ctxt.v6.dest_addr, sizeof(uint32_t) * 4) != 0)
				{
					rohc_comp_debug(context, "  not same IPv6 addresses");
					goto bad_context;
				}
				rohc_comp_debug(context, "  same IPv6 addresses");
				if(base_header.ipv6->flow_label1 != ip_context->ctxt.v6.flow_label1 ||
				   base_header.ipv6->flow_label2 != ip_context->ctxt.v6.flow_label2)
				{
					rohc_comp_debug(context, "  not same IPv6 flow label");
					goto bad_context;
				}
				next_proto = base_header.ipv6->next_header;
				if(next_proto != ip_context->ctxt.v6.next_header)
				{
					rohc_comp_debug(context, "  IPv6 not same protocol %d", next_proto);
					goto bad_context;
				}
				++base_header.ipv6;
				for(ip_ext_pos = 0;
				    ip_ext_pos < ip_context->ctxt.v6.opts_nr && rohc_is_tunneling(next_proto);
				    ip_ext_pos++)
				{
					const ipv6_option_context_t *const opt_ctxt =
						&(ip_context->ctxt.v6.opts[ip_ext_pos]);

					next_proto = base_header.ipv6_opt->next_header;
					if(next_proto != opt_ctxt->generic.next_header)
					{
						rohc_comp_debug(context, "  not same IPv6 option (%d != %d)",
						                next_proto, opt_ctxt->generic.next_header);
						goto bad_context;
					}
					rohc_comp_debug(context, "  same IPv6 option %d", next_proto);
					base_header.uint8 += (base_header.ipv6_opt->length + 1) << 3;
				}
				if(ip_ext_pos < ip_context->ctxt.v6.opts_nr)
				{
					rohc_comp_debug(context, "  less IP extension headers than context");
					goto bad_context;
				}
				if(rohc_is_tunneling(next_proto))
				{
					rohc_comp_debug(context, "  more IP extension headers than context");
					goto bad_context;
				}
				break;
			default:
				assert(0);
				goto bad_context;
		}
	}

	if(ip_hdr_pos < tcp_context->ip_contexts_nr)
	{
		rohc_comp_debug(context, "  less IP headers than context");
		goto bad_context;
	}

	if(rohc_is_tunneling(next_proto))
	{
		rohc_comp_debug(context, "  more IP headers than context");
		goto bad_context;
	}

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
	struct sc_tcp_context *const tcp_context = context->specific;
	ip_context_t *ip_inner_context;
	const tcphdr_t *tcp;
	int counter;
	size_t i;

	assert(rohc_pkt != NULL);

	*packet_type = ROHC_PACKET_UNKNOWN;

	/* at the beginning, no item transmitted for the compressed list of TCP options */
	for(i = 0; i <= MAX_TCP_OPTION_INDEX; i++)
	{
		tcp_context->tmp.is_tcp_opts_list_item_present[i] = false;
	}

	/* detect changes between new uncompressed packet and context */
	if(!tcp_detect_changes(context, uncomp_pkt, &ip_inner_context, &tcp))
	{
		rohc_comp_warn(context, "failed to detect changes in uncompressed packet");
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
	*packet_type = tcp_decide_packet(context, ip_inner_context, tcp);

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
		                         rohc_pkt, rohc_pkt_max_len, *packet_type,
		                         payload_offset);
		if(counter < 0)
		{
			rohc_comp_warn(context, "failed to build CO packet");
			goto error;
		}
	}
	else /* ROHC_PACKET_IR or ROHC_PACKET_IR_DYN */
	{
		assert((*packet_type) == ROHC_PACKET_IR ||
		       (*packet_type) == ROHC_PACKET_IR_DYN);

		counter = code_IR_packet(context, &uncomp_pkt->outer_ip, uncomp_pkt->len,
		                         rohc_pkt, rohc_pkt_max_len, *packet_type,
		                         payload_offset);
		if(counter < 0)
		{
			rohc_comp_warn(context, "failed to build IR(-DYN) packet");
			goto error;
		}
	}
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "current ROHC packet", rohc_pkt, counter);

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
 * @brief Encode an IP/TCP packet as IR or IR-DYN packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param packet_size       The length of the uncompressed packet (in bytes)
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *const ip,
                          const int packet_size __attribute__((unused)),
                          unsigned char *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
{
	multi_ptr_t mptr;
	size_t first_position;
	size_t crc_position;
	size_t counter;
	int ret;

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type,
	                      context->cid, rohc_pkt, rohc_pkt_max_len,
	                      &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the %zu-byte "
		               "ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_pkt_max_len);
		goto error;
	}
	counter = ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %zu byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* part 2: type of packet */
	if(packet_type == ROHC_PACKET_IR)
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

	/* add static chain for IR packet only */
	if(packet_type == ROHC_PACKET_IR)
	{
		ret = tcp_code_static_part(context, ip, packet_size, rohc_pkt + counter,
		                           rohc_pkt_max_len - counter);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to code static chain of the IR packet");
			goto error;
		}
		counter += ret;
		mptr.uint8 += ret;
		rohc_dump_buf(context->compressor->trace_callback,
		              context->compressor->trace_callback_priv,
		              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
		              "current ROHC packet (with static part)", rohc_pkt, counter);
	}

	/* add dynamic chain */
	ret = tcp_code_dyn_part(context, ip, packet_size, rohc_pkt + counter,
	                        rohc_pkt_max_len - counter, payload_offset);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to code static chain of the IR packet");
		goto error;
	}
	counter += ret;
	mptr.uint8 += ret;
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "current ROHC packet (with dynamic part)", rohc_pkt, counter);

	/* part 5 */
	rohc_pkt[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt,
	                                       counter, CRC_INIT_8,
	                                       context->compressor->crc_table_8);
	rohc_comp_debug(context, "CRC (header length = %zu, crc = 0x%x)",
	                counter, rohc_pkt[crc_position]);

	rohc_comp_debug(context, "IR(-DYN) packet, length %zu", counter);
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "current ROHC packet", rohc_pkt, counter);

	return counter;

error:
	return -1;
}


/**
 * @brief Code the static part of an IR packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param packet_size       The length of the uncompressed packet (in bytes)
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int tcp_code_static_part(struct rohc_comp_ctxt *const context,
                                const struct ip_packet *const ip,
                                const int packet_size __attribute__((unused)),
                                unsigned char *const rohc_pkt,
                                const size_t rohc_pkt_max_len __attribute__((unused)))
{
	struct sc_tcp_context *const tcp_context = context->specific;
	base_header_ip_t base_header;
	multi_ptr_t mptr;
	size_t ip_hdr_pos;
	uint8_t protocol;

	base_header.ipvx = (base_header_ip_vx_t *) ip->data;
	mptr.uint8 = rohc_pkt;

	/* add IP parts of static chain */
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		size_t ip_ext_pos;

		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

		if(base_header.ipvx->version == IPV4)
		{
			mptr.uint8 = tcp_code_static_ip_part(context, base_header, mptr);
			/* get the transport protocol */
			protocol = base_header.ipv4->protocol;
			base_header.ipv4++;
		}
		else if(base_header.ipvx->version == IPV6)
		{
			mptr.uint8 = tcp_code_static_ip_part(context, base_header, mptr);
			protocol = base_header.ipv6->next_header;
			base_header.ipv6++;
			for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
			{
				const ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);

				rohc_comp_debug(context, "IPv6 option #%zu: type %u / length %zu",
				                ip_ext_pos + 1, protocol,
				                opt_ctxt->generic.option_length);
				mptr.uint8 = tcp_code_static_ipv6_option_part(context, mptr,
				                                              protocol, base_header);
				if(mptr.uint8 == NULL)
				{
					rohc_comp_warn(context, "failed to code the IPv6 extension part "
					               "of the static chain");
					goto error;
				}
				protocol = base_header.ipv6_opt->next_header;
				base_header.uint8 += opt_ctxt->generic.option_length;
			}
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u",
			               base_header.ipvx->version);
			assert(0);
			goto error;
		}
		rohc_comp_debug(context, "counter = %d, protocol = %d",
		                (int)(mptr.uint8 - rohc_pkt), protocol);
	}

	/* add TCP static part */
	mptr.uint8 = tcp_code_static_tcp_part(context, base_header.tcphdr, mptr);

	return (mptr.uint8 - rohc_pkt);

error:
	return -1;
}


/**
 * @brief Code the dynamic part of an IR or IR-DYN packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param packet_size       The length of the uncompressed packet (in bytes)
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param[out] parsed_len   The length of uncompressed data parsed
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int tcp_code_dyn_part(struct rohc_comp_ctxt *const context,
                             const struct ip_packet *const ip,
                             const int packet_size __attribute__((unused)),
                             unsigned char *const rohc_pkt,
                             const size_t rohc_pkt_max_len __attribute__((unused)),
                             size_t *const parsed_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	base_header_ip_t base_header;
	multi_ptr_t mptr;
	size_t ip_hdr_pos;
	uint8_t protocol;

	base_header.ipvx = (base_header_ip_vx_t *) ip->data;
	mptr.uint8 = rohc_pkt;

	/* add dynamic chain for both IR and IR-DYN packet */
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const bool is_inner = (ip_hdr_pos + 1 == tcp_context->ip_contexts_nr);
		size_t ip_ext_pos;

		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

		mptr.uint8 = tcp_code_dynamic_ip_part(context, ip_context, base_header,
		                                      mptr, is_inner);

		if(base_header.ipvx->version == IPV4)
		{
			/* get the transport protocol */
			protocol = base_header.ipv4->protocol;
			base_header.ipv4++;
		}
		else if(base_header.ipvx->version == IPV6)
		{
			protocol = base_header.ipv6->next_header;
			base_header.ipv6++;
			for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
			{
				ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);

				rohc_comp_debug(context, "IPv6 option %u", protocol);
				mptr.uint8 =
				   tcp_code_dynamic_ipv6_option_part(context, opt_ctxt, mptr,
				                                     protocol, base_header);
				if(mptr.uint8 == NULL)
				{
					rohc_comp_warn(context, "failed to code the IPv6 extension part "
					               "of the dynamic chain");
					goto error;
				}
				protocol = base_header.ipv6_opt->next_header;
				base_header.uint8 += opt_ctxt->generic.option_length;
			}
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u",
			               base_header.ipvx->version);
			assert(0);
			goto error;
		}
	}

	/* add TCP dynamic part */
	mptr.uint8 = tcp_code_dynamic_tcp_part(context, base_header.uint8, mptr);
	if(mptr.uint8 == NULL)
	{
		rohc_comp_warn(context, "failed to code the TCP part of the dynamic chain");
		goto error;
	}

	/* skip TCP options */
	base_header.uint8 += (base_header.tcphdr->data_offset << 2);
	*parsed_len = (base_header.uint8 - ip->data);

	return (mptr.uint8 - rohc_pkt);

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
	size_t size;
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
			mptr.ip_rout_opt_static->length = base_header.ipv6_opt->length;
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
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv6 option static part", mptr.uint8, size);
#endif

	return mptr.uint8 + size;

error:
	return NULL;
}


/**
 * @brief Build the dynamic part of the IPv6 option header.
 *
 * @param context      The compression context
 * @param opt_ctxt     The compression context of the IPv6 option
 * @param mptr         The current pointer in the rohc-packet-under-build buffer
 * @param protocol     The IPv6 protocol option
 * @param base_header  The IP header
 * @return             The new pointer in the rohc-packet-under-build buffer,
 *                     NULL if a problem occurs
 */
static uint8_t * tcp_code_dynamic_ipv6_option_part(struct rohc_comp_ctxt *const context,
																	ipv6_option_context_t *const opt_ctxt,
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
			memcpy(opt_ctxt->generic.data, base_header.ipv6_opt->value, size);
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
				opt_ctxt->gre.sequence_number =
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
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv6 option dynamic part", mptr.uint8, size);
#endif

	return mptr.uint8 + size;

error:
	return NULL;
}


/**
 * @brief Build the irregular part of the IPv6 option header.
 *
 * @param context      The compression context
 * @param opt_ctxt     The compression context of the IPv6 option
 * @param mptr         The current pointer in the rohc-packet-under-build buffer
 * @param protocol     The IPv6 protocol option
 * @param base_header  The IP header
 * @return             The new pointer in the rohc-packet-under-build buffer,
 *                     NULL if a problem occurs
 */
static uint8_t * tcp_code_irregular_ipv6_option_part(struct rohc_comp_ctxt *const context,
																	  ipv6_option_context_t *const opt_ctxt,
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
				uint8_t *ptr2 = (uint8_t*) base_header.ip_gre_opt->datas;
				*(mptr.uint8++) = *ptr2++;
				*(mptr.uint8++) = *ptr2;
			}
			// sequence_number =:= optional_lsb_7_or_31(s_flag.UVALUE)
			if(base_header.ip_gre_opt->s_flag != 0)
			{
				sequence_number = rohc_ntoh32(base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag]);
				ret = c_lsb_7_or_31(opt_ctxt->gre.sequence_number,
				                    sequence_number, mptr.uint8);
				if(ret < 0)
				{
					rohc_comp_warn(context, "lsb_7_or_31(seq_number)");
					goto error;
				}
				mptr.uint8 += ret;
				opt_ctxt->gre.sequence_number =
				   base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag];
			}
			break;
		case ROHC_IPPROTO_AH:
			sequence_number = rohc_ntoh32(base_header.ip_ah_opt->sequence_number);
			ret = c_lsb_7_or_31(opt_ctxt->ah.sequence_number,
			                    sequence_number, mptr.uint8);
			if(ret < 0)
			{
				rohc_comp_warn(context, "lsb_7_or_31(seq_number) failed");
				goto error;
			}
			mptr.uint8 += ret;
			opt_ctxt->ah.sequence_number = sequence_number;
			size = (base_header.ip_ah_opt->length - 1) << 3;
			memcpy(mptr.uint8,base_header.ip_ah_opt->auth_data,size);
			mptr.uint8 += size;
			break;
		default:
			break;
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv6 option irregular part", mptr.uint8, mptr.uint8 - ptr);
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
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IP static part", mptr.uint8, size);
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
                                          ip_context_t *const ip_context,
                                          base_header_ip_t base_header,
                                          multi_ptr_t mptr,
                                          int is_innermost)
{
	int size;

	if(base_header.ipvx->version == IPV4)
	{
		uint16_t ip_id;

		assert( ip_context->ctxt.v4.version == IPV4 );

		/* Read the IP_ID */
		ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
		rohc_comp_debug(context, "ip_id_behavior = %d, last IP-ID = 0x%04x, "
		                "IP-ID = 0x%04x", ip_context->ctxt.v4.ip_id_behavior,
		                ip_context->ctxt.v4.last_ip_id, ip_id);

		mptr.ipv4_dynamic1->reserved = 0;
		mptr.ipv4_dynamic1->df = base_header.ipv4->df;
		// cf RFC4996 page 60/61 ip_id_behavior_choice() and ip_id_enc_dyn()
		if(is_innermost)
		{
			// All behavior values possible
			mptr.ipv4_dynamic1->ip_id_behavior = ip_context->ctxt.v4.ip_id_behavior;
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
			ip_context->ctxt.v4.ip_id_behavior = mptr.ipv4_dynamic1->ip_id_behavior;
		}
		ip_context->ctxt.v4.last_ip_id_behavior = ip_context->ctxt.v4.ip_id_behavior;
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
			uint16_t ip_id_nbo;

			if(mptr.ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
			{
				ip_id_nbo = swab16(base_header.ipv4->ip_id);
			}
			else
			{
				ip_id_nbo = base_header.ipv4->ip_id;
			}
			mptr.ipv4_dynamic2->ip_id = ip_id_nbo;
			rohc_comp_debug(context, "ip_id_behavior = %d, IP-ID = 0x%04x",
			                mptr.ipv4_dynamic1->ip_id_behavior,
			                rohc_ntoh16(ip_id_nbo));
			size = sizeof(ipv4_dynamic2_t);
		}

		ip_context->ctxt.v4.dscp = base_header.ipv4->dscp;
		ip_context->ctxt.v4.ttl_hopl = base_header.ipv4->ttl_hopl;
		ip_context->ctxt.v4.df = base_header.ipv4->df;
		ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(base_header.ipv4->ip_id);
	}
	else
	{
		assert( ip_context->ctxt.v6.version == IPV6 );

		mptr.ipv6_dynamic->dscp = DSCP_V6(base_header.ipv6);
		mptr.ipv6_dynamic->ip_ecn_flags = base_header.ipv6->ip_ecn_flags;
		mptr.ipv6_dynamic->ttl_hopl = base_header.ipv6->ttl_hopl;

		ip_context->ctxt.v6.dscp = DSCP_V6(base_header.ipv6);
		ip_context->ctxt.v6.ttl_hopl = base_header.ipv6->ttl_hopl;

		size = sizeof(ipv6_dynamic_t);
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IP dynamic part", mptr.uint8, size);
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
                                            const ip_context_t *const ip_context,
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
	                base_header.ipvx->version, ip_context->ctxt.v4.ip_id_behavior);

	if(base_header.ipvx->version == IPV4)
	{

		// ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE )
		if(ip_context->ctxt.v4.ip_id_behavior == IP_ID_BEHAVIOR_RAND)
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
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IP irregular part", rohc_data_orig,
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
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "TCP header", (unsigned char *) tcp, sizeof(tcphdr_t));

	mptr.tcp_static->src_port = tcp->src_port;
	rohc_comp_debug(context, "TCP source port = %d (0x%04x)",
	                rohc_ntoh16(tcp->src_port), rohc_ntoh16(tcp->src_port));

	mptr.tcp_static->dst_port = tcp->dst_port;
	rohc_comp_debug(context, "TCP destination port = %d (0x%04x)",
	                rohc_ntoh16(tcp->dst_port), rohc_ntoh16(tcp->dst_port));

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "TCP static part", mptr.uint8, sizeof(tcp_static_t));

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
	struct sc_tcp_context *const tcp_context = context->specific;
	const tcphdr_t *tcp;
	tcp_dynamic_t *tcp_dynamic;
	unsigned char *options;
	int options_length;
	int indicator;
	int ret;

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

	tcp_dynamic->msn = rohc_hton16(tcp_context->msn);
	tcp_dynamic->seq_num = tcp->seq_num;

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
	ret = c_static_or_irreg16(false /* TODO */, rohc_hton16(tcp_context->ack_stride),
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

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG, "TCP dynamic part",
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
		rohc_dump_buf(context->compressor->trace_callback,
		              context->compressor->trace_callback_priv,
		              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
		              "TCP options", options, options_length);

		/* Save the begin of the list */
		pBeginList = mptr.uint8++;
		/* List is empty */
		*pBeginList = 0;

		for(i = options_length, opt_pos = 0;
		    i > 0 && opt_pos < tcp_context->tmp.tcp_opts_nr;
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
					assert(opt_len == 1);
					rohc_comp_debug(context, "TCP option EOL");
					break;
				case TCP_OPT_NOP: // No Operation
					assert(opt_len == 1);
					rohc_comp_debug(context, "TCP option NOP");
					break;
				case TCP_OPT_MSS: // Max Segment Size
					if(opt_len != TCP_OLEN_MSS)
					{
						rohc_comp_warn(context, "malformed TCP option #%zu: unexpected "
						               "length for MSS option: %u found in packet while "
						               "%u expected", opt_pos + 1, opt_len, TCP_OLEN_MSS);
						goto error;
					}
					memcpy(&tcp_context->tcp_option_maxseg,options + 2,2);
					rohc_comp_debug(context, "TCP option MAXSEG = %d (0x%x)",
					                rohc_ntoh16(tcp_context->tcp_option_maxseg),
					                rohc_ntoh16(tcp_context->tcp_option_maxseg));
					break;
				case TCP_OPT_WS: // Window
					if(opt_len != TCP_OLEN_WS)
					{
						rohc_comp_warn(context, "malformed TCP option #%zu: unexpected "
						               "length for WS option: %u found in packet while "
						               "%u expected", opt_pos + 1, opt_len, TCP_OLEN_WS);
						goto error;
					}
					rohc_comp_debug(context, "TCP option WINDOW = %d",
					                *(options + 2));
					tcp_context->tcp_option_window = *(options + 2);
					break;
				case TCP_OPT_SACK_PERM: // see RFC2018
					if(opt_len != TCP_OLEN_SACK_PERM)
					{
						rohc_comp_warn(context, "malformed TCP option #%zu: unexpected "
						               "length for SACK Permitted option: %u found in "
						               "packet while %u expected", opt_pos + 1, opt_len,
						               TCP_OLEN_SACK_PERM);
						goto error;
					}
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
					memcpy(tcp_context->tcp_option_sackblocks, options + 1,
					       tcp_context->tcp_option_sack_length);
					break;
				case TCP_OPT_TS:
				{
					const struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (options + 2);

					if(opt_len != TCP_OLEN_TS)
					{
						rohc_comp_warn(context, "malformed TCP option #%zu: unexpected "
						               "length for TS option: %u found in packet while "
						               "%u expected", opt_pos + 1, opt_len, TCP_OLEN_TS);
						goto error;
					}

					rohc_comp_debug(context, "TCP option TIMESTAMP = 0x%04x 0x%04x",
					                rohc_ntoh32(opt_ts->ts), rohc_ntoh32(opt_ts->ts_reply));

					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;
					tcp_context->tcp_option_timestamp_init = true;
					c_add_wlsb(tcp_context->opt_ts_req_wlsb, tcp_context->msn,
					           rohc_ntoh32(opt_ts->ts));
					c_add_wlsb(tcp_context->opt_ts_reply_wlsb, tcp_context->msn,
					           rohc_ntoh32(opt_ts->ts_reply));
					break;
				}
				default:
				{
					/* TODO: check max length */
					// Save length
					assert(opt_len >= 2);
					assert(tcp_context->tcp_options_list[opt_idx].used);
					tcp_context->tcp_options_list[opt_idx].value[0] = opt_len - 2;
					// Save value
					memcpy(tcp_context->tcp_options_list[opt_idx].value + 1, options + 2,
					       tcp_context->tcp_options_list[opt_idx].value[0]);
					break;
				}
			}
			assert(tcp_context->tcp_options_list[opt_idx].used);
			tcp_context->tcp_options_list[opt_idx].nr_trans++;

			// Update length
			switch(*options)
			{
				case TCP_OPT_EOL: // End Of List
					i = 0; /* consume all remaining bytes of options */
					++options;
					break;
				case TCP_OPT_NOP: // No Operation
					--i;
					++options;
					break;
				case TCP_OPT_MSS: // Max Segment Size
					i -= TCP_OLEN_MSS;
					options += TCP_OLEN_MSS;
					break;
				case TCP_OPT_WS: // Window
					i -= TCP_OLEN_WS;
					options += TCP_OLEN_WS;
					break;
				case TCP_OPT_SACK_PERM: // see RFC2018
					i -= TCP_OLEN_SACK_PERM;
					options += TCP_OLEN_SACK_PERM;
					break;
				case TCP_OPT_SACK:
					i -= opt_len;
					options += opt_len;
					break;
				case TCP_OPT_TS:
					i -= TCP_OLEN_TS;
					options += TCP_OLEN_TS;
					break;
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
				case TCP_OPT_MSS:
					/* COMPRESSED mss_list_item {
					 *   mss =:= irregular(16) [ 16 ];
					 * }
					 */
					rohc_comp_debug(context, "  item MSS");
					memcpy(mptr.uint8, options + 2, sizeof(uint16_t));
					mptr.uint8 += sizeof(uint16_t);
					/* skip option */
					i -= TCP_OLEN_MSS;
					options += TCP_OLEN_MSS;
					break;
				case TCP_OPT_WS:
					/* COMPRESSED wscale_list_item {
					 *   wscale =:= irregular(8) [ 8 ];
					 * }
					 */
					rohc_comp_debug(context, "  item WSCALE");
					*(mptr.uint8) = options[2];
					mptr.uint8++;
					/* skip option */
					i -= TCP_OLEN_WS;
					options += TCP_OLEN_WS;
					break;
				case TCP_OPT_TS:
					/* COMPRESSED tsopt_list_item {
					 *   tsval  =:= irregular(32) [ 32 ];
					 *   tsecho =:= irregular(32) [ 32 ];
					 * }
					 */
					rohc_comp_debug(context, "  item Timestamp");
					memcpy(mptr.uint8, options + 2, sizeof(uint32_t) * 2);
					mptr.uint8 += sizeof(uint32_t) * 2;
					/* skip option */
					i -= TCP_OLEN_TS;
					options += TCP_OLEN_TS;
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
				case TCP_OPT_SACK_PERM:
					/* COMPRESSED sack_permitted_list_item {
					 * }
					 */
					rohc_comp_debug(context, "  item SACK permitted: empty");
					/* skip option */
					i -= TCP_OLEN_SACK_PERM;
					options += TCP_OLEN_SACK_PERM;
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

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG, "TCP dynamic part",
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
	struct sc_tcp_context *const tcp_context = context->specific;
	uint8_t *remain_data = rohc_data;
	bool is_ok;

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
		    opt_idx <= MAX_TCP_OPTION_INDEX && opts_offset < opts_len;
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

				if(opt_type == TCP_OPT_TS)
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
					c_add_wlsb(tcp_context->opt_ts_req_wlsb, tcp_context->msn,
					           rohc_ntoh32(opt_ts->ts));
					c_add_wlsb(tcp_context->opt_ts_reply_wlsb, tcp_context->msn,
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
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "TCP irregular part", rohc_data, remain_data - rohc_data);
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
	else if(sack_field < 0x20000000)
	{
		/* discriminator '110' */
		*(ptr++) = 0xc0 | ((sack_field >> 24) & 0x1f);
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
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG, "TCP option SACK",
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
 * @brief Parse the uncompressed TCP options for changes
 *
 * @param context        The compression context
 * @param tcp            The TCP header
 * @param[out] opts_len  The length (in bytes) of the TCP options
 * @return               true if the TCP options were successfully parsed and
 *                       can be compressed, false otherwise
 */
static bool tcp_detect_options_changes(struct rohc_comp_ctxt *const context,
                                       const tcphdr_t *const tcp,
                                       size_t *const opts_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	uint8_t *opts;
	size_t opt_pos;
	size_t opt_len;
	size_t opts_offset;
	size_t opts_nr = 0;
	uint8_t opt_idx;

	tcp_context->tmp.is_tcp_opts_list_struct_changed = false;
	tcp_context->tmp.opt_ts_present = false;
	tcp_context->tmp.tcp_opts_nr = 0;
	tcp_context->tmp.tcp_opts_idx_max = 0;

	opts = ((uint8_t *) tcp) + sizeof(tcphdr_t);
	*opts_len = (tcp->data_offset << 2) - sizeof(tcphdr_t);

	rohc_comp_debug(context, "parse %zu-byte TCP options", *opts_len);

	for(opt_idx = TCP_INDEX_GENERIC7; opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
	{
		if(tcp_context->tcp_options_list[opt_idx].used)
		{
			tcp_context->tcp_options_list[opt_idx].age++;
		}
	}

	for(opt_pos = 0, opts_offset = 0;
	    opt_pos < ROHC_TCP_OPTS_MAX && opts_offset < (*opts_len);
	    opt_pos++, opts_offset += opt_len)
	{
		const uint8_t opt_type = opts[opts_offset];

		rohc_comp_debug(context, "  TCP option %u found", opt_type);

		if(opt_type == TCP_OPT_NOP)
		{
			/* 1-byte TCP option NOP */
			opt_len = 1;
		}
		else if(opt_type == TCP_OPT_EOL)
		{
			/* TCP option EOL consumes all the remaining bytes of options */
			opt_len = (*opts_len) - opts_offset;
		}
		else
		{
			/* multi-byte TCP options: check minimal length and get length */
			if((opts_offset + 1) >= (*opts_len))
			{
				rohc_comp_warn(context, "malformed TCP header: not enough room "
				               "for length field of option %u", opt_type);
				goto error;
			}
			opt_len = opts[opts_offset + 1];
			if(opt_len < 2)
			{
				rohc_comp_warn(context, "malformed TCP header: option %u is "
				               "%zu-byte length, but it should be at least "
				               "2-byte length", opt_type, opt_len);
				goto error;
			}
			if((opts_offset + opt_len) > (*opts_len))
			{
				rohc_comp_warn(context, "malformed TCP header: not enough room "
				               "for option %u (%zu bytes required but only %zu "
				               "available)", opt_type, opt_len,
				               (*opts_len) - opts_offset);
				goto error;
			}

			if(opt_type == TCP_OPT_TS)
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
		rohc_comp_debug(context, "    option is %zu-byte long", opt_len);

		/* determine the index of the TCP option */
		if(opt_type < TCP_LIST_ITEM_MAP_LEN && tcp_options_index[opt_type] >= 0)
		{
			/* TCP option got a reserved index */
			opt_idx = tcp_options_index[opt_type];
			rohc_comp_debug(context, "    option '%s' (%u) will use reserved "
			                "index %u", tcp_opt_get_descr(opt_type), opt_type,
			                opt_idx);
		}
		else /* TCP option doesn't have a reserved index */
		{
			int opt_idx_free = -1;
			size_t oldest_idx = 0;
			size_t oldest_idx_age = 0;

			/* find the index that was used for the same option in previous
			 * packets, or the first unused one */
			for(opt_idx = TCP_INDEX_GENERIC7;
			    opt_idx_free < 0 && opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
			{
				if(tcp_context->tcp_options_list[opt_idx].used &&
				   tcp_context->tcp_options_list[opt_idx].type == opt_type)
				{
					opt_idx_free = opt_idx;
				}
			}
			for(opt_idx = TCP_INDEX_GENERIC7;
			    opt_idx_free < 0 && opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
			{
				if(!tcp_context->tcp_options_list[opt_idx].used)
				{
					opt_idx_free = opt_idx;
				}
			}
			if(opt_idx_free < 0)
			{
				for(opt_idx = TCP_INDEX_GENERIC7; opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
				{
					if(tcp_context->tcp_options_list[opt_idx].used &&
					   tcp_context->tcp_options_list[opt_idx].age > oldest_idx_age)
					{
					   oldest_idx_age = tcp_context->tcp_options_list[opt_idx].age;
						oldest_idx = opt_idx;
					}
				}
				opt_idx_free = oldest_idx;
			}
			opt_idx = opt_idx_free;
		}
		if(tcp_context->tcp_options_list[opt_idx].used)
		{
			rohc_comp_debug(context, "    option '%s' (%u) will use same "
			                "index %u as in previous packet",
			                tcp_opt_get_descr(opt_type), opt_type, opt_idx);
			if(tcp_context->tcp_options_list[opt_idx].age > 0)
			{
				tcp_context->tcp_options_list[opt_idx].age--;
			}
		}
		else
		{
			/* now index used by this option */
			tcp_context->tcp_options_list[opt_idx].used = true;
			tcp_context->tcp_options_list[opt_idx].type = opt_type;
			tcp_context->tcp_options_list[opt_idx].nr_trans = 0;
			tcp_context->tcp_options_list[opt_idx].age = 0;
			rohc_comp_debug(context, "    option '%s' (%u) will use new index %u",
			                tcp_opt_get_descr(opt_type), opt_type, opt_idx);
		}
		tcp_context->tmp.tcp_opts_list_indexes[opt_pos] = opt_idx;
		tcp_context->tmp.tcp_opts_nr++;
		if(opt_idx > tcp_context->tmp.tcp_opts_idx_max)
		{
			tcp_context->tmp.tcp_opts_idx_max = opt_idx;
		}

		/* was the TCP option present at the very same location in previous
		 * packet? */
		if(opt_pos >= tcp_context->tcp_opts_list_struct_nr ||
		   tcp_context->tcp_opts_list_struct[opt_pos] != opt_type)
		{
			rohc_comp_debug(context, "    option was not present at the very "
			                "same location in previous packet");
			tcp_context->tmp.is_tcp_opts_list_struct_changed = true;
		}
		else
		{
			rohc_comp_debug(context, "    option was at the very same location "
			                "in previous packet");
		}

		/* record the structure of the current list TCP options in context */
		tcp_context->tcp_opts_list_struct[opt_pos] = opt_type;
	}
	if(opt_pos >= ROHC_TCP_OPTS_MAX && opts_offset != (*opts_len))
	{
		rohc_comp_warn(context, "unexpected TCP header: too many TCP options: "
		               "%zu options found in packet but only %u options "
		               "possible", opt_pos, ROHC_TCP_OPTS_MAX);
		goto error;
	}
	opts_nr = opt_pos;

	/* fewer options than in previous packet? */
	for(opt_pos = opts_nr; opt_pos < tcp_context->tcp_opts_list_struct_nr; opt_pos++)
	{
		rohc_comp_debug(context, "  TCP option %d is not present anymore",
		                tcp_context->tcp_opts_list_struct[opt_pos]);
		tcp_context->tmp.is_tcp_opts_list_struct_changed = true;
	}

	if(tcp_context->tmp.is_tcp_opts_list_struct_changed)
	{
		/* the new structure has never been transmitted yet */
		rohc_comp_debug(context, "structure of TCP options list changed, "
		                "compressed list must be transmitted in the compressed "
		                "base header");
		tcp_context->tcp_opts_list_struct_nr = opts_nr;
		tcp_context->tcp_opts_list_struct_nr_trans = 0;
	}
	else if(tcp_context->tcp_opts_list_struct_nr_trans <
	        context->compressor->list_trans_nr)
	{
		/* the structure was transmitted but not enough times */
		rohc_comp_debug(context, "structure of TCP options list changed in "
		                "the last few packets, compressed list must be "
		                "transmitted at least %zu times more in the compressed "
		                "base header", context->compressor->list_trans_nr -
		                tcp_context->tcp_opts_list_struct_nr_trans);
		tcp_context->tmp.is_tcp_opts_list_struct_changed = true;
		assert(tcp_context->tcp_opts_list_struct_nr == opts_nr);
		tcp_context->tcp_opts_list_struct_nr_trans++;
	}
	else
	{
		rohc_comp_debug(context, "structure of TCP options list is unchanged, "
		                "compressed list may be omitted from the compressed "
		                "base header, any content changes may be transmitted "
		                "in the irregular chain");
		assert(tcp_context->tcp_opts_list_struct_nr == opts_nr);
	}

	/* use 4-bit XI or 8-bit XI ? */
	if(tcp_context->tmp.tcp_opts_idx_max <= 7)
	{
		rohc_comp_debug(context, "compressed TCP options list will be able to "
		                "use 4-bit XI since the largest index is %u",
		                tcp_context->tmp.tcp_opts_idx_max);
	}
	else
	{
		assert(tcp_context->tmp.tcp_opts_idx_max <= MAX_TCP_OPTION_INDEX);
		rohc_comp_debug(context, "compressed TCP options list will use 8-bit "
		                "XI since the largest index is %u",
		                tcp_context->tmp.tcp_opts_idx_max);
	}

	return true;

error:
	return false;
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
	struct sc_tcp_context *const tcp_context = context->specific;
	uint8_t compressed_options[40];
	uint8_t *ptr_compressed_options;
	uint8_t *options;
	int options_length;
	uint8_t m;
	int i;

	assert(tcp != NULL);
	assert(comp_opts != NULL);
	assert(comp_opts_len != NULL);

	/* retrieve TCP options */
	options = ((uint8_t *) tcp) + sizeof(tcphdr_t);
	options_length = (tcp->data_offset << 2) - sizeof(tcphdr_t);
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "TCP options", options, options_length);

	/* number and type of XI fields: will be set after list processing */
	*comp_opts_len = 0;
	comp_opts[*comp_opts_len] = 0;
	(*comp_opts_len)++;

	ptr_compressed_options = compressed_options;

	// see RFC4996 page 25-26
	for(m = 0, i = options_length; m < tcp_context->tmp.tcp_opts_nr && i > 0; m++)
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
		assert(tcp_context->tcp_options_list[opt_idx].used);

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

		if(i < opt_len)
		{
			rohc_comp_warn(context, "malformed TCP option #%u: available data should "
			               "be at least %u bytes but is %u-byte long only", m + 1,
			               opt_len, i);
			goto error;
		}

		// If option already used
		if(tcp_context->tcp_options_list[opt_idx].nr_trans > 0)
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
				case TCP_INDEX_MSS: // Max Segment Size
					                 // If same value that in the context
					if(memcmp(&tcp_context->tcp_option_maxseg,options + 2,2) == 0)
					{
						i -= TCP_OLEN_MSS;
						options += TCP_OLEN_MSS;
						item_needed = false;
					}
					else
					{
						item_needed = true;
					}
					break;
				case TCP_INDEX_WS: // Window
					                // If same value that in the context
					if(tcp_context->tcp_option_window == *(options + 2) )
					{
						i -= TCP_OLEN_WS;
						options += TCP_OLEN_WS;
						item_needed = false;
					}
					else
					{
						item_needed = true;
					}
					break;
				case TCP_INDEX_TS:
				{
					if(memcmp(&tcp_context->tcp_option_timestamp, options + 2,
								 sizeof(struct tcp_option_timestamp)) == 0)
					{
						i -= TCP_OLEN_TS;
						options += TCP_OLEN_TS;
						item_needed = false;
					}
					else
					{
						item_needed = true;
					}
					break;
				}
				case TCP_INDEX_SACK_PERM: // see RFC2018
					i -= TCP_OLEN_SACK_PERM;
					options += TCP_OLEN_SACK_PERM;
					item_needed = false;
					break;
				case TCP_INDEX_SACK: // see RFC2018
					if(tcp_context->tcp_option_sack_length == *(options + 1) &&
					   memcmp(tcp_context->tcp_option_sackblocks, options + 2,*(options + 1)) == 0)
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
						i -= opt_len;
						options += opt_len;
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
				case TCP_INDEX_SACK_PERM: // see RFC2018
					i -= TCP_OLEN_SACK_PERM;
					options += TCP_OLEN_SACK_PERM;
					item_needed = false;
					break;
				case TCP_INDEX_MSS: // Max Segment Size
				case TCP_INDEX_WS:
				case TCP_INDEX_TS:
				case TCP_INDEX_SACK:
				default:
				{
					item_needed = true;
					// Save length
					assert(opt_len >= 2);
					tcp_context->tcp_options_list[opt_idx].value[0] = opt_len - 2;
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
			                "index %u do%s transmit an item", m, opt_idx,
			                item_needed ? "" : " not");
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
			                "index %u do%s transmit an item", m, opt_idx,
			                item_needed ? "" : " not");
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
				case TCP_OPT_NOP: // No Operation
				case TCP_OPT_EOL: // End Of List
				case TCP_OPT_SACK_PERM: // see RFC2018
					assert(0); /* those options should never need an item */
					break;
				case TCP_OPT_MSS: // Max Segment Size
					// see RFC4996 page 64
					options += 2;
					*(ptr_compressed_options++) = *(options++);
					comp_opt_len++;
					*(ptr_compressed_options++) = *(options++);
					comp_opt_len++;
					i -= TCP_OLEN_MSS;
					break;
				case TCP_OPT_WS: // Window
					// see RFC4996 page 65
					options += 2;
					*(ptr_compressed_options++) = *(options++);
					comp_opt_len++;
					i -= TCP_OLEN_WS;
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
					break;
				}
				case TCP_OPT_TS:
				{
					const struct tcp_option_timestamp *const opt_ts =
						(struct tcp_option_timestamp *) (options + 2);

					rohc_comp_debug(context, "TCP option TIMESTAMP = 0x%04x 0x%04x",
					                rohc_ntoh32(opt_ts->ts), rohc_ntoh32(opt_ts->ts_reply));
					memcpy(ptr_compressed_options, opt_ts, sizeof(struct tcp_option_timestamp));
					ptr_compressed_options += sizeof(struct tcp_option_timestamp);
					comp_opt_len += sizeof(struct tcp_option_timestamp);

					/* save value after compression */
					tcp_context->tcp_option_timestamp.ts = opt_ts->ts;
					tcp_context->tcp_option_timestamp.ts_reply = opt_ts->ts_reply;
					c_add_wlsb(tcp_context->opt_ts_req_wlsb, tcp_context->msn,
					           rohc_ntoh32(opt_ts->ts));
					c_add_wlsb(tcp_context->opt_ts_reply_wlsb, tcp_context->msn,
					           rohc_ntoh32(opt_ts->ts_reply));

					i -= TCP_OLEN_TS;
					options += TCP_OLEN_TS;
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
					break;
				}
			}
			tcp_context->tmp.is_tcp_opts_list_item_present[m] = true;
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

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG, "TCP compressed options",
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
                          unsigned char *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	ip_context_t *ip_inner_context = NULL;
	base_header_ip_t base_header_inner = { .uint8 = NULL };
	base_header_ip_t base_header;
	tcphdr_t *tcp;
	size_t remain_data_len;
	int counter;
	size_t first_position;
	multi_ptr_t mptr;
	uint8_t save_first_byte;
	size_t payload_size = 0;
	int ip_inner_ecn = 0;
	uint8_t protocol;
	uint8_t crc_computed;
	int i;
	int ret;
	size_t ip_hdr_pos;

	rohc_comp_debug(context, "code CO packet (CID = %zu)", context->cid);

	rohc_comp_debug(context, "parse the %zu-byte IP packet", ip->size);
	base_header.ipvx = (base_header_ip_vx_t *) ip->data;
	remain_data_len = ip->size;
	assert(tcp_context->ip_contexts_nr > 0);
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		size_t ip_ext_pos;

		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);

		base_header_inner.ipvx = base_header.ipvx;
		ip_inner_context = ip_context;

		if(base_header.ipvx->version == IPV4)
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
			ip_inner_ecn = base_header.ipv4->ip_ecn_flags;
			payload_size = rohc_ntoh16(base_header.ipv4->length) - ipv4_hdr_len;

			/* skip IPv4 header */
			rohc_comp_debug(context, "skip %zu-byte IPv4 header with "
			                "Protocol 0x%02x", ipv4_hdr_len, protocol);
			remain_data_len -= ipv4_hdr_len;
			base_header.uint8 += ipv4_hdr_len;
		}
		else /* IPv6 */
		{
			if(remain_data_len < sizeof(base_header_ip_v6_t) )
			{
				goto error;
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

			/* skip IPv6 extension headers */
			for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
			{
				const ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);

				rohc_comp_debug(context, "skip %zu-byte IPv6 extension header "
				                "with Next Header 0x%02x",
				                opt_ctxt->generic.option_length, protocol);
				protocol = base_header.ipv6_opt->next_header;
				base_header.uint8 += opt_ctxt->generic.option_length;
			}
		}
	}

	if(remain_data_len < sizeof(tcphdr_t) )
	{
		rohc_comp_debug(context, "insufficient size for TCP header");
		goto error;
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
	rohc_comp_debug(context, "%s CID %zu encoded on %d byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, counter - 1);

	/* part 4: dynamic part of outer and inner IP header and dynamic part
	 * of next header */

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
	base_header.ipvx = (base_header_ip_vx_t *)ip->data;
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		size_t ip_ext_pos;

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
				break;
			case IPV6:
				/* get the transport protocol */
				protocol = base_header.ipv6->next_header;
				++base_header.ipv6;
				for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
				{
					ipv6_option_context_t *const opt_ctxt =
						&(ip_context->ctxt.v6.opts[ip_ext_pos]);

					mptr.uint8 =
					   tcp_code_irregular_ipv6_option_part(context, opt_ctxt,
					                                       mptr, protocol,
					                                       base_header);
					if(mptr.uint8 == NULL)
					{
						rohc_comp_warn(context, "failed to encode the IPv6 "
						               "extension part of the irregular chain");
						goto error;
					}
					protocol = base_header.ipv6_opt->next_header;
					base_header.uint8 += opt_ctxt->generic.option_length;
				}
				break;
			default:
				goto error;
		}

	}

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

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "CO packet", rohc_pkt, counter);

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
								 ip_context_t *const ip_context,
								 base_header_ip_t base_header,
								 unsigned char *const rohc_pkt,
								 const size_t rohc_pkt_max_len __attribute__((unused)), /* TODO */
                         const rohc_packet_t packet_type,
                         const tcphdr_t *const tcp,
								 const uint8_t crc)
{
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
	c_base_header.co_common->msn = tcp_context->msn & 0xf;
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
	encoded_ack_len =
		variable_length_32_enc(rohc_ntoh32(tcp_context->old_tcphdr.ack_num),
		                       rohc_ntoh32(tcp->ack_num),
		                       tcp_context->tmp.nr_ack_bits_63,
		                       tcp_context->tmp.nr_ack_bits_16383,
		                       mptr.uint8, &indicator);
	c_base_header.co_common->ack_indicator = indicator;
	mptr.uint8 += encoded_ack_len;
	rohc_comp_debug(context, "encode ACK number 0x%08x on %zu bytes with "
	                "indicator %d", rohc_ntoh32(tcp->ack_num),
	                encoded_ack_len, c_base_header.co_common->ack_indicator);

	/* ack_stride */ /* TODO: comparison with new computed ack_stride? */
	ret = c_static_or_irreg16(false /* TODO */, rohc_hton16(tcp_context->ack_stride),
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
	ret = c_static_or_irreg16(tcp->window, !!(tcp_context->tmp.nr_window_bits == 0),
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
		ret = c_optional_ip_id_lsb(context, ip_context->ctxt.v4.ip_id_behavior,
		                           tcp_context->tmp.ip_id,
		                           tcp_context->tmp.ip_id_delta,
		                           tcp_context->tmp.nr_ip_id_bits_3,
		                           mptr.uint8, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode optional_ip_id_lsb(ip_id)");
			goto error;
		}
		c_base_header.co_common->ip_id_indicator = indicator;
		mptr.uint8 += ret;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		c_base_header.co_common->ip_id_behavior = ip_context->ctxt.v4.ip_id_behavior;
		rohc_comp_debug(context, "size = %u, ip_id_indicator = %d, "
		                "ip_id_behavior = %d",
		                (unsigned int) (mptr.uint8 - puchar),
		                c_base_header.co_common->ip_id_indicator,
		                c_base_header.co_common->ip_id_behavior);

		/* dscp_present =:= irregular(1) [ 1 ] */
		c_base_header.co_common->dscp_present =
			dscp_encode(&mptr, ip_context->ctxt.vx.dscp, base_header.ipv4->dscp);
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %u bytes",
		                c_base_header.co_common->dscp_present,
		                ip_context->ctxt.vx.dscp, base_header.ipv4->dscp,
		                (unsigned int) (mptr.uint8 - puchar));
		ip_context->ctxt.vx.dscp = base_header.ipv4->dscp;

		/* ttl_hopl */
		ret = c_static_or_irreg8(ip_context->ctxt.vx.ttl_hopl,
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
		ip_context->ctxt.v4.df = base_header.ipv4->df;
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
			dscp_encode(&mptr, ip_context->ctxt.vx.dscp, DSCP_V6(base_header.ipv6));
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %u bytes",
		                c_base_header.co_common->dscp_present,
		                ip_context->ctxt.vx.dscp, DSCP_V6(base_header.ipv6),
		                (unsigned int) (mptr.uint8 - puchar));
		ip_context->ctxt.vx.dscp = DSCP_V6(base_header.ipv6);

		/* ttl_hopl */
		ret = c_static_or_irreg8(ip_context->ctxt.vx.ttl_hopl,
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
		ret = c_static_or_irreg16(!!(tcp_context->old_tcphdr.urg_ptr == tcp->urg_ptr),
		                          tcp->urg_ptr, mptr.uint8, &indicator);
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

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG, "compressed header",
	              c_base_header.uint8, mptr.uint8 - c_base_header.uint8);

	counter = mptr.uint8 - rohc_pkt;

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "co_header", rohc_pkt, counter);

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	ip_context->ctxt.v4.last_ip_id_behavior = ip_context->ctxt.v4.ip_id_behavior;
	ip_context->ctxt.v4.last_ip_id = tcp_context->tmp.ip_id;
	ip_context->ctxt.vx.ttl_hopl = tcp_context->tmp.ttl_hopl;

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
	uint32_t seq_num;

	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd1 != NULL);

	rohc_comp_debug(context, "code rnd_1 packet");

	rnd1->discriminator = 0x2e; /* '101110' */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3ffff;
	rnd1->seq_num1 = (seq_num >> 16) & 0x3;
	rnd1->seq_num2 = rohc_hton16(seq_num & 0xffff);
	rnd1->msn = tcp_context->msn & 0xf;
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
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd2 != NULL);

	rohc_comp_debug(context, "code rnd_2 packet");

	rnd2->discriminator = 0x0c; /* '1100' */
	rnd2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	rnd2->msn = tcp_context->msn & 0xf;
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
	uint16_t ack_num;

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
	rnd3->msn = tcp_context->msn & 0xf;
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
	assert(tcp_context != NULL);
	assert(tcp_context->ack_stride != 0);
	assert(tcp != NULL);
	assert(rnd4 != NULL);

	rohc_comp_debug(context, "code rnd_4 packet");

	rnd4->discriminator = 0x0d; /* '1101' */
	rnd4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	rnd4->msn = tcp_context->msn & 0xf;
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
	uint16_t seq_num;
	uint16_t ack_num;

	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd5 != NULL);

	rohc_comp_debug(context, "code rnd_5 packet");

	rnd5->discriminator = 0x04; /* '100' */
	rnd5->psh_flag = tcp->psh_flag;
	rnd5->msn = tcp_context->msn & 0xf;

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
	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd6 != NULL);

	rohc_comp_debug(context, "code rnd_6 packet");

	rnd6->discriminator = 0x0a; /* '1010' */
	rnd6->header_crc = 0; /* for CRC computation */
	rnd6->psh_flag = tcp->psh_flag;
	rnd6->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	rnd6->msn = tcp_context->msn & 0xf;
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
	uint32_t ack_num;

	assert(tcp_context != NULL);
	assert(tcp != NULL);
	assert(rnd7 != NULL);

	rohc_comp_debug(context, "code rnd_7 packet");

	rnd7->discriminator = 0x2f; /* '101111' */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x3ffff;
	rnd7->ack_num1 = (ack_num >> 16) & 0x03;
	rnd7->ack_num2 = rohc_hton16(ack_num & 0xffff);
	rnd7->window = tcp->window;
	rnd7->msn = tcp_context->msn & 0xf;
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
										const ip_context_t *const ip_context,
										struct sc_tcp_context *const tcp_context,
										const base_header_ip_t ip,
										const tcphdr_t *const tcp,
										const uint8_t crc,
										rnd_8_t *const rnd8,
										size_t *const rnd8_len)
{
	uint32_t seq_num;
	size_t comp_opts_len;
	uint8_t ttl_hl;
	uint8_t msn;
	bool is_ok;

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
	msn = tcp_context->msn & 0xf;
	rnd8->msn1 = (msn >> 3) & 0x01;
	rnd8->msn2 = msn & 0x07;

	rnd8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	if(ip.ipvx->version == IPV4)
	{
		assert(ip_context->ctxt.vx.version == IPV4);
		ttl_hl = ip.ipv4->ttl_hopl;
	}
	else
	{
		assert(ip.ipvx->version == IPV6);
		assert(ip_context->ctxt.vx.version == IPV6);
		ttl_hl = ip.ipv6->ttl_hopl;
	}
	rnd8->ttl_hopl = c_lsb(context, 3, 3, ip_context->ctxt.vx.ttl_hopl, ttl_hl);
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
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_1_t *const seq1)
{
	uint32_t seq_num;

	assert(ip_context->ctxt.vx.version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq1 != NULL);

	rohc_comp_debug(context, "code seq_1 packet");

	seq1->discriminator = 0x0a; /* '1010' */
	seq1->ip_id = tcp_context->tmp.ip_id_delta & 0x0f;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq1->ip_id);
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	seq1->seq_num = rohc_hton16(seq_num);
	seq1->msn = tcp_context->msn & 0xf;
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
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_2_t *const seq2)
{
	assert(ip_context->ctxt.vx.version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq2 != NULL);

	rohc_comp_debug(context, "code seq_2 packet");

	seq2->discriminator = 0x1a; /* '11010' */
	seq2->ip_id1 = (tcp_context->tmp.ip_id_delta >> 4) & 0x7;
	seq2->ip_id2 = tcp_context->tmp.ip_id_delta & 0xf;
	rohc_comp_debug(context, "7-bit IP-ID offset 0x%x%x", seq2->ip_id1, seq2->ip_id2);
	seq2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	seq2->msn = tcp_context->msn & 0xf;
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
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_3_t *const seq3)
{
	assert(ip_context->ctxt.vx.version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq3 != NULL);

	rohc_comp_debug(context, "code seq_3 packet");

	seq3->discriminator = 0x09; /* '1001' */
	seq3->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq3->ip_id);
	seq3->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq3->msn = tcp_context->msn & 0xf;
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
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_4_t *const seq4)
{
	assert(ip_context->ctxt.vx.version == IPV4);
	assert(tcp_context != NULL);
	assert(tcp_context->ack_stride != 0);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq4 != NULL);

	rohc_comp_debug(context, "code seq_4 packet");

	seq4->discriminator = 0x00; /* '0' */
	seq4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	seq4->ip_id = tcp_context->tmp.ip_id_delta & 0x7;
	rohc_comp_debug(context, "3-bit IP-ID offset 0x%x", seq4->ip_id);
	seq4->msn = tcp_context->msn & 0xf;
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
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_5_t *const seq5)
{
	uint32_t seq_num;

	assert(ip_context->ctxt.vx.version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq5 != NULL);

	rohc_comp_debug(context, "code seq_5 packet");

	seq5->discriminator = 0x08; /* '1000' */
	seq5->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq5->ip_id);
	seq5->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	seq5->seq_num = rohc_hton16(seq_num);
	seq5->msn = tcp_context->msn & 0xf;
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
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_6_t *const seq6)
{
	uint8_t seq_num_scaled;

	assert(ip_context->ctxt.vx.version == IPV4);
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
	seq6->ip_id = tcp_context->tmp.ip_id_delta & 0x7f;
	rohc_comp_debug(context, "7-bit IP-ID offset 0x%x", seq6->ip_id);
	seq6->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq6->msn = tcp_context->msn & 0xf;
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
                                const ip_context_t *const ip_context,
                                struct sc_tcp_context *const tcp_context,
                                const base_header_ip_t ip,
                                const tcphdr_t *const tcp,
                                const uint8_t crc,
                                seq_7_t *const seq7)
{
	uint16_t window;

	assert(ip_context->ctxt.vx.version == IPV4);
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
	seq7->ip_id = tcp_context->tmp.ip_id_delta & 0x1f;
	rohc_comp_debug(context, "5-bit IP-ID offset 0x%x", seq7->ip_id);
	seq7->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq7->msn = tcp_context->msn & 0xf;
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
                              const ip_context_t *const ip_context,
                              struct sc_tcp_context *const tcp_context,
                              const base_header_ip_t ip,
                              const tcphdr_t *const tcp,
                              const uint8_t crc,
                              seq_8_t *const seq8,
                              size_t *const seq8_len)
{
	size_t comp_opts_len;
	uint16_t ack_num;
	uint16_t seq_num;
	bool is_ok;

	assert(ip_context->ctxt.vx.version == IPV4);
	assert(tcp_context != NULL);
	assert(ip.ipvx->version == IPV4);
	assert(tcp != NULL);
	assert(seq8 != NULL);
	assert(seq8_len != NULL);

	rohc_comp_debug(context, "code seq_8 packet");

	seq8->discriminator = 0x0b; /* '1011' */

	/* IP-ID */
	seq8->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq8->ip_id);

	seq8->list_present = 0; /* options are set later */
	seq8->header_crc = 0; /* for CRC computation */
	seq8->msn = tcp_context->msn & 0xf;
	seq8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	seq8->ttl_hopl = c_lsb(context, 3, 3, ip_context->ctxt.vx.ttl_hopl,
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
 * @param context             The compression context to compare
 * @param uncomp_pkt          The uncompressed packet to compare
 * @param[out] ip_inner_ctxt  The context of the inner IP header
 * @param[out] tcp            The TCP header found in uncompressed headers
 * @return                    true if changes were successfully detected,
 *                            false if a problem occurred
 */
static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               const struct net_pkt *const uncomp_pkt,
                               ip_context_t **const ip_inner_ctxt,
                               const tcphdr_t **const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	base_header_ip_t base_header_inner;
	base_header_ip_t base_header;
#ifdef TODO
	uint8_t new_context_state;
#endif
	size_t ip_hdrs_nr;
	size_t hdrs_len;
	uint8_t protocol;
	size_t opts_len;
	int ecn_used;

	base_header.ipvx = (base_header_ip_vx_t *) uncomp_pkt->outer_ip.data;
	hdrs_len = 0;
	ecn_used = 0;
	ip_hdrs_nr = 0;
	do
	{
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdrs_nr]);

		rohc_comp_debug(context, "found IPv%d header #%zu",
		                base_header.ipvx->version, ip_hdrs_nr + 1);

		base_header_inner.ipvx = base_header.ipvx;
		*ip_inner_ctxt = ip_context;

		if(base_header.ipvx->version == IPV4)
		{
			/* get the transport protocol */
			protocol = base_header.ipv4->protocol;
			ecn_used |= base_header.ipv4->ip_ecn_flags;
			hdrs_len += sizeof(base_header_ip_v4_t);
			base_header.ipv4++;
		}
		else if(base_header.ipvx->version == IPV6)
		{
			size_t ip_ext_pos;

			protocol = base_header.ipv6->next_header;
			ecn_used |= base_header.ipv6->ip_ecn_flags;
			hdrs_len += sizeof(base_header_ip_v6_t);
			base_header.ipv6++;

			ip_ext_pos = 0;
			while(rohc_is_ipv6_opt(protocol))
			{
				ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);
				size_t ip_ext_len;

				rohc_comp_debug(context, "  found IP extension header %u", protocol);
				switch(protocol)
				{
					case ROHC_IPPROTO_HOPOPTS: // IPv6 Hop-by-Hop options
					case ROHC_IPPROTO_ROUTING: // IPv6 routing header
					case ROHC_IPPROTO_DSTOPTS: // IPv6 destination options
					case ROHC_IPPROTO_AH:
						if(context->num_sent_packets == 0 ||
						   base_header.ipv6_opt->length != opt_ctxt->generic.length ||
						   memcmp(base_header.ipv6_opt->value, opt_ctxt->generic.data,
						          opt_ctxt->generic.option_length - 2) != 0)
						{
							rohc_comp_debug(context, "  IPv6 option %u changed of length "
							                "and/or content (%u -> %u)", protocol,
							                opt_ctxt->generic.length,
							                base_header.ipv6_opt->length);
							assert(base_header.ipv6_opt->length < MAX_IPV6_OPTION_LENGTH);
							opt_ctxt->generic.option_length =
							   (base_header.ipv6_opt->length + 1) << 3;
							opt_ctxt->generic.length = base_header.ipv6_opt->length;
							memcpy(opt_ctxt->generic.data, base_header.ipv6_opt->value,
							       opt_ctxt->generic.option_length - 2);
#ifdef TODO
							new_context_state = ROHC_COMP_STATE_IR;
#endif
						}
						else
						{
							rohc_comp_debug(context, "  IPv6 option %u did not change",
							                protocol);
						}
						break;
					case ROHC_IPPROTO_GRE:
						if(base_header.ip_gre_opt->c_flag != opt_ctxt->gre.c_flag)
						{
							rohc_comp_debug(context, "  IPv6 option %d c_flag changed "
							                "(%d -> %d)", protocol, opt_ctxt->gre.c_flag,
							                base_header.ip_gre_opt->c_flag);
#ifdef TODO
							new_context_state = ROHC_COMP_STATE_IR;
#endif
						}
						break;
					case ROHC_IPPROTO_MINE:
						if(base_header.ip_mime_opt->s_bit != opt_ctxt->mime.s_bit)
						{
							rohc_comp_debug(context, "  IPv6 option %d s_bit changed "
							                "(0x%x -> 0x%x)", protocol,
							                opt_ctxt->mime.s_bit,
							                base_header.ip_mime_opt->s_bit);
							opt_ctxt->mime.option_length =
							   (2 + base_header.ip_mime_opt->s_bit) << 3;
#ifdef TODO
							new_context_state = ROHC_COMP_STATE_IR;
#endif
							break;
						}
						if(base_header.ip_mime_opt->checksum != opt_ctxt->mime.checksum)
						{
							rohc_comp_debug(context, "  IPv6 option %d checksum "
							                "changed (0x%x -> 0x%x)", protocol,
							                opt_ctxt->mime.checksum,
							                base_header.ip_mime_opt->checksum);
#ifdef TODO
							new_context_state = ROHC_COMP_STATE_IR;
#endif
							break;
						}
						break;
				}
				protocol = base_header.ipv6_opt->next_header;
				ip_ext_len = (base_header.ipv6_opt->length + 1) << 3;
				base_header.uint8 += ip_ext_len;
				hdrs_len += ip_ext_len;
				ip_ext_pos++;
			}
		}
		else
		{
			rohc_comp_warn(context, "unknown IP header with version %u",
			               base_header.ipvx->version);
			goto error;
		}
	}
	while(protocol != ROHC_IPPROTO_TCP && hdrs_len < uncomp_pkt->outer_ip.size);

	/* next header is the TCP header */
	*tcp = base_header.tcphdr;
	ecn_used |= (*tcp)->ecn_flags;
	tcp_context->ecn_used = ecn_used;
	rohc_comp_debug(context, "ecn_used %d", tcp_context->ecn_used);
	base_header.uint8 += sizeof(tcphdr_t);
	hdrs_len = sizeof(tcphdr_t);

	/* determine the IP-ID behavior of the innermost IPv4 header */
	if(base_header_inner.ipvx->version == IPV4)
	{
		const uint16_t ip_id = rohc_ntoh16(base_header_inner.ipv4->ip_id);

		rohc_comp_debug(context, "IP-ID behaved as %s",
		                tcp_ip_id_behavior_get_descr((*ip_inner_ctxt)->ctxt.v4.ip_id_behavior));
		rohc_comp_debug(context, "IP-ID = 0x%04x -> 0x%04x",
		                (*ip_inner_ctxt)->ctxt.v4.last_ip_id, ip_id);

		if(context->num_sent_packets == 0)
		{
			/* first packet, be optimistic: choose sequential behavior */
			(*ip_inner_ctxt)->ctxt.v4.ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
		}
		else
		{
			(*ip_inner_ctxt)->ctxt.v4.ip_id_behavior =
				tcp_detect_ip_id_behavior((*ip_inner_ctxt)->ctxt.v4.last_ip_id, ip_id);
		}
		rohc_comp_debug(context, "IP-ID now behaves as %s",
		                tcp_ip_id_behavior_get_descr((*ip_inner_ctxt)->ctxt.v4.ip_id_behavior));
	}

	/* parse TCP options for changes */
	if(!tcp_detect_options_changes(context, *tcp, &opts_len))
	{
		rohc_comp_warn(context, "failed to detect changes in the uncompressed "
		               "TCP options");
		goto error;
	}
	base_header.uint8 += opts_len;
	hdrs_len += opts_len;

	/* find the offset of the payload and its size */
	assert(uncomp_pkt->len >= hdrs_len);
	tcp_context->tmp.payload_len = uncomp_pkt->len - hdrs_len;
	rohc_comp_debug(context, "payload length = %zu bytes",
	                tcp_context->tmp.payload_len);

	/* compute or find the new SN */
	tcp_context->msn = c_tcp_get_next_msn(context);
	rohc_comp_debug(context, "MSN = 0x%04x / %u", tcp_context->msn, tcp_context->msn);

	return true;

error:
	return false;
}


/**
 * @brief Determine the MSN value for the next packet
 *
 * Profile MSN is an internal increasing 16-bit number. See RFC 6846, §6.1.1.
 *
 * @param context     The compression context
 * @return            The MSN value for the next ROHC packet
 */
static uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	return ((tcp_context->msn + 1) % 0xffff);
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
	/* TODO: be conform with RFC */
	/* TODO: use generic function? */
	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			if(context->ir_count < MAX_IR_COUNT)
			{
				rohc_comp_debug(context, "no enough packets transmitted in IR "
				                "state for the moment (%zu/%d), so stay in IR "
				                "state", context->ir_count, MAX_IR_COUNT);
			}
			else
			{
				rohc_comp_change_state(context, ROHC_COMP_STATE_FO);
			}
			break;
		case ROHC_COMP_STATE_FO: /* The First Order (FO) state */
			if(context->fo_count < MAX_FO_COUNT)
			{
				rohc_comp_debug(context, "no enough packets transmitted in FO "
				                "state for the moment (%zu/%d), so stay in FO "
				                "state", context->fo_count, MAX_FO_COUNT);
			}
			else
			{
				rohc_comp_change_state(context, ROHC_COMP_STATE_SO);
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
	struct sc_tcp_context *const tcp_context = context->specific;

	base_header_ip_t base_header;
	base_header_ip_t inner_ip_hdr = { .uint8 = NULL };
	size_t remain_data_len;
	const ip_context_t *inner_ip_ctxt = NULL;
	uint8_t protocol;
	tcphdr_t *tcp;
	uint32_t seq_num_hbo;
	uint32_t ack_num_hbo;
	size_t ip_hdr_pos;

	/* how many bits are required to encode the new SN ? */
	if(context->state == ROHC_COMP_STATE_IR)
	{
		/* send all bits in IR state */
		tcp_context->tmp.nr_msn_bits = 16;
		rohc_comp_debug(context, "IR state: force using %zu bits to encode "
		                "new SN", tcp_context->tmp.nr_msn_bits);
	}
	else
	{
		/* send only required bits in FO or SO states */
		if(!wlsb_get_k_16bits(tcp_context->msn_wlsb, tcp_context->msn,
		                      &tcp_context->tmp.nr_msn_bits))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for MSN 0x%04x", tcp_context->msn);
			goto error;
		}
	}
	rohc_comp_debug(context, "%zu bits are required to encode new MSN 0x%04x",
	                tcp_context->tmp.nr_msn_bits, tcp_context->msn);
	/* add the new MSN to the W-LSB encoding object */
	/* TODO: move this after successful packet compression */
	c_add_wlsb(tcp_context->msn_wlsb, tcp_context->msn, tcp_context->msn);

	/* parse IP headers */
	base_header.ipvx = (base_header_ip_vx_t *) uncomp_pkt->data;
	remain_data_len = uncomp_pkt->len;
	tcp_context->tmp.ttl_irregular_chain_flag = 0;
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		uint8_t ttl_hopl;
		size_t ip_ext_pos;

		rohc_comp_debug(context, "found IPv%d", base_header.ipvx->version);
		inner_ip_ctxt = ip_context;

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
				if(ttl_hopl != ip_context->ctxt.v4.ttl_hopl)
				{
					tcp_context->tmp.ttl_irregular_chain_flag |= 1;
					rohc_comp_debug(context, "last ttl_hopl = 0x%02x, ttl_hopl = "
					                "0x%02x, ttl_irregular_chain_flag = %d",
					                ip_context->ctxt.v4.ttl_hopl, ttl_hopl,
					                tcp_context->tmp.ttl_irregular_chain_flag);
				}

				/* skip IPv4 header */
				rohc_comp_debug(context, "skip %zu-byte IPv4 header with "
				                "Protocol 0x%02x", ipv4_hdr_len, protocol);
				inner_ip_hdr.uint8 = base_header.uint8;
				remain_data_len -= ipv4_hdr_len;
				base_header.uint8 += ipv4_hdr_len;
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
				if(ttl_hopl != ip_context->ctxt.v6.ttl_hopl)
				{
					tcp_context->tmp.ttl_irregular_chain_flag |= 1;
					rohc_comp_debug(context, "last ttl_hopl = 0x%02x, ttl_hopl = "
					                "0x%02x, ttl_irregular_chain_flag = %d",
					                ip_context->ctxt.v6.ttl_hopl, ttl_hopl,
					                tcp_context->tmp.ttl_irregular_chain_flag);
				}

				/* skip IPv6 header */
				rohc_comp_debug(context, "skip %zd-byte IPv6 header with Next "
				                "Header 0x%02x", sizeof(base_header_ip_v6_t),
				                protocol);
				inner_ip_hdr.uint8 = base_header.uint8;
				remain_data_len -= sizeof(base_header_ip_v6_t);
				++base_header.ipv6;

				/* skip IPv6 extension headers */
				for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
				{
					const ipv6_option_context_t *const opt_ctxt =
						&(ip_context->ctxt.v6.opts[ip_ext_pos]);

					rohc_comp_debug(context, "skip %zu-byte IPv6 extension header "
					                "with Next Header 0x%02x",
					                opt_ctxt->generic.option_length, protocol);
					protocol = base_header.ipv6_opt->next_header;
					base_header.uint8 += opt_ctxt->generic.option_length;
				}
				break;
			default:
				goto error;
		}
	}

	tcp_context->tmp.ip_ttl_changed =
		(tcp_context->tmp.ttl_irregular_chain_flag != 0);
	tcp_field_descr_change(context, "TTL", tcp_context->tmp.ip_ttl_changed);

	if(inner_ip_hdr.ipvx->version == IPV4)
	{
		tcp_context->tmp.ip_id = rohc_ntoh16(inner_ip_hdr.ipv4->ip_id);

		/* does IP-ID behavior changed? */
		tcp_context->tmp.ip_id_behavior_changed =
			(inner_ip_ctxt->ctxt.v4.last_ip_id_behavior != inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		tcp_field_descr_change(context, "IP-ID behavior",
		                       tcp_context->tmp.ip_id_behavior_changed);

		/* compute the new IP-ID / SN delta */
		if(inner_ip_ctxt->ctxt.v4.ip_id_behavior == IP_ID_BEHAVIOR_SEQ)
		{
			tcp_context->tmp.ip_id_delta = tcp_context->tmp.ip_id - tcp_context->msn;
			rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (behavior = %d)",
			                tcp_context->tmp.ip_id_delta, tcp_context->tmp.ip_id_delta,
			                inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		}
		else if(inner_ip_ctxt->ctxt.v4.ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
		{
			tcp_context->tmp.ip_id = swab16(tcp_context->tmp.ip_id);
			tcp_context->tmp.ip_id_delta = tcp_context->tmp.ip_id - tcp_context->msn;
			rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (behavior = %d)",
			                tcp_context->tmp.ip_id_delta, tcp_context->tmp.ip_id_delta,
			                inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		}
		else
		{
			tcp_context->tmp.ip_id_delta = 0; /* unused */
		}

		/* how many bits are required to encode the new IP-ID / SN delta ? */
		if(context->state == ROHC_COMP_STATE_IR ||
		   (inner_ip_ctxt->ctxt.v4.ip_id_behavior != IP_ID_BEHAVIOR_SEQ &&
		    inner_ip_ctxt->ctxt.v4.ip_id_behavior != IP_ID_BEHAVIOR_SEQ_SWAP))
		{
			/* send all bits in IR state */
			tcp_context->tmp.nr_ip_id_bits_3 = 16;
			tcp_context->tmp.nr_ip_id_bits_1 = 16;
			rohc_comp_debug(context, "IR state: force using 16 bits to encode "
			                "new IP-ID delta");
		}
		else
		{
			/* send only required bits in FO or SO states */
			if(!wlsb_get_kp_16bits(tcp_context->ip_id_wlsb, tcp_context->tmp.ip_id_delta,
			                       3, &(tcp_context->tmp.nr_ip_id_bits_3)))
			{
				rohc_comp_warn(context, "failed to find the minimal number of bits "
				               "required for innermost IP-ID delta 0x%04x and p = 3",
				                tcp_context->tmp.ip_id_delta);
				goto error;
			}
			rohc_comp_debug(context, "%zu bits are required to encode new innermost "
			                "IP-ID delta 0x%04x with p = 3",
			                tcp_context->tmp.nr_ip_id_bits_3,
			                tcp_context->tmp.ip_id_delta);
			if(!wlsb_get_kp_16bits(tcp_context->ip_id_wlsb, tcp_context->tmp.ip_id_delta,
			                       1, &(tcp_context->tmp.nr_ip_id_bits_1)))
			{
				rohc_comp_warn(context, "failed to find the minimal number of bits "
				               "required for innermost IP-ID delta 0x%04x and p = 1",
				                tcp_context->tmp.ip_id_delta);
				goto error;
			}
			rohc_comp_debug(context, "%zu bits are required to encode new innermost "
			                "IP-ID delta 0x%04x with p = 1",
			                tcp_context->tmp.nr_ip_id_bits_1,
			                tcp_context->tmp.ip_id_delta);
		}
		/* add the new IP-ID / SN delta to the W-LSB encoding object */
		/* TODO: move this after successful packet compression */
		c_add_wlsb(tcp_context->ip_id_wlsb, tcp_context->msn,
		           tcp_context->tmp.ip_id_delta);

		tcp_context->tmp.ip_df_changed =
			(inner_ip_hdr.ipv4->df != inner_ip_ctxt->ctxt.v4.df);
		tcp_field_descr_change(context, "DF", tcp_context->tmp.ip_df_changed);

		tcp_context->tmp.dscp_changed =
			(inner_ip_hdr.ipv4->dscp != inner_ip_ctxt->ctxt.v4.dscp);
		tcp_field_descr_change(context, "DSCP", tcp_context->tmp.dscp_changed);

		tcp_context->tmp.ttl_hopl = inner_ip_hdr.ipv4->ttl_hopl;

		tcp = (tcphdr_t *) (inner_ip_hdr.ipv4 + 1);
	}
	else /* IPv6 */
	{
		/* no IP-ID for IPv6 */
		tcp_context->tmp.ip_id = 0;
		tcp_context->tmp.ip_id_delta = 0;
		tcp_context->tmp.ip_id_behavior_changed = false;
		tcp_context->tmp.nr_ip_id_bits_3 = 0;
		tcp_context->tmp.nr_ip_id_bits_1 = 0;

		tcp_context->tmp.ip_df_changed = false; /* no DF for IPv6 */

		tcp_context->tmp.dscp_changed =
			(DSCP_V6(inner_ip_hdr.ipv6) != inner_ip_ctxt->ctxt.v6.dscp);
		tcp_field_descr_change(context, "DSCP", tcp_context->tmp.dscp_changed);

		tcp_context->tmp.ttl_hopl = inner_ip_hdr.ipv6->ttl_hopl;

		tcp = (tcphdr_t *) (inner_ip_hdr.ipv6 + 1);
	}

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

	/* how many bits are required to encode the new TCP window? */
	if(context->state == ROHC_COMP_STATE_IR)
	{
		/* send all bits in IR state */
		tcp_context->tmp.nr_window_bits = 16;
		rohc_comp_debug(context, "IR state: force using 16 bits to encode "
		                "new TCP window");
	}
	else
	{
		/* send only required bits in FO or SO states */
		if(!wlsb_get_kp_16bits(tcp_context->window_wlsb, rohc_ntoh16(tcp->window),
		                       ROHC_LSB_SHIFT_TCP_WINDOW,
		                       &tcp_context->tmp.nr_window_bits))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for TCP window 0x%04x", rohc_ntoh16(tcp->window));
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new TCP window "
		                "0x%04x", tcp_context->tmp.nr_window_bits,
		                rohc_ntoh16(tcp->window));
	}
	/* TODO: move this after successful packet compression */
	c_add_wlsb(tcp_context->window_wlsb, tcp_context->msn, rohc_ntoh16(tcp->window));

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
	/* TODO: move this after successful packet compression */
	c_add_wlsb(tcp_context->seq_wlsb, tcp_context->msn, seq_num_hbo);
	if(tcp_context->seq_num_factor != 0)
	{
		/* TODO: move this after successful packet compression */
		c_add_wlsb(tcp_context->seq_scaled_wlsb, tcp_context->msn,
		           tcp_context->seq_num_scaled);
	}

	/* how many bits are required to encode the new ACK number? */
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
		rohc_comp_debug(context, "IR state: force using 32 bits to encode new "
		                "ACK number");
	}
	else
	{
		/* send only required bits in FO or SO states */
		if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 65535,
		                       &tcp_context->tmp.nr_ack_bits_65535))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for ACK number 0x%08x and p = 65535",
			               ack_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new ACK "
		                "number 0x%08x with p = 65535",
		                tcp_context->tmp.nr_ack_bits_65535, ack_num_hbo);
		if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 32767,
		                       &tcp_context->tmp.nr_ack_bits_32767))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for ACK number 0x%08x and p = 32767",
			               ack_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new ACK "
		                "number 0x%08x with p = 32767",
		                tcp_context->tmp.nr_ack_bits_32767, ack_num_hbo);
		if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 16383,
		                       &tcp_context->tmp.nr_ack_bits_16383))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for ACK number 0x%08x and p = 16383",
			               ack_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new ACK "
		                "number 0x%08x with p = 16383",
		                tcp_context->tmp.nr_ack_bits_16383, ack_num_hbo);
		if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 8191,
		                       &tcp_context->tmp.nr_ack_bits_8191))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for ACK number 0x%08x and p = 8191",
			               ack_num_hbo);
			goto error;
		}
		rohc_comp_debug(context, "%zd bits are required to encode new ACK "
		                "number 0x%08x with p = 8191",
		                tcp_context->tmp.nr_ack_bits_8191, ack_num_hbo);
		if(!wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 63,
		                       &tcp_context->tmp.nr_ack_bits_63))
		{
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for ACK number 0x%08x and p = 63",
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
			rohc_comp_warn(context, "failed to find the minimal number of bits "
			               "required for scaled ACK number 0x%08x",
			               tcp_context->ack_num_scaled);
			goto error;
		}
		rohc_comp_debug(context, "%zu bits are required to encode new scaled "
		                "ACK number 0x%08x",
		                tcp_context->tmp.nr_ack_scaled_bits,
		                tcp_context->ack_num_scaled);
	}
	/* TODO: move this after successful packet compression */
	c_add_wlsb(tcp_context->ack_wlsb, tcp_context->msn, ack_num_hbo);
	/* TODO: move this after successful packet compression */
	c_add_wlsb(tcp_context->ack_scaled_wlsb, tcp_context->msn,
	           tcp_context->ack_num_scaled);

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
static rohc_packet_t tcp_decide_packet(struct rohc_comp_ctxt *const context,
                                       const ip_context_t *const ip_inner_context,
                                       const tcphdr_t *const tcp)
{
	rohc_packet_t packet_type;

	switch(context->state)
	{
		case ROHC_COMP_STATE_IR: /* The Initialization and Refresh (IR) state */
			rohc_comp_debug(context, "code IR packet");
			packet_type = ROHC_PACKET_IR;
			context->ir_count++;
			break;
		case ROHC_COMP_STATE_FO: /* The First Order (FO) state */
			rohc_comp_debug(context, "code IR-DYN packet");
			packet_type = ROHC_PACKET_IR_DYN;
			context->fo_count++;
			break;
		case ROHC_COMP_STATE_SO: /* The Second Order (SO) state */
			context->so_count++;
			packet_type = tcp_decide_SO_packet(context, ip_inner_context, tcp);
			break;
		default:
#if defined(NDEBUG) || defined(__KERNEL__) || defined(ENABLE_DEAD_CODE)
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
                                          const ip_context_t *const ip_inner_context,
                                          const tcphdr_t *const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	rohc_packet_t packet_type;

	if(!sdvl_can_length_be_encoded(tcp_context->tmp.nr_opt_ts_req_bits_0x40000) ||
	   !sdvl_can_length_be_encoded(tcp_context->tmp.nr_opt_ts_reply_bits_0x40000))
	{
		rohc_comp_debug(context, "force packet IR-DYN because the TCP option "
		                "changed too much");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(tcp_context->tmp.nr_msn_bits > 4)
	{
		rohc_comp_debug(context, "force packet IR-DYN because the MSN changed "
		                "too much");
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
		if(ip_inner_context->ctxt.vx.ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP &&
		   tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
		   tcp_context->tmp.nr_ack_bits_8191 <= 15 &&
		   tcp_context->tmp.nr_window_bits == 0)
		{
			/* IP_ID_BEHAVIOR_SEQ or IP_ID_BEHAVIOR_SEQ_SWAP */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else if(tcp_context->tmp.nr_seq_bits_65535 <= 16 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        tcp_context->tmp.nr_window_bits == 0)
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
	else if(ip_inner_context->ctxt.vx.ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP)
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
			if(tcp_context->tmp.nr_window_bits == 0 &&
			   tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
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
		else if(tcp_context->tmp.nr_window_bits > 0)
		{
			/* seq_7 or co_common */
			if(/* TODO: no more than 15 bits of TCP window */
			   tcp_context->tmp.nr_ip_id_bits_3 <= 5 &&
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
			if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
			   tcp_context->tmp.nr_seq_bits_32767 <= 16 &&
			   true /* TODO: no more than 4 bits of SN */)
			{
				/* seq_1 is possible */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_1;
			}
			else if(tcp_context->tmp.nr_ip_id_bits_3 <= 7 &&
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
			if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
			   tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
			   true /* TODO: no more than 4 bits of SN */)
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_3;
			}
			else if(tcp_context->tmp.nr_ip_id_bits_1 <= 3 &&
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
			if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
			   tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
			   tcp_context->tmp.nr_seq_bits_32767 <= 16 &&
			   true /* TODO: no more than 4 bits of SN */)
			{
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_SEQ_5;
			}
			else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
			        tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
			        tcp_context->tmp.nr_seq_scaled_bits <= 4 &&
			        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
			        true /* TODO: no more than 4 bits of SN */)
			{
				TRACE_GOTO_CHOICE;
				assert(tcp_context->tmp.payload_len > 0);
				packet_type = ROHC_PACKET_TCP_SEQ_6;
			}
			else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
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
	else if(ip_inner_context->ctxt.vx.ip_id_behavior == IP_ID_BEHAVIOR_RAND ||
	        ip_inner_context->ctxt.vx.ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
	{
		/* IP_ID_BEHAVIOR_RAND or IP_ID_BEHAVIOR_ZERO:
		 * co_common or rnd_X packet types */

		if(tcp_context->tmp.is_tcp_opts_list_struct_changed)
		{
			if(tcp_context->tmp.nr_window_bits == 0 &&
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
				if(tcp_context->tmp.nr_window_bits == 0 &&
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
			else if(tcp_context->tmp.nr_window_bits > 0)
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
		               ip_inner_context->ctxt.vx.ip_id_behavior);
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
 * @brief Update the profile when feedback is received
 *
 * This function is one of the functions that must exist in one profile for
 * the framework to work.
 *
 * @param context  The compression context
 * @param feedback The feedback information
 * @return         true if the feedback was successfully handled,
 *                 false if the feedback could not be taken into account
 */
static bool c_tcp_feedback(struct rohc_comp_ctxt *const context,
                           const struct c_feedback *const feedback)
{
	/* TODO: duplicated from RFC3095 */
	struct sc_tcp_context *const tcp_context = context->specific;
	uint8_t *remain_data; /* pointer to the profile-specific data
	                         in the feedback packet */
	size_t remain_len;
	uint32_t sn;

	assert(context->used == 1);
	assert(feedback->cid == context->cid);
	assert(feedback->data != NULL);

	remain_data = feedback->data + feedback->specific_offset;
	remain_len = feedback->specific_size;

	switch(feedback->type)
	{
		case 1: /* FEEDBACK-1 */
			rohc_comp_debug(context, "FEEDBACK-1 received");
			assert(remain_len == 1);
			sn = remain_data[0] & 0xff;

			/* according to RFC 3095, §4.5.2, ack W-LSB values only in R-mode */
			if(context->mode == ROHC_R_MODE)
			{
				/* ack outer/inner IP-ID only if IPv4, but always ack SN */
#if 0 /* TODO */
				if(rfc3095_ctxt->outer_ip_flags.version == IPV4)
				{
					c_ack_sn_wlsb(rfc3095_ctxt->outer_ip_flags.info.v4.ip_id_window, sn);
				}
				if(rfc3095_ctxt->ip_hdr_nr > 1 &&
				   rfc3095_ctxt->inner_ip_flags.version == IPV4)
				{
					c_ack_sn_wlsb(rfc3095_ctxt->inner_ip_flags.info.v4.ip_id_window, sn);
				}
#endif
				c_ack_sn_wlsb(tcp_context->msn_wlsb, sn);
			}
			break;

		case 2: /* FEEDBACK-2 */
			rohc_comp_debug(context, "FEEDBACK-2 received");
			assert(remain_len >= 2);
			if(!c_tcp_feedback_2(context, feedback))
			{
				rohc_comp_warn(context, "failed to handle FEEDBACK-2");
				goto error;
			}
			break;

		default: /* not FEEDBACK-1 nor FEEDBACK-2 */
			rohc_comp_warn(context, "feedback type not implemented (%d)",
			               feedback->type);
			goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Update the profile when FEEDBACK-2 is received
 *
 * @param context  The compression context
 * @param feedback The feedback information
 * @return         true if the feedback was successfully handled,
 *                 false if the feedback could not be taken into account
 */
static bool c_tcp_feedback_2(struct rohc_comp_ctxt *const context,
                             const struct c_feedback *const feedback)
{
	/* TODO: duplicated from RFC3095 */
	struct sc_tcp_context *const tcp_context = context->specific;
	uint8_t *remain_data; /* pointer to the profile-specific data
	                         in the feedback packet */
	size_t remain_len;
	unsigned int crc_in_packet = 0; /* initialized to avoid a GCC warning */
	bool is_crc_used = false;
	bool sn_not_valid = false;
	uint32_t sn;
	uint8_t mode;

	assert(context->specific != NULL);
	assert(context->used == 1);
	assert(feedback->type == 2);
	assert(feedback->cid == context->cid);
	assert(feedback->data != NULL);

	remain_data = feedback->data + feedback->specific_offset;
	remain_len = feedback->specific_size;
	assert(remain_len >= 2);

	/* retrieve new mode and acked SN */
	mode = (remain_data[0] >> 4) & 3;
	sn = ((remain_data[0] & 0x0f) << 8) + (remain_data[1] & 0xff);
	assert((sn & 0x0fff) == sn);
	remain_data += 2;
	remain_len -= 2;

	/* parse FEEDBACK-2 options */
	while(remain_len > 0)
	{
		const uint8_t opt = (remain_data[0] >> 4) & 0x0f;
		const uint8_t optlen = (remain_data[0] & 0x0f) + 1;

		/* check min length */
		if(remain_len < optlen)
		{
			rohc_comp_warn(context, "%zu-byte FEEDBACK-2 is too short for "
			               "%u-byte option %u", remain_len, optlen, opt);
			goto error;
		}

		switch(opt)
		{
			case 1: /* CRC */
				crc_in_packet = remain_data[1];
				is_crc_used = true;
				remain_data[1] = 0; /* set to zero for crc computation */
				break;
			case 3: /* SN-Not-Valid */
				sn_not_valid = true;
				break;
			case 4: /* SN */
				if((sn & 0xff000000) != 0)
				{
					rohc_comp_warn(context, "more than 32 bits used for feedback "
					               "SN, truncate unexpected value");
					sn &= 0x00ffffff;
				}
				sn = (sn << 8) + (remain_data[1] & 0xff);
				break;
			case 2: /* Reject */
			case 7: /* Loss */
			default:
				rohc_comp_warn(context, "unknown feedback option %u", opt);
				break;
		}

		remain_data += optlen;
		remain_len -= optlen;
	}

	/* check CRC if present in feedback */
	if(is_crc_used)
	{
		uint8_t crc_computed;

		/* compute the CRC of the feedback packet */
		crc_computed = crc_calculate(ROHC_CRC_TYPE_8, feedback->data,
		                             feedback->size, CRC_INIT_8,
		                             context->compressor->crc_table_8);

		/* ignore feedback in case of bad CRC */
		if(crc_in_packet != crc_computed)
		{
			rohc_comp_debug(context, "CRC check failed (size = %zu)",
			                feedback->size);
			goto error;
		}
	}

	/* change mode if present in feedback */
	if(mode != 0 && mode != context->mode)
	{
		rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		          "mode change (%d -> %d) requested by feedback for CID %zu",
		          context->mode, mode, context->cid);

		/* mode can be changed only if feedback is protected by a CRC */
		if(is_crc_used)
		{
			rohc_comp_change_mode(context, mode);
		}
		else
		{
			rohc_comp_warn(context, "mode change requested without CRC");
		}
	}

	/* act according to the type of feedback */
	switch(feedback->acktype)
	{
		case ACK:
		{
			rohc_comp_debug(context, "ACK received (CID = %zu, SN = 0x%08x, "
			                "SN-not-valid = %d)", feedback->cid, sn,
			                sn_not_valid ? 1 : 0);
			/* according to RFC 3095, §4.5.2, ack W-LSB values only in R-mode */
			/* acknowledge IP-ID and SN only if SN is considered as valid */
			if(context->mode == ROHC_R_MODE && !sn_not_valid)
			{
				/* ack outer/inner IP-ID only if IPv4, but always ack SN */
#if 0 /* TODO */
				if(rfc3095_ctxt->outer_ip_flags.version == IPV4)
				{
					c_ack_sn_wlsb(rfc3095_ctxt->outer_ip_flags.info.v4.ip_id_window, sn);
				}
				if(rfc3095_ctxt->ip_hdr_nr > 1 &&
				   rfc3095_ctxt->inner_ip_flags.version == IPV4)
				{
					c_ack_sn_wlsb(rfc3095_ctxt->inner_ip_flags.info.v4.ip_id_window, sn);
				}
#endif
				c_ack_sn_wlsb(tcp_context->msn_wlsb, sn);
			}
			break;
		}

		case NACK:
		{
			rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			          "NACK received for CID %zu", feedback->cid);
			if(context->state == ROHC_COMP_STATE_SO)
			{
				rohc_comp_change_state(context, ROHC_COMP_STATE_FO);
			}
			break;
		}

		case STATIC_NACK:
		{
			rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			          "STATIC-NACK received for CID %zu", feedback->cid);
			rohc_comp_change_state(context, ROHC_COMP_STATE_IR);
			break;
		}

		case RESERVED:
		{
			rohc_comp_warn(context, "reserved field used");
			goto error;
		}

		default:
		{
			/* impossible value */
			rohc_comp_warn(context, "unknown ACK type %d", feedback->acktype);
			goto error;
		}
	}

	return true;

error:
	return false;
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
	.reinit_context = rohc_comp_reinit_context,
	.feedback       = c_tcp_feedback,
	.use_udp_port   = rohc_comp_use_udp_port,
};

