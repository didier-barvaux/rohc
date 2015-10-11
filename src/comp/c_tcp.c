/*
 * Copyright 2012,2013,2014,2015 Didier Barvaux
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
#include "protocols/ip.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "schemes/cid.h"
#include "schemes/ip_id_offset.h"
#include "schemes/rfc4996.h"
#include "c_tcp_opts_list.h"
#include "sdvl.h"
#include "crc.h"
#include "rohc_bit_ops.h"

#include <assert.h>
#include <stdlib.h>
#ifdef __KERNEL__
#  include <endian.h>
#else
#  include <string.h>
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
	/** Whether at least one of the static part of the IPv6 extensions changed
	 * in the current packet */
	bool is_ipv6_exts_list_static_changed;

	/* the length of the TCP payload (headers and options excluded) */
	size_t payload_len;

	/** The minimal number of bits required to encode the MSN value */
	size_t nr_msn_bits;

	/** Whether the TCP window changed or not */
	size_t tcp_window_changed;
	/** The minimal number of bits required to encode the TCP window */
	size_t nr_window_bits_16383;

	/** Whether the TCP sequence number changed or not */
	bool tcp_seq_num_changed;
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

	/* innermost IPv4 TTL or IPv6 Hop Limit */
	uint8_t ttl_hopl;
	size_t nr_ttl_hopl_bits;
	bool ttl_hopl_changed;
	/* outer IPv4 TTLs or IPv6 Hop Limits */
	int ttl_irreg_chain_flag;
	bool outer_ip_ttl_changed;

	bool ip_df_changed;
	bool dscp_changed;

	bool tcp_ack_flag_changed;
	bool tcp_urg_flag_present;
	bool tcp_urg_flag_changed;

	/** Whether the ecn_used flag changed or not */
	bool ecn_used_changed;
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
 * @brief Define the common IP header context to IPv4 and IPv6.
 */
typedef struct __attribute__((packed)) ipvx_context
{
	uint8_t version:4;
	uint8_t unused:4;

	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;

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
	uint8_t version:4;
	uint8_t df:1;
	uint8_t unused:3;

	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;

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
	/* TODO: GRE not yet supported */
	/* TODO: MINE not yet supported */
	/* TODO: AH not yet supported */
} ipv6_option_context_t;


/**
 * @brief Define the IPv6 header context.
 */
typedef struct __attribute__((packed)) ipv6_context
{
	uint8_t version:4;
	uint8_t unused:4;

	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;

	uint8_t next_header;

	uint8_t ttl_hopl;

	uint8_t ip_id_behavior;
	uint8_t last_ip_id_behavior;

	uint32_t flow_label:20;

	uint32_t src_addr[4];
	uint32_t dest_addr[4];

	size_t opts_nr;
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


/** Define the TCP part of the profile decompression context */
struct sc_tcp_context
{
	/// The number of times the sequence number field was added to the compressed header
	int tcp_seq_num_change_count;
	/** The number of times the window field was added to the compressed header */
	size_t tcp_window_change_count;

	/** Explicit Congestion Notification used */
	bool ecn_used;
	/** The number of times the ECN fields were added to the compressed header */
	size_t ecn_used_change_count;
	/** The number of times the ECN fields were not needed */
	size_t ecn_used_zero_count;

	uint32_t tcp_last_seq_num;

	uint16_t msn;               /**< The Master Sequence Number (MSN) */
	struct c_wlsb *msn_wlsb;    /**< The W-LSB decoding context for MSN */

	struct c_wlsb *ttl_hopl_wlsb;
	size_t ttl_hopl_change_count;

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

	size_t ack_deltas_next;
	uint16_t ack_deltas_width[20];
	uint16_t ack_stride;
	uint32_t ack_num_scaled;
	uint16_t ack_num_residue;
	size_t ack_num_scaling_nr;

	/** The compression context for TCP options */
	struct c_tcp_opts_ctxt tcp_opts;

	/// The previous TCP header
	struct tcphdr old_tcphdr;

	/// @brief TCP-specific temporary variables that are used during one single
	///        compression of packet
	struct tcp_tmp_variables tmp;

	size_t ip_contexts_nr;
	ip_context_t ip_contexts[ROHC_TCP_MAX_IP_HDRS];
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
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

static uint16_t c_tcp_get_next_msn(const struct rohc_comp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));

static bool rohc_comp_tcp_are_ipv6_exts_acceptable(const struct rohc_comp *const comp,
                                                   uint8_t *const next_proto,
                                                   const uint8_t *const exts,
                                                   const size_t max_exts_len,
                                                   size_t *const exts_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static bool tcp_detect_changes(struct rohc_comp_ctxt *const context,
                               const struct net_pkt *const uncomp_pkt,
                               ip_context_t **const ip_inner_context,
                               const struct tcphdr **const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static bool tcp_detect_changes_ipv6_exts(struct rohc_comp_ctxt *const context,
                                         ip_context_t *const ip_context,
                                         uint8_t *const protocol,
                                         const uint8_t *const exts,
                                         const size_t max_exts_len,
                                         size_t *const exts_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 6)));

static void tcp_decide_state(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

static bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt,
                                     const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static bool tcp_encode_uncomp_ip_fields(struct rohc_comp_ctxt *const context,
                                        const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static bool tcp_encode_uncomp_tcp_fields(struct rohc_comp_ctxt *const context,
                                         const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static rohc_packet_t tcp_decide_packet(struct rohc_comp_ctxt *const context,
                                       const ip_context_t *const ip_inner_context,
                                       const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_FO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct tcphdr *const tcp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context,
                                             const ip_context_t *const ip_inner_context,
                                             const struct tcphdr *const tcp,
                                             const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
	__attribute__((warn_unused_result, nonnull(1, 2)));

/* static chain */
static int tcp_code_static_part(struct rohc_comp_ctxt *const context,
                                const struct ip_packet *const ip,
                                uint8_t *const rohc_pkt,
                                const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int tcp_code_static_ipv4_part(const struct rohc_comp_ctxt *const context,
                                     const struct ipv4_hdr *const ipv4,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int tcp_code_static_ipv6_part(const struct rohc_comp_ctxt *const context,
                                     const struct ipv6_hdr *const ipv6,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));
static int tcp_code_static_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                         const struct ipv6_opt *const ipv6_opt,
                                         const uint8_t protocol,
                                         uint8_t *const rohc_data,
                                         const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int tcp_code_static_tcp_part(const struct rohc_comp_ctxt *const context,
                                    const struct tcphdr *const tcp,
                                    uint8_t *const rohc_data,
                                    const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* dynamic chain */
static int tcp_code_dyn_part(struct rohc_comp_ctxt *const context,
                             const struct ip_packet *const ip,
                             uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len,
                             size_t *const parsed_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static int tcp_code_dynamic_ipv4_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv4_hdr *const ipv4,
                                      const bool is_innermost,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static int tcp_code_dynamic_ipv6_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv6_hdr *const ipv6,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));
static int tcp_code_dynamic_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                          ipv6_option_context_t *const opt_ctxt,
                                          const struct ipv6_opt *const ipv6_opt,
                                          const uint8_t protocol,
                                          uint8_t *const rohc_data,
                                          const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static int tcp_code_dynamic_tcp_part(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

/* irregular chain */
static int tcp_code_irreg_chain(struct rohc_comp_ctxt *const context,
                                const struct ip_packet *const ip,
                                const uint8_t ip_inner_ecn,
                                const struct tcphdr *const tcp,
                                uint8_t *const rohc_pkt,
                                const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));
static int tcp_code_irregular_ipv4_part(const struct rohc_comp_ctxt *const context,
                                        const ip_context_t *const ip_context,
                                        const struct ipv4_hdr *const ipv4,
                                        const bool is_innermost,
                                        const bool ecn_used,
                                        const uint8_t ip_inner_ecn,
                                        const bool ttl_irreg_chain_flag,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 8)));
static int tcp_code_irregular_ipv6_part(const struct rohc_comp_ctxt *const context,
                                        const ip_context_t *const ip_context,
                                        const struct ipv6_hdr *const ipv6,
                                        const bool is_innermost,
                                        const bool ecn_used,
                                        const uint8_t ip_inner_ecn,
                                        const bool ttl_irreg_chain_flag,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 8)));
static int tcp_code_irregular_ipv6_opt_part(struct rohc_comp_ctxt *const context,
                                            ipv6_option_context_t *const opt_ctxt,
                                            const struct ipv6_opt *const ipv6_opt,
                                            const uint8_t protocol,
                                            uint8_t *const rohc_data,
                                            const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
static int tcp_code_irregular_tcp_part(const struct rohc_comp_ctxt *const context,
                                       const struct tcphdr *const tcp,
                                       const uint8_t ip_inner_ecn,
                                       uint8_t *const rohc_data,
                                       const size_t rohc_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

/* IR and CO packets */
static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *const ip,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));

static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *ip,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));
static int co_baseheader(struct rohc_comp_ctxt *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_t *const ip_inner_context,
                         const struct ip_hdr *const inner_ip_hdr,
                         const size_t inner_ip_hdr_len,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         const rohc_packet_t packet_type,
                         const struct tcphdr *const tcp,
                         const uint8_t crc)
	__attribute__((nonnull(1, 2, 3, 4, 6, 9), warn_unused_result));


/*
 * Functions that build the rnd_X packets
 */

static int c_tcp_build_rnd_1(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_2(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_3(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_4(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_5(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_6(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_7(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 2, 3, 5), warn_unused_result));

static int c_tcp_build_rnd_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));


/*
 * Functions that build the seq_X packets
 */

static int c_tcp_build_seq_1(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_2(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_3(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_4(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_5(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_6(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_7(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_seq_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));

static int c_tcp_build_co_common(const struct rohc_comp_ctxt *const context,
                                 const ip_context_t *const inner_ip_ctxt,
                                 struct sc_tcp_context *const tcp_context,
                                 const struct ip_hdr *const inner_ip_hdr,
                                 const size_t inner_ip_hdr_len,
                                 const struct tcphdr *const tcp,
                                 const uint8_t crc,
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
	__attribute__((nonnull(1, 2, 3, 4, 6, 8), warn_unused_result));



/*
 * Misc functions
 */

static tcp_ip_id_behavior_t tcp_detect_ip_id_behavior(const uint16_t last_ip_id,
                                                      const uint16_t new_ip_id)
	__attribute__((warn_unused_result, const));

static void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
                                         const uint8_t pkt_ecn_vals,
                                         const uint8_t pkt_outer_dscp_changed,
                                         const uint8_t pkt_res_val)
	__attribute__((nonnull(1)));

static void tcp_field_descr_change(const struct rohc_comp_ctxt *const context,
                                   const char *const name,
                                   const bool changed,
                                   const size_t nr_trans)
	__attribute__((nonnull(1, 2)));

static void tcp_field_descr_present(const struct rohc_comp_ctxt *const context,
                                    const char *const name,
                                    const bool present)
	__attribute__((nonnull(1, 2)));

static bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
                                       const size_t nr_trans)
	__attribute__((warn_unused_result, const));
static bool tcp_is_ack_stride_static(const uint16_t ack_stride,
                                     const size_t nr_trans)
	__attribute__((warn_unused_result, const));

static bool c_tcp_feedback(struct rohc_comp_ctxt *const context,
                           const enum rohc_feedback_type feedback_type,
                           const uint8_t *const packet,
                           const size_t packet_len,
                           const uint8_t *const feedback_data,
                           const size_t feedback_data_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 5)));

static bool c_tcp_feedback_2(struct rohc_comp_ctxt *const context,
                             const uint8_t *const packet,
                             const size_t packet_len,
                             const uint8_t *const feedback_data,
                             const size_t feedback_data_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static void c_tcp_feedback_ack(struct rohc_comp_ctxt *const context,
                               const uint32_t sn_bits,
                               const size_t sn_bits_nr,
                               const bool sn_not_valid)
	__attribute__((nonnull(1)));


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
 *
 * @todo TODO: the code that parses IP headers in IP/UDP/RTP profiles could
 *             probably be re-used (and maybe enhanced if needed)
 */
static bool c_tcp_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
{
	const struct rohc_comp *const comp = context->compressor;
	struct sc_tcp_context *tcp_context;
	const uint8_t *remain_data = packet->outer_ip.data;
	size_t remain_len = packet->outer_ip.size;
	const struct tcphdr *tcp;
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

	/* create contexts for IP headers and their extensions */
	tcp_context->ip_contexts_nr = 0;
	do
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context =
			&(tcp_context->ip_contexts[tcp_context->ip_contexts_nr]);

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip->version);
		ip_context->version = ip->version;
		ip_context->ctxt.vx.version = ip->version;

		switch(ip->version)
		{
			case IPV4:
			{
				const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

				assert(remain_len >= sizeof(struct ipv4_hdr));
				proto = ipv4->protocol;

				ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(ipv4->id);
				rohc_comp_debug(context, "IP-ID 0x%04x", ip_context->ctxt.v4.last_ip_id);
				ip_context->ctxt.v4.last_ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
				ip_context->ctxt.v4.ip_id_behavior = IP_ID_BEHAVIOR_SEQ;
				ip_context->ctxt.v4.protocol = proto;
				ip_context->ctxt.v4.dscp = ipv4->dscp;
				ip_context->ctxt.v4.df = ipv4->df;
				ip_context->ctxt.v4.ttl_hopl = ipv4->ttl;
				ip_context->ctxt.v4.src_addr = ipv4->saddr;
				ip_context->ctxt.v4.dst_addr = ipv4->daddr;

				remain_data += sizeof(struct ipv4_hdr);
				remain_len -= sizeof(struct ipv4_hdr);
				break;
			}
			case IPV6:
			{
				const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

				assert(remain_len >= sizeof(struct ipv6_hdr));
				proto = ipv6->nh;

				ip_context->ctxt.v6.ip_id_behavior = IP_ID_BEHAVIOR_RAND;
				ip_context->ctxt.v6.next_header = proto;
				ip_context->ctxt.v6.dscp = remain_data[1];
				ip_context->ctxt.v6.ttl_hopl = ipv6->hl;
				ip_context->ctxt.v6.flow_label = ipv6_get_flow_label(ipv6);
				memcpy(ip_context->ctxt.v6.src_addr, &ipv6->saddr,
				       sizeof(struct ipv6_addr));
				memcpy(ip_context->ctxt.v6.dest_addr, &ipv6->daddr,
				       sizeof(struct ipv6_addr));

				remain_data += sizeof(struct ipv6_hdr);
				remain_len -= sizeof(struct ipv6_hdr);

				rohc_comp_debug(context, "parse IPv6 extension headers");
				ip_context->ctxt.v6.opts_nr = 0;
				while(rohc_is_ipv6_opt(proto))
				{
					ipv6_option_context_t *const ipv6_opt_ctxt =
						&(ip_context->ctxt.v6.opts[ip_context->ctxt.v6.opts_nr]);

					switch(proto)
					{
						case ROHC_IPPROTO_HOPOPTS:  /* IPv6 Hop-by-Hop options */
						case ROHC_IPPROTO_ROUTING:  /* IPv6 routing header */
						case ROHC_IPPROTO_DSTOPTS:  /* IPv6 destination options */
						{
							const struct ipv6_opt *const ipv6_opt =
								(struct ipv6_opt *) remain_data;

							assert(remain_len >= sizeof(struct ipv6_opt));

							size_option = (ipv6_opt->length + 1) << 3;
							rohc_comp_debug(context, "  IPv6 extension header is %zu-byte long",
							                size_option);
							ipv6_opt_ctxt->generic.option_length = size_option;
							memcpy(&ipv6_opt_ctxt->generic.data, &ipv6_opt->value,
							       size_option - 2);
							proto = ipv6_opt->next_header;
							break;
						}
						// case ROHC_IPPROTO_ESP : ???
						case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
						case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
						case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
						default:
						{
							goto free_context;
						}
					}
					remain_data += size_option;
					remain_len -= size_option;
					ip_context->ctxt.v6.opts_nr++;
				}
				break;
			}
			default:
			{
				goto free_context;
			}
		}

		tcp_context->ip_contexts_nr++;
	}
	while(rohc_is_tunneling(proto) && tcp_context->ip_contexts_nr < ROHC_TCP_MAX_IP_HDRS);

	/* profile cannot handle the packet if it bypasses internal limit of IP headers */
	if(rohc_is_tunneling(proto))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "too many IP headers for TCP profile (%u headers max)",
		           ROHC_TCP_MAX_IP_HDRS);
		goto free_context;
	}

	/* create context for TCP header */
	tcp_context->tcp_seq_num_change_count = 0;
	tcp_context->ttl_hopl_change_count = 0;
	tcp_context->tcp_window_change_count = 0;
	tcp_context->ecn_used = false;
	tcp_context->ecn_used_change_count = MAX_FO_COUNT;
	tcp_context->ecn_used_zero_count = 0;
	tcp_context->tcp_last_seq_num = -1;

	/* TCP header begins just after the IP headers */
	assert(remain_len >= sizeof(struct tcphdr));
	tcp = (struct tcphdr *) remain_data;
	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(struct tcphdr));

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

	/* innermost IPv4 TTL or IPv6 Hop Limit */
	tcp_context->ttl_hopl_wlsb =
		c_create_wlsb(8, comp->wlsb_window_width, ROHC_LSB_SHIFT_TCP_TTL);
	if(tcp_context->ttl_hopl_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for innermost IPv4 TTL or "
		           "IPv6 Hop Limit");
		goto free_wlsb_ip_id;
	}

	/* TCP window */
	tcp_context->window_wlsb =
		c_create_wlsb(16, comp->wlsb_window_width, ROHC_LSB_SHIFT_TCP_WINDOW);
	if(tcp_context->window_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP window");
		goto free_wlsb_ttl_hopl;
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
	tcp_context->tcp_opts.structure_nr_trans = 0;
	tcp_context->tcp_opts.structure_nr = 0;
	// Initialize TCP options list index used
	for(i = 0; i <= MAX_TCP_OPTION_INDEX; i++)
	{
		tcp_context->tcp_opts.list[i].used = false;
	}

	/* no TCP option Timestamp received yet */
	tcp_context->tcp_opts.is_timestamp_init = false;
	/* TCP option Timestamp (request) */
	tcp_context->tcp_opts.ts_req_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->tcp_opts.ts_req_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "request");
		goto free_wlsb_ack_scaled;
	}
	/* TCP option Timestamp (reply) */
	tcp_context->tcp_opts.ts_reply_wlsb =
		c_create_wlsb(32, comp->wlsb_window_width, ROHC_LSB_SHIFT_VAR);
	if(tcp_context->tcp_opts.ts_reply_wlsb == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "failed to create W-LSB context for TCP option Timestamp "
		           "reply");
		goto free_wlsb_opt_ts_req;
	}

	return true;

free_wlsb_opt_ts_req:
	c_destroy_wlsb(tcp_context->tcp_opts.ts_req_wlsb);
free_wlsb_ack_scaled:
	c_destroy_wlsb(tcp_context->ack_scaled_wlsb);
free_wlsb_ack:
	c_destroy_wlsb(tcp_context->ack_wlsb);
free_wlsb_seq_scaled:
	c_destroy_wlsb(tcp_context->seq_scaled_wlsb);
free_wlsb_seq:
	c_destroy_wlsb(tcp_context->seq_wlsb);
free_wlsb_window:
	c_destroy_wlsb(tcp_context->window_wlsb);
free_wlsb_ttl_hopl:
	c_destroy_wlsb(tcp_context->ttl_hopl_wlsb);
free_wlsb_ip_id:
	c_destroy_wlsb(tcp_context->ip_id_wlsb);
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

	c_destroy_wlsb(tcp_context->tcp_opts.ts_reply_wlsb);
	c_destroy_wlsb(tcp_context->tcp_opts.ts_req_wlsb);
	c_destroy_wlsb(tcp_context->ack_scaled_wlsb);
	c_destroy_wlsb(tcp_context->ack_wlsb);
	c_destroy_wlsb(tcp_context->seq_scaled_wlsb);
	c_destroy_wlsb(tcp_context->seq_wlsb);
	c_destroy_wlsb(tcp_context->window_wlsb);
	c_destroy_wlsb(tcp_context->ip_id_wlsb);
	c_destroy_wlsb(tcp_context->ttl_hopl_wlsb);
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
	/* TODO: should avoid code duplication by using net_pkt as
	 * rohc_comp_rfc3095_check_profile() does */
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
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;

		/* check minimal length for IP version */
		if(remain_len < sizeof(struct ip_hdr))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "failed to determine the version of IP header #%zu",
			           ip_hdrs_nr + 1);
			goto bad_profile;
		}

		if(ip->version == IPV4)
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
			if(ipv4_is_fragment(ipv4))
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
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			size_t ipv6_exts_len;

			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL, "found IPv6");
			if(remain_len < sizeof(struct ipv6_hdr))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "uncompressed packet too short for IP header #%zu",
				           ip_hdrs_nr + 1);
				goto bad_profile;
			}
			next_proto = ipv6->nh;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* payload length shall be correct */
			if(rohc_ntoh16(ipv6->plen) != remain_len)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: payload "
				           "length is %u while it shall be %zu", ip_hdrs_nr + 1,
				           rohc_ntoh16(ipv6->plen), remain_len);
				goto bad_profile;
			}

			/* reject packets with malformed IPv6 extension headers or IPv6
			 * extension headers that are not compatible with the TCP profile */
			if(!rohc_comp_tcp_are_ipv6_exts_acceptable(comp, &next_proto,
			                                           remain_data, remain_len,
			                                           &ipv6_exts_len))
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "IP packet #%zu is not supported by the profile: "
				           "malformed or incompatible IPv6 extension headers "
				           "detected", ip_hdrs_nr + 1);
				goto bad_profile;
			}
			remain_data += ipv6_exts_len;
			remain_len -= ipv6_exts_len;
		}
		else
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "unsupported version %u for header #%zu",
			           ip->version, ip_hdrs_nr + 1);
			goto bad_profile;
		}
		ip_hdrs_nr++;
	}
	while(rohc_is_tunneling(next_proto) && ip_hdrs_nr < ROHC_TCP_MAX_IP_HDRS);

	/* profile cannot handle the packet if it bypasses internal limit of IP headers */
	if(rohc_is_tunneling(next_proto))
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

	/* reject packets with malformed TCP options or TCP options that are not
	 * compatible with the TCP profile */
	if(!rohc_comp_tcp_are_options_acceptable(comp, tcp_header->options,
	                                         tcp_header->data_offset))
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "malformed or incompatible TCP options detected");
		goto bad_profile;
	}

	return true;

bad_profile:
	return false;
}


/**
 * @brief Whether IPv6 extension headers are acceptable for TCP profile or not
 *
 * TCP options are acceptable if:
 *  - the last IPv6 extension header is not truncated,
 *  - no more than \e ROHC_TCP_MAX_IPV6_EXT_HDRS extension headers are present,
 *  - each extension header is present only once (except Destination that may
 *    occur twice).
 *
 * @param comp                The ROHC compressor
 * @param[in,out] next_proto  in: the protocol type of the first extension header
 *                            out: the protocol type of the transport header
 * @param exts                The beginning of the IPv6 extension headers
 * @param max_exts_len        The maximum length (in bytes) of the extension headers
 * @param[out] exts_len       The length (in bytes) of the IPv6 extension headers
 * @return                    true if the IPv6 extension headers are acceptable,
 *                            false if they are not
 *
 * @see ROHC_TCP_MAX_IPV6_EXT_HDRS
 */
static bool rohc_comp_tcp_are_ipv6_exts_acceptable(const struct rohc_comp *const comp,
                                                   uint8_t *const next_proto,
                                                   const uint8_t *const exts,
                                                   const size_t max_exts_len,
                                                   size_t *const exts_len)
{
	uint8_t ipv6_ext_types_count[ROHC_IPPROTO_MAX + 1] = { 0 };
	const uint8_t *remain_data = exts;
	size_t remain_len = max_exts_len;
	size_t ipv6_ext_nr;

	(*exts_len) = 0;

	ipv6_ext_nr = 0;
	while(rohc_is_ipv6_opt(*next_proto) && ipv6_ext_nr < ROHC_TCP_MAX_IPV6_EXT_HDRS)
	{
		size_t ext_len;

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "  found extension header #%zu of type %u",
		           ipv6_ext_nr + 1, *next_proto);

		switch(*next_proto)
		{
			case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop options */
			case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
			case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination options */
			{
				const struct ipv6_opt *const ipv6_opt =
					(struct ipv6_opt *) remain_data;

				if(remain_len < (sizeof(ipv6_opt) - 1))
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "packet too short for IPv6 extension header");
					goto bad_exts;
				}

				ext_len = (ipv6_opt->length + 1) << 3;
				if(remain_len < ext_len)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "packet too short for IPv6 extension header");
					goto bad_exts;
				}
				(*next_proto) = ipv6_opt->next_header;

				/* RFC 2460 §4 reads:
				 *   The Hop-by-Hop Options header, when present, must
				 *   immediately follow the IPv6 header.
				 *   [...]
				 *   The same action [ie. reject packet] should be taken if a
				 *   node encounters a Next Header value of zero in any header other
				 *   than an IPv6 header. */
				if((*next_proto) == ROHC_IPPROTO_HOPOPTS && ipv6_ext_nr != 0)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed IPv6 header: the Hop-By-Hop extension "
					           "header should be the very first extension header, "
					           "not the #%zu one", ipv6_ext_nr + 1);
					goto bad_exts;
				}
				break;
			}
			// case ROHC_IPPROTO_ESP : ???
			case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
			case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
			case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
			default:
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "malformed IPv6 header: unsupported IPv6 extension "
				           "header %u detected", *next_proto);
				goto bad_exts;
			}
		}
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "  extension header is %zu-byte long", ext_len);
		remain_data += ext_len;
		remain_len -= ext_len;

		ipv6_ext_nr++;
		(*exts_len) += ext_len;
		if(ipv6_ext_types_count[*next_proto] >= 255)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "too many IPv6 extension header of type 0x%02x", *next_proto);
			goto bad_exts;
		}
		ipv6_ext_types_count[*next_proto]++;
	}

	/* profile cannot handle the packet if it bypasses internal limit of
	 * IPv6 extension headers */
	if(ipv6_ext_nr > ROHC_TCP_MAX_IPV6_EXT_HDRS)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "IP header got too many IPv6 extension headers for TCP profile "
		           "(%u headers max)", ROHC_TCP_MAX_IPV6_EXT_HDRS);
		goto bad_exts;
	}

	/* RFC 2460 §4.1 reads:
	 *   Each extension header should occur at most once, except for the
	 *   Destination Options header which should occur at most twice (once
	 *   before a Routing header and once before the upper-layer header). */
	{
		unsigned int ext_type;

		for(ext_type = 0; ext_type <= ROHC_IPPROTO_MAX; ext_type++)
		{
			if(ext_type == ROHC_IPPROTO_DSTOPTS && ipv6_ext_types_count[ext_type] > 2)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "malformed IPv6 header: the Destination extension "
				           "header should occur at most twice, but it was "
				           "found %u times", ipv6_ext_types_count[ext_type]);
				goto bad_exts;
			}
			else if(ext_type != ROHC_IPPROTO_DSTOPTS && ipv6_ext_types_count[ext_type] > 1)
			{
				rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
				           "malformed IPv6 header: the extension header of type "
				           "%u header should occur at most once, but it was found "
				           "%u times", ext_type, ipv6_ext_types_count[ext_type]);
				goto bad_exts;
			}
		}
	}

	return true;

bad_exts:
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
 *
 * @todo TODO: the code that parses IP headers in IP/UDP/RTP profiles could
 *             probably be re-used (and maybe enhanced if needed)
 */
static bool c_tcp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint8_t *remain_data = packet->outer_ip.data;
	size_t remain_len = packet->outer_ip.size;
	size_t ip_hdr_pos;
	uint8_t next_proto = ROHC_IPPROTO_IPIP;
	const struct tcphdr *tcp;
	bool is_tcp_same;

	/* parse the IP headers (lengths already checked while checking profile) */
	for(ip_hdr_pos = 0;
	    ip_hdr_pos < tcp_context->ip_contexts_nr && rohc_is_tunneling(next_proto);
	    ip_hdr_pos++)
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		size_t ip_ext_pos;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip->version);
		if(ip->version != ip_context->version)
		{
			rohc_comp_debug(context, "  not same IP version");
			goto bad_context;
		}

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			/* check source and destination addresses */
			if(ipv4->saddr != ip_context->ctxt.v4.src_addr ||
			   ipv4->daddr != ip_context->ctxt.v4.dst_addr)
			{
				rohc_comp_debug(context, "  not same IPv4 addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv4 addresses");

			/* check transport protocol */
			next_proto = ipv4->protocol;
			if(next_proto != ip_context->ctxt.v4.protocol)
			{
				rohc_comp_debug(context, "  IPv4 not same protocol");
				goto bad_context;
			}
			rohc_comp_debug(context, "  IPv4 same protocol %d", next_proto);

			/* skip IPv4 header */
			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			/* check source and destination addresses */
			if(memcmp(&ipv6->saddr, ip_context->ctxt.v6.src_addr,
			          sizeof(struct ipv6_addr)) != 0 ||
			   memcmp(&ipv6->daddr, ip_context->ctxt.v6.dest_addr,
			          sizeof(struct ipv6_addr)) != 0)
			{
				rohc_comp_debug(context, "  not same IPv6 addresses");
				goto bad_context;
			}
			rohc_comp_debug(context, "  same IPv6 addresses");

			/* check Flow Label */
			if(ipv6_get_flow_label(ipv6) != ip_context->ctxt.v6.flow_label)
			{
				rohc_comp_debug(context, "  not same IPv6 flow label");
				goto bad_context;
			}

			/* check next header protocol */
			next_proto = ipv6->nh;
			if(next_proto != ip_context->ctxt.v6.next_header)
			{
				rohc_comp_debug(context, "  IPv6 not same protocol %d", next_proto);
				goto bad_context;
			}
			rohc_comp_debug(context, "  IPv6 same protocol %d", next_proto);

			/* skip IPv6 base header */
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* check IPv6 extension headers */
			for(ip_ext_pos = 0;
			    ip_ext_pos < ip_context->ctxt.v6.opts_nr && rohc_is_tunneling(next_proto);
			    ip_ext_pos++)
			{
				const ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);
				const struct ipv6_opt *const ipv6_opt =
					(struct ipv6_opt *) remain_data;
				size_t opt_len;

				assert(remain_len >= sizeof(struct ipv6_opt));

				/* check next header protocol */
				next_proto = ipv6_opt->next_header;
				if(next_proto != opt_ctxt->generic.next_header)
				{
					rohc_comp_debug(context, "  not same IPv6 option (%d != %d)",
					                next_proto, opt_ctxt->generic.next_header);
					goto bad_context;
				}
				rohc_comp_debug(context, "  same IPv6 option %d", next_proto);

				/* skip extension header */
				opt_len = (ipv6_opt->length + 1) << 3;
				remain_data += opt_len;
				remain_len -= opt_len;
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
		}
		else
		{
			rohc_comp_warn(context, "unsupported version %u for header #%zu",
			               ip->version, ip_hdr_pos + 1);
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

	assert(remain_len >= sizeof(struct tcphdr));
	tcp = (struct tcphdr *) remain_data;
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
 *
 * @todo TODO: the code that parses IP headers in IP/UDP/RTP profiles could
 *             probably be re-used (and maybe enhanced if needed)
 */
static int c_tcp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        uint8_t *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	ip_context_t *ip_inner_context;
	const struct tcphdr *tcp;
	int counter;
	size_t i;

	assert(rohc_pkt != NULL);

	*packet_type = ROHC_PACKET_UNKNOWN;

	/* at the beginning, no item transmitted for the compressed list of TCP options */
	for(i = 0; i <= MAX_TCP_OPTION_INDEX; i++)
	{
		tcp_context->tcp_opts.tmp.is_list_item_present[i] = false;
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
	if(!tcp_encode_uncomp_fields(context, uncomp_pkt, tcp))
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
		counter = code_CO_packet(context, &uncomp_pkt->outer_ip, rohc_pkt,
		                         rohc_pkt_max_len, *packet_type, payload_offset);
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

		counter = code_IR_packet(context, &uncomp_pkt->outer_ip, rohc_pkt,
		                         rohc_pkt_max_len, *packet_type, payload_offset);
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
	memcpy(&(tcp_context->old_tcphdr), tcp, sizeof(struct tcphdr));
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

	/* ACK number sent once more, count the number of transmissions to
	 * know when scaled ACK number is possible */
	if(tcp_context->ack_stride != 0 &&
	   tcp_context->ack_num_scaling_nr < ROHC_INIT_TS_STRIDE_MIN)
	{
		tcp_context->ack_num_scaling_nr++;
		rohc_comp_debug(context, "unscaled ACK number was transmitted %zu / %u "
		                "times since the scaling factor or residue changed",
		                tcp_context->ack_num_scaling_nr, ROHC_INIT_TS_STRIDE_MIN);
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
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_IR_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *const ip,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
{
	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;
	size_t first_position;
	size_t crc_position;
	size_t rohc_hdr_len = 0;
	int ret;

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	ret = code_cid_values(context->compressor->medium.cid_type,
	                      context->cid, rohc_remain_data, rohc_remain_len,
	                      &first_position);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the %zu-byte "
		               "ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_remain_len);
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_hdr_len += ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %d byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, ret - 1);

	/* type of packet */
	if(packet_type == ROHC_PACKET_IR)
	{
		rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR;
	}
	else /* ROHC_PACKET_IR_DYN */
	{
		rohc_pkt[first_position] = ROHC_PACKET_TYPE_IR_DYN;
	}
	rohc_comp_debug(context, "packet type = 0x%02x", rohc_pkt[first_position]);

	/* enough room for profile ID and CRC? */
	if(rohc_remain_len < 2)
	{
		rohc_comp_warn(context, "ROHC buffer too small for IR(-DYN) packet: "
		               "2 bytes required for profile ID and CRC, but only "
		               "%zu bytes available", rohc_remain_len);
		goto error;
	}

	/* profile ID */
	rohc_comp_debug(context, "profile ID = 0x%02x", context->profile->id);
	rohc_remain_data[0] = context->profile->id;
	rohc_remain_data++;
	rohc_remain_len--;
	rohc_hdr_len++;

	/* the CRC is computed later since it must be computed over the whole packet
	 * with an empty CRC field */
	rohc_comp_debug(context, "CRC = 0x00 for CRC calculation");
	crc_position = rohc_hdr_len;
	rohc_remain_data[0] = 0;
	rohc_remain_data++;
	rohc_remain_len--;
	rohc_hdr_len++;

	/* add static chain for IR packet only */
	if(packet_type == ROHC_PACKET_IR)
	{
		ret = tcp_code_static_part(context, ip, rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build the static chain of the "
			               "IR(-DYN) packet");
			goto error;
		}
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
		rohc_hdr_len += ret;
		rohc_dump_buf(context->compressor->trace_callback,
		              context->compressor->trace_callback_priv,
		              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
		              "current ROHC packet (with static part)",
		              rohc_pkt, rohc_hdr_len);
	}

	/* add dynamic chain */
	ret = tcp_code_dyn_part(context, ip, rohc_remain_data,
	                        rohc_remain_len, payload_offset);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the dynamic chain of the "
		               "IR(-DYN) packet");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
#endif
	rohc_hdr_len += ret;
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "current ROHC packet (with dynamic part)",
	              rohc_pkt, rohc_hdr_len);

	/* IR(-DYN) header was successfully built, compute the CRC */
	rohc_pkt[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, rohc_pkt,
	                                       rohc_hdr_len, CRC_INIT_8,
	                                       context->compressor->crc_table_8);
	rohc_comp_debug(context, "CRC (header length = %zu, crc = 0x%x)",
	                rohc_hdr_len, rohc_pkt[crc_position]);

	rohc_comp_debug(context, "IR(-DYN) packet, length %zu", rohc_hdr_len);
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "current ROHC packet", rohc_pkt, rohc_hdr_len);

	return rohc_hdr_len;

error:
	return -1;
}


/**
 * @brief Code the static part of an IR packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int tcp_code_static_part(struct rohc_comp_ctxt *const context,
                                const struct ip_packet *const ip,
                                uint8_t *const rohc_pkt,
                                const size_t rohc_pkt_max_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const uint8_t *remain_data = ip->data;
	size_t remain_len = ip->size;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	size_t ip_hdr_pos;
	int ret;

	/* add IP parts of static chain */
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip_hdr = (struct ip_hdr *) remain_data;
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		size_t ip_ext_pos;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip_hdr->version);

		if(ip_hdr->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			ret = tcp_code_static_ipv4_part(context, ipv4, rohc_remain_data,
			                                rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv4 base header part "
				               "of the static chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip_hdr->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			uint8_t protocol;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			ret = tcp_code_static_ipv6_part(context, ipv6, rohc_remain_data,
			                                rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv6 base header part "
				               "of the static chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			protocol = ipv6->nh;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				const ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);

				rohc_comp_debug(context, "IPv6 option #%zu: type %u / length %zu",
				                ip_ext_pos + 1, protocol,
				                opt_ctxt->generic.option_length);
				ret = tcp_code_static_ipv6_opt_part(context, ipv6_opt, protocol,
				                                    rohc_remain_data, rohc_remain_len);
				if(ret < 0)
				{
					rohc_comp_warn(context, "failed to build the IPv6 extension header "
					               "part of the static chain");
					goto error;
				}
				rohc_remain_data += ret;
				rohc_remain_len -= ret;

				protocol = ipv6_opt->next_header;
				remain_data += opt_ctxt->generic.option_length;
				remain_len -= opt_ctxt->generic.option_length;
			}
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u", ip_hdr->version);
			assert(0);
			goto error;
		}
	}

	/* add TCP static part */
	{
		const struct tcphdr *const tcp = (struct tcphdr *) remain_data;

		assert(remain_len >= sizeof(struct tcphdr));

		ret = tcp_code_static_tcp_part(context, tcp, rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build the TCP header part of the "
			               "static chain");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
#endif
		rohc_remain_len -= ret;
	}

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Code the dynamic part of an IR or IR-DYN packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param[out] parsed_len   The length of uncompressed data parsed
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int tcp_code_dyn_part(struct rohc_comp_ctxt *const context,
                             const struct ip_packet *const ip,
                             uint8_t *const rohc_pkt,
                             const size_t rohc_pkt_max_len,
                             size_t *const parsed_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	ip_context_t *inner_ip_context = NULL;

	const uint8_t *remain_data = ip->data;
	size_t remain_len = ip->size;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	const struct ip_hdr *inner_ip_hdr = NULL;
	size_t ip_hdr_pos;
	int ret;

	/* there is at least one IP header otherwise it won't be the IP/TCP profile */
	assert(tcp_context->ip_contexts_nr > 0);

	/* add dynamic chain for both IR and IR-DYN packet */
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip_hdr = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const bool is_inner = !!(ip_hdr_pos + 1 == tcp_context->ip_contexts_nr);
		size_t ip_ext_pos;

		/* the last IP header is the innermost one */
		inner_ip_context = ip_context;
		inner_ip_hdr = (struct ip_hdr *) remain_data;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip_hdr->version);

		if(ip_hdr->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			ret = tcp_code_dynamic_ipv4_part(context, ip_context, ipv4, is_inner,
			                                 rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv4 base header part "
				               "of the dynamic chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip_hdr->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			uint8_t protocol;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			ret = tcp_code_dynamic_ipv6_part(context, ip_context, ipv6,
			                                 rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv6 base header part "
				               "of the dynamic chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			protocol = ipv6->nh;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);

				rohc_comp_debug(context, "IPv6 option %u", protocol);
				ret = tcp_code_dynamic_ipv6_opt_part(context, opt_ctxt, ipv6_opt,
				                                     protocol, rohc_remain_data,
				                                     rohc_remain_len);
				if(ret < 0)
				{
					rohc_comp_warn(context, "failed to build the IPv6 extension "
					               "header part of the dynamic chain");
					goto error;
				}
				rohc_remain_data += ret;
				rohc_remain_len -= ret;

				protocol = ipv6_opt->next_header;
				remain_data += opt_ctxt->generic.option_length;
				remain_len -= opt_ctxt->generic.option_length;
			}
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u", ip_hdr->version);
			assert(0);
			goto error;
		}
	}

	/* handle TCP header */
	{
		const struct tcphdr *const tcp = (struct tcphdr *) remain_data;

		assert(remain_len >= sizeof(struct tcphdr));

		/* add TCP dynamic part */
		ret = tcp_code_dynamic_tcp_part(context, tcp, rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to build the TCP header part of the "
			               "dynamic chain");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
#endif
		rohc_remain_len -= ret;

		/* skip TCP header and options */
		remain_data += (tcp->data_offset << 2);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		remain_len -= (tcp->data_offset << 2);
#endif
		*parsed_len = remain_data - ip->data;
	}

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		inner_ip_context->ctxt.v4.last_ip_id_behavior =
			inner_ip_context->ctxt.v4.ip_id_behavior;
		inner_ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(inner_ipv4->id);
		inner_ip_context->ctxt.v4.df = inner_ipv4->df;
		inner_ip_context->ctxt.vx.dscp = inner_ipv4->dscp;
	}
	else if(inner_ip_hdr->version == IPV6)
	{
		const struct ipv6_hdr *const inner_ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		inner_ip_context->ctxt.vx.dscp = ipv6_get_dscp(inner_ipv6);
	}
	else
	{
		rohc_comp_warn(context, "unexpected IP version %u", inner_ip_hdr->version);
		assert(0);
		goto error;
	}
	inner_ip_context->ctxt.vx.ttl_hopl = tcp_context->tmp.ttl_hopl;

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv6 option header
 *
 * @param context         The compression context
 * @param ipv6_opt        The IPv6 extension header
 * @param protocol        The protocol of the IPv6 extension header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_static_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                         const struct ipv6_opt *const ipv6_opt,
                                         const uint8_t protocol,
                                         uint8_t *const rohc_data,
                                         const size_t rohc_max_len)
{
	ip_opt_static_t *const ip_opt_static = (ip_opt_static_t *) rohc_data;
	size_t ipv6_opt_static_len = sizeof(ip_opt_static_t);

	if(rohc_max_len < ipv6_opt_static_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv6 extension "
		               "header static part: %zu bytes required, but only %zu bytes "
		               "available", ipv6_opt_static_len, rohc_max_len);
		goto error;
	}

	/* next header and length are common to all options */
	ip_opt_static->next_header = ipv6_opt->next_header;
	ip_opt_static->length = ipv6_opt->length;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop option */
		case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination option */
		{
			/* no payload transmitted for those options, nothing to do */
			break;
		}
		case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
		{
			ip_rout_opt_static_t *const ip_rout_opt_static =
				(ip_rout_opt_static_t *) rohc_data;
			ipv6_opt_static_len = (ipv6_opt->length + 1) << 3;
			if(rohc_max_len < ipv6_opt_static_len)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv6 extension "
				               "header static part: %zu bytes required, but only %zu "
				               "bytes available", ipv6_opt_static_len, rohc_max_len);
				goto error;
			}
			memcpy(ip_rout_opt_static->value, ipv6_opt->value, ipv6_opt_static_len - 2);
			break;
		}
		case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
		case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
		case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
		default:
		{
			assert(0);
			goto error;
		}
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv6 option static part", rohc_data, ipv6_opt_static_len);
#endif

	return ipv6_opt_static_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv6 option header
 *
 * @param context         The compression context
 * @param opt_ctxt        The compression context of the IPv6 option
 * @param ipv6_opt        The IPv6 extension header
 * @param protocol        The protocol of the IPv6 extension header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_ipv6_opt_part(const struct rohc_comp_ctxt *const context,
                                          ipv6_option_context_t *const opt_ctxt,
                                          const struct ipv6_opt *const ipv6_opt,
                                          const uint8_t protocol,
                                          uint8_t *const rohc_data,
                                          const size_t rohc_max_len)
{
	size_t ipv6_opt_dynamic_len;

	switch(protocol)
	{
		case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop option */
		case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination option */
		{
			ipv6_opt_dynamic_len = ((ipv6_opt->length + 1) << 3) - 2;
			if(rohc_max_len < ipv6_opt_dynamic_len)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv6 extension "
				               "header dynamic part: %zu bytes required, but only %zu "
				               "bytes available", ipv6_opt_dynamic_len, rohc_max_len);
				goto error;
			}
			memcpy(rohc_data, ipv6_opt->value, ipv6_opt_dynamic_len);
			/* TODO: should not update context there */
			memcpy(opt_ctxt->generic.data, ipv6_opt->value, ipv6_opt_dynamic_len);
			break;
		}
		case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
		{
			/* the dynamic part of the routing header is empty */
			ipv6_opt_dynamic_len = 0;
			break;
		}
		case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
		case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
		case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
		default:
		{
			assert(0);
			goto error;
		}
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv6 option dynamic part", rohc_data, ipv6_opt_dynamic_len);
#endif

	return ipv6_opt_dynamic_len;

error:
	return -1;
}


/**
 * @brief Build the irregular part of the IPv6 option header
 *
 * @param context         The compression context
 * @param opt_ctxt        The compression context of the IPv6 option
 * @param ipv6_opt        The IPv6 extension header
 * @param protocol        The protocol of the IPv6 extension header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_irregular_ipv6_opt_part(struct rohc_comp_ctxt *const context __attribute__((unused)),
                                            ipv6_option_context_t *const opt_ctxt __attribute__((unused)),
                                            const struct ipv6_opt *const ipv6_opt __attribute__((unused)),
                                            const uint8_t protocol,
                                            uint8_t *const rohc_data __attribute__((unused)),
                                            const size_t rohc_max_len __attribute__((unused)))
{
	size_t irreg_ipv6_opt_len = 0;

	switch(protocol)
	{
		case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
		case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
		case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
			assert(0);
			break;
		default:
			break;
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv6 option irregular part", rohc_data, irreg_ipv6_opt_len);
#endif

	return irreg_ipv6_opt_len;
}


/**
 * @brief Build the static part of the IPv4 header
 *
 * @param context         The compression context
 * @param ipv4            The IPv4 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_static_ipv4_part(const struct rohc_comp_ctxt *const context,
                                     const struct ipv4_hdr *const ipv4,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
{
	ipv4_static_t *const ipv4_static = (ipv4_static_t *) rohc_data;
	const size_t ipv4_static_len = sizeof(ipv4_static_t);

	if(rohc_max_len < ipv4_static_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv4 static part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv4_static_len, rohc_max_len);
		goto error;
	}

	ipv4_static->version_flag = 0;
	ipv4_static->reserved = 0;
	ipv4_static->protocol = ipv4->protocol;
	rohc_comp_debug(context, "IPv4 protocol = %u", ipv4_static->protocol);
	ipv4_static->src_addr = ipv4->saddr;
	ipv4_static->dst_addr = ipv4->daddr;

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv4 static part", rohc_data, ipv4_static_len);
#endif

	return ipv4_static_len;

error:
	return -1;
}


/**
 * @brief Build the static part of the IPv6 header
 *
 * @param context         The compression context
 * @param ipv6            The IPv6 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_static_ipv6_part(const struct rohc_comp_ctxt *const context,
                                     const struct ipv6_hdr *const ipv6,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
{
	size_t ipv6_static_len;

	if(ipv6->flow1 == 0 && ipv6->flow2 == 0)
	{
		ipv6_static1_t *const ipv6_static1 = (ipv6_static1_t *) rohc_data;

		ipv6_static_len = sizeof(ipv6_static1_t);
		if(rohc_max_len < ipv6_static_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv6 static part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv6_static_len, rohc_max_len);
			goto error;
		}

		ipv6_static1->version_flag = 1;
		ipv6_static1->reserved1 = 0;
		ipv6_static1->flow_label_enc_discriminator = 0;
		ipv6_static1->reserved2 = 0;
		ipv6_static1->next_header = ipv6->nh;
		memcpy(ipv6_static1->src_addr, &ipv6->saddr, sizeof(struct ipv6_addr));
		memcpy(ipv6_static1->dst_addr, &ipv6->daddr, sizeof(struct ipv6_addr));
	}
	else
	{
		ipv6_static2_t *const ipv6_static2 = (ipv6_static2_t *) rohc_data;

		ipv6_static_len = sizeof(ipv6_static2_t);
		if(rohc_max_len < ipv6_static_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv6 static part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv6_static_len, rohc_max_len);
			goto error;
		}

		ipv6_static2->version_flag = 1;
		ipv6_static2->reserved = 0;
		ipv6_static2->flow_label_enc_discriminator = 1;
		ipv6_static2->flow_label1 = ipv6->flow1;
		ipv6_static2->flow_label2 = ipv6->flow2;
		ipv6_static2->next_header = ipv6->nh;
		memcpy(ipv6_static2->src_addr, &ipv6->saddr, sizeof(struct ipv6_addr));
		memcpy(ipv6_static2->dst_addr, &ipv6->daddr, sizeof(struct ipv6_addr));
	}
	rohc_comp_debug(context, "IPv6 next header = %u", ipv6->nh);

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv6 static part", rohc_data, ipv6_static_len);
#endif

	return ipv6_static_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv4 header
 *
 * @param context         The compression context
 * @param ip_context      The specific IP compression context
 * @param ipv4            The IPv4 header
 * @param is_innermost    true if the IP header is the innermost of the packet,
 *                        false otherwise
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_ipv4_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv4_hdr *const ipv4,
                                      const bool is_innermost,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
{
	ipv4_dynamic1_t *const ipv4_dynamic1 = (ipv4_dynamic1_t *) rohc_data;
	size_t ipv4_dynamic_len = sizeof(ipv4_dynamic1_t);
	uint16_t ip_id;

	assert(ip_context->ctxt.vx.version == IPV4);

	if(rohc_max_len < ipv4_dynamic_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv4 dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv4_dynamic_len, rohc_max_len);
		goto error;
	}

	/* IP-ID */
	ip_id = rohc_ntoh16(ipv4->id);
	rohc_comp_debug(context, "ip_id_behavior = %d, last IP-ID = 0x%04x, "
	                "IP-ID = 0x%04x", ip_context->ctxt.v4.ip_id_behavior,
	                ip_context->ctxt.v4.last_ip_id, ip_id);

	ipv4_dynamic1->reserved = 0;
	ipv4_dynamic1->df = ipv4->df;

	/* IP-ID behavior
	 * cf. RFC4996 page 60/61 ip_id_behavior_choice() and ip_id_enc_dyn() */
	if(is_innermost)
	{
		/* all behavior values possible */
		ipv4_dynamic1->ip_id_behavior = ip_context->ctxt.v4.ip_id_behavior;
	}
	else
	{
		/* only IP_ID_BEHAVIOR_RAND or IP_ID_BEHAVIOR_ZERO */
		if(ipv4->id == 0)
		{
			ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_ZERO;
		}
		else
		{
			ipv4_dynamic1->ip_id_behavior = IP_ID_BEHAVIOR_RAND;
		}
		/* TODO: should not update context there */
		ip_context->ctxt.v4.ip_id_behavior = ipv4_dynamic1->ip_id_behavior;
	}
	/* TODO: should not update context there */
	ip_context->ctxt.v4.last_ip_id_behavior = ip_context->ctxt.v4.ip_id_behavior;

	ipv4_dynamic1->dscp = ipv4->dscp;
	ipv4_dynamic1->ip_ecn_flags = ipv4->ecn;
	ipv4_dynamic1->ttl_hopl = ipv4->ttl;

	/* IP-ID itself
	 * cf. RFC4996 page 60/61 ip_id_enc_dyn() */
	if(ipv4_dynamic1->ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
	{
		rohc_comp_debug(context, "ip_id_behavior = %d", ipv4_dynamic1->ip_id_behavior);
	}
	else
	{
		ipv4_dynamic2_t *const ipv4_dynamic2 = (ipv4_dynamic2_t *) rohc_data;

		ipv4_dynamic_len = sizeof(ipv4_dynamic2_t);
		if(rohc_max_len < ipv4_dynamic_len)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv4 dynamic part: "
			               "%zu bytes required, but only %zu bytes available",
			               ipv4_dynamic_len, rohc_max_len);
			goto error;
		}

		ipv4_dynamic2->ip_id = ipv4->id;
		rohc_comp_debug(context, "ip_id_behavior = %d, IP-ID = 0x%04x",
		                ipv4_dynamic1->ip_id_behavior, rohc_ntoh16(ipv4->id));
	}

	/* TODO: should not update context there */
	ip_context->ctxt.v4.dscp = ipv4->dscp;
	ip_context->ctxt.v4.ttl_hopl = ipv4->ttl;
	ip_context->ctxt.v4.df = ipv4->df;
	ip_context->ctxt.v4.last_ip_id = rohc_ntoh16(ipv4->id);

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IPv4 dynamic part", rohc_data, ipv4_dynamic_len);
#endif

	return ipv4_dynamic_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the IPv6 header
 *
 * @param context         The compression context
 * @param ip_context      The specific IP compression context
 * @param ipv6            The IPv6 header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_ipv6_part(const struct rohc_comp_ctxt *const context,
                                      ip_context_t *const ip_context,
                                      const struct ipv6_hdr *const ipv6,
                                      uint8_t *const rohc_data,
                                      const size_t rohc_max_len)
{
	ipv6_dynamic_t *const ipv6_dynamic = (ipv6_dynamic_t *) rohc_data;
	const size_t ipv6_dynamic_len = sizeof(ipv6_dynamic_t);
	const uint8_t dscp = ipv6_get_dscp(ipv6);

	assert(ip_context->ctxt.v6.version == IPV6);

	if(rohc_max_len < ipv6_dynamic_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the IPv6 dynamic part: "
		               "%zu bytes required, but only %zu bytes available",
		               ipv6_dynamic_len, rohc_max_len);
		goto error;
	}

	ipv6_dynamic->dscp = dscp;
	ipv6_dynamic->ip_ecn_flags = ipv6->ecn;
	ipv6_dynamic->ttl_hopl = ipv6->hl;

	/* TODO: should not update context there */
	ip_context->ctxt.v6.dscp = dscp;
	ip_context->ctxt.v6.ttl_hopl = ipv6->hl;

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IP dynamic part", rohc_data, ipv6_dynamic_len);
#endif

	return ipv6_dynamic_len;

error:
	return -1;
}


/**
 * @brief Code the irregular chain of one CO packet
 *
 * @param context           The compression context
 * @param ip                The outer IP header
 * @param ip_inner_ecn      The ECN flags of the innermost IP header
 * @param tcp               The uncompressed TCP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int tcp_code_irreg_chain(struct rohc_comp_ctxt *const context,
                                const struct ip_packet *const ip,
                                const uint8_t ip_inner_ecn,
                                const struct tcphdr *const tcp,
                                uint8_t *const rohc_pkt,
                                const size_t rohc_pkt_max_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const uint8_t *remain_data = ip->data;
	size_t remain_len = ip->size;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	size_t ip_hdr_pos;
	int ret;

	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip_hdr = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const bool is_innermost = !!(ip_hdr_pos == (tcp_context->ip_contexts_nr - 1));

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip_hdr->version);

		/* irregular part for IP header */
		if(ip_hdr->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			ret = tcp_code_irregular_ipv4_part(context, ip_context, ipv4, is_innermost,
			                                   tcp_context->ecn_used, ip_inner_ecn,
			                                   tcp_context->tmp.ttl_irreg_chain_flag,
			                                   rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv4 base header part "
				               "of the irregular chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
		}
		else if(ip_hdr->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			uint8_t protocol;
			size_t ip_ext_pos;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			ret = tcp_code_irregular_ipv6_part(context, ip_context, ipv6, is_innermost,
			                                   tcp_context->ecn_used, ip_inner_ecn,
			                                   tcp_context->tmp.ttl_irreg_chain_flag,
			                                   rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to build the IPv6 base header part "
				               "of the irregular chain");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;

			protocol = ipv6->nh;
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* irregular part for IPv6 extension headers */
			for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);

				ret = tcp_code_irregular_ipv6_opt_part(context, opt_ctxt, ipv6_opt,
				                                       protocol, rohc_remain_data,
				                                       rohc_remain_len);
				if(ret < 0)
				{
					rohc_comp_warn(context, "failed to encode the IPv6 extension headers "
					               "part of the irregular chain");
					goto error;
				}
				rohc_remain_data += ret;
				rohc_remain_len -= ret;

				protocol = ipv6_opt->next_header;
				remain_data += opt_ctxt->generic.option_length;
				remain_len -= opt_ctxt->generic.option_length;
			}
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u", ip_hdr->version);
			assert(0);
			goto error;
		}
	}

	/* TCP part (base header + options) of the irregular chain */
	ret = tcp_code_irregular_tcp_part(context, tcp, ip_inner_ecn,
	                                  rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the TCP header part "
		               "of the irregular chain");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the irregular part of the IPv4 header
 *
 * See RFC 4996 page 63
 *
 * @param context               The compression context
 * @param ip_context            The specific IP compression context
 * @param ipv4                  The IPv4 header
 * @param is_innermost          True if IP header is the innermost of the packet
 * @param ecn_used              The indicator of ECN usage
 * @param ip_inner_ecn          The ECN flags of the IP innermost header
 * @param ttl_irreg_chain_flag  Whether the TTL of an outer header changed
 * @param[out] rohc_data        The ROHC packet being built
 * @param rohc_max_len          The max remaining length in the ROHC buffer
 * @return                      The length appended in the ROHC buffer if positive,
 *                              -1 in case of error
 */
static int tcp_code_irregular_ipv4_part(const struct rohc_comp_ctxt *const context,
                                        const ip_context_t *const ip_context,
                                        const struct ipv4_hdr *const ipv4,
                                        const bool is_innermost,
                                        const bool ecn_used,
                                        const uint8_t ip_inner_ecn,
                                        const bool ttl_irreg_chain_flag,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
{
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	assert(ip_context->ctxt.vx.version == IPV4);

	rohc_comp_debug(context, "ecn_used = %d, is_innermost = %d, "
	                "ttl_irreg_chain_flag = %d, ip_inner_ecn = %u",
	                ecn_used, is_innermost, ttl_irreg_chain_flag, ip_inner_ecn);
	rohc_comp_debug(context, "IP version = 4, ip_id_behavior = %d",
	                ip_context->ctxt.v4.ip_id_behavior);

	/* ip_id =:= ip_id_enc_irreg( ip_id_behavior.UVALUE ) */
	if(ip_context->ctxt.v4.ip_id_behavior == IP_ID_BEHAVIOR_RAND)
	{
		if(rohc_remain_len < sizeof(uint16_t))
		{
			rohc_comp_warn(context, "ROHC buffer too small for the IPv4 base header "
			               "irregular part: %zu bytes required for random IP-ID, "
			               "but only %zu bytes available", sizeof(uint16_t),
			               rohc_remain_len);
			goto error;
		}
		memcpy(rohc_remain_data, &ipv4->id, sizeof(uint16_t));
		rohc_remain_data += sizeof(uint16_t);
		rohc_remain_len -= sizeof(uint16_t);
		rohc_comp_debug(context, "random IP-ID 0x%04x", rohc_ntoh16(ipv4->id));
	}

	if(!is_innermost)
	{
		/* ipv4_outer_with/without_ttl_irregular:
		 *   dscp =:= static_or_irreg( ecn_used.UVALUE )
		 *   ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE ) */
		if(ecn_used)
		{
			if(rohc_remain_len < 1)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv4 base header "
				               "irregular part: 1 byte required for DSCP and ECN, "
				               "but only %zu bytes available", rohc_remain_len);
				goto error;
			}
			rohc_remain_data[0] = ipv4->dscp_ecn;
			rohc_comp_debug(context, "DSCP / ip_ecn_flags = 0x%02x",
			                rohc_remain_data[0]);
			rohc_remain_data++;
			rohc_remain_len--;
		}

		/* ipv4_outer_with_ttl_irregular:
		 *   ttl_hopl =:= irregular(8) */
		if(ttl_irreg_chain_flag)
		{
			if(rohc_remain_len < 1)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv4 base header "
				               "irregular part: 1 byte required for TTL, but only "
				               "%zu bytes available", rohc_remain_len);
				goto error;
			}
			rohc_remain_data[0] = ipv4->ttl;
			rohc_comp_debug(context, "ttl_hopl = 0x%02x", rohc_remain_data[0]);
			rohc_remain_data++;
			rohc_remain_len--;
		}
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IP irregular part",
	              rohc_data, rohc_max_len - rohc_remain_len);
#endif

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the irregular part of the IPv6 header
 *
 * See RFC 4996 page 63
 *
 * @param context               The compression context
 * @param ip_context            The specific IP compression context
 * @param ipv6                  The IPv6 header
 * @param is_innermost          True if IP header is the innermost of the packet
 * @param ecn_used              The indicator of ECN usage
 * @param ip_inner_ecn          The ECN flags of the IP innermost header
 * @param ttl_irreg_chain_flag  Whether the TTL of an outer header changed
 * @param[out] rohc_data        The ROHC packet being built
 * @param rohc_max_len          The max remaining length in the ROHC buffer
 * @return                      The length appended in the ROHC buffer if positive,
 *                              -1 in case of error
 */
static int tcp_code_irregular_ipv6_part(const struct rohc_comp_ctxt *const context,
                                        const ip_context_t *const ip_context,
                                        const struct ipv6_hdr *const ipv6,
                                        const bool is_innermost,
                                        const bool ecn_used,
                                        const uint8_t ip_inner_ecn,
                                        const bool ttl_irreg_chain_flag,
                                        uint8_t *const rohc_data,
                                        const size_t rohc_max_len)
{
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	assert(ip_context->ctxt.vx.version == IPV6);

	rohc_comp_debug(context, "ecn_used = %d, is_innermost = %d, "
	                "ttl_irreg_chain_flag = %d, ip_inner_ecn = %u",
	                ecn_used, is_innermost, ttl_irreg_chain_flag, ip_inner_ecn);
	rohc_comp_debug(context, "IP version = 6, ip_id_behavior = %d",
	                ip_context->ctxt.v4.ip_id_behavior);

	if(!is_innermost)
	{
		/* ipv6_outer_with/without_ttl_irregular:
		 *   dscp =:= static_or_irreg( ecn_used.UVALUE )
		 *   ip_ecn_flags =:= static_or_irreg( ecn_used.UVALUE ) */
		if(ecn_used)
		{
			if(rohc_remain_len < 1)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv6 base header "
				               "irregular part: 1 byte required for DSCP and ECN, "
				               "but only %zu bytes available", rohc_remain_len);
				goto error;
			}
			rohc_remain_data[0] = ipv6_get_tc(ipv6);
			rohc_comp_debug(context, "add DSCP and ip_ecn_flags = 0x%02x",
			                rohc_remain_data[0]);
			rohc_remain_data++;
			rohc_remain_len--;
		}
		/* ipv6_outer_with_ttl_irregular:
		 *   ttl_hopl =:= irregular(8) */
		if(ttl_irreg_chain_flag)
		{
			if(rohc_remain_len < 1)
			{
				rohc_comp_warn(context, "ROHC buffer too small for the IPv6 base header "
				               "irregular part: 1 byte required for Hop Limit, but "
				               "only %zu bytes available", rohc_remain_len);
				goto error;
			}
			rohc_remain_data[0] = ipv6->hl;
			rohc_comp_debug(context, "add ttl_hopl = 0x%02x", rohc_remain_data[0]);
			rohc_remain_data++;
			rohc_remain_len--;
		}
	}

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "IP irregular part",
	              rohc_data, rohc_max_len - rohc_remain_len);
#endif

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the static part of the TCP header
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
 * @param context         The compression context
 * @param tcp             The TCP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_static_tcp_part(const struct rohc_comp_ctxt *const context,
                                    const struct tcphdr *const tcp,
                                    uint8_t *const rohc_data,
                                    const size_t rohc_max_len)
{
	tcp_static_t *const tcp_static = (tcp_static_t *) rohc_data;
	const size_t tcp_static_len = sizeof(tcp_static_t);

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "TCP header", (uint8_t *) tcp, sizeof(struct tcphdr));

	if(rohc_max_len < tcp_static_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP static part: "
		               "%zu bytes required, but only %zu bytes available",
		               tcp_static_len, rohc_max_len);
		goto error;
	}

	tcp_static->src_port = tcp->src_port;
	rohc_comp_debug(context, "TCP source port = %d (0x%04x)",
	                rohc_ntoh16(tcp->src_port), rohc_ntoh16(tcp->src_port));

	tcp_static->dst_port = tcp->dst_port;
	rohc_comp_debug(context, "TCP destination port = %d (0x%04x)",
	                rohc_ntoh16(tcp->dst_port), rohc_ntoh16(tcp->dst_port));

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "TCP static part", rohc_data, tcp_static_len);

	return tcp_static_len;

error:
	return -1;
}


/**
 * @brief Build the dynamic part of the TCP header.
 *
 * \verbatim

 Dynamic part of TCP header:

TODO

\endverbatim
 *
 * @param context         The compression context
 * @param tcp             The TCP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_dynamic_tcp_part(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp,
                                     uint8_t *const rohc_data,
                                     const size_t rohc_max_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const size_t min_tcp_hdr_len = sizeof(struct tcphdr) / sizeof(uint32_t);

	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;

	tcp_dynamic_t *const tcp_dynamic = (tcp_dynamic_t *) rohc_remain_data;
	size_t tcp_dynamic_len = sizeof(tcp_dynamic_t);

	int indicator;
	int ret;

	rohc_comp_debug(context, "TCP dynamic part (minimal length = %zd)",
	                tcp_dynamic_len);

	if(rohc_remain_len < tcp_dynamic_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
		               "%zu bytes required at minimum, but only %zu bytes available",
		               tcp_dynamic_len, rohc_remain_len);
		goto error;
	}

	rohc_comp_debug(context, "TCP seq = 0x%04x, ack_seq = 0x%04x",
	                rohc_ntoh32(tcp->seq_num), rohc_ntoh32(tcp->ack_num));
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d",
	                *(uint16_t*)(((uint8_t*)tcp) + 12),
	                tcp->res_flags, tcp->data_offset, tcp->rsf_flags,
	                tcp->ecn_flags, tcp->urg_flag, tcp->ack_flag,
	                tcp->psh_flag);
	rohc_comp_debug(context, "TCP window = 0x%04x, check = 0x%x, "
	                "urg_ptr = %d", rohc_ntoh16(tcp->window),
	                rohc_ntoh16(tcp->checksum), rohc_ntoh16(tcp->urg_ptr));

	tcp_dynamic->ecn_used = tcp_context->ecn_used;
	tcp_dynamic->tcp_res_flags = tcp->res_flags;
	tcp_dynamic->tcp_ecn_flags = tcp->ecn_flags;
	tcp_dynamic->urg_flag = tcp->urg_flag;
	tcp_dynamic->ack_flag = tcp->ack_flag;
	tcp_dynamic->psh_flag = tcp->psh_flag;
	tcp_dynamic->rsf_flags = tcp->rsf_flags;
	tcp_dynamic->msn = rohc_hton16(tcp_context->msn);
	tcp_dynamic->seq_num = tcp->seq_num;

	rohc_remain_data += sizeof(tcp_dynamic_t);
	rohc_remain_len -= sizeof(tcp_dynamic_t);

	/* TODO: should not update context here */
	tcp_context->tcp_last_seq_num = rohc_ntoh32(tcp->seq_num);
	tcp_context->tcp_seq_num_change_count++;

	/* ack_zero flag and ACK number: always check for the ACK number value even
	 * if the ACK flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those bits
	 * will be ignored at reception */
	ret = c_zero_or_irreg32(tcp->ack_num, rohc_remain_data, rohc_remain_len,
	                        &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode zero_or_irreg(ack_number)");
		goto error;
	}
	tcp_dynamic->ack_zero = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "TCP ack_number %spresent",
	                tcp_dynamic->ack_zero ? "not " : "");

	/* enough room for encoded window and checksum? */
	if(rohc_remain_len < (sizeof(uint16_t) + sizeof(uint16_t)))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
		               "%zu bytes required for TCP window and checksum, but only "
		               "%zu bytes available", sizeof(uint16_t) + sizeof(uint16_t),
		               rohc_remain_len);
		goto error;
	}

	/* window */
	memcpy(rohc_remain_data, &tcp->window, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	/* checksum */
	memcpy(rohc_remain_data, &tcp->checksum, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);

	/* urp_zero flag and URG pointer: always check for the URG pointer value
	 * even if the URG flag is not set in the uncompressed TCP header, this is
	 * important to transmit all packets without any change, even if those
	 * bits will be ignored at reception */
	ret = c_zero_or_irreg16(tcp->urg_ptr, rohc_remain_data, rohc_remain_len,
	                        &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode zero_or_irreg(urg_ptr)");
		goto error;
	}
	tcp_dynamic->urp_zero = indicator;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "TCP urg_ptr %spresent",
	                tcp_dynamic->urp_zero ? "not " : "");

	/* ack_stride */
	{
		const bool is_ack_stride_static =
			tcp_is_ack_stride_static(tcp_context->ack_stride,
			                         tcp_context->ack_num_scaling_nr);
		ret = c_static_or_irreg16(rohc_hton16(tcp_context->ack_stride),
		                          is_ack_stride_static,
		                          rohc_remain_data, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ack_stride)");
			goto error;
		}
		tcp_dynamic->ack_stride_flag = indicator;
		rohc_remain_data += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "TCP ack_stride %spresent",
		                tcp_dynamic->ack_stride_flag ? "" : "not ");
	}

	/* list of TCP options */
	if(tcp->data_offset == min_tcp_hdr_len)
	{
		rohc_comp_debug(context, "TCP no options!");

		/* see RFC4996, §6.3.3 : no XI items, PS = 0, m = 0 */
		if(rohc_remain_len < 1)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the TCP dynamic part: "
			               "1 byte required for empty list of TCP option, but only "
			               "%zu bytes available", rohc_remain_len);
			goto error;
		}
		rohc_remain_data[0] = 0x00;
		rohc_remain_data++;
		rohc_remain_len--;
	}
	else
	{
		ret = c_tcp_code_tcp_opts_list_item(context, tcp, tcp_context->msn,
		                                    true, &tcp_context->tcp_opts,
		                                    rohc_remain_data, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode the list of TCP options "
			               "in the dynamic chain");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		rohc_remain_data += ret;
#endif
		rohc_remain_len -= ret;
	}

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG, "TCP dynamic part",
	              rohc_data, rohc_max_len - rohc_remain_len);

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Build the irregular part of the TCP header.
 *
 * @param context         The compression context
 * @param tcp             The TCP header
 * @param ip_inner_ecn    The ECN flags of the innermost IP header
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int tcp_code_irregular_tcp_part(const struct rohc_comp_ctxt *const context,
                                       const struct tcphdr *const tcp,
                                       const uint8_t ip_inner_ecn,
                                       uint8_t *const rohc_data,
                                       const size_t rohc_max_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	uint8_t *rohc_remain_data = rohc_data;
	size_t rohc_remain_len = rohc_max_len;
	int ret;

	/* ip_ecn_flags = := tcp_irreg_ip_ecn(ip_inner_ecn)
	 * tcp_res_flags =:= static_or_irreg(ecn_used.CVALUE,4)
	 * tcp_ecn_flags =:= static_or_irreg(ecn_used.CVALUE,2) */
	if(tcp_context->ecn_used)
	{
		if(rohc_remain_len < 1)
		{
			rohc_comp_warn(context, "ROHC buffer too small for the TCP irregular "
			               "part: 1 byte required for ECN used flag, but only %zu "
			               "bytes available", rohc_remain_len);
			goto error;
		}
		rohc_remain_data[0] =
			(ip_inner_ecn << 6) | (tcp->res_flags << 2) | tcp->ecn_flags;
		rohc_comp_debug(context, "add inner IP ECN + TCP ECN + TCP RES = 0x%02x",
		                rohc_remain_data[0]);
		rohc_remain_data++;
		rohc_remain_len--;
	}

	/* checksum =:= irregular(16) */
	if(rohc_remain_len < sizeof(uint16_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP irregular "
		               "part: %zu bytes required for TCP checksum, but only %zu "
		               "bytes available", sizeof(uint16_t), rohc_remain_len);
		goto error;
	}
	memcpy(rohc_remain_data, &tcp->checksum, sizeof(uint16_t));
	rohc_remain_data += sizeof(uint16_t);
	rohc_remain_len -= sizeof(uint16_t);
	rohc_comp_debug(context, "add TCP checksum = 0x%04x",
	                rohc_ntoh16(tcp->checksum));

	/* irregular part for TCP options */
	ret = c_tcp_code_tcp_opts_irreg(context, tcp, tcp_context->msn,
		                             &tcp_context->tcp_opts, rohc_remain_data,
		                             rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to compress TCP options in irregular chain");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

#if ROHC_EXTRA_DEBUG == 1
	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "TCP irregular part",
	              rohc_data, rohc_max_len - rohc_remain_len);
#endif

	return (rohc_max_len - rohc_remain_len);

error:
	return -1;
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
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       The type of ROHC packet to create
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int code_CO_packet(struct rohc_comp_ctxt *const context,
                          const struct ip_packet *ip,
                          uint8_t *const rohc_pkt,
                          const size_t rohc_pkt_max_len,
                          const rohc_packet_t packet_type,
                          size_t *const payload_offset)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const uint8_t *remain_data = ip->data;
	size_t remain_len = ip->size;

	uint8_t *rohc_remain_data = rohc_pkt;
	size_t rohc_remain_len = rohc_pkt_max_len;

	ip_context_t *inner_ip_ctxt = NULL;
	const struct ip_hdr *inner_ip_hdr = NULL;
	size_t inner_ip_hdr_len = 0;

	const struct tcphdr *tcp;
	size_t pos_1st_byte;
	size_t pos_2nd_byte;
	uint8_t save_first_byte;
	size_t payload_size = 0;
	uint8_t ip_inner_ecn = 0;
	uint8_t crc_computed;
	size_t ip_hdr_pos;
	int ret;

	rohc_comp_debug(context, "code CO packet (CID = %zu)", context->cid);

	/* parse the IP headers and their extension headers */
	rohc_comp_debug(context, "parse the %zu-byte IP packet", remain_len);
	assert(tcp_context->ip_contexts_nr > 0);
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip_hdr = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		uint8_t protocol;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip_hdr->version);

		inner_ip_hdr = (struct ip_hdr *) remain_data;
		inner_ip_hdr_len = remain_len;
		inner_ip_ctxt = ip_context;

		if(ip_hdr->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;
			size_t ipv4_hdr_len;

			assert(remain_len >= sizeof(struct ipv4_hdr));

			protocol = ipv4->protocol;
			ip_inner_ecn = ipv4->ecn;
			ipv4_hdr_len = ipv4->ihl * sizeof(uint32_t);
			payload_size = rohc_ntoh16(ipv4->tot_len) - ipv4_hdr_len;

			/* skip IPv4 header */
			rohc_comp_debug(context, "skip %zu-byte IPv4 header with "
			                "Protocol 0x%02x", ipv4_hdr_len, protocol);
			remain_data += ipv4_hdr_len;
			remain_len -= ipv4_hdr_len;
		}
		else if(ip_hdr->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			size_t ip_ext_pos;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			protocol = ipv6->nh;
			ip_inner_ecn = ipv6->ecn;
			payload_size = rohc_ntoh16(ipv6->plen);

			/* skip IPv6 header */
			rohc_comp_debug(context, "skip %zu-byte IPv6 header with Next Header "
			                "0x%02x", sizeof(struct ipv6_hdr), protocol);
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* skip IPv6 extension headers */
			for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				const ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);

				protocol = ipv6_opt->next_header;
				rohc_comp_debug(context, "skip %zu-byte IPv6 extension header "
				                "with Next Header 0x%02x",
				                opt_ctxt->generic.option_length, protocol);
				remain_data += opt_ctxt->generic.option_length;
				remain_len -= opt_ctxt->generic.option_length;
			}
		}
		else
		{
			rohc_comp_warn(context, "unexpected IP version %u", ip_hdr->version);
			assert(0);
			goto error;
		}
	}

	/* parse the TCP header */
	assert(remain_len >= sizeof(struct tcphdr));
	tcp = (struct tcphdr *) remain_data;
	{
		const size_t tcp_data_offset = tcp->data_offset << 2;

		assert(remain_len >= tcp_data_offset);
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

	/* write Add-CID or large CID bytes: 'pos_1st_byte' indicates the location
	 * where first header byte shall be written, 'pos_2nd_byte' indicates the
	 * location where the next header bytes shall be written */
	ret = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                      rohc_remain_data, rohc_remain_len, &pos_1st_byte);
	if(ret < 1)
	{
		rohc_comp_warn(context, "failed to encode %s CID %zu: maybe the "
		               "%zu-byte ROHC buffer is too small",
		               context->compressor->medium.cid_type == ROHC_SMALL_CID ?
		               "small" : "large", context->cid, rohc_remain_len);
		goto error;
	}
	pos_2nd_byte = ret;
	rohc_remain_data += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "%s CID %zu encoded on %d byte(s)",
	                context->compressor->medium.cid_type == ROHC_SMALL_CID ?
	                "small" : "large", context->cid, ret - 1);

	/* The CO headers are written as a contiguous block. There is a problem in
	 * case of large CIDs. In such a case, the CID octets are not located at the
	 * beginning of the ROHC header. The first CO octet is located before the
	 * CID octet(s) and the remaining CO octets are located after the CID octet(s).
	 * To workaround that situation, the last CID octet is saved before writing
	 * the CO header and restored afterwards */
	save_first_byte = rohc_remain_data[-1];
	rohc_remain_data--;
	rohc_remain_len++;

	ret = co_baseheader(context, tcp_context,
	                    inner_ip_ctxt, inner_ip_hdr, inner_ip_hdr_len,
	                    rohc_remain_data, rohc_remain_len,
	                    packet_type, tcp, crc_computed);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the CO base header");
		goto error;
	}
	rohc_remain_data += ret;
	rohc_remain_len -= ret;

	/* add irregular chain */
	ret = tcp_code_irreg_chain(context, ip, ip_inner_ecn, tcp,
	                           rohc_remain_data, rohc_remain_len);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build the irregular chain of the "
		               "CO packet");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	rohc_remain_data += ret;
#endif
	rohc_remain_len -= ret;

	/* end of workaround: restore the saved octet */
	if(context->compressor->medium.cid_type != ROHC_SMALL_CID)
	{
		rohc_pkt[pos_1st_byte] = rohc_pkt[pos_2nd_byte - 1];
		rohc_pkt[pos_2nd_byte - 1] = save_first_byte;
	}

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "CO packet", rohc_pkt, rohc_pkt_max_len - rohc_remain_len);

	return (rohc_pkt_max_len - rohc_remain_len);

error:
	return -1;
}


/**
 * @brief Compress the innermost IP header AND the TCP header
 *
 * See RFC4996 page 77
 *
 * @param context           The compression context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @return                  The position in the rohc-packet-under-build buffer
 *                          -1 in case of problem
 */
static int co_baseheader(struct rohc_comp_ctxt *const context,
                         struct sc_tcp_context *const tcp_context,
                         ip_context_t *const inner_ip_ctxt,
                         const struct ip_hdr *const inner_ip_hdr,
                         const size_t inner_ip_hdr_len,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len,
                         const rohc_packet_t packet_type,
                         const struct tcphdr *const tcp,
                         const uint8_t crc)
{
	size_t rohc_hdr_len = 0;
	int ret;

	rohc_comp_debug(context, "code %s packet", rohc_get_packet_descr(packet_type));

	switch(packet_type)
	{
		case ROHC_PACKET_TCP_RND_1:
			ret = c_tcp_build_rnd_1(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_2:
			ret = c_tcp_build_rnd_2(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_3:
			ret = c_tcp_build_rnd_3(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_4:
			ret = c_tcp_build_rnd_4(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_5:
			ret = c_tcp_build_rnd_5(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_6:
			ret = c_tcp_build_rnd_6(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_7:
			ret = c_tcp_build_rnd_7(context, tcp_context, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_RND_8:
			ret = c_tcp_build_rnd_8(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_1:
			ret = c_tcp_build_seq_1(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_2:
			ret = c_tcp_build_seq_2(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_3:
			ret = c_tcp_build_seq_3(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_4:
			ret = c_tcp_build_seq_4(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_5:
			ret = c_tcp_build_seq_5(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_6:
			ret = c_tcp_build_seq_6(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_7:
			ret = c_tcp_build_seq_7(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_SEQ_8:
			ret = c_tcp_build_seq_8(context, inner_ip_ctxt, tcp_context,
			                        inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                        rohc_pkt, rohc_pkt_max_len);
			break;
		case ROHC_PACKET_TCP_CO_COMMON:
			ret = c_tcp_build_co_common(context, inner_ip_ctxt, tcp_context,
			                            inner_ip_hdr, inner_ip_hdr_len, tcp, crc,
			                            rohc_pkt, rohc_pkt_max_len);
			break;
		default:
			rohc_comp_debug(context, "unexpected packet type %d", packet_type);
			assert(0);
			ret = -1;
			break;
	}
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to build CO packet type '%s'",
		               rohc_get_packet_descr(packet_type));
		goto error;
	}
	rohc_hdr_len += ret;

	rohc_dump_buf(context->compressor->trace_callback,
	              context->compressor->trace_callback_priv,
	              ROHC_TRACE_COMP, ROHC_TRACE_DEBUG,
	              "co_header", rohc_pkt, rohc_hdr_len);

	/* update context with new values (done at the very end to avoid wrongly
	 * updating the context in case of compression failure) */
	assert(inner_ip_hdr_len >= 1);
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		inner_ip_ctxt->ctxt.v4.last_ip_id_behavior = inner_ip_ctxt->ctxt.v4.ip_id_behavior;
		inner_ip_ctxt->ctxt.v4.last_ip_id = rohc_ntoh16(inner_ipv4->id);
		inner_ip_ctxt->ctxt.v4.df = inner_ipv4->df;
		inner_ip_ctxt->ctxt.vx.dscp = inner_ipv4->dscp;
	}
	else
	{
		const struct ipv6_hdr *const inner_ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		inner_ip_ctxt->ctxt.vx.dscp = ipv6_get_dscp(inner_ipv6);
	}
	inner_ip_ctxt->ctxt.vx.ttl_hopl = tcp_context->tmp.ttl_hopl;

	return rohc_hdr_len;

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_1 packet
 *
 * Send LSBs of sequence number
 * See RFC4996 page 81
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_1(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_1_t *const rnd1 = (rnd_1_t *) rohc_data;
	uint32_t seq_num;

	if(rohc_max_len < sizeof(rnd_1_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_1 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_1_t), rohc_max_len);
		goto error;
	}

	rnd1->discriminator = 0x2e; /* '101110' */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3ffff;
	rnd1->seq_num1 = (seq_num >> 16) & 0x3;
	rnd1->seq_num2 = rohc_hton16(seq_num & 0xffff);
	rnd1->msn = tcp_context->msn & 0xf;
	rnd1->psh_flag = tcp->psh_flag;
	rnd1->header_crc = crc;

	return sizeof(rnd_1_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_2 packet
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 81
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_2(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_2_t *const rnd2 = (rnd_2_t *) rohc_data;

	if(rohc_max_len < sizeof(rnd_2_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_2 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_2_t), rohc_max_len);
		goto error;
	}

	rnd2->discriminator = 0x0c; /* '1100' */
	rnd2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	rnd2->msn = tcp_context->msn & 0xf;
	rnd2->psh_flag = tcp->psh_flag;
	rnd2->header_crc = crc;

	return sizeof(rnd_2_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_3 packet
 *
 * Send acknowlegment number LSBs
 * See RFC4996 page 81
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_3(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_3_t *const rnd3 = (rnd_3_t *) rohc_data;
	uint16_t ack_num;

	if(rohc_max_len < sizeof(rnd_3_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_3 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_3_t), rohc_max_len);
		goto error;
	}

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

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_4 packet
 *
 * Send acknowlegment number scaled
 * See RFC4996 page 81
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_4(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_4_t *const rnd4 = (rnd_4_t *) rohc_data;

	assert(tcp_context->ack_stride != 0);

	if(rohc_max_len < sizeof(rnd_4_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_4 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_4_t), rohc_max_len);
		goto error;
	}

	rnd4->discriminator = 0x0d; /* '1101' */
	rnd4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	rnd4->msn = tcp_context->msn & 0xf;
	rnd4->psh_flag = tcp->psh_flag;
	rnd4->header_crc = crc;

	return sizeof(rnd_4_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_5 packet
 *
 * Send ACK and sequence number
 * See RFC4996 page 82
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_5(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_5_t *const rnd5 = (rnd_5_t *) rohc_data;
	uint16_t seq_num;
	uint16_t ack_num;

	if(rohc_max_len < sizeof(rnd_5_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_5 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_5_t), rohc_max_len);
		goto error;
	}

	rnd5->discriminator = 0x04; /* '100' */
	rnd5->psh_flag = tcp->psh_flag;
	rnd5->msn = tcp_context->msn & 0xf;
	rnd5->header_crc = crc;

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

	return sizeof(rnd_5_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_6 packet
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 82
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_6(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_6_t *const rnd6 = (rnd_6_t *) rohc_data;

	if(rohc_max_len < sizeof(rnd_6_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_6 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_6_t), rohc_max_len);
		goto error;
	}

	rnd6->discriminator = 0x0a; /* '1010' */
	rnd6->header_crc = crc;
	rnd6->psh_flag = tcp->psh_flag;
	rnd6->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	rnd6->msn = tcp_context->msn & 0xf;
	rnd6->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;

	return sizeof(rnd_6_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_7 packet
 *
 * Send ACK and window
 * See RFC4996 page 82
 *
 * @param context         The compression context
 * @param tcp_context     The specific TCP context
 * @param tcp             The TCP header to compress
 * @param crc             The CRC on the uncompressed headers
 * @param[out] rohc_data  The ROHC packet being built
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @return                The length appended in the ROHC buffer if positive,
 *                        -1 in case of error
 */
static int c_tcp_build_rnd_7(const struct rohc_comp_ctxt *const context,
                             const struct sc_tcp_context *const tcp_context,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_7_t *const rnd7 = (rnd_7_t *) rohc_data;
	uint32_t ack_num;

	if(rohc_max_len < sizeof(rnd_7_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_7 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_7_t), rohc_max_len);
		goto error;
	}

	rnd7->discriminator = 0x2f; /* '101111' */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x3ffff;
	rnd7->ack_num1 = (ack_num >> 16) & 0x03;
	rnd7->ack_num2 = rohc_hton16(ack_num & 0xffff);
	rnd7->window = tcp->window;
	rnd7->msn = tcp_context->msn & 0xf;
	rnd7->psh_flag = tcp->psh_flag;
	rnd7->header_crc = crc;

	return sizeof(rnd_7_t);

error:
	return -1;
}


/**
 * @brief Build a TCP rnd_8 packet
 *
 * Send LSBs of TTL, RSF flags, change ECN behavior and options list
 * See RFC4996 page 82
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_rnd_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	rnd_8_t *const rnd8 = (rnd_8_t *) rohc_data;
	uint32_t seq_num;
	size_t comp_opts_len;
	uint8_t ttl_hl;
	uint8_t msn;
	int ret;

	if(rohc_max_len < sizeof(rnd_8_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the rnd_8 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(rnd_8_t), rohc_max_len);
		goto error;
	}

	rnd8->discriminator = 0x16; /* '10110' */
	rnd8->rsf_flags = rsf_index_enc(tcp->rsf_flags);
	rnd8->list_present = 0; /* options are set later */
	rnd8->header_crc = crc;
	rohc_comp_debug(context, "CRC 0x%x", rnd8->header_crc);

	/* MSN */
	msn = tcp_context->msn & 0xf;
	rnd8->msn1 = (msn >> 3) & 0x01;
	rnd8->msn2 = msn & 0x07;

	rnd8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	assert(inner_ip_hdr_len >= 1);
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
		assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
		ttl_hl = ipv4->ttl;
	}
	else
	{
		const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		assert(inner_ip_hdr->version == IPV6);
		assert(inner_ip_hdr_len >= sizeof(struct ipv6_hdr));
		assert(inner_ip_ctxt->ctxt.vx.version == IPV6);
		ttl_hl = ipv6->hl;
	}
	rnd8->ttl_hopl = ttl_hl & 0x7;
	rnd8->ecn_used = GET_REAL(tcp_context->ecn_used);

	/* sequence number */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	rnd8->seq_num = rohc_hton16(seq_num);
	rohc_comp_debug(context, "16 bits of sequence number = 0x%04x", seq_num);

	/* ACK number */
	rnd8->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);

	/* include the list of TCP options if the structure of the list changed
	 * or if some static options changed (irregular chain cannot transmit
	 * static options) */
	if(tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		rnd8->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, tcp, tcp_context->msn,
		                                    false, &tcp_context->tcp_opts,
		                                    rnd8->options,
		                                    rohc_max_len - sizeof(rnd_8_t));
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
		comp_opts_len = ret;
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		rnd8->list_present = 0;
		comp_opts_len = 0;
	}

	return (sizeof(rnd_8_t) + comp_opts_len);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_1 packet
 *
 * Send LSBs of sequence number
 * See RFC4996 page 83
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_1(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_1_t *const seq1 = (seq_1_t *) rohc_data;
	uint32_t seq_num;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_1_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_1 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_1_t), rohc_max_len);
		goto error;
	}

	seq1->discriminator = 0x0a; /* '1010' */
	seq1->ip_id = tcp_context->tmp.ip_id_delta & 0x0f;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq1->ip_id);
	seq_num = rohc_ntoh32(tcp->seq_num) & 0xffff;
	seq1->seq_num = rohc_hton16(seq_num);
	seq1->msn = tcp_context->msn & 0xf;
	seq1->psh_flag = tcp->psh_flag;
	seq1->header_crc = crc;

	return sizeof(seq_1_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_2 packet
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 83
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_2(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_2_t *const seq2 = (seq_2_t *) rohc_data;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_2_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_2 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_2_t), rohc_max_len);
		goto error;
	}

	seq2->discriminator = 0x1a; /* '11010' */
	seq2->ip_id1 = (tcp_context->tmp.ip_id_delta >> 4) & 0x7;
	seq2->ip_id2 = tcp_context->tmp.ip_id_delta & 0xf;
	rohc_comp_debug(context, "7-bit IP-ID offset 0x%x%x", seq2->ip_id1, seq2->ip_id2);
	seq2->seq_num_scaled = tcp_context->seq_num_scaled & 0xf;
	seq2->msn = tcp_context->msn & 0xf;
	seq2->psh_flag = tcp->psh_flag;
	seq2->header_crc = crc;

	return sizeof(seq_2_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_3 packet
 *
 * Send acknowledgment number LSBs
 * See RFC4996 page 83
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_3(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_3_t *const seq3 = (seq_3_t *) rohc_data;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_3_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_3 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_3_t), rohc_max_len);
		goto error;
	}

	seq3->discriminator = 0x09; /* '1001' */
	seq3->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq3->ip_id);
	seq3->ack_num = rohc_hton16(rohc_ntoh32(tcp->ack_num) & 0xffff);
	seq3->msn = tcp_context->msn & 0xf;
	seq3->psh_flag = tcp->psh_flag;
	seq3->header_crc = crc;

	return sizeof(seq_3_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_4 packet
 *
 * Send scaled acknowledgment number scaled
 * See RFC4996 page 84
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_4(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_4_t *const seq4 = (seq_4_t *) rohc_data;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);
	assert(tcp_context->ack_stride != 0);

	if(rohc_max_len < sizeof(seq_4_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_4 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_4_t), rohc_max_len);
		goto error;
	}

	seq4->discriminator = 0x00; /* '0' */
	seq4->ack_num_scaled = tcp_context->ack_num_scaled & 0xf;
	seq4->ip_id = tcp_context->tmp.ip_id_delta & 0x7;
	rohc_comp_debug(context, "3-bit IP-ID offset 0x%x", seq4->ip_id);
	seq4->msn = tcp_context->msn & 0xf;
	seq4->psh_flag = tcp->psh_flag;
	seq4->header_crc = crc;

	return sizeof(seq_4_t);

error:
	return -1;
}


/**
 * @brief Build a TCP seq_5 packet
 *
 * Send ACK and sequence number
 * See RFC4996 page 84
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_5(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_5_t *const seq5 = (seq_5_t *) rohc_data;
	uint32_t seq_num;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_5_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_5 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_5_t), rohc_max_len);
		goto error;
	}

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

error:
	return -1;
}


/**
 * @brief Build a TCP seq_6 packet
 *
 * See RFC4996 page 84
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_6(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_6_t *const seq6 = (seq_6_t *) rohc_data;
	uint8_t seq_num_scaled;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_6_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_6 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_6_t), rohc_max_len);
		goto error;
	}

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

error:
	return -1;
}


/**
 * @brief Build a TCP seq_7 packet
 *
 * Send ACK and window
 * See RFC4996 page 85
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_7(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             const struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_7_t *const seq7 = (seq_7_t *) rohc_data;
	uint16_t window;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_7_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_7 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_7_t), rohc_max_len);
		goto error;
	}

	seq7->discriminator = 0x0c; /* '1100' */

	/* window */
	window = rohc_ntoh16(tcp->window) & 0x7fff;
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

error:
	return -1;
}


/**
 * @brief Build a TCP seq_8 packet
 *
 * Send LSBs of TTL, RSF flags, change ECN behavior, and options list
 * See RFC4996 page 85
 *
 * @param context           The compression context
 * @param inner_ip_ctxt     The specific IP innermost context
 * @param tcp_context       The specific TCP context
 * @param inner_ip_hdr      The innermost IP header
 * @param inner_ip_hdr_len  The length of the innermost IP header
 * @param tcp               The TCP header to compress
 * @param crc               The CRC on the uncompressed headers
 * @param[out] rohc_data    The ROHC packet being built
 * @param rohc_max_len      The max remaining length in the ROHC buffer
 * @return                  The length appended in the ROHC buffer if positive,
 *                          -1 in case of error
 */
static int c_tcp_build_seq_8(const struct rohc_comp_ctxt *const context,
                             const ip_context_t *const inner_ip_ctxt,
                             struct sc_tcp_context *const tcp_context,
                             const struct ip_hdr *const inner_ip_hdr,
                             const size_t inner_ip_hdr_len,
                             const struct tcphdr *const tcp,
                             const uint8_t crc,
                             uint8_t *const rohc_data,
                             const size_t rohc_max_len)
{
	seq_8_t *const seq8 = (seq_8_t *) rohc_data;
	const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
	size_t comp_opts_len;
	uint16_t ack_num;
	uint16_t seq_num;
	int ret;

	assert(inner_ip_ctxt->ctxt.vx.version == IPV4);
	assert(inner_ip_hdr_len >= sizeof(struct ipv4_hdr));
	assert(inner_ip_hdr->version == IPV4);

	if(rohc_max_len < sizeof(seq_8_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the seq_8 header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(seq_8_t), rohc_max_len);
		goto error;
	}

	seq8->discriminator = 0x0b; /* '1011' */

	/* IP-ID */
	seq8->ip_id = tcp_context->tmp.ip_id_delta & 0xf;
	rohc_comp_debug(context, "4-bit IP-ID offset 0x%x", seq8->ip_id);

	seq8->list_present = 0; /* options are set later */
	seq8->header_crc = crc;
	rohc_comp_debug(context, "CRC = 0x%x", seq8->header_crc);
	seq8->msn = tcp_context->msn & 0xf;
	seq8->psh_flag = tcp->psh_flag;

	/* TTL/HL */
	seq8->ttl_hopl = ipv4->ttl & 0x7;

	/* ecn_used */
	seq8->ecn_used = GET_REAL(tcp_context->ecn_used);

	/* ACK number */
	ack_num = rohc_ntoh32(tcp->ack_num) & 0x7fff;
	seq8->ack_num1 = (ack_num >> 8) & 0x7f;
	seq8->ack_num2 = ack_num & 0xff;
	rohc_comp_debug(context, "ack_number = 0x%04x (0x%02x 0x%02x)",
	                ack_num, seq8->ack_num1, seq8->ack_num2);

	seq8->rsf_flags = rsf_index_enc(tcp->rsf_flags);

	/* sequence number */
	seq_num = rohc_ntoh32(tcp->seq_num) & 0x3fff;
	seq8->seq_num1 = (seq_num >> 8) & 0x3f;
	seq8->seq_num2 = seq_num & 0xff;
	rohc_comp_debug(context, "seq_number = 0x%04x (0x%02x 0x%02x)",
	                seq_num, seq8->seq_num1, seq8->seq_num2);

	/* include the list of TCP options if the structure of the list changed
	 * or if some static options changed (irregular chain cannot transmit
	 * static options) */
	if(tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		seq8->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, tcp, tcp_context->msn,
		                                    false, &tcp_context->tcp_opts,
		                                    seq8->options,
		                                    rohc_max_len - sizeof(rnd_8_t));
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
		comp_opts_len = ret;
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		seq8->list_present = 0;
		comp_opts_len = 0;
	}

	return (sizeof(seq_8_t) + comp_opts_len);

error:
	return -1;
}


/**
 * @brief Build a TCP co_common packet
 *
 * @param context             The compression context
 * @param inner_ip_ctxt       The specific IP  text
 * @param tcp_context         The specific TCP context
 * @param inner_ip_hdr        The innermost IP header
 * @param inner_ip_hdr_len    The length of the innermost IP header
 * @param tcp                 The TCP header to compress
 * @param crc                 The CRC on the uncompressed headers
 * @param[out] rohc_data      The ROHC packet being built
 * @param rohc_max_len        The max remaining length in the ROHC buffer
 * @return                    true if the packet is successfully built,
 *                            false otherwise
 */
static int c_tcp_build_co_common(const struct rohc_comp_ctxt *const context,
                                 const ip_context_t *const inner_ip_ctxt,
                                 struct sc_tcp_context *const tcp_context,
                                 const struct ip_hdr *const inner_ip_hdr,
                                 const size_t inner_ip_hdr_len,
                                 const struct tcphdr *const tcp,
                                 const uint8_t crc,
                                 uint8_t *const rohc_data,
                                 const size_t rohc_max_len)
{
	co_common_t *const co_common = (co_common_t *) rohc_data;
	uint8_t *co_common_opt = (uint8_t *) (co_common + 1); /* optional part */
	size_t co_common_opt_len = 0;
	size_t rohc_remain_len = rohc_max_len - sizeof(co_common_t);
	size_t encoded_seq_len;
	size_t encoded_ack_len;
	int indicator;
	int ret;

	if(rohc_max_len < sizeof(co_common_t))
	{
		rohc_comp_warn(context, "ROHC buffer too small for the co_common header: "
		               "%zu bytes required, but only %zu bytes available",
		               sizeof(co_common_t), rohc_max_len);
		goto error;
	}

	rohc_comp_debug(context, "ttl_irreg_chain_flag = %d",
	                tcp_context->tmp.ttl_irreg_chain_flag);

	co_common->discriminator = 0x7D; // '1111101'
	co_common->ttl_hopl_outer_flag = tcp_context->tmp.ttl_irreg_chain_flag;

	rohc_comp_debug(context, "TCP ack_flag = %d, psh_flag = %d, rsf_flags = %d",
	                tcp->ack_flag, tcp->psh_flag, tcp->rsf_flags);
	// =:= irregular(1) [ 1 ];
	co_common->ack_flag = tcp->ack_flag;
	// =:= irregular(1) [ 1 ];
	co_common->psh_flag = tcp->psh_flag;
	// =:= rsf_index_enc [ 2 ];
	co_common->rsf_flags = rsf_index_enc(tcp->rsf_flags);
	// =:= lsb(4, 4) [ 4 ];
	co_common->msn = tcp_context->msn & 0xf;

	/* seq_number */
	ret = variable_length_32_enc(rohc_ntoh32(tcp_context->old_tcphdr.seq_num),
	                             rohc_ntoh32(tcp->seq_num),
	                             tcp_context->tmp.nr_seq_bits_63,
	                             tcp_context->tmp.nr_seq_bits_16383,
	                             co_common_opt, rohc_remain_len, &indicator);
	co_common->seq_indicator = indicator;
	encoded_seq_len = ret;
	co_common_opt += encoded_seq_len;
	co_common_opt_len += encoded_seq_len;
	rohc_remain_len -= encoded_seq_len;
	rohc_comp_debug(context, "encode sequence number 0x%08x on %zu bytes with "
	                "indicator %d", rohc_ntoh32(tcp->seq_num), encoded_seq_len,
	                co_common->seq_indicator);

	/* ack_number */
	ret = variable_length_32_enc(rohc_ntoh32(tcp_context->old_tcphdr.ack_num),
	                             rohc_ntoh32(tcp->ack_num),
	                             tcp_context->tmp.nr_ack_bits_63,
	                             tcp_context->tmp.nr_ack_bits_16383,
	                             co_common_opt, rohc_remain_len, &indicator);
	co_common->ack_indicator = indicator;
	encoded_ack_len = ret;
	co_common_opt += encoded_ack_len;
	co_common_opt_len += encoded_ack_len;
	rohc_remain_len -= encoded_ack_len;
	rohc_comp_debug(context, "encode ACK number 0x%08x on %zu bytes with "
	                "indicator %d", rohc_ntoh32(tcp->ack_num), encoded_ack_len,
	                co_common->ack_indicator);

	/* ack_stride */
	{
		const bool is_ack_stride_static =
			tcp_is_ack_stride_static(tcp_context->ack_stride,
			                         tcp_context->ack_num_scaling_nr);
		ret = c_static_or_irreg16(rohc_hton16(tcp_context->ack_stride),
		                          is_ack_stride_static,
		                          co_common_opt, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ack_stride)");
			goto error;
		}
		co_common->ack_stride_indicator = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "ack_stride_indicator = %d, ack_stride 0x%x on "
		                "%d bytes", co_common->ack_stride_indicator,
		                tcp_context->ack_stride, ret);
	}

	/* window */
	ret = c_static_or_irreg16(tcp->window, !tcp_context->tmp.tcp_window_changed,
	                          co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(window)");
		goto error;
	}
	co_common->window_indicator = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "window_indicator = %d, window = 0x%x on %d bytes",
	                co_common->window_indicator, rohc_ntoh16(tcp->window), ret);

	/* innermost IP-ID */
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		// =:= irregular(1) [ 1 ];
		rohc_comp_debug(context, "optional_ip_id_lsb(behavior = %d, IP-ID = 0x%04x, "
		                "IP-ID offset = 0x%04x, nr of bits required for WLSB encoding "
		                "= %zu)", inner_ip_ctxt->ctxt.v4.ip_id_behavior,
		                rohc_ntoh16(inner_ipv4->id), tcp_context->tmp.ip_id_delta,
		                tcp_context->tmp.nr_ip_id_bits_3);
		ret = c_optional_ip_id_lsb(inner_ip_ctxt->ctxt.v4.ip_id_behavior,
		                           inner_ipv4->id,
		                           tcp_context->tmp.ip_id_delta,
		                           tcp_context->tmp.nr_ip_id_bits_3,
		                           co_common_opt, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode optional_ip_id_lsb(ip_id)");
			goto error;
		}
		co_common->ip_id_indicator = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		co_common->ip_id_behavior = inner_ip_ctxt->ctxt.v4.ip_id_behavior;
		rohc_comp_debug(context, "ip_id_indicator = %d, "
		                "ip_id_behavior = %d (innermost IP-ID encoded on %d bytes)",
		                co_common->ip_id_indicator, co_common->ip_id_behavior, ret);
	}
	else
	{
		// =:= irregular(1) [ 1 ];
		co_common->ip_id_indicator = 0;
		// =:= ip_id_behavior_choice(true) [ 2 ];
		co_common->ip_id_behavior = IP_ID_BEHAVIOR_RAND;
		rohc_comp_debug(context, "ip_id_indicator = %d, "
		                "ip_id_behavior = %d (innermost IP-ID encoded on 0 byte)",
		                co_common->ip_id_indicator, co_common->ip_id_behavior);
	}

	// cf RFC3168 and RFC4996 page 20 :
	// =:= one_bit_choice [ 1 ];
	co_common->ecn_used = GET_REAL(tcp_context->ecn_used);
	rohc_comp_debug(context, "ecn_used = %d", GET_REAL(co_common->ecn_used));

	/* urg_flag */
	co_common->urg_flag = tcp->urg_flag;
	rohc_comp_debug(context, "urg_flag = %d", co_common->urg_flag);
	/* urg_ptr */
	ret = c_static_or_irreg16(tcp->urg_ptr,
	                          !!(tcp_context->old_tcphdr.urg_ptr == tcp->urg_ptr),
	                          co_common_opt, rohc_remain_len, &indicator);
	if(ret < 0)
	{
		rohc_comp_warn(context, "failed to encode static_or_irreg(urg_ptr)");
		goto error;
	}
	co_common->urg_ptr_present = indicator;
	co_common_opt += ret;
	co_common_opt_len += ret;
	rohc_remain_len -= ret;
	rohc_comp_debug(context, "urg_ptr_present = %d (URG pointer encoded on %d bytes)",
	                co_common->urg_ptr_present, ret);

	assert(inner_ip_hdr_len >= 1);
	if(inner_ip_hdr->version == IPV4)
	{
		const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) inner_ip_hdr;

		/* dscp_present =:= irregular(1) [ 1 ] */
		ret = dscp_encode(inner_ip_ctxt->ctxt.vx.dscp, ipv4->dscp,
		                  co_common_opt, rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode dscp_encode(dscp)");
			goto error;
		}
		co_common->dscp_present = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %d bytes",
		                co_common->dscp_present, inner_ip_ctxt->ctxt.vx.dscp,
		                ipv4->dscp, ret);

		/* ttl_hopl */
		ret = c_static_or_irreg8(inner_ip_ctxt->ctxt.vx.ttl_hopl,
		                         tcp_context->tmp.ttl_hopl, co_common_opt,
		                         rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ttl_hopl)");
			goto error;
		}
		rohc_comp_debug(context, "TTL = 0x%02x -> 0x%02x",
		                inner_ip_ctxt->ctxt.vx.ttl_hopl, tcp_context->tmp.ttl_hopl);
		co_common->ttl_hopl_present = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "ttl_hopl_present = %d (TTL encoded on %d bytes)",
		                co_common->ttl_hopl_present, ret);

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		co_common->df = ipv4->df;
	}
	else
	{
		const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) inner_ip_hdr;
		const uint8_t dscp = ipv6_get_dscp(ipv6);

		/* dscp_present =:= irregular(1) [ 1 ] */
		ret = dscp_encode(inner_ip_ctxt->ctxt.vx.dscp, dscp, co_common_opt,
		                  rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode dscp_encode(dscp)");
			goto error;
		}
		co_common->dscp_present = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "dscp_present = %d (context = 0x%02x, "
		                "value = 0x%02x) => length = %d bytes",
		                co_common->dscp_present, inner_ip_ctxt->ctxt.vx.dscp,
		                dscp, ret);

		/* ttl_hopl */
		ret = c_static_or_irreg8(inner_ip_ctxt->ctxt.vx.ttl_hopl,
		                         tcp_context->tmp.ttl_hopl, co_common_opt,
		                         rohc_remain_len, &indicator);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to encode static_or_irreg(ttl_hopl)");
			goto error;
		}
		rohc_comp_debug(context, "HOPL = 0x%02x -> 0x%02x",
		                inner_ip_ctxt->ctxt.vx.ttl_hopl, tcp_context->tmp.ttl_hopl);
		co_common->ttl_hopl_present = indicator;
		co_common_opt += ret;
		co_common_opt_len += ret;
		rohc_remain_len -= ret;
		rohc_comp_debug(context, "ttl_hopl_present = %d (HOPL encoded on %d bytes)",
		                co_common->ttl_hopl_present, ret);

		// =:= dont_fragment(version.UVALUE) [ 1 ];
		co_common->df = 0;
	}
	rohc_comp_debug(context, "DF = %d", co_common->df);

	// =:= compressed_value(1, 0) [ 1 ];
	co_common->reserved = 0;

	/* include the list of TCP options if the structure of the list changed
	 * or if some static options changed (irregular chain cannot transmit
	 * static options) */
	if(tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
	{
		/* the structure of the list of TCP options changed or at least one of
		 * the static option changed, compress them */
		co_common->list_present = 1;
		ret = c_tcp_code_tcp_opts_list_item(context, tcp, tcp_context->msn,
		                                    false, &tcp_context->tcp_opts,
		                                    co_common_opt, rohc_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "failed to compress TCP options");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
		co_common_opt += ret;
		rohc_remain_len -= ret;
#endif
		co_common_opt_len += ret;
		rohc_comp_debug(context, "compressed list of TCP options: %d-byte list "
		                "present", ret);
	}
	else
	{
		/* the structure of the list of TCP options didn't change */
		rohc_comp_debug(context, "compressed list of TCP options: list not present");
		co_common->list_present = 0;
	}

	// =:= crc7(THIS.UVALUE,THIS.ULENGTH) [ 7 ];
	co_common->header_crc = crc;
	rohc_comp_debug(context, "CRC = 0x%x", co_common->header_crc);

	return (sizeof(co_common_t) + co_common_opt_len);

error:
	return -1;
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
                               const struct tcphdr **const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint8_t *remain_data = uncomp_pkt->outer_ip.data;
	size_t remain_len = uncomp_pkt->outer_ip.size;

	const uint8_t *inner_ip_hdr = NULL;
	ip_version inner_ip_version = IP_UNKNOWN;

	size_t ip_hdrs_nr;
	size_t hdrs_len;
	uint8_t protocol;
	size_t opts_len;
	bool pkt_outer_dscp_changed;
	bool last_pkt_outer_dscp_changed;
	uint8_t pkt_ecn_vals;

	/* no IPv6 extension got its static part changed at the beginning */
	tcp_context->tmp.is_ipv6_exts_list_static_changed = false;

	hdrs_len = 0;
	pkt_outer_dscp_changed = 0;
	last_pkt_outer_dscp_changed = false;
	pkt_ecn_vals = 0;
	ip_hdrs_nr = 0;
	do
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdrs_nr]);

		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d header #%zu",
		                ip->version, ip_hdrs_nr + 1);

		pkt_outer_dscp_changed =
			!!(pkt_outer_dscp_changed || last_pkt_outer_dscp_changed);
		inner_ip_hdr = remain_data;
		inner_ip_version = ip->version;
		*ip_inner_ctxt = ip_context;

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;

			if(remain_len < sizeof(struct ipv4_hdr))
			{
				rohc_comp_warn(context, "not enough data for IPv4 header #%zu",
				               ip_hdrs_nr + 1);
				goto error;
			}

			protocol = ipv4->protocol;
			last_pkt_outer_dscp_changed = !!(ipv4->dscp != ip_context->ctxt.vx.dscp);
			pkt_ecn_vals |= ipv4->ecn;

			remain_data += sizeof(struct ipv4_hdr);
			remain_len -= sizeof(struct ipv4_hdr);
			hdrs_len += sizeof(struct ipv4_hdr);
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;
			uint8_t dscp;
			size_t exts_len;

			if(remain_len < sizeof(struct ipv6_hdr))
			{
				rohc_comp_warn(context, "not enough data for IPv6 header #%zu",
				               ip_hdrs_nr + 1);
				goto error;
			}

			protocol = ipv6->nh;
			dscp = (remain_data[1] >> 2) & 0x3f;
			last_pkt_outer_dscp_changed = !!(dscp != ip_context->ctxt.vx.dscp);
			pkt_ecn_vals |= remain_data[1] & 0x3;

			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);
			hdrs_len += sizeof(struct ipv6_hdr);

			if(!tcp_detect_changes_ipv6_exts(context, ip_context, &protocol,
			                                 remain_data, remain_len, &exts_len))
			{
				rohc_comp_warn(context, "failed to detect changes in IPv6 extension headers");
				goto error;
			}
			remain_data += exts_len;
			remain_len -= exts_len;
			hdrs_len += exts_len;
		}
		else
		{
			rohc_comp_warn(context, "unknown IP header with version %u", ip->version);
			goto error;
		}
		rohc_comp_debug(context, "  DSCP did%s change",
		                last_pkt_outer_dscp_changed ? "" : "n't");

		ip_hdrs_nr++;
	}
	while(protocol != ROHC_IPPROTO_TCP && hdrs_len < uncomp_pkt->outer_ip.size);

	/* next header is the TCP header */
	if(remain_len < sizeof(struct tcphdr))
	{
		rohc_comp_warn(context, "not enough data for TCP header");
		goto error;
	}
	*tcp = (struct tcphdr *) remain_data;
	pkt_ecn_vals |= (*tcp)->ecn_flags;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += sizeof(struct tcphdr);
	remain_len -= sizeof(struct tcphdr);
#endif
	hdrs_len += sizeof(struct tcphdr);

	/* parse TCP options for changes */
	if(!tcp_detect_options_changes(context, *tcp, &tcp_context->tcp_opts, &opts_len))
	{
		rohc_comp_warn(context, "failed to detect changes in the uncompressed "
		               "TCP options");
		goto error;
	}
	rohc_comp_debug(context, "%zu bytes of TCP options successfully parsed",
	                opts_len);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += opts_len;
	remain_len -= opts_len;
#endif
	hdrs_len += opts_len;

	/* what value for ecn_used? */
	tcp_detect_ecn_used_behavior(context, pkt_ecn_vals, pkt_outer_dscp_changed,
	                             (*tcp)->res_flags);

	/* determine the IP-ID behavior of the innermost IPv4 header */
	if(inner_ip_version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4_hdr = (struct ipv4_hdr *) inner_ip_hdr;
		const uint16_t ip_id = rohc_ntoh16(inner_ipv4_hdr->id);

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
 * @brief Detect changes about IPv6 extension headers between packet and context
 *
 * @param context           The compression context to compare
 * @param ip_context        The specific IP compression context
 * @param[in,out] protocol  in: the protocol type of the first extension header
 *                          out: the protocol type of the transport header
 * @param exts              The beginning of the IPv6 extension headers
 * @param max_exts_len      The maximum length (in bytes) of the extension headers
 * @param[out] exts_len     The length (in bytes) of the IPv6 extension headers
 * @return                  true if changes were successfully detected,
 *                          false if a problem occurred
 */
static bool tcp_detect_changes_ipv6_exts(struct rohc_comp_ctxt *const context,
                                         ip_context_t *const ip_context,
                                         uint8_t *const protocol,
                                         const uint8_t *const exts,
                                         const size_t max_exts_len,
                                         size_t *const exts_len)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint8_t *remain_data = exts;
	size_t remain_len = max_exts_len;
	size_t ext_pos;

	(*exts_len) = 0;

	ext_pos = 0;
	while(rohc_is_ipv6_opt(*protocol))
	{
		ipv6_option_context_t *const opt_ctxt = &(ip_context->ctxt.v6.opts[ext_pos]);
		const struct ipv6_opt *const ext = (struct ipv6_opt *) remain_data;
		size_t ext_len;

		rohc_comp_debug(context, "  found IP extension header %u", *protocol);

		if(remain_len < (sizeof(struct ipv6_opt) - 1))
		{
			rohc_comp_warn(context, "malformed IPv6 extension header: remaining "
			               "data too small for minimal IPv6 header");
			goto error;
		}
		ext_len = (ext->length + 1) << 3;
		if(remain_len < ext_len)
		{
			rohc_comp_warn(context, "malformed IPv6 extension header: remaining "
			               "data too small for IPv6 header");
			goto error;
		}

		switch(*protocol)
		{
			case ROHC_IPPROTO_HOPOPTS: /* IPv6 Hop-by-Hop option */
			case ROHC_IPPROTO_ROUTING: /* IPv6 routing header */
			case ROHC_IPPROTO_DSTOPTS: /* IPv6 destination option */
				if(context->num_sent_packets > 0 &&
				   ext->length == opt_ctxt->generic.length &&
				   memcmp(ext->value, opt_ctxt->generic.data,
				          opt_ctxt->generic.option_length - 2) == 0)
				{
					rohc_comp_debug(context, "  IPv6 option %u did not change",
					                *protocol);
				}
				else
				{
					rohc_comp_debug(context, "  IPv6 option %u changed of length "
					                "and/or content (%u -> %u)", *protocol,
					                opt_ctxt->generic.length, ext->length);

					/* static chain is required if option length changed */
					if(ext->length != opt_ctxt->generic.length)
					{
						rohc_comp_debug(context, "  IPv6 option %u changed of "
						                "length, static chain is required", *protocol);
						tcp_context->tmp.is_ipv6_exts_list_static_changed = true;
					}

					/* record option in context */
					/* TODO: should not update context there */
					assert(ext->length < MAX_IPV6_OPTION_LENGTH);
					opt_ctxt->generic.option_length = ext_len;
					opt_ctxt->generic.length = ext->length;
					memcpy(opt_ctxt->generic.data, ext->value,
					       opt_ctxt->generic.option_length - 2);
				}
				break;
			case ROHC_IPPROTO_GRE:  /* TODO: GRE not yet supported */
			case ROHC_IPPROTO_MINE: /* TODO: MINE not yet supported */
			case ROHC_IPPROTO_AH:   /* TODO: AH not yet supported */
			default:
				assert(0);
				break;
		}
		(*protocol) = ext->next_header;

		remain_data += ext_len;
		remain_len -= ext_len;

		(*exts_len) += ext_len;
		ext_pos++;
	}

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
	rohc_comp_state_t curr_state = context->state;
	rohc_comp_state_t next_state;

	if(curr_state == ROHC_COMP_STATE_IR)
	{
		if(context->ir_count < MAX_IR_COUNT)
		{
			rohc_comp_debug(context, "no enough packets transmitted in IR state "
			                "for the moment (%zu/%d), so stay in IR state",
			                context->ir_count, MAX_IR_COUNT);
			next_state = ROHC_COMP_STATE_IR;
		}
		else
		{
			rohc_comp_debug(context, "enough packets transmitted in IR state (%zu/%u), "
			                "go to SO state", context->ir_count, MAX_IR_COUNT);
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_FO)
	{
		if(context->fo_count < MAX_FO_COUNT)
		{
			rohc_comp_debug(context, "no enough packets transmitted in FO state "
			                "for the moment (%zu/%u), so stay in FO state",
			                context->fo_count, MAX_FO_COUNT);
			next_state = ROHC_COMP_STATE_FO;
		}
		else
		{
			rohc_comp_debug(context, "enough packets transmitted in FO state (%zu/%u), "
			                "go to SO state", context->fo_count, MAX_FO_COUNT);
			next_state = ROHC_COMP_STATE_SO;
		}
	}
	else if(curr_state == ROHC_COMP_STATE_SO)
	{
		/* do not change state */
		rohc_comp_debug(context, "stay in SO state");
		next_state = ROHC_COMP_STATE_SO;
		/* TODO: handle NACK and STATIC-NACK */
	}
	else
	{
		rohc_comp_warn(context, "unexpected compressor state %d", curr_state);
		assert(0);
		return;
	}

	rohc_comp_change_state(context, next_state);

	/* periodic context refreshes (RFC6846, §5.2.1.2) */
	if(context->mode == ROHC_U_MODE)
	{
		rohc_comp_periodic_down_transition(context);
	}
}


/**
 * @brief Encode uncompressed fields with the corresponding encoding scheme
 *
 * @param context      The compression context
 * @param uncomp_pkt   The uncompressed packet to encode
 * @param tcp          The uncompressed TCP header to encode
 * @return             true in case of success,
 *                     false otherwise
 */
static bool tcp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt,
                                     const struct tcphdr *const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	/* how many bits are required to encode the new SN ? */
	tcp_context->tmp.nr_msn_bits =
		wlsb_get_k_16bits(tcp_context->msn_wlsb, tcp_context->msn);
	rohc_comp_debug(context, "%zu bits are required to encode new MSN 0x%04x",
	                tcp_context->tmp.nr_msn_bits, tcp_context->msn);
	/* add the new MSN to the W-LSB encoding object */
	/* TODO: move this after successful packet compression */
	c_add_wlsb(tcp_context->msn_wlsb, tcp_context->msn, tcp_context->msn);

	if(!tcp_encode_uncomp_ip_fields(context, uncomp_pkt))
	{
		rohc_comp_warn(context, "failed to encode the uncompressed fields "
		               "of the IP headers");
		goto error;
	}

	if(!tcp_encode_uncomp_tcp_fields(context, tcp))
	{
		rohc_comp_warn(context, "failed to encode the uncompressed fields "
		               "of the TCP header");
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Encode uncompressed IP fields with the corresponding encoding scheme
 *
 * @param context      The compression context
 * @param uncomp_pkt   The uncompressed packet to encode
 * @return             true in case of success,
 *                     false otherwise
 */
static bool tcp_encode_uncomp_ip_fields(struct rohc_comp_ctxt *const context,
                                        const struct net_pkt *const uncomp_pkt)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const uint8_t *remain_data = uncomp_pkt->data;
	size_t remain_len = uncomp_pkt->len;

	const ip_context_t *inner_ip_ctxt = NULL;
	const uint8_t *inner_ip_hdr = NULL;
	ip_version inner_ip_version = IP_UNKNOWN;

	uint8_t protocol;
	size_t ip_hdr_pos;

	/* there is at least one IP header otherwise it won't be the IP/TCP profile */
	assert(tcp_context->ip_contexts_nr > 0);

	/* parse IP headers */
	tcp_context->tmp.ttl_irreg_chain_flag = 0;
	for(ip_hdr_pos = 0; ip_hdr_pos < tcp_context->ip_contexts_nr; ip_hdr_pos++)
	{
		const struct ip_hdr *const ip = (struct ip_hdr *) remain_data;
		const ip_context_t *const ip_context = &(tcp_context->ip_contexts[ip_hdr_pos]);
		const bool is_innermost = !!(ip_hdr_pos + 1 == tcp_context->ip_contexts_nr);
		uint8_t ttl_hopl;
		size_t ip_ext_pos;

		/* retrieve IP version */
		assert(remain_len >= sizeof(struct ip_hdr));
		rohc_comp_debug(context, "found IPv%d", ip->version);

		inner_ip_ctxt = ip_context;
		inner_ip_hdr = remain_data;
		inner_ip_version = ip->version;

		if(ip->version == IPV4)
		{
			const struct ipv4_hdr *const ipv4 = (struct ipv4_hdr *) remain_data;
			size_t ipv4_hdr_len;

			assert(remain_len >= sizeof(struct ipv4_hdr));
			ipv4_hdr_len = ipv4->ihl * sizeof(uint32_t);
			assert(remain_len >= ipv4_hdr_len);

			/* get the transport protocol */
			protocol = ipv4->protocol;

			/* irregular chain? */
			ttl_hopl = ipv4->ttl;
			if(!is_innermost && ttl_hopl != ip_context->ctxt.v4.ttl_hopl)
			{
				tcp_context->tmp.ttl_irreg_chain_flag |= 1;
				rohc_comp_debug(context, "last ttl_hopl = 0x%02x, ttl_hopl = "
				                "0x%02x, ttl_irreg_chain_flag = %d",
				                ip_context->ctxt.v4.ttl_hopl, ttl_hopl,
				                tcp_context->tmp.ttl_irreg_chain_flag);
			}

			/* skip IPv4 header */
			rohc_comp_debug(context, "skip %zu-byte IPv4 header with "
			                "Protocol 0x%02x", ipv4_hdr_len, protocol);
			remain_data += ipv4_hdr_len;
			remain_len -= ipv4_hdr_len;
		}
		else if(ip->version == IPV6)
		{
			const struct ipv6_hdr *const ipv6 = (struct ipv6_hdr *) remain_data;

			assert(remain_len >= sizeof(struct ipv6_hdr));

			/* get the transport protocol */
			protocol = ipv6->nh;

			/* irregular chain? */
			ttl_hopl = ipv6->hl;
			if(!is_innermost && ttl_hopl != ip_context->ctxt.v6.ttl_hopl)
			{
				tcp_context->tmp.ttl_irreg_chain_flag |= 1;
				rohc_comp_debug(context, "last ttl_hopl = 0x%02x, ttl_hopl = "
				                "0x%02x, ttl_irreg_chain_flag = %d",
				                ip_context->ctxt.v6.ttl_hopl, ttl_hopl,
				                tcp_context->tmp.ttl_irreg_chain_flag);
			}

			/* skip IPv6 header */
			rohc_comp_debug(context, "skip %zd-byte IPv6 header with Next "
			                "Header 0x%02x", sizeof(struct ipv6_hdr), protocol);
			remain_data += sizeof(struct ipv6_hdr);
			remain_len -= sizeof(struct ipv6_hdr);

			/* skip IPv6 extension headers */
			for(ip_ext_pos = 0; ip_ext_pos < ip_context->ctxt.v6.opts_nr; ip_ext_pos++)
			{
				const struct ipv6_opt *const ipv6_opt = (struct ipv6_opt *) remain_data;
				const ipv6_option_context_t *const opt_ctxt =
					&(ip_context->ctxt.v6.opts[ip_ext_pos]);

				rohc_comp_debug(context, "skip %zu-byte IPv6 extension header "
				                "with Next Header 0x%02x",
				                opt_ctxt->generic.option_length, protocol);
				protocol = ipv6_opt->next_header;
				remain_data += opt_ctxt->generic.option_length;
				remain_len -= opt_ctxt->generic.option_length;
			}
		}
		else
		{
			assert(0);
			goto error;
		}
	}

	tcp_context->tmp.outer_ip_ttl_changed =
		(tcp_context->tmp.ttl_irreg_chain_flag != 0);
	tcp_field_descr_change(context, "one or more outer TTL values",
	                       tcp_context->tmp.outer_ip_ttl_changed, 0);

	if(inner_ip_version == IPV4)
	{
		const struct ipv4_hdr *const inner_ipv4 = (struct ipv4_hdr *) inner_ip_hdr;
		const uint16_t ip_id = rohc_ntoh16(inner_ipv4->id);

		/* does IP-ID behavior changed? */
		tcp_context->tmp.ip_id_behavior_changed =
			(inner_ip_ctxt->ctxt.v4.last_ip_id_behavior != inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		tcp_field_descr_change(context, "IP-ID behavior",
		                       tcp_context->tmp.ip_id_behavior_changed, 0);

		/* compute the new IP-ID / SN delta */
		if(inner_ip_ctxt->ctxt.v4.ip_id_behavior == IP_ID_BEHAVIOR_SEQ)
		{
			tcp_context->tmp.ip_id_delta = ip_id - tcp_context->msn;
			rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (behavior = %d)",
			                tcp_context->tmp.ip_id_delta, tcp_context->tmp.ip_id_delta,
			                inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		}
		else if(inner_ip_ctxt->ctxt.v4.ip_id_behavior == IP_ID_BEHAVIOR_SEQ_SWAP)
		{
			tcp_context->tmp.ip_id_delta = swab16(ip_id) - tcp_context->msn;
			rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (behavior = %d)",
			                tcp_context->tmp.ip_id_delta, tcp_context->tmp.ip_id_delta,
			                inner_ip_ctxt->ctxt.v4.ip_id_behavior);
		}
		else
		{
			tcp_context->tmp.ip_id_delta = 0; /* unused */
		}

		/* how many bits are required to encode the new IP-ID / SN delta ? */
		if(inner_ip_ctxt->ctxt.v4.ip_id_behavior != IP_ID_BEHAVIOR_SEQ &&
		   inner_ip_ctxt->ctxt.v4.ip_id_behavior != IP_ID_BEHAVIOR_SEQ_SWAP)
		{
			/* send all bits if IP-ID behavior is not sequential */
			tcp_context->tmp.nr_ip_id_bits_3 = 16;
			tcp_context->tmp.nr_ip_id_bits_1 = 16;
			rohc_comp_debug(context, "force using 16 bits to encode new IP-ID delta "
			                "(non-sequential)");
		}
		else
		{
			/* send only required bits in FO or SO states */
			tcp_context->tmp.nr_ip_id_bits_3 =
				wlsb_get_kp_16bits(tcp_context->ip_id_wlsb,
				                   tcp_context->tmp.ip_id_delta, 3);
			rohc_comp_debug(context, "%zu bits are required to encode new innermost "
			                "IP-ID delta 0x%04x with p = 3",
			                tcp_context->tmp.nr_ip_id_bits_3,
			                tcp_context->tmp.ip_id_delta);
			tcp_context->tmp.nr_ip_id_bits_1 =
				wlsb_get_kp_16bits(tcp_context->ip_id_wlsb,
				                   tcp_context->tmp.ip_id_delta, 1);
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
			!!(inner_ipv4->df != inner_ip_ctxt->ctxt.v4.df);
		tcp_field_descr_change(context, "DF", tcp_context->tmp.ip_df_changed, 0);

		tcp_context->tmp.dscp_changed =
			!!(inner_ipv4->dscp != inner_ip_ctxt->ctxt.v4.dscp);
		tcp_field_descr_change(context, "DSCP", tcp_context->tmp.dscp_changed, 0);

		tcp_context->tmp.ttl_hopl = inner_ipv4->ttl;
	}
	else /* IPv6 */
	{
		const struct ipv6_hdr *const inner_ipv6 = (struct ipv6_hdr *) inner_ip_hdr;

		/* no IP-ID for IPv6 */
		tcp_context->tmp.ip_id_delta = 0;
		tcp_context->tmp.ip_id_behavior_changed = false;
		tcp_context->tmp.nr_ip_id_bits_3 = 0;
		tcp_context->tmp.nr_ip_id_bits_1 = 0;

		tcp_context->tmp.ip_df_changed = false; /* no DF for IPv6 */

		tcp_context->tmp.dscp_changed =
			!!(ipv6_get_dscp(inner_ipv6) != inner_ip_ctxt->ctxt.v6.dscp);
		tcp_field_descr_change(context, "DSCP", tcp_context->tmp.dscp_changed, 0);

		tcp_context->tmp.ttl_hopl = inner_ipv6->hl;
	}

	/* encode innermost IPv4 TTL or IPv6 Hop Limit */
	if(tcp_context->tmp.ttl_hopl != inner_ip_ctxt->ctxt.vx.ttl_hopl)
	{
		tcp_context->tmp.ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count = 0;
	}
	else if(tcp_context->ttl_hopl_change_count < MAX_FO_COUNT)
	{
		tcp_context->tmp.ttl_hopl_changed = true;
		tcp_context->ttl_hopl_change_count++;
	}
	else
	{
		tcp_context->tmp.ttl_hopl_changed = false;
	}
	tcp_context->tmp.nr_ttl_hopl_bits =
		wlsb_get_k_8bits(tcp_context->ttl_hopl_wlsb, tcp_context->tmp.ttl_hopl);
	rohc_comp_debug(context, "%zu bits are required to encode new innermost "
	                "TTL/Hop Limit 0x%02x with p = 3",
	                tcp_context->tmp.nr_ttl_hopl_bits,
	                tcp_context->tmp.ttl_hopl);
	/* add the new TTL/Hop Limit to the W-LSB encoding object */
	/* TODO: move this after successful packet compression */
	c_add_wlsb(tcp_context->ttl_hopl_wlsb, tcp_context->msn,
	           tcp_context->tmp.ttl_hopl);

	return true;

error:
	return false;
}


/**
 * @brief Encode uncompressed TCP fields with the corresponding encoding scheme
 *
 * @param context  The compression context
 * @param tcp      The uncompressed TCP header to encode
 * @return         true in case of success, false otherwise
 */
static bool tcp_encode_uncomp_tcp_fields(struct rohc_comp_ctxt *const context,
                                         const struct tcphdr *const tcp)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	const uint32_t seq_num_hbo = rohc_ntoh32(tcp->seq_num);
	const uint32_t ack_num_hbo = rohc_ntoh32(tcp->ack_num);

	rohc_comp_debug(context, "new TCP seq = 0x%08x, ack_seq = 0x%08x",
	                seq_num_hbo, ack_num_hbo);
	rohc_comp_debug(context, "old TCP seq = 0x%08x, ack_seq = 0x%08x",
	                rohc_ntoh32(tcp_context->old_tcphdr.seq_num),
	                rohc_ntoh32(tcp_context->old_tcphdr.ack_num));
	rohc_comp_debug(context, "TCP begin = 0x%04x, res_flags = %d, "
	                "data offset = %d, rsf_flags = %d, ecn_flags = %d, "
	                "URG = %d, ACK = %d, PSH = %d",
	                *(uint16_t *)(((uint8_t *) tcp) + 12),
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
	                       tcp_context->tmp.tcp_ack_flag_changed, 0);
	tcp_context->tmp.tcp_urg_flag_present = (tcp->urg_flag != 0);
	tcp_field_descr_present(context, "URG flag",
	                        tcp_context->tmp.tcp_urg_flag_present);
	tcp_context->tmp.tcp_urg_flag_changed =
		(tcp->urg_flag != tcp_context->old_tcphdr.urg_flag);
	tcp_field_descr_change(context, "URG flag",
	                       tcp_context->tmp.tcp_urg_flag_changed, 0);
	tcp_field_descr_change(context, "ECN flag",
	                       tcp_context->tmp.ecn_used_changed,
	                       tcp_context->ecn_used_change_count);
	if(tcp->rsf_flags != 0)
	{
		rohc_comp_debug(context, "RSF flags is set in current packet");
	}

	/* how many bits are required to encode the new TCP window? */
	if(tcp->window != tcp_context->old_tcphdr.window)
	{
		tcp_context->tmp.tcp_window_changed = true;
		tcp_context->tcp_window_change_count = 0;
	}
	else if(tcp_context->tcp_window_change_count < MAX_FO_COUNT)
	{
		tcp_context->tmp.tcp_window_changed = true;
		tcp_context->tcp_window_change_count++;
	}
	else
	{
		tcp_context->tmp.tcp_window_changed = false;
	}
	tcp_field_descr_change(context, "TCP window", tcp_context->tmp.tcp_window_changed,
	                       tcp_context->tcp_window_change_count);
	tcp_context->tmp.nr_window_bits_16383 =
		wlsb_get_kp_16bits(tcp_context->window_wlsb, rohc_ntoh16(tcp->window),
		                   ROHC_LSB_SHIFT_TCP_WINDOW);
	rohc_comp_debug(context, "%zu bits are required to encode new TCP window "
	                "0x%04x with p = %d", tcp_context->tmp.nr_window_bits_16383,
	                rohc_ntoh16(tcp->window), ROHC_LSB_SHIFT_TCP_WINDOW);
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
	{
		const uint32_t old_ack_num_hbo = rohc_ntoh32(tcp_context->old_tcphdr.ack_num);
		const uint32_t ack_delta = ack_num_hbo - old_ack_num_hbo;
		uint16_t ack_stride = 0;
		uint32_t ack_num_scaled;
		uint32_t ack_num_residue;

		/* change ack_stride only if the ACK delta that was most used over the
		 * sliding window changed */
		rohc_comp_debug(context, "ACK delta with previous packet = 0x%04x", ack_delta);
		if(ack_delta == 0)
		{
			ack_stride = tcp_context->ack_stride;
		}
		else
		{
			size_t ack_stride_count = 0;
			size_t i;
			size_t j;

			/* TODO: should update context at the very end only */
			tcp_context->ack_deltas_width[tcp_context->ack_deltas_next] = ack_delta;
			tcp_context->ack_deltas_next = (tcp_context->ack_deltas_next + 1) % 20;

			for(i = 0; i < 20; i++)
			{
				const uint16_t val =
					tcp_context->ack_deltas_width[(tcp_context->ack_deltas_next + i) % 20];
				size_t val_count = 1;

				for(j = i + 1; j < 20; j++)
				{
					if(val == tcp_context->ack_deltas_width[(tcp_context->ack_deltas_next + j) % 20])
					{
						val_count++;
					}
				}

				if(val_count > ack_stride_count)
				{
					ack_stride = val;
					ack_stride_count = val_count;
					if(ack_stride_count > (20/2))
					{
						break;
					}
				}
			}
			rohc_comp_debug(context, "ack_stride 0x%04x was used %zu times in the "
			                "last 20 packets", ack_stride, ack_stride_count);
		}

		/* compute new scaled ACK number & residue */
		c_field_scaling(&ack_num_scaled, &ack_num_residue, ack_stride, ack_num_hbo);
		rohc_comp_debug(context, "ack_number = 0x%x, scaled = 0x%x, factor = %u, "
		                "residue = 0x%x", ack_num_hbo, ack_num_scaled,
		                ack_stride, ack_num_residue);

		if(context->num_sent_packets == 0)
		{
			/* no need to transmit the ack_stride until it becomes non-zero */
			tcp_context->ack_num_scaling_nr = ROHC_INIT_TS_STRIDE_MIN;
		}
		else
		{
			if(ack_stride != tcp_context->ack_stride ||
			   ack_num_residue != tcp_context->ack_num_residue)
			{
				/* ACK number is not scalable with same parameters any more */
				tcp_context->ack_num_scaling_nr = 0;
			}
			rohc_comp_debug(context, "unscaled ACK number was transmitted at least "
			                "%zu / %u times since the scaling factor or residue changed",
			                tcp_context->ack_num_scaling_nr, ROHC_INIT_TS_STRIDE_MIN);
		}

		/* TODO: should update context at the very end only */
		tcp_context->ack_num_scaled = ack_num_scaled;
		tcp_context->ack_num_residue = ack_num_residue;
		tcp_context->ack_stride = ack_stride;
	}

	/* how many bits are required to encode the new sequence number? */
	tcp_context->tmp.tcp_seq_num_changed =
		(tcp->seq_num != tcp_context->old_tcphdr.seq_num);
	tcp_context->tmp.nr_seq_bits_65535 =
		wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 65535);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 65535",
	                tcp_context->tmp.nr_seq_bits_65535, seq_num_hbo);
	tcp_context->tmp.nr_seq_bits_32767 =
		wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 32767);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 32767",
	                tcp_context->tmp.nr_seq_bits_32767, seq_num_hbo);
	tcp_context->tmp.nr_seq_bits_16383 =
		wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 16383);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 16383",
	                tcp_context->tmp.nr_seq_bits_16383, seq_num_hbo);
	tcp_context->tmp.nr_seq_bits_8191 =
		wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 8191);
	rohc_comp_debug(context, "%zd bits are required to encode new sequence "
	                "number 0x%08x with p = 8191",
	                tcp_context->tmp.nr_seq_bits_8191, seq_num_hbo);
	tcp_context->tmp.nr_seq_bits_63 =
		wlsb_get_kp_32bits(tcp_context->seq_wlsb, seq_num_hbo, 63);
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
		tcp_context->tmp.nr_seq_scaled_bits =
			wlsb_get_k_32bits(tcp_context->seq_scaled_wlsb, tcp_context->seq_num_scaled);
		rohc_comp_debug(context, "%zu bits are required to encode new scaled "
		                "sequence number 0x%08x", tcp_context->tmp.nr_seq_scaled_bits,
		                tcp_context->seq_num_scaled);
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
	tcp_context->tmp.nr_ack_bits_65535 =
		wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 65535);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 65535",
	                tcp_context->tmp.nr_ack_bits_65535, ack_num_hbo);
	tcp_context->tmp.nr_ack_bits_32767 =
		wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 32767);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 32767",
	                tcp_context->tmp.nr_ack_bits_32767, ack_num_hbo);
	tcp_context->tmp.nr_ack_bits_16383 =
		wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 16383);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 16383",
	                tcp_context->tmp.nr_ack_bits_16383, ack_num_hbo);
	tcp_context->tmp.nr_ack_bits_8191 =
		wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 8191);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 8191",
	                tcp_context->tmp.nr_ack_bits_8191, ack_num_hbo);
	tcp_context->tmp.nr_ack_bits_63 =
		wlsb_get_kp_32bits(tcp_context->ack_wlsb, ack_num_hbo, 63);
	rohc_comp_debug(context, "%zd bits are required to encode new ACK "
	                "number 0x%08x with p = 63",
	                tcp_context->tmp.nr_ack_bits_63, ack_num_hbo);
	if(!tcp_is_ack_scaled_possible(tcp_context->ack_stride,
	                               tcp_context->ack_num_scaling_nr))
	{
		tcp_context->tmp.nr_ack_scaled_bits = 32;
	}
	else
	{
		tcp_context->tmp.nr_ack_scaled_bits =
			wlsb_get_k_32bits(tcp_context->ack_scaled_wlsb, tcp_context->ack_num_scaled);
		rohc_comp_debug(context, "%zu bits are required to encode new scaled "
		                "ACK number 0x%08x", tcp_context->tmp.nr_ack_scaled_bits,
		                tcp_context->ack_num_scaled);
	}
	/* TODO: move this after successful packet compression */
	c_add_wlsb(tcp_context->ack_wlsb, tcp_context->msn, ack_num_hbo);
	if(tcp_context->ack_stride != 0)
	{
		/* TODO: move this after successful packet compression */
		c_add_wlsb(tcp_context->ack_scaled_wlsb, tcp_context->msn,
		           tcp_context->ack_num_scaled);
	}

	/* how many bits are required to encode the new timestamp echo request and
	 * timestamp echo reply? */
	if(!tcp_context->tcp_opts.tmp.opt_ts_present)
	{
		/* no bit to send */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000 = 0;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000 = 0;
		rohc_comp_debug(context, "no TS option: 0 bit required to encode the "
		                "new timestamp echo request/reply numbers");
	}
	else if(!tcp_context->tcp_opts.is_timestamp_init)
	{
		/* send all bits for the first occurrence of the TCP TS option */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000 = 32;
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000 = 32;
		rohc_comp_debug(context, "first occurrence of TCP TS option: force "
		                "using 32 bits to encode new timestamp echo "
		                "request/reply numbers");
	}
	else
	{
		/* send only required bits in FO or SO states */

		/* how many bits are required to encode the timestamp echo request
		 * with p = -1 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1 =
			wlsb_get_kp_32bits(tcp_context->tcp_opts.ts_req_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_req,
			                   ROHC_LSB_SHIFT_TCP_TS_1B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = %d",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1,
		                tcp_context->tcp_opts.tmp.ts_req, ROHC_LSB_SHIFT_TCP_TS_1B);

		/* how many bits are required to encode the timestamp echo request
		 * with p = 0x40000 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000 =
			wlsb_get_kp_32bits(tcp_context->tcp_opts.ts_req_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_req,
			                   ROHC_LSB_SHIFT_TCP_TS_3B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = 0x%x",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000,
		                tcp_context->tcp_opts.tmp.ts_req, ROHC_LSB_SHIFT_TCP_TS_3B);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = 0x4000000 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000 =
			wlsb_get_kp_32bits(tcp_context->tcp_opts.ts_req_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_req,
			                   ROHC_LSB_SHIFT_TCP_TS_4B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo request 0x%08x with p = 0x%x",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000,
		                tcp_context->tcp_opts.tmp.ts_req, ROHC_LSB_SHIFT_TCP_TS_4B);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = -1 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1 =
			wlsb_get_kp_32bits(tcp_context->tcp_opts.ts_reply_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_reply,
			                   ROHC_LSB_SHIFT_TCP_TS_1B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = %d",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1,
		                tcp_context->tcp_opts.tmp.ts_reply, ROHC_LSB_SHIFT_TCP_TS_1B);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = 0x40000 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000 =
			wlsb_get_kp_32bits(tcp_context->tcp_opts.ts_reply_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_reply,
			                   ROHC_LSB_SHIFT_TCP_TS_3B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = 0x%x",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000,
		                tcp_context->tcp_opts.tmp.ts_reply, ROHC_LSB_SHIFT_TCP_TS_3B);

		/* how many bits are required to encode the timestamp echo reply
		 * with p = 0x4000000 ? */
		tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000 =
			wlsb_get_kp_32bits(tcp_context->tcp_opts.ts_reply_wlsb,
			                   tcp_context->tcp_opts.tmp.ts_reply,
			                   ROHC_LSB_SHIFT_TCP_TS_4B);
		rohc_comp_debug(context, "%zu bits are required to encode new "
		                "timestamp echo reply 0x%08x with p = 0x%x",
		                tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000,
		                tcp_context->tcp_opts.tmp.ts_reply, ROHC_LSB_SHIFT_TCP_TS_4B);
	}

	return true;
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
                                       const struct tcphdr *const tcp)
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
			context->fo_count++;
			packet_type = tcp_decide_FO_packet(context, ip_inner_context, tcp);
			break;
		case ROHC_COMP_STATE_SO: /* The Second Order (SO) state */
			context->so_count++;
			packet_type = tcp_decide_SO_packet(context, ip_inner_context, tcp);
			break;
		case ROHC_COMP_STATE_UNKNOWN:
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
 * @brief Decide which packet to send when in FO state.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param tcp               The TCP header to compress
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_8,
 *                              ROHC_PACKET_TCP_SEQ_8 and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_packet(const struct rohc_comp_ctxt *const context,
                                          const ip_context_t *const ip_inner_context,
                                          const struct tcphdr *const tcp)
{
	const bool crc7_at_least = true;
	return tcp_decide_FO_SO_packet(context, ip_inner_context, tcp, crc7_at_least);
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
                                          const struct tcphdr *const tcp)
{
	const bool crc7_at_least = false;
	return tcp_decide_FO_SO_packet(context, ip_inner_context, tcp, crc7_at_least);
}


/**
 * @brief Decide which packet to send when in FO or SO state.
 *
 * @param context           The compression context
 * @param ip_inner_context  The context of the inner IP header
 * @param tcp               The TCP header to compress
 * @param crc7_at_least     Whether packet types with CRC strictly smaller
 *                          than 8 bits are allowed or not
 * @return                  \li The packet type among ROHC_PACKET_IR,
 *                              ROHC_PACKET_IR_DYN, ROHC_PACKET_TCP_RND_[1-8],
 *                              ROHC_PACKET_TCP_SEQ_[1-8] and
 *                              ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_SO_packet(const struct rohc_comp_ctxt *const context,
                                             const ip_context_t *const ip_inner_context,
                                             const struct tcphdr *const tcp,
                                             const bool crc7_at_least)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	rohc_packet_t packet_type;

	if(tcp_context->tmp.is_ipv6_exts_list_static_changed)
	{
		rohc_comp_debug(context, "force packet IR because at least one IPv6 option "
		                "changed of length");
		packet_type = ROHC_PACKET_IR;
	}
	else if((tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_minus_1 > ROHC_SDVL_MAX_BITS_IN_2_BYTES &&
	         tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x40000 > ROHC_SDVL_MAX_BITS_IN_3_BYTES &&
	         tcp_context->tcp_opts.tmp.nr_opt_ts_req_bits_0x4000000 > ROHC_SDVL_MAX_BITS_IN_4_BYTES) ||
	        (tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_minus_1 > ROHC_SDVL_MAX_BITS_IN_2_BYTES &&
	         tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x40000 > ROHC_SDVL_MAX_BITS_IN_3_BYTES &&
	         tcp_context->tcp_opts.tmp.nr_opt_ts_reply_bits_0x4000000 > ROHC_SDVL_MAX_BITS_IN_4_BYTES))
	{
		rohc_comp_debug(context, "force packet IR-DYN because the TCP TS option "
		                "changed too much");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(tcp_context->tmp.nr_msn_bits > 4)
	{
		rohc_comp_debug(context, "force packet IR-DYN because the MSN changed "
		                "too much");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(!rsf_index_enc_possible(tcp->rsf_flags))
	{
		rohc_comp_debug(context, "force packet IR-DYN because the RSF flags are "
		                "not compressible");
		packet_type = ROHC_PACKET_IR_DYN;
	}
	else if(tcp_context->tmp.outer_ip_ttl_changed ||
	        tcp_context->tmp.ip_id_behavior_changed ||
	        tcp_context->tmp.ip_df_changed ||
	        tcp_context->tmp.dscp_changed ||
	        tcp_context->tmp.tcp_ack_flag_changed ||
	        tcp_context->tmp.tcp_urg_flag_present ||
	        tcp_context->tmp.tcp_urg_flag_changed ||
	        tcp_context->old_tcphdr.urg_ptr != tcp->urg_ptr ||
	        !tcp_is_ack_stride_static(tcp_context->ack_stride,
	                                  tcp_context->ack_num_scaling_nr))
	{
		TRACE_GOTO_CHOICE;
		packet_type = ROHC_PACKET_TCP_CO_COMMON;
	}
	else if(tcp_context->tmp.ecn_used_changed ||
	        tcp_context->tmp.ttl_hopl_changed)
	{
		/* use compressed header with a 7-bit CRC (rnd_8, seq_8 or common):
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if too many LSB of sequence number are required
		 *  - use common if too many LSB of innermost TTL/Hop Limit are required
		 *  - use common if window changed */
		if(ip_inner_context->ctxt.vx.ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP &&
		   tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
		   tcp_context->tmp.nr_ack_bits_8191 <= 15 &&
		   tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
		   !tcp_context->tmp.tcp_window_changed)
		{
			/* IP_ID_BEHAVIOR_SEQ or IP_ID_BEHAVIOR_SEQ_SWAP */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_8;
		}
		else if(ip_inner_context->ctxt.vx.ip_id_behavior > IP_ID_BEHAVIOR_SEQ_SWAP &&
		        tcp_context->tmp.nr_seq_bits_65535 <= 16 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        tcp_context->tmp.nr_ttl_hopl_bits <= 3 &&
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
	else if(ip_inner_context->ctxt.vx.ip_id_behavior <= IP_ID_BEHAVIOR_SEQ_SWAP)
	{
		/* IP_ID_BEHAVIOR_SEQ or IP_ID_BEHAVIOR_SEQ_SWAP:
		 * co_common or seq_X packet types */
		packet_type = tcp_decide_FO_SO_packet_seq(context, tcp, crc7_at_least);
	}
	else if(ip_inner_context->ctxt.vx.ip_id_behavior == IP_ID_BEHAVIOR_RAND ||
	        ip_inner_context->ctxt.vx.ip_id_behavior == IP_ID_BEHAVIOR_ZERO)
	{
		/* IP_ID_BEHAVIOR_RAND or IP_ID_BEHAVIOR_ZERO:
		 * co_common or rnd_X packet types */
		packet_type = tcp_decide_FO_SO_packet_rnd(context, tcp, crc7_at_least);
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
 * @brief Decide which seq packet to send when in FO or SO state.
 *
 * @param context           The compression context
 * @param tcp               The TCP header to compress
 * @param crc7_at_least     Whether packet types with CRC strictly smaller
 *                          than 8 bits are allowed or not
 * @return                  \li The packet type among ROHC_PACKET_TCP_SEQ_[1-8]
 *                              and ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_SO_packet_seq(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	rohc_packet_t packet_type;

	if(tcp->rsf_flags != 0 ||
	   tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
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
		   tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
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
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_window_bits_16383 <= 15 &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 5 &&
		   tcp_context->tmp.nr_ack_bits_32767 <= 16 &&
		   !tcp_context->tmp.tcp_seq_num_changed)
		{
			/* seq_7 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_7;
		}
		else
		{
			/* rnd_7 is not possible, rnd_8 neither so fallback on co_common */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	}
	else if(tcp->ack_flag == 0 ||
	        (tcp->ack_flag != 0 && !tcp_context->tmp.tcp_ack_num_changed))
	{
		/* seq_2, seq_1 or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 7 &&
		   tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		   tcp_context->tmp.nr_seq_scaled_bits <= 4)
		{
			/* seq_2 is possible */
			TRACE_GOTO_CHOICE;
			assert(tcp_context->tmp.payload_len > 0);
			packet_type = ROHC_PACKET_TCP_SEQ_2;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        tcp_context->tmp.nr_seq_bits_32767 <= 16)
		{
			/* seq_1 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_1;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
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
	else if(!tcp_context->tmp.tcp_seq_num_changed)
	{
		/* seq_4, seq_3, or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_1 <= 3 &&
		   tcp_is_ack_scaled_possible(tcp_context->ack_stride,
		                              tcp_context->ack_num_scaling_nr) &&
		   tcp_context->tmp.nr_ack_scaled_bits <= 4)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_4;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_3;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
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
	else
	{
		/* sequence and acknowledgment numbers changed:
		 * seq_6, seq_5, seq_8 or co_common */
		if(!crc7_at_least &&
		   tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		   tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		   tcp_context->tmp.nr_seq_scaled_bits <= 4 &&
		   tcp_context->tmp.nr_ack_bits_16383 <= 16)
		{
			TRACE_GOTO_CHOICE;
			assert(tcp_context->tmp.payload_len > 0);
			packet_type = ROHC_PACKET_TCP_SEQ_6;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        tcp_context->tmp.nr_seq_bits_32767 <= 16)
		{
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_SEQ_5;
		}
		else if(tcp_context->tmp.nr_ip_id_bits_3 <= 4 &&
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

	return packet_type;
}


/**
 * @brief Decide which rnd packet to send when in FO or SO state.
 *
 * @param context           The compression context
 * @param tcp               The TCP header to compress
 * @param crc7_at_least     Whether packet types with CRC strictly smaller
 *                          than 8 bits are allowed or not
 * @return                  \li The packet type among ROHC_PACKET_TCP_SEQ_[1-8]
 *                              and ROHC_PACKET_TCP_CO_COMMON in case of success
 *                          \li ROHC_PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t tcp_decide_FO_SO_packet_rnd(const struct rohc_comp_ctxt *const context,
                                                 const struct tcphdr *const tcp,
                                                 const bool crc7_at_least)
{
	struct sc_tcp_context *const tcp_context = context->specific;
	rohc_packet_t packet_type;

	if(tcp->rsf_flags != 0 ||
	   tcp_context->tcp_opts.tmp.do_list_struct_changed ||
	   tcp_context->tcp_opts.tmp.do_list_static_changed)
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
		if(tcp->rsf_flags != 0)
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
		else if(tcp_context->tmp.tcp_window_changed)
		{
			if(!crc7_at_least &&
			   !tcp_context->tmp.tcp_seq_num_changed &&
			   tcp_context->tmp.nr_ack_bits_65535 <= 18)
			{
				/* rnd_7 is possible */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_RND_7;
			}
			else
			{
				/* rnd_7 is not possible, rnd_8 neither so fallback on co_common */
				TRACE_GOTO_CHOICE;
				packet_type = ROHC_PACKET_TCP_CO_COMMON;
			}
		}
		else if(!crc7_at_least &&
		        !tcp_context->tmp.tcp_ack_num_changed &&
		        tcp_context->tmp.payload_len > 0 &&
		        tcp_context->seq_num_scaling_nr >= ROHC_INIT_TS_STRIDE_MIN &&
		        tcp_context->tmp.nr_seq_scaled_bits <= 4)
		{
			/* rnd_2 is possible */
			assert(tcp_context->tmp.payload_len > 0);
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_2;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        tcp_is_ack_scaled_possible(tcp_context->ack_stride,
		                                   tcp_context->ack_num_scaling_nr) &&
		        tcp_context->tmp.nr_ack_scaled_bits <= 4 &&
		        !tcp_context->tmp.tcp_seq_num_changed)
		{
			/* rnd_4 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_4;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        !tcp_context->tmp.tcp_seq_num_changed &&
		        tcp_context->tmp.nr_ack_bits_8191 <= 15)
		{
			/* rnd_3 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_3;
		}
		else if(!crc7_at_least &&
		        tcp_context->tmp.nr_seq_bits_65535 <= 18 &&
		        !tcp_context->tmp.tcp_ack_num_changed)
		{
			/* rnd_1 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_1;
		}
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
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
		else if(!crc7_at_least &&
		        tcp->ack_flag != 0 &&
		        tcp_context->tmp.nr_seq_bits_8191 <= 14 &&
		        tcp_context->tmp.nr_ack_bits_8191 <= 15)
		{
			/* ACK number present */
			/* rnd_5 is possible */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_5;
		}
		else if(/* !tcp_context->tmp.tcp_window_changed && */
		        tcp_context->tmp.nr_ack_bits_16383 <= 16 &&
		        tcp_context->tmp.nr_seq_bits_65535 <= 16)
		{
			/* fallback on rnd_8 */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_RND_8;
		}
		else
		{
			/* rnd_8 is not possible, fallback on co_common */
			TRACE_GOTO_CHOICE;
			packet_type = ROHC_PACKET_TCP_CO_COMMON;
		}
	} /* end of case 'unchanged structure of the list of TCP options' */

	/* IP-ID is NOT sequential, so only co_common and rnd_X packets are allowed */
	assert(packet_type == ROHC_PACKET_TCP_CO_COMMON ||
	       (packet_type >= ROHC_PACKET_TCP_RND_1 &&
	        packet_type <= ROHC_PACKET_TCP_RND_8));

	return packet_type;
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

	if(is_ip_id_increasing(last_ip_id, new_ip_id))
	{
		behavior = IP_ID_BEHAVIOR_SEQ;
	}
	else
	{
		const uint16_t swapped_last_ip_id = swab16(last_ip_id);
		const uint16_t swapped_new_ip_id = swab16(new_ip_id);

		if(is_ip_id_increasing(swapped_last_ip_id, swapped_new_ip_id))
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
 * @brief Detect the behavior of the IP/TCP ECN flags and TCP RES flags
 *
 * What value for ecn_used? The ecn_used controls the presence of IP ECN flags,
 * TCP ECN flags, but also TCP RES flags.
 *
 * @param[in,out] context         The compression context to compare
 * @param pkt_ecn_vals            The values of the IP/ECN flags in the current packet
 * @param pkt_outer_dscp_changed  Whether at least one DSCP changed in the current packet
 * @param pkt_res_val             The TCP RES flags in the current packet
 */
static void tcp_detect_ecn_used_behavior(struct rohc_comp_ctxt *const context,
                                         const uint8_t pkt_ecn_vals,
                                         const uint8_t pkt_outer_dscp_changed,
                                         const uint8_t pkt_res_val)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	const bool ecn_used_change_needed_by_outer_dscp =
		(pkt_outer_dscp_changed && !tcp_context->ecn_used);
	const bool tcp_res_flag_changed =
		(pkt_res_val != tcp_context->old_tcphdr.res_flags);
	const bool ecn_used_change_needed_by_res_flags =
		(tcp_res_flag_changed && !tcp_context->ecn_used);
	const bool ecn_used_change_needed_by_ecn_flags_unset =
		(pkt_ecn_vals == 0 && tcp_context->ecn_used);
	const bool ecn_used_change_needed_by_ecn_flags_set =
		(pkt_ecn_vals != 0 && !tcp_context->ecn_used);
	const bool ecn_used_change_needed =
		(ecn_used_change_needed_by_outer_dscp ||
		 ecn_used_change_needed_by_res_flags ||
		 ecn_used_change_needed_by_ecn_flags_unset ||
		 ecn_used_change_needed_by_ecn_flags_set);

	tcp_field_descr_change(context, "RES flags", tcp_res_flag_changed, 0);
	rohc_comp_debug(context, "ECN: context did%s use ECN",
	                tcp_context->ecn_used ? "" : "n't");
	rohc_comp_debug(context, "ECN: packet does%s use ECN",
	                pkt_ecn_vals != 0 ? "" : "n't");

	/* is a change of ecn_used value required? */
	if(ecn_used_change_needed)
	{
		/* a change of ecn_used value seems to be required */
		if(ecn_used_change_needed_by_ecn_flags_unset &&
		   tcp_context->ecn_used_zero_count < MAX_FO_COUNT)
		{
			/* do not change ecn_used = 0 too quickly, wait for a few packets
			 * that do not need ecn_used = 1 to actually perform the change */
			rohc_comp_debug(context, "ECN: packet doesn't use ECN any more but "
			                "context does, wait for %zu more packets without ECN "
			                "before changing the context ecn_used parameter",
			                MAX_FO_COUNT - tcp_context->ecn_used_zero_count);
			tcp_context->tmp.ecn_used_changed = false;
			tcp_context->ecn_used_zero_count++;
		}
		else
		{
			rohc_comp_debug(context, "ECN: behavior changed");
			tcp_context->tmp.ecn_used_changed = true;
			tcp_context->ecn_used =
				!!(pkt_ecn_vals != 0 || tcp_res_flag_changed || pkt_outer_dscp_changed);
			tcp_context->ecn_used_change_count = 0;
			tcp_context->ecn_used_zero_count = 0;
		}
	}
	else if(tcp_context->ecn_used_change_count < MAX_FO_COUNT)
	{
		rohc_comp_debug(context, "ECN: behavior didn't change but changed a few "
		                "packet before");
		tcp_context->tmp.ecn_used_changed = true;
		tcp_context->ecn_used_change_count++;
		tcp_context->ecn_used_zero_count = 0;
	}
	else
	{
		rohc_comp_debug(context, "ECN: behavior didn't change");
		tcp_context->tmp.ecn_used_changed = false;
		tcp_context->ecn_used_zero_count = 0;
	}
	rohc_comp_debug(context, "ECN: context does%s use ECN",
	                tcp_context->ecn_used ? "" : "n't");
}


/**
 * @brief Print a debug trace for the field change
 *
 * @param context  The compression context
 * @param name     The name of the field
 * @param changed  Whether the field changed or not
 * @param nr_trans The number of times the field was transmitted since
 *                 the last change
 */
static void tcp_field_descr_change(const struct rohc_comp_ctxt *const context,
                                   const char *const name,
                                   const bool changed,
                                   const size_t nr_trans)
{
	if(!changed)
	{
		rohc_comp_debug(context, "%s did not change", name);
	}
	else if(nr_trans == 0)
	{
		rohc_comp_debug(context, "%s did change with the current packet", name);
	}
	else
	{
		rohc_comp_debug(context, "%s did change %zu packets before", name, nr_trans);
	}
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
 * @brief Whether the ACK number may be transmitted scaled or not
 *
 * The ACK number may be transmitted scaled if:
 *  \li the \e ack_stride scaling factor is non-zero,
 *  \li both the \e ack_stride scaling factor and the scaling residue didn't
 *      change in the last few packets
 *
 * @param ack_stride  The \e ack_stride scaling factor
 * @param nr_trans    The number of transmissions since last change
 * @return            true if the ACK number may be transmitted scaled,
 *                    false if the ACK number shall be transmitted unscaled
 */
static bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
                                       const size_t nr_trans)
{
	return (ack_stride != 0 && nr_trans >= ROHC_INIT_TS_STRIDE_MIN);
}


/**
 * @brief Whether the \e ack_stride scaling factor shall be transmitted or not
 *
 * @param ack_stride  The \e ack_stride scaling factor
 * @param nr_trans    The number of transmissions since last change
 * @return            true if the ACK number may be transmitted scaled,
 *                    false if the ACK number shall be transmitted unscaled
 */
static bool tcp_is_ack_stride_static(const uint16_t ack_stride,
                                     const size_t nr_trans)
{
	return (ack_stride == 0 || nr_trans >= ROHC_INIT_TS_STRIDE_MIN);
}


/**
 * @brief Update the profile when feedback is received
 *
 * This function is one of the functions that must exist in one profile for
 * the framework to work.
 *
 * @param context            The compression context
 * @param feedback_type      The feedback type
 * @param packet             The whole feedback packet with CID bits
 * @param packet_len         The length of the whole feedback packet with CID bits
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @return                   true if the feedback was successfully handled,
 *                           false if the feedback could not be taken into account
 */
static bool c_tcp_feedback(struct rohc_comp_ctxt *const context,
                           const enum rohc_feedback_type feedback_type,
                           const uint8_t *const packet,
                           const size_t packet_len,
                           const uint8_t *const feedback_data,
                           const size_t feedback_data_len)
{
	const uint8_t *remain_data = feedback_data;
	size_t remain_len = feedback_data_len;

	if(feedback_type == ROHC_FEEDBACK_1)
	{
		const bool sn_not_valid = false;
		uint32_t sn_bits;
		size_t sn_bits_nr;

		rohc_comp_debug(context, "FEEDBACK-1 received");
		assert(remain_len == 1);

		/* get the 8 LSB bits of the acknowledged SN */
		sn_bits = remain_data[0] & 0xff;
		sn_bits_nr = 8;

		rohc_comp_debug(context, "ACK received (CID = %zu, %zu-bit SN = 0x%02x)",
		                context->cid, sn_bits_nr, sn_bits);

		/* the compressor received a positive ACK */
		c_tcp_feedback_ack(context, sn_bits, sn_bits_nr, sn_not_valid);
	}
	else if(feedback_type == ROHC_FEEDBACK_2)
	{
		rohc_comp_debug(context, "FEEDBACK-2 received");

		if(!c_tcp_feedback_2(context, packet, packet_len, feedback_data,
		                     feedback_data_len))
		{
			rohc_comp_warn(context, "failed to handle FEEDBACK-2");
			goto error;
		}
	}
	else /* not FEEDBACK-1 nor FEEDBACK-2 */
	{
		rohc_comp_warn(context, "feedback type not implemented (%d)", feedback_type);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Update the profile when FEEDBACK-2 is received
 *
 * @param context            The compression context
 * @param packet             The whole feedback packet with CID bits
 * @param packet_len         The length of the whole feedback packet with CID bits
 * @param feedback_data      The feedback data without the CID bits
 * @param feedback_data_len  The length of the feedback data without the CID bits
 * @return                   true if the feedback was successfully handled,
 *                           false if the feedback could not be taken into account
 */
static bool c_tcp_feedback_2(struct rohc_comp_ctxt *const context,
                             const uint8_t *const packet,
                             const size_t packet_len,
                             const uint8_t *const feedback_data,
                             const size_t feedback_data_len)
{
	const uint8_t *remain_data = feedback_data;
	size_t remain_len = feedback_data_len;
	const struct rohc_feedback_2_rfc6846 *feedback2;

	size_t opts_present[ROHC_FEEDBACK_OPT_MAX] = { 0 };

	uint8_t crc_in_packet;
	size_t crc_pos_from_end;

	uint32_t sn_bits;
	size_t sn_bits_nr;

	/* retrieve acked SN */
	if(remain_len < sizeof(struct rohc_feedback_2_rfc6846))
	{
		rohc_comp_warn(context, "malformed FEEDBACK-2: packet too short for the "
		               "minimal %zu-byte header, only %zu bytes remaining",
		               sizeof(struct rohc_feedback_2_rfc6846), remain_len);
		goto error;
	}
	feedback2 = (const struct rohc_feedback_2_rfc6846 *) feedback_data;
	sn_bits = (feedback2->sn1 << 8) | feedback2->sn2;
	sn_bits_nr = 6 + 8;
	crc_in_packet = feedback2->crc;
	crc_pos_from_end = remain_len - 2;
	remain_data += 3;
	remain_len -= 3;

	/* parse FEEDBACK-2 options */
	if(!rohc_comp_feedback_parse_opts(context, packet, packet_len,
	                                  remain_data, remain_len,
	                                  opts_present, &sn_bits, &sn_bits_nr,
	                                  crc_in_packet, crc_pos_from_end))
	{
		rohc_comp_warn(context, "malformed FEEDBACK-2: failed to parse options");
		goto error;
	}

	/* change from U- to O-mode once feedback channel is established */
	rohc_comp_change_mode(context, ROHC_O_MODE);

	/* act according to the type of feedback */
	switch(feedback2->ack_type)
	{
		case ROHC_FEEDBACK_ACK:
		{
			const bool sn_not_valid = !!(opts_present[ROHC_FEEDBACK_OPT_SN_NOT_VALID] > 0);

			rohc_comp_debug(context, "ACK received (CID = %zu, %zu-bit SN = 0x%x, "
			                "SN-not-valid = %d)", context->cid, sn_bits_nr, sn_bits,
			                GET_REAL(sn_not_valid));

			/* the compressor received a positive ACK */
			c_tcp_feedback_ack(context, sn_bits, sn_bits_nr, sn_not_valid);
			break;
		}
		case ROHC_FEEDBACK_NACK:
		{
			/* RFC3095 §5.4.1.1.1: NACKs, downward transition */
			rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			          "NACK received for CID %zu", context->cid);
			/* the compressor transits back to the FO state */
			if(context->state == ROHC_COMP_STATE_SO)
			{
				rohc_comp_change_state(context, ROHC_COMP_STATE_FO);
			}
			/* TODO: use the SN field to determine the latest packet successfully
			 * decompressed and then determine what fields need to be updated */
			break;
		}
		case ROHC_FEEDBACK_STATIC_NACK:
		{
			/* RFC3095 §5.4.1.1.1: NACKs, downward transition */
			rohc_info(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			          "STATIC-NACK received for CID %zu", context->cid);
			/* the compressor transits back to the IR state */
			rohc_comp_change_state(context, ROHC_COMP_STATE_IR);
			/* TODO: use the SN field to determine the latest packet successfully
			 * decompressed and then determine what fields need to be updated */
			break;
		}
		case ROHC_FEEDBACK_RESERVED:
		{
			/* RFC3095 §5.7.6.1: reserved (MUST NOT be used for parseability) */
			rohc_comp_warn(context, "malformed FEEDBACK-2: reserved ACK type used");
			goto error;
		}
		default:
		{
			/* impossible value */
			rohc_comp_warn(context, "malformed FEEDBACK-2: unknown ACK type %u",
			               feedback2->ack_type);
			goto error;
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Perform the required actions after the reception of a positive ACK
 *
 * @param context       The compression context that received a positive ACK
 * @param sn_bits       The LSB bits of the acknowledged SN
 * @param sn_bits_nr    The number of LSB bits of the acknowledged SN
 * @param sn_not_valid  Whether the received SN may be considered as valid or not
 */
static void c_tcp_feedback_ack(struct rohc_comp_ctxt *const context,
                               const uint32_t sn_bits,
                               const size_t sn_bits_nr,
                               const bool sn_not_valid)
{
	struct sc_tcp_context *const tcp_context = context->specific;

	if(context->state != ROHC_COMP_STATE_SO)
	{
		/* RFC 6846, §5.2.2.1:
		 *   The compressor MAY use acknowledgment feedback (ACKs) to move to a
		 *   higher compression state.
		 *   Upon reception of an ACK for a context-updating packet, the
		 *   compressor obtains confidence that the decompressor has received the
		 *   acknowledged packet and that it has observed changes in the packet
		 *   flow up to the acknowledged packet. */
		/* TODO: not implemented yet, use the SN field to determine if it acknowledges
		 * one of the "context-updating" packets that was transmitted since the context
		 * last needed updates */
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK may make the compressor "
		                "transit to the SO state more quickly, but feature is not "
		                "implemented yet");
	}

	/* the W-LSB encoding scheme as defined by function lsb() in RFC4997 use a
	 * sliding window with a large limited maximum width ; once the feedback channel
	 * is established, positive ACKs may remove older values from the windows */
	if(!sn_not_valid)
	{
		size_t acked_nr;

		/* ack TTL or Hop Limit */
		acked_nr = wlsb_ack(tcp_context->ttl_hopl_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TTL or Hop Limit W-LSB", acked_nr);
		/* ack innermost IP-ID */
		acked_nr = wlsb_ack(tcp_context->ip_id_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from innermost IP-ID W-LSB", acked_nr);
		/* ack TCP window */
		acked_nr = wlsb_ack(tcp_context->window_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP window W-LSB", acked_nr);
		/* ack TCP (scaled) sequence number */
		acked_nr = wlsb_ack(tcp_context->seq_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP sequence number W-LSB", acked_nr);
		acked_nr = wlsb_ack(tcp_context->seq_scaled_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP scaled sequence number W-LSB", acked_nr);
		/* ack TCP (scaled) acknowledgment number */
		acked_nr = wlsb_ack(tcp_context->ack_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP acknowledgment number W-LSB", acked_nr);
		acked_nr = wlsb_ack(tcp_context->ack_scaled_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP scaled acknowledgment number W-LSB", acked_nr);
		/* ack TCP TS option */
		acked_nr = wlsb_ack(tcp_context->tcp_opts.ts_req_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP TS request W-LSB", acked_nr);
		acked_nr = wlsb_ack(tcp_context->tcp_opts.ts_reply_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from TCP TS reply W-LSB", acked_nr);
		/* ack SN */
		acked_nr = wlsb_ack(tcp_context->msn_wlsb, sn_bits, sn_bits_nr);
		rohc_comp_debug(context, "FEEDBACK-2: positive ACK removed %zu values "
		                "from SN W-LSB", acked_nr);
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
	.reinit_context = rohc_comp_reinit_context,
	.feedback       = c_tcp_feedback,
};

