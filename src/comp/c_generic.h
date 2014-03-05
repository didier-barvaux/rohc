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
 * @file c_generic.h
 * @brief ROHC generic compression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_GENERIC_H
#define ROHC_COMP_GENERIC_H

#include "rohc_comp_internals.h"
#include "rohc_packets.h"
#include "schemes/list.h"
#include "ip.h"
#include "crc.h"

#include <stdlib.h>


/**
 * @brief Store information about an IPv4 header between the different
 *        compressions of IP packets.
 *
 * Defines an object that contains counters, flags and structures related to an
 * IPv4 header and that need to be saved between the different compressions of
 * packets. A compression context owns objects like this for the two first
 * IPv4 headers.
 */
struct ipv4_header_info
{
	/// A window to store the IP-ID
	struct c_wlsb *ip_id_window;

	/// The previous IP header
	struct ipv4_hdr old_ip;

	/// The number of times the DF field was added to the compressed header
	int df_count;
	/// @brief The number of times the IP-ID is specified as random in the
	///        compressed header
	int rnd_count;
	/// @brief The number of times the IP-ID is specified as coded in Network
	///        Byte Order (NBO) in the compressed header
	int nbo_count;
	/// @brief The number of times the IP-ID is specified as static in the
	///        compressed header
	int sid_count;

	/// Whether the IP-ID is considered as random or not
	int rnd;
	/// Whether the IP-ID is considered as coded in NBO or not
	int nbo;
	/// Whether the IP-ID is considered as static or not
	int sid;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        random or not
	int old_rnd;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        coded in NBO or not
	int old_nbo;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        static or not
	int old_sid;

	/// The delta between the IP-ID and the current Sequence Number (SN)
	/// (overflow over 16 bits is expected when SN > IP-ID)
	uint16_t id_delta;
};


/**
 * @brief Store information about an IPv6 header between the different
 *        compressions of IP packets.
 *
 * Defines an object that contains counters, flags and structures related to an
 * IPv6 header and that need to be saved between the different compressions of
 * packets. A compression context owns objects like this for the two first
 * IPv6 headers.
 */
struct ipv6_header_info
{
	/// The previous IPv6 header
	struct ipv6_hdr old_ip;
	/// The extension compressor
	struct list_comp ext_comp;
};


/**
 * @brief Store information about an IP (IPv4 or IPv6) header between the
 *        different compressions of IP packets.
 */
struct ip_header_info
{
	ip_version version;            ///< The version of the IP header

	/// The number of times the TOS/TC field was added to the compressed header
	int tos_count;
	/// The number of times the TTL/HL field was added to the compressed header
	int ttl_count;
	/// @brief The number of times the Protocol/Next Header field was added to
	///        the compressed header
	int protocol_count;

	/** Whether the old_* members of the struct and in its children are
	 *  initialized or not */
	bool is_first_header;

	union
	{
		struct ipv4_header_info v4; ///< The IPv4-specific header info
		struct ipv6_header_info v6; ///< The IPv6-specific header info
	} info;                        ///< The version specific header info
};


/**
 * @brief Structure that contains variables that are used during one single
 *        compression of packet.
 *
 * Structure that contains variables that are temporary, i.e. variables that
 * will only be used for the compression of the current packet. These variables
 * must be reinitialized every time a new packet arrive.
 *
 * @see c_init_tmp_variables
 */
struct generic_tmp_vars
{
	/// The number of fields that changed in the outer IP header
	unsigned short changed_fields;
	/// The number of fields that changed in the inner IP header
	unsigned short changed_fields2;
	/// The number of static fields that changed in the two IP headers
	int send_static;
	/// The number of dynamic fields that changed in the two IP headers
	int send_dynamic;

	/// The number of bits needed to encode the Sequence Number (SN)
	size_t nr_sn_bits;
	/// The number of bits needed to encode the IP-ID of the outer IP header
	size_t nr_ip_id_bits;
	/// The number of bits needed to encode the IP-ID of the inner IP header
	size_t nr_ip_id_bits2;

	/// The type of packet the compressor must send: IR, IR-DYN, UO*
	rohc_packet_t packet_type;
};


/**
 * @brief The generic compression context
 *
 * The object defines the generic context that manages IP(/nextheader) and
 * IP/IP(/nextheader) packets. nextheader is managed by the profile-specific
 * part of the context.
 */
struct c_generic_context
{
	/// The Sequence Number (SN), may be 16-bit or 32-bit long
	uint32_t sn;
	/// A window used to encode the SN
	struct c_wlsb *sn_window;

	/// The number of packets sent while in Initialization & Refresh (IR) state
	int ir_count;
	/// The number of packets sent while in First Order (FO) state
	int fo_count;
	/// The number of packets sent while in Second Order (SO) state
	int so_count;

	/// @brief The number of packet sent while in SO state, used for the periodic
	///        refreshes of the context
	/// @see periodic_down_transition
	size_t go_back_fo_count;
	/// @brief The number of packet sent while in FO or SO state, used for the
	///        periodic refreshes of the context
	/// @see periodic_down_transition
	size_t go_back_ir_count;

	/** The number of IP headers */
	size_t ip_hdr_nr;
	/// Information about the outer IP header
	struct ip_header_info outer_ip_flags;
	/// Information about the inner IP header
	struct ip_header_info inner_ip_flags;

	/// Temporary variables that are used during one single compression of packet
	struct generic_tmp_vars tmp;

	/* below are some information and handlers to manage the next header
	 * (if any) located just after the IP headers (1 or 2 IP headers) */

	/// The protocol number registered by IANA for the next header protocol
	unsigned int next_header_proto;
	/// The length of the next header
	unsigned int next_header_len;

	/** The handler for encoding profile-specific uncompressed header fields */
	int (*encode_uncomp_fields)(struct c_context *const context,
	                            const struct net_pkt *const uncomp_pkt)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/// @brief The handler used to decide the state that should be used for the
	///        next packet
	void (*decide_state)(struct c_context *const context);
	/** @brief The handler used to decide which packet to send in FO state */
	rohc_packet_t (*decide_FO_packet)(const struct c_context *context);
	/** @brief The handler used to decide which packet to send in SO state */
	rohc_packet_t (*decide_SO_packet)(const struct c_context *context);
	/** The handler used to decide which extension to send */
	rohc_ext_t (*decide_extension)(const struct c_context *context);

	/// The handler used to initialize some data just before the IR packet build
	void (*init_at_IR)(const struct c_context *context,
	                   const unsigned char *next_header);

	/** Determine the next SN value */
	uint32_t (*get_next_sn)(const struct c_context *const context,
	                        const struct net_pkt *const uncomp_pkt)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/// @brief The handler used to add the static part of the next header to the
	///        ROHC packet
	size_t (*code_static_part)(const struct c_context *const context,
	                           const unsigned char *const next_header,
	                           unsigned char *const dest,
	                           const size_t counter)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	/// @brief The handler used to add the dynamic part of the next header to the
	///        ROHC pachet
	size_t (*code_dynamic_part)(const struct c_context *const context,
	                            const unsigned char *const next_header,
	                            unsigned char *const dest,
	                            const size_t counter)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	/// @brief The handler used to add the IR/IR-DYN remainder header to the
	///        ROHC pachet
	size_t (*code_ir_remainder)(const struct c_context *const context,
	                            unsigned char *const dest,
	                            const size_t counter)
		__attribute__((warn_unused_result, nonnull(1, 2)));

	/// @brief The handler used to add an additional header in the head of the
	///        UO-0, UO-1 and UO-2 packets
	size_t (*code_UO_packet_head)(const struct c_context *const context,
	                              const unsigned char *const next_header,
	                              unsigned char *const dest,
	                              const size_t counter,
	                              size_t *const first_position)
		__attribute__((warn_unused_result, nonnull(1,2, 3, 5)));

	/// @brief The handler used to add an additional header in the tail of the
	///        UO-0, UO-1 and UO-2 packets
	size_t (*code_uo_remainder)(const struct c_context *const context,
	                            const unsigned char *const next_header,
	                            unsigned char *const dest,
	                            const size_t counter)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	/// @brief The handler used to compute the CRC-STATIC value
	uint8_t (*compute_crc_static)(const uint8_t *const ip,
	                              const uint8_t *const ip2,
	                              const uint8_t *const next_header,
	                              const rohc_crc_type_t crc_type,
	                              const uint8_t init_val,
	                              const uint8_t *const crc_table)
		__attribute__((nonnull(1, 3, 6), warn_unused_result));

	/// @brief The handler used to compute the CRC-DYNAMIC value
	uint8_t (*compute_crc_dynamic)(const uint8_t *const ip,
	                               const uint8_t *const ip2,
	                               const uint8_t *const next_header,
	                               const rohc_crc_type_t crc_type,
	                               const uint8_t init_val,
	                               const uint8_t *const crc_table)
		__attribute__((nonnull(1, 3, 6), warn_unused_result));

	/// Profile-specific data
	void *specific;
};


/*
 * Function prototypes.
 */

bool c_generic_create(struct c_context *const context,
                      const rohc_lsb_shift_t sn_shift,
                      const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 3)));
void c_generic_destroy(struct c_context *const context)
	__attribute__((nonnull(1)));

bool c_generic_check_profile(const struct rohc_comp *const comp,
                             const struct net_pkt *const packet)
		__attribute__((warn_unused_result, nonnull(1, 2)));

void change_state(struct c_context *const context,
                  const rohc_comp_state_t new_state)
	__attribute__((nonnull(1)));

rohc_ext_t decide_extension(const struct c_context *const context)
	__attribute__((warn_unused_result, nonnull(1)));

int c_generic_encode(struct c_context *const context,
                     const struct net_pkt *const uncomp_pkt,
                     unsigned char *const rohc_pkt,
                     const size_t rohc_pkt_max_len,
                     rohc_packet_t *const packet_type,
                     int *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

bool c_generic_reinit_context(struct c_context *const context);

void c_generic_feedback(struct c_context *const context,
                        const struct c_feedback *feedback);

bool c_generic_use_udp_port(const struct c_context *const context,
                            const unsigned int port);

void decide_state(struct c_context *const context);

void rohc_get_ipid_bits(const struct c_context *const context,
                        size_t *const nr_innermost_bits,
                        size_t *const nr_outermost_bits)
	__attribute__((nonnull(1, 2, 3)));

#endif

