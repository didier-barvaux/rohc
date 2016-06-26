/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2008,2009,2010,2012,2013 Viveris Technologies
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
 * @file   rohc_decomp_rfc3095.c
 * @brief  Generic framework for RFC3095-based decompression profiles such as
 *         IP-only, UDP, UDP-Lite, ESP, and RTP profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

#ifndef ROHC_DECOMP_RFC3095_H
#define ROHC_DECOMP_RFC3095_H

#include "rohc_decomp.h"
#include "rohc_decomp_internals.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "schemes/decomp_wlsb.h"
#include "schemes/ip_id_offset.h"
#include "schemes/decomp_list.h"
#include "protocols/udp_lite.h"
#include "ip.h"
#include "crc.h"

#include <stddef.h>
#ifdef __KERNEL__
#  include <linux/types.h>
#else
#  include <stdbool.h>
#endif


/** The outer or inner IP bits extracted from ROHC headers */
struct rohc_extr_ip_bits
{
	uint8_t version:4;  /**< The version bits found in static chain of IR
	                         header */

	uint8_t tos;     /**< The TOS/TC bits found in dynamic chain of IR/IR-DYN
	                      header or in extension header */
	size_t tos_nr;   /**< The number of TOS/TC bits found */

	uint16_t id;     /**< The IP-ID bits found in dynamic chain of IR/IR-DYN
	                      header, in UO* base header, in extension header and
	                      in remainder of UO* header */
	size_t id_nr;    /**< The number of IP-ID bits found */
	bool is_id_enc;  /**< Whether value(IP-ID) is encoded or not */

	uint8_t df:1;    /**< The DF bits found in dynamic chain of IR/IR-DYN
	                      header or in extension header */
	size_t df_nr;    /**< The number of DF bits found */

	uint8_t ttl;     /**< The TTL/HL bits found in dynamic chain of IR/IR-DYN
	                      header or in extension header */
	size_t ttl_nr;   /**< The number of TTL/HL bits found */

	uint8_t proto;   /**< The protocol/next header bits found static chain
	                      of IR header or in extension header */
	size_t proto_nr; /**< The number of protocol/next header bits */

	uint8_t nbo:1;   /**< The NBO bits found in dynamic chain of IR/IR-DYN
	                      header or in extension header */
	size_t nbo_nr;   /**< The number of NBO bits found */

	uint8_t rnd:1;   /**< The RND bits found in dynamic chain of IR/IR-DYN
	                      header or in extension header */
	size_t rnd_nr;   /**< The number of RND bits found */

	uint8_t sid:1;   /**< The SID bits found in dynamic chain of IR/IR-DYN
	                      header or in extension header */
	size_t sid_nr;   /**< The number of SID bits found */

	uint32_t flowid:20;  /**< The IPv6 flow ID bits found in static chain of
	                          IR header */
	size_t flowid_nr;    /**< The number of flow label bits */

	uint8_t saddr[16];   /**< The source address bits found in static chain of
	                          IR header */
	size_t saddr_nr;     /**< The number of source address bits */

	uint8_t daddr[16];   /**< The destination address bits found in static
	                          chain of IR header */
	size_t daddr_nr;     /**< The number of source address bits */
};


/**
 * @brief The bits extracted from ROHC UO* base headers
 *
 * @see parse_uo0
 * @see parse_uo1
 * @see parse_uor2
 */
struct rohc_extr_bits
{
	bool is_context_reused; /**< Whether the context is re-used or not */

	/* SN */
	uint32_t sn;         /**< The SN bits found in ROHC header */
	size_t sn_nr;        /**< The number of SN bits found in ROHC header */
	bool is_sn_enc;      /**< Whether value(SN) is encoded with W-LSB or not */
	rohc_lsb_ref_t lsb_ref_type; /**< The reference to use for LSB decoding
	                                  (used for context repair after CRC failure) */
	bool sn_ref_offset;         /**< Optional offset to add to the reference SN
	                                 (used for context repair after CRC failure) */

	/** bits related to outer IP header */
	struct rohc_extr_ip_bits outer_ip;

	/** bits related to inner IP header */
	struct rohc_extr_ip_bits inner_ip;

	/* X (extension) flag */
	uint8_t ext_flag:1;     /**< X (extension) flag */

	/* Mode bits */
	uint8_t mode:2;         /**< The Mode bits found in ROHC header */
	size_t mode_nr;         /**< The number of Mode bits found in ROHC header */


	/* bits below are for UDP-based profiles only
	   @todo TODO should be moved in d_udp.c */

	uint16_t udp_src;     /**< The UDP source port bits found in static chain
	                           of IR header */
	size_t udp_src_nr;    /**< The number of UDP source port bits */

	uint16_t udp_dst;     /**< The UDP destination port bits in static chain
	                           of IR header */
	size_t udp_dst_nr;    /**< The number of UDP destination port bits */

	rohc_tristate_t udp_check_present; /**< Whether the UDP checksum field is
	                                        encoded in the ROHC packet or not */
	uint16_t udp_check;   /**< The UDP checksum bits found in dynamic chain
	                           of IR/IR-DYN header or in remainder of UO*
	                           header */
	size_t udp_check_nr;  /**< The number of UDP checksum bits */


	/* bits below are for UDP-Lite-based profiles only
	   @todo TODO should be moved in d_udp_lite.c */

	rohc_packet_cce_t cce_pkt; /**< TODO */
	rohc_tristate_t cfp;       /**< TODO */
	rohc_tristate_t cfi;       /**< TODO */
	uint16_t udp_lite_cc;      /**< The UDP-Lite CC bits found in dynamic
	                                chain of IR/IR-DYN header or in remainder
	                                of UO* header */
	size_t udp_lite_cc_nr;     /**< The number of UDP-Lite CC bits */


	/* bits below are for RTP profile only
	   @todo TODO should be moved in d_rtp.c */

	/* RTP version */
	uint8_t rtp_version:2;  /**< The RTP version bits found in dynamic chain
	                             of IR/IR-DYN header */
	size_t rtp_version_nr;  /**< The number of RTP version bits */

	/* RTP Padding (R-P) flag */
	uint8_t rtp_p:1;        /**< The RTP Padding bits found in dynamic chain
	                             of IR/IR-DYN header or in extension header */
	size_t rtp_p_nr;        /**< The number of RTP Padding bits */

	/* RTP eXtension (R-X) flag */
	uint8_t rtp_x:1;        /**< The RTP eXtension (R-X) bits found in
	                             extension header */
	size_t rtp_x_nr;        /**< The number of RTP X bits */

	/* RTP CSRC Count (CC) */
	uint8_t rtp_cc:4;       /**< The RTP CSRC Count bits found in dynamic
	                             chain of IR/IR-DYN header */
	size_t rtp_cc_nr;       /**< The number of the RTP CSRC Count bits */

	/* RTP Marker (M) flag */
	uint8_t rtp_m:1;        /**< The RTP Marker (M) bits found in dynamic chain
	                             of IR/IR-DYN header, UO* base header and
	                             extension header */
	size_t rtp_m_nr;        /**< The number of the RTP Marker (M) bits */

	/* RTP Payload Type (RTP-PT) */
	uint8_t rtp_pt:7;       /**< The RTP Payload Type (PT) bits found in
	                             dynamic chain of IR/IR-DYN header or in
	                             extension header */
	size_t rtp_pt_nr;       /**< The number of RTP PT bits found in header */

	/* RTP TimeStamp (TS) */
	uint32_t ts;            /**< The TS bits found in dynamic chain of
	                             IR/IR-DYN header, in UO* base header or in
	                             extension header */
	size_t ts_nr;           /**< The number of TS bits found in ROHC header */
	bool is_ts_scaled;      /**< Whether TS is transmitted scaled or not */

	/* RTP Synchronization SouRCe (SSRC)  identifier */
	uint32_t rtp_ssrc;      /**< The SSRC bits found in static chain of
	                             IR header */
	size_t rtp_ssrc_nr;     /**< The number of SSRC bits found in header */


	/* bits below are for ESP profile only
	   @todo TODO should be moved in d_esp.c */

	/* ESP Security Parameters Index (SPI) */
	uint32_t esp_spi;      /**< The SPI bits found in static chain of
	                             IR header */
	size_t esp_spi_nr;     /**< The number of SPI bits found in header */
};


/** The outer or inner IP values decoded from the extracted ROHC bits */
struct rohc_decoded_ip_values
{
	uint8_t version:4;   /**< The decoded version field */
	uint8_t tos;         /**< The decoded TOS/TC field */
	uint16_t id;         /**< The decoded IP-ID field (IPv4 only) */
	uint8_t df:1;        /**< The decoded DF field (IPv4 only) */
	uint8_t ttl;         /**< The decoded TTL/HL field */
	uint8_t proto;       /**< The decoded protocol/NH field */
	uint8_t nbo:1;       /**< The decoded NBO field (IPv4 only) */
	uint8_t rnd:1;       /**< The decoded RND field (IPv4 only) */
	uint8_t sid:1;       /**< The decoded SID field (IPv4 only) */
	uint32_t flowid:20;  /**< The decoded flow ID field (IPv6 only) */
	uint8_t saddr[16];   /**< The decoded source address field */
	uint8_t daddr[16];   /**< The decoded destination address field */
};


/**
 * @brief The values decoded from the bits extracted from ROHC header
 *
 * @see decode_values_from_bits
 * @see rtp_decode_values_from_bits
 */
struct rohc_decoded_values
{
	bool is_context_reused; /**< Whether the context is re-used or not */

	uint32_t sn;  /**< The decoded SN value */

	rohc_mode_t mode;  /**< The operation mode asked by compressor */

	/** The decoded values for the outer IP header */
	struct rohc_decoded_ip_values outer_ip;
	/** The decoded values for the inner IP header */
	struct rohc_decoded_ip_values inner_ip;

	/* bits below are for UDP-based profile only
	   @todo TODO should be moved in d_udp.c */
	uint16_t udp_src;   /**< The decoded UDP source port */
	uint16_t udp_dst;   /**< The decoded UDP destination port bits */
	uint16_t udp_check; /**< The decoded UDP checksum */
	rohc_tristate_t udp_check_present; /**< Whether the UDP checksum field is
	                                        encoded in the ROHC packet or not */

	/* bits below are for UDP-Lite-based profile only
	   @todo TODO should be moved in d_udp_lite.c */
	rohc_packet_cce_t cce_pkt; /**< TODO */
	rohc_tristate_t cfp;       /**< TODO */
	rohc_tristate_t cfi;       /**< TODO */
	uint16_t udp_lite_cc;      /**< The decoded UDP-Lite CC */

	/* bits below are for RTP profile only
	   @todo TODO should be moved in d_rtp.c */
	uint8_t rtp_version:2;  /**< The decoded RTP version */
	uint8_t rtp_p:1;        /**< The decoded RTP Padding (R-P) flag */
	uint8_t rtp_x:1;        /**< The decoded RTP eXtension (R-X) flag */
	uint8_t rtp_cc:4;       /**< The decoded RTP CSRC Count */
	uint8_t rtp_m:1;        /**< The decoded RTP Marker (M) flag */
	uint8_t rtp_pt:7;       /**< The decoded RTP Payload Type (RTP-PT) */
	uint32_t ts;            /**< The decoded RTP TimeStamp (TS) value */
	uint32_t rtp_ssrc;      /**< The decoded SSRC value */

	/* bits below are for ESP profile only
	   @todo TODO should be moved in d_esp.c */
	uint32_t esp_spi;       /**< The decoded ESP SPI */
};


/**
 * @brief Store information about an IP header between the different
 *        decompressions of IP packets.
 *
 * Defines an object that contains flags and structures related to an IP header
 * and that need to be saved between the different decompressions of packets. A
 * decompression context owns objects like this for the two first IP headers.
 */
struct rohc_decomp_rfc3095_changes
{
	/// The IP header
	struct ip_packet ip;

	/// Whether the IP-ID is considered as random or not (IPv4 only)
	int rnd;
	/// Whether the IP-ID is considered as coded in NBO or not (IPv4 only)
	int nbo;
	/// Whether the IP-ID is considered as static or not (IPv4 only)
	int sid;

	/// The next header located after the IP header(s)
	void *next_header;
	/// The length of the next header
	unsigned int next_header_len;
};


/**
 * @brief The generic decompression context for RFC3095-based profiles
 *
 * The object defines the generic context that manages IP(/nextheader) and
 * IP/IP(/nextheader) packets. nextheader is managed by the profile-specific
 * part of the context.
 */
struct rohc_decomp_rfc3095_ctxt
{
	/// Information about the outer IP header
	struct rohc_decomp_rfc3095_changes *outer_ip_changes;
	/// Information about the inner IP header
	struct rohc_decomp_rfc3095_changes *inner_ip_changes;

	/** The LSB shift parameter for the Sequence Number (SN) */
	rohc_lsb_shift_t sn_lsb_p;
	/// The LSB decoding context for the Sequence Number (SN)
	struct rohc_lsb_decode *sn_lsb_ctxt;
	/// The IP-ID of the outer IP header
	struct ip_id_offset_decode *outer_ip_id_offset_ctxt;
	/// The IP-ID of the inner IP header
	struct ip_id_offset_decode *inner_ip_id_offset_ctxt;

	/// The list decompressor of the outer IP header
	struct list_decomp list_decomp1;
	/// The list decompressor of the inner IP header
	struct list_decomp list_decomp2;

	/// Whether the decompressed packet contains a 2nd IP header
	int multiple_ip;

	/* below are some information and handlers to manage the next header
	 * (if any) located just after the IP headers (1 or 2 IP headers) */

	/// The IP protocol ID of the protocol the context is able to decompress
	unsigned short next_header_proto;

	/// The length of the next header
	unsigned int next_header_len;

	/// @brief The handler used to parse the static part of the next header
	///        in the ROHC packet
	int (*parse_static_next_hdr)(const struct rohc_decomp_ctxt *const context,
	                             const uint8_t *packet,
	                             size_t length,
	                             struct rohc_extr_bits *const bits);

	/// @brief The handler used to parse the dynamic part of the next header
	///        in the ROHC packet
	int (*parse_dyn_next_hdr)(const struct rohc_decomp_ctxt *const context,
	                          const uint8_t *packet,
	                          const size_t length,
	                          struct rohc_extr_bits *const bits);

	/**
	 * @brief The handler used to parse the extension 3 of the UO* ROHC packet
	 *
	 * @param context           The decompression context
	 * @param rohc_data         The ROHC data to parse
	 * @param rohc_data_len     The length of the ROHC data to parse
	 * @param packet_type       The type of ROHC packet to parse
	 * @param bits              IN: the bits already found in base header
	 *                          OUT: the bits found in the extension header 3
	 * @return                  The data length read from the ROHC packet,
	 *                          -2 in case packet must be reparsed,
	 *                          -1 in case of error
	 */
	int (*parse_ext3)(const struct rohc_decomp_ctxt *const context,
	                  const uint8_t *const rohc_data,
	                  const size_t rohc_data_len,
	                  const rohc_packet_t packet_type,
	                  struct rohc_extr_bits *const bits)
		__attribute__((warn_unused_result, nonnull(1, 2, 5)));

	/// The handler used to parse the tail of the UO* ROHC packet
	int (*parse_uo_remainder)(const struct rohc_decomp_ctxt *const context,
	                          const uint8_t *packet,
	                          unsigned int length,
	                          struct rohc_extr_bits *const bits);

	/** The handler used to decode extracted for next header */
	bool (*decode_values_from_bits)(const struct rohc_decomp_ctxt *context,
	                                const struct rohc_extr_bits *const bits,
	                                struct rohc_decoded_values *const decoded)
		__attribute__((warn_unused_result, nonnull(1, 2, 3)));

	/** The handler used to build the uncompressed next header */
	int (*build_next_header)(const struct rohc_decomp_ctxt *const context,
	                         const struct rohc_decoded_values *const decoded,
	                         uint8_t *const dest,
	                         const unsigned int payload_len);

	/// @brief The handler used to compute the CRC-STATIC value
	uint8_t (*compute_crc_static)(const uint8_t *const ip,
	                              const uint8_t *const ip2,
	                              const uint8_t *const next_header,
	                              const rohc_crc_type_t crc_type,
	                              const uint8_t init_val,
	                              const uint8_t *const crc_table);

	/// @brief The handler used to compute the CRC-DYNAMIC value
	uint8_t (*compute_crc_dynamic)(const uint8_t *const ip,
	                               const uint8_t *const ip2,
	                               const uint8_t *const next_header,
	                               const rohc_crc_type_t crc_type,
	                               const uint8_t init_val,
	                               const uint8_t *const crc_table);

	/** The handler used to update context with decoded next header fields */
	void (*update_context)(struct rohc_decomp_ctxt *const context,
	                       const struct rohc_decoded_values *const decoded)
		__attribute__((nonnull(1, 2)));

	/// Profile-specific data
	void *specific;
};


/*
 * Public function prototypes.
 */

bool rohc_decomp_rfc3095_create(const struct rohc_decomp_ctxt *const context,
                                struct rohc_decomp_rfc3095_ctxt **const persist_ctxt,
                                struct rohc_decomp_volat_ctxt *const volat_ctxt,
                                rohc_trace_callback2_t trace_cb,
                                void *const trace_cb_priv,
                                const int profile_id)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

void rohc_decomp_rfc3095_destroy(struct rohc_decomp_rfc3095_ctxt *const rfc3095_ctxt,
                                 const struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((nonnull(1, 2)));

bool rfc3095_decomp_parse_pkt(const struct rohc_decomp_ctxt *const context,
                              const struct rohc_buf rohc_packet,
                              const size_t large_cid_len,
                              rohc_packet_t *const packet_type,
                              struct rohc_decomp_crc *const extr_crc,
                              struct rohc_extr_bits *const bits,
                              size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 4, 5, 6, 7)));

rohc_status_t rfc3095_decomp_build_hdrs(const struct rohc_decomp *const decomp,
                                        const struct rohc_decomp_ctxt *const context,
                                        const rohc_packet_t packet_type,
                                        const struct rohc_decomp_crc *const extr_crc,
                                        const struct rohc_decoded_values *const decoded,
                                        const size_t payload_len,
                                        struct rohc_buf *const uncomp_hdrs,
                                        size_t *const uncomp_hdrs_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5, 7, 8)));

bool rfc3095_decomp_decode_bits(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_extr_bits *const bits,
                                const size_t payload_len __attribute__((unused)),
                                struct rohc_decoded_values *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

void rfc3095_decomp_update_ctxt(struct rohc_decomp_ctxt *const context,
                                const struct rohc_decoded_values *const decoded,
                                const size_t payload_len,
                                bool *const do_change_mode)
	__attribute__((nonnull(1, 2, 4)));

bool rfc3095_decomp_attempt_repair(const struct rohc_decomp *const decomp,
                                   const struct rohc_decomp_ctxt *const context,
                                   const struct rohc_ts pkt_arrival_time,
                                   struct rohc_decomp_crc_corr_ctxt *const crc_corr,
                                   struct rohc_extr_bits *const extr_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

uint32_t rohc_decomp_rfc3095_get_sn(const struct rohc_decomp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1)));



/*
 * Helper functions
 */


static inline bool is_ipv4_pkt(const struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, pure, always_inline));

static inline bool is_ipv4_rnd_pkt(const struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, pure, always_inline));

static inline bool is_ipv4_non_rnd_pkt(const struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, pure, always_inline));


/**
 * @brief Is the given IP header IPV4 wrt packet?
 *
 * @param bits  The bits extracted from packet
 * @return      true if IPv4, false if IPv6
 */
static inline bool is_ipv4_pkt(const struct rohc_extr_ip_bits *const bits)
{
	return (bits->version == IPV4);
}


/**
 * @brief Is the given IP header IPv4 and its IP-ID random wrt packet?
 *
 * @param bits  The bits extracted from packet
 * @return      true if IPv4 and random, false otherwise
 */
static inline bool is_ipv4_rnd_pkt(const struct rohc_extr_ip_bits *const bits)
{
	return (is_ipv4_pkt(bits) && bits->rnd == 1);
}


/**
 * @brief Is the given IP header IPv4 and its IP-ID non-random wrt packet?
 *
 * @param bits  The bits extracted from packet
 * @return      true if IPv4 and non-random, false otherwise
 */
static inline bool is_ipv4_non_rnd_pkt(const struct rohc_extr_ip_bits *const bits)
{
	return (is_ipv4_pkt(bits) && bits->rnd == 0);
}


#endif

