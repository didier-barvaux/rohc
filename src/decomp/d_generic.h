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
 * @file d_generic.h
 * @brief ROHC generic decompression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 */

#ifndef D_GENERIC_H
#define D_GENERIC_H

#include "rohc_decomp.h"
#include "rohc_packets.h"
#include "comp_list.h"
#include "lsb_decode.h"
#include "ip_id.h"
#include "ip.h"

#include <stddef.h>
#include <stdbool.h>


#define MAX_ITEM 15
#if MAX_ITEM <= 7
	#error "translation table must be larger enough for indexes stored on 3 bits"
#endif

#define LIST_COMP_WINDOW 100

#define L 5


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
	/* SN */
	uint16_t sn;            /**< The SN bits found in ROHC header */
	size_t sn_nr;           /**< The number of SN bits found in ROHC header */

	/** bits related to outer IP header */
	struct rohc_extr_ip_bits outer_ip;

	/** bits related to inner IP header */
	struct rohc_extr_ip_bits inner_ip;

	/* CRC */
	uint8_t crc;            /**< The CRC bits found in ROHC header */
	size_t crc_nr;          /**< The number of CRC bits found in ROHC header */

	/* X (extension) flag */
	uint8_t ext_flag:1;     /**< X (extension) flag */


	/* bits below are for UDP-based profiles only
	   @todo TODO should be moved in d_udp.c */

	uint16_t udp_src;     /**< The UDP source port bits found in static chain
	                           of IR header */
	size_t udp_src_nr;    /**< The number of UDP source port bits */

	uint16_t udp_dst;     /**< The UDP destination port bits in static chain
	                           of IR header */
	size_t udp_dst_nr;    /**< The number of UDP destination port bits */

	uint16_t udp_check;   /**< The UDP checksum bits found in dynamic chain
	                           of IR/IR-DYN header or in remainder of UO*
	                           header */
	size_t udp_check_nr;  /**< The number of UDP checksum bits */


	/* bits below are for UDP-Lite-based profiles only
	   @todo TODO should be moved in d_udp_lite.c */

	uint16_t udp_lite_cc;     /**< The UDP-Lite CC bits found in dynamic
	                               chain of IR/IR-DYN header or in remainder
	                               of UO* header */
	size_t udp_lite_cc_nr;    /**< The number of UDP-Lite CC bits */


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
	uint32_t flowid:20;  /**< The decoded flow ID field (IPv6 only) */
	uint8_t saddr[16];   /**< The decoded source address field */
	uint8_t daddr[16];   /**< The decoded destination address field */
};


/**
 * @brief The values decoded from the bits extracted from ROHC header
 *
 * @see decode_uo0
 * @see decode_uo1
 * @see decode_uor2
 * @see decode_values_from_bits
 * @see rtp_decode_values_from_bits
 */
struct rohc_decoded_values
{
	uint16_t sn;  /**< The decoded SN value */

	/** The decoded values for the outer IP header */
	struct rohc_decoded_ip_values outer_ip;
	/** The decoded values for the inner IP header */
	struct rohc_decoded_ip_values inner_ip;

	/* bits below are for UDP-based profile only
	   @todo TODO should be moved in d_udp.c */
	uint16_t udp_src;   /**< The decoded UDP source port */
	uint16_t udp_dst;   /**< The decoded UDP destination port bits */
	uint16_t udp_check; /**< The decoded UDP checksum */

	/* bits below are for UDP-Lite-based profile only
	   @todo TODO should be moved in d_udp_lite.c */
	uint16_t udp_lite_cc;   /**< The decoded UDP-Lite CC */

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
};


/**
 * @brief Store information about an IP header between the different
 *        decompressions of IP packets.
 *
 * Defines an object that contains flags and structures related to an IP header
 * and that need to be saved between the different decompressions of packets. A
 * decompression context owns objects like this for the two first IP headers.
 */
struct d_generic_changes
{
	/// The IP header
	struct ip_packet ip;

	/// Whether the IP-ID is considered as random or not (IPv4 only)
	int rnd;
	/// Whether the IP-ID is considered as coded in NBO or not (IPv4 only)
	int nbo;

	/// The next header located after the IP header(s)
	unsigned char *next_header;
	/// The length of the next header
	unsigned int next_header_len;
};


/**
 * @brief The generic decompression context
 *
 * The object defines the generic context that manages IP(/nextheader) and
 * IP/IP(/nextheader) packets. nextheader is managed by the profile-specific
 * part of the context.
 */
struct d_generic_context
{
	/// Information about the outer IP header
	struct d_generic_changes *outer_ip_changes;
	/// Information about the inner IP header
	struct d_generic_changes *inner_ip_changes;

	/// The LSB decoding context for the Sequence Number (SN)
	struct rohc_lsb_decode *sn_lsb_ctxt;
	/// The IP-ID of the outer IP header
	struct d_ip_id_decode ip_id1;
	/// The IP-ID of the inner IP header
	struct d_ip_id_decode ip_id2;

	/// The list decompressor of the outer IP header
	struct list_decomp *list_decomp1;
	/// The list decompressor of the inner IP header
	struct list_decomp *list_decomp2;

	/// Whether the decompressed packet contains a 2nd IP header
	int multiple_ip;

	/// The type of packet the decompressor may receive: IR, IR-DYN, UO*
	rohc_packet_t packet_type;

	/* below are some information and handlers to manage the next header
	 * (if any) located just after the IP headers (1 or 2 IP headers) */

	/// The IP protocol ID of the protocol the context is able to decompress
	unsigned short next_header_proto;

	/// The length of the next header
	unsigned int next_header_len;

	/// @brief The handler used to parse the static part of the next header
	///        in the ROHC packet
	int (*parse_static_next_hdr)(struct d_generic_context *context,
	                             const unsigned char *packet,
	                             unsigned int length,
	                             struct rohc_extr_bits *const bits);

	/// @brief The handler used to parse the dynamic part of the next header
	///        in the ROHC packet
	int (*parse_dyn_next_hdr)(struct d_generic_context *context,
	                          const unsigned char *packet,
	                          unsigned int length,
	                          struct rohc_extr_bits *const bits);

	/// The handler used to parse the tail of the UO* ROHC packet
	int (*parse_uo_tail)(struct d_generic_context *context,
	                     const unsigned char *packet,
	                     unsigned int length,
	                     struct rohc_extr_bits *const bits);

	/** The handler used to decoded bits extracted from ROHC headers */
	bool (*decode_values_from_bits)(const struct d_context *context,
	                                const struct rohc_extr_bits bits,
	                                struct rohc_decoded_values *const decoded);

	/** The handler used to build the uncompressed next header */
	int (*build_next_header)(const struct d_generic_context *const context,
	                         const struct rohc_decoded_values decoded,
	                         unsigned char *dest,
	                         const unsigned int payload_len);


	/// @brief The handler used to compute the CRC-STATIC value
	unsigned int (*compute_crc_static)(const unsigned char *const ip,
	                                   const unsigned char *const ip2,
	                                   const unsigned char *const next_header,
	                                   const unsigned int crc_type,
	                                   const unsigned int init_val,
	                                   const unsigned char *const crc_table);

	/// @brief The handler used to compute the CRC-DYNAMIC value
	unsigned int (*compute_crc_dynamic)(const unsigned char *const ip,
	                                    const unsigned char *const ip2,
	                                    const unsigned char *const next_header,
	                                    const unsigned int crc_type,
	                                    const unsigned int init_val,
	                                    const unsigned char *const crc_table);

	/// Profile-specific data
	void *specific;

	/// Correction counter (see e and f in 5.3.2.2.4 of the RFC 3095)
	unsigned int correction_counter;

	/// The timestamp of the last CRC-approved packet
	unsigned int last_packet_time;
	/// The timestamp of the current packet (not yet CRC-tested)
	unsigned int current_packet_time;
	/// The average inter-packet time over the last few packets
	unsigned int inter_arrival_time;
};


/**
 * @brief The list decompressor
 */
struct list_decomp
{
	/// The reference list
	struct c_list *ref_list;
	/// The table of lists
	struct c_list *list_table[LIST_COMP_WINDOW];
	/// The compression based table
	struct rohc_list_item based_table[MAX_ITEM];
	/// The translation table
	struct d_translation trans_table[MAX_ITEM];
	/// counter in list table
	int counter_list;
	/// counter which indicates if the list is reference list
	int counter;
	/// boolean which indicates if there is a list to decompress
	bool is_present;
	/// boolean which indicates if the ref list must be decompressed
	int ref_ok;

	/// The handler used to free the based table
	void (*free_table)(struct list_decomp *decomp);
	/// The handler used to add the extension to IP packet
	int (*encode_extension)(struct list_decomp *const decomp,
	                        const uint8_t ip_nh_type,
	                        unsigned char *dest);
	/// The handler used to check if the index
	/// corresponds to an existing item
	int (*check_index)(struct list_decomp *decomp, int index);
	/// The handler used to create the item at
	/// the corresponding index of the based table
	bool (*create_item)(const unsigned char *data,
	                    int length,
	                    int index,
	                    struct list_decomp *decomp);
	/// The handler used to get the size of an extension
	int (*get_ext_size)(const unsigned char *data, const size_t data_len);
};


/*
 * Public function prototypes.
 */

void * d_generic_create(void);

void d_generic_destroy(void *context);

int d_generic_decode(struct rohc_decomp *decomp,
                     struct d_context *context,
                     const unsigned char *const rohc_packet,
                     const unsigned int rohc_length,
                     const size_t add_cid_len,
                     const size_t large_cid_len,
                     unsigned char *dest);

int d_generic_decode_ir(struct rohc_decomp *decomp,
                        struct d_context *context,
                        const unsigned char *const rohc_packet,
                        const unsigned int rohc_length,
                        int large_cid_len,
                        int is_addcid_used,
                        unsigned char *dest);

int d_generic_get_sn(struct d_context *context);

rohc_packet_t find_packet_type(struct rohc_decomp *decomp,
                               struct d_context *context,
                               const unsigned char *packet,
                               const size_t rohc_length,
                               const size_t large_cid_len);

#endif

