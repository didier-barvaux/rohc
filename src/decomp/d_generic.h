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
#include "rohc_decomp_internals.h"
#include "rohc_packets.h"
#include "comp_list.h"
#include "lsb_decode.h"
#include "ip_id_offset_decode.h"
#include "ip.h"
#include "crc.h"

#include <stddef.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif


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
	rohc_lsb_ref_t sn_ref_type; /**< The SN reference to use for LSB decoding
	                                 (used for context repair after CRC failure) */
	bool sn_ref_offset;         /**< Optional offset to add to the reference SN
	                                 (used for context repair after CRC failure) */

	/** bits related to outer IP header */
	struct rohc_extr_ip_bits outer_ip;

	/** bits related to inner IP header */
	struct rohc_extr_ip_bits inner_ip;

	/* CRC */
	rohc_crc_type_t crc_type; /**< The type of CRC that protect the ROHC header */
	uint8_t crc;              /**< The CRC bits found in ROHC header */
	size_t crc_nr;            /**< The number of CRC bits found in ROHC header */

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
 * @see decode_uo0
 * @see decode_uo1
 * @see decode_uor2
 * @see decode_values_from_bits
 * @see rtp_decode_values_from_bits
 */
struct rohc_decoded_values
{
	uint32_t sn;  /**< The decoded SN value */

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
struct d_generic_changes
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
	unsigned char *next_header;
	/// The length of the next header
	unsigned int next_header_len;
};


/**
 * @brief The different correction algorithms available in case of CRC failure
 */
typedef enum
{
	ROHC_DECOMP_CRC_CORR_SN_NONE    = 0, /**< No correction */
	ROHC_DECOMP_CRC_CORR_SN_WRAP    = 1, /**< Correction of SN wraparound */
	ROHC_DECOMP_CRC_CORR_SN_UPDATES = 2, /**< Correction of incorrect SN updates */

} rohc_decomp_crc_corr_t;


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
	struct ip_id_offset_decode *outer_ip_id_offset_ctxt;
	/// The IP-ID of the inner IP header
	struct ip_id_offset_decode *inner_ip_id_offset_ctxt;

	/// The list decompressor of the outer IP header
	struct list_decomp *list_decomp1;
	/// The list decompressor of the inner IP header
	struct list_decomp *list_decomp2;

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
	int (*parse_static_next_hdr)(const struct d_context *const context,
	                             const unsigned char *packet,
	                             size_t length,
	                             struct rohc_extr_bits *const bits);

	/// @brief The handler used to parse the dynamic part of the next header
	///        in the ROHC packet
	int (*parse_dyn_next_hdr)(const struct d_context *const context,
	                          const uint8_t *packet,
	                          const size_t length,
	                          struct rohc_extr_bits *const bits);

	/**
	 * @brief The handler used to parse the extension 3 of the UO* ROHC packet
	 *
	 * @param decomp            The ROHC decompressor
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
	int (*parse_extension3)(const struct rohc_decomp *const decomp,
	                        const struct d_context *const context,
	                        const unsigned char *const rohc_data,
	                        const size_t rohc_data_len,
	                        const rohc_packet_t packet_type,
	                        struct rohc_extr_bits *const bits)
		__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));

	/// The handler used to parse the tail of the UO* ROHC packet
	int (*parse_uo_remainder)(const struct d_context *const context,
	                          const unsigned char *packet,
	                          unsigned int length,
	                          struct rohc_extr_bits *const bits);

	/** The handler used to decode extracted for next header */
	bool (*decode_values_from_bits)(const struct d_context *context,
	                                const struct rohc_extr_bits bits,
	                                struct rohc_decoded_values *const decoded);

	/** The handler used to build the uncompressed next header */
	int (*build_next_header)(const struct d_context *const context,
	                         const struct rohc_decoded_values decoded,
	                         unsigned char *dest,
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
	void (*update_context)(const struct d_context *context,
	                       const struct rohc_decoded_values decoded);

	/// Profile-specific data
	void *specific;


	/*
	 * for correction upon CRC failure
	 */

	/** The algorithm being used for correction CRC failure */
	rohc_decomp_crc_corr_t crc_corr;
	/** Correction counter (see e and f in 5.3.2.2.4 of the RFC 3095) */
	size_t correction_counter;
/** The number of last packets to record arrival times for */
#define ROHC_MAX_ARRIVAL_TIMES  10U
	/** The arrival times for the last packets */
	struct timespec arrival_times[ROHC_MAX_ARRIVAL_TIMES];
	/** The number of arrival times in arrival_times */
	size_t arrival_times_nr;
	/** The index for the arrival time of the next packet */
	size_t arrival_times_index;
	/** The arrival time of the current packet */
	struct timespec cur_arrival_time;
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


	/* Functions for handling the data to decompress */

	/// The handler used to free the based table
	void (*free_table)(struct list_decomp *decomp);
	/// The handler used to add the extension to IP packet
	size_t (*encode_extension)(const struct list_decomp *const decomp,
	                           const uint8_t ip_nh_type,
	                           unsigned char *const dest);
	/// The handler used to check if the index
	/// corresponds to an existing item
	bool(*check_index)(const struct list_decomp *const decomp,
	                   const int index);
	/// The handler used to create the item at
	/// the corresponding index of the based table
	bool (*create_item)(const unsigned char *const data,
	                    const size_t length,
	                    const int index,
	                    struct list_decomp *const decomp);
	/// The handler used to get the size of an extension
	int (*get_ext_size)(const unsigned char *data, const size_t data_len);


	/* Traces */

	/** The callback function used to manage traces */
	rohc_trace_callback_t trace_callback;
	/** The profile ID the decompression list was created for */
	int profile_id;
};


/*
 * Public function prototypes.
 */

void * d_generic_create(const struct d_context *const context,
                        rohc_trace_callback_t trace_callback,
                        const int profile_id)
	__attribute__((nonnull(1, 2), warn_unused_result));

void d_generic_destroy(void *const context)
	__attribute__((nonnull(1)));

int d_generic_decode(struct rohc_decomp *const decomp,
                     struct d_context *const context,
                     const struct timespec arrival_time,
                     const unsigned char *const rohc_packet,
                     const size_t rohc_length,
                     const size_t add_cid_len,
                     const size_t large_cid_len,
                     unsigned char *uncomp_packet,
                     rohc_packet_t *const packet_type);

uint32_t d_generic_get_sn(const struct d_context *const context);



/*
 * Helper functions
 */


static inline bool is_ipv4_pkt(const struct rohc_extr_ip_bits bits)
	__attribute__((warn_unused_result, const));

static inline bool is_ipv4_rnd_pkt(const struct rohc_extr_ip_bits bits)
	__attribute__((warn_unused_result, const));

static inline bool is_ipv4_non_rnd_pkt(const struct rohc_extr_ip_bits bits)
	__attribute__((warn_unused_result, const));


/**
 * @brief Is the given IP header IPV4 wrt packet?
 *
 * @param bits  The bits extracted from packet
 * @return      true if IPv4, false if IPv6
 */
static inline bool is_ipv4_pkt(const struct rohc_extr_ip_bits bits)
{
	return (bits.version == IPV4);
}


/**
 * @brief Is the given IP header IPv4 and its IP-ID random wrt packet?
 *
 * @param bits  The bits extracted from packet
 * @return      true if IPv4 and random, false otherwise
 */
static inline bool is_ipv4_rnd_pkt(const struct rohc_extr_ip_bits bits)
{
	return (is_ipv4_pkt(bits) && bits.rnd == 1);
}


/**
 * @brief Is the given IP header IPv4 and its IP-ID non-random wrt packet?
 *
 * @param bits  The bits extracted from packet
 * @return      true if IPv4 and non-random, false otherwise
 */
static inline bool is_ipv4_non_rnd_pkt(const struct rohc_extr_ip_bits bits)
{
	return (is_ipv4_pkt(bits) && bits.rnd == 0);
}


#endif

