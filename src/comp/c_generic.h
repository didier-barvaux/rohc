/**
 * @file c_generic.h
 * @brief ROHC generic compression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_GENERIC_H
#define C_GENERIC_H

#include <netinet/ip.h>
#include <string.h>

#include "rohc_comp.h"


/**
 * @brief The maximal delta accepted between two consecutive IPv4 ID so that it
 *        can be considered as coded in Network Byte Order (NBO)
 */
#define IPID_MAX_DELTA  20


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
	struct iphdr old_ip;

	/// The number of times the DF field was added to the compressed header
	int df_count;
	/// @brief The number of times the IP-ID is specified as random in the
	///        compressed header
	int rnd_count;
	/// @brief The number of times the IP-ID is specified as coded in Network
	///        Byte Order (NBO) in the compressed header
	int nbo_count;

	/// Whether the IP-ID is considered as random or not
	int rnd;
	/// Whether the IP-ID is considered as coded in NBO or not
	int nbo;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        random or not
	int old_rnd;
	/// @brief Whether the IP-ID of the previous IP header was considered as
	///        coded in NBO or not
	int old_nbo;

	/// The delta between the IP-ID and the current Sequence Number (SN)
	int id_delta;
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
	struct ip6_hdr old_ip;
};


/**
 * @brief Store information about an IP (IPv4 or IPv6) header between the
 *        different compressions of IP packets.
 */
struct ip_header_info
{
	ip_version  version;           ///< The version of the IP header

	/// The number of times the TOS/TC field was added to the compressed header
	int tos_count;
	/// The number of times the TTL/HL field was added to the compressed header
	int ttl_count;
	/// @brief The number of times the Protocol/Next Header field was added to
	///        the compressed header
	int protocol_count;

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
struct generic_tmp_variables
{
	/// The number of IP headers in the packet to compress (1 or 2 only)
	int nr_of_ip_hdr;

	/// The number of fields that changed in the outer IP header
	unsigned short changed_fields;
	/// The number of fields that changed in the inner IP header
	unsigned short changed_fields2;
	/// The number of static fields that changed in the two IP headers
	int send_static;
	/// The number of dynamic fields that changed in the two IP headers
	int send_dynamic;

	/// The number of bits needed to encode the Sequence Number (SN)
	int nr_sn_bits;
	/// The number of bits needed to encode the IP-ID of the outer IP header
	int nr_ip_id_bits;
	/// The number of bits needed to encode the IP-ID of the inner IP header
	int nr_ip_id_bits2;

	/// The type of packet the compressor must send: IR, IR-DYN, UO*
	int packet_type;

	/// The maximal size of the compressed packet
	int max_size;
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
	/// The Sequence Number (SN)
	unsigned int sn;
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
	int go_back_fo_count;
	/// @brief The number of packet sent while in FO or SO state, used for the
	///        periodic refreshes of the context
	/// @see periodic_down_transition
	int go_back_ir_count;
	/// @brief The minimal number of IR-DYN packets the compressor must sent
	///        before sending UO* packets
	int ir_dyn_count;

	/// Information about the outer IP header
	struct ip_header_info ip_flags;
	/// Information about the inner IP header
	struct ip_header_info ip2_flags;
	/// Whether the ip2_flags object is initialized or not
	int is_ip2_initialized;

	/// Temporary variables that are used during one single compression of packet
	struct generic_tmp_variables tmp_variables;

	/* below are some information and handlers to manage the next header
	 * (if any) located just after the IP headers (1 or 2 IP headers) */

	/// The protocol number registered by IANA for the next header protocol
	unsigned int next_header_proto;
	/// The length of the next header
	unsigned int next_header_len;

	/// @brief The handler used to decide the state that should be used for the
	///        next packet
	void (*decide_state)(struct c_context *context);

	/// The handler used to initialize some data just before the IR packet build
	void (*init_at_IR)(struct c_context *context,
	                   const unsigned char *next_header);

	/// @brief The handler used to add the static part of the next header to the
	///        ROHC packet
	int (*code_static_part)(struct c_context *context,
	                        const unsigned char *next_header,
	                        unsigned char *dest, int counter);

	/// @brief The handler used to add the dynamic part of the next header to the
	///        ROHC pachet
	int (*code_dynamic_part)(struct c_context *context,
	                         const unsigned char *next_header,
	                         unsigned char *dest, int counter);

	/// @brief The handler used to add an additional header in the head of the
	///        UO-0, UO-1 and UO-2 packets
	int (*code_UO_packet_head)(struct c_context *context,
	                           const unsigned char *next_header,
	                           unsigned char *dest, int counter,
	                           int *first_position);

	/// @brief The handler used to add an additional header in the tail of the
	///        UO-0, UO-1 and UO-2 packets
	int (*code_UO_packet_tail)(struct c_context *context,
	                           const unsigned char *next_header,
	                           unsigned char *dest, int counter);

	/// Profile-specific data	
	void *specific;
};


/*
 * Function prototypes.
 */

int c_generic_create(struct c_context *context, const struct ip_packet ip);
void c_generic_destroy(struct c_context *context);

void change_mode(struct c_context *context, rohc_mode new_mode);
void change_state(struct c_context *context, rohc_c_state new_state);

int c_generic_encode(struct c_context *context,
                     const struct ip_packet ip,
                     int packet_size,
                     unsigned char *dest,
                     int dest_size,
                     int *payload_offset);

void c_generic_feedback(struct c_context *context, struct c_feedback *feedback);

void decide_state(struct c_context *context);


#endif

