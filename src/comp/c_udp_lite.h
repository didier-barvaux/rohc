/**
 * @file c_udp_lite.c
 * @brief ROHC compression context for the UDP-Lite profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef C_UDP_LITE_H
#define C_UDP_LITE_H

#include <netinet/udp.h>

#include "rohc_comp.h"
#include "c_generic.h"
#include "c_udp.h"


#ifndef IPPROTO_UDPLITE
/// define UDP-Lite protocol number if not defined by the system
#define IPPROTO_UDPLITE  136
#warning "UDP-Lite not defined on the system, define the protocol number"
#endif

/// @brief The maximal number of times the checksum coverage dit not change
///        or may be inferred
#define MAX_LITE_COUNT 2


/**
 * @brief Define the UDP-Lite-specific temporary variables in the profile
 *        compression context.
 *
 * This object must be used by the UDP-specific compression context
 * sc_udp_lite_context.
 *
 * @see sc_udp_lite_context
 */
struct udp_lite_tmp_variables
{
	/// The size of the UDP-Lite packet (header + payload)
	int udp_size;
};


/**
 * @brief Define the UDP-Lite part of the profile compression context.
 *
 * This object must be used with the generic part of the compression
 * context c_generic_context.
 *
 * @see c_generic_context
 */
struct sc_udp_lite_context
{
	/// Whether the Coverage Field is Present or not
	int cfp;
	/// Whether the Coverage Field is Inferred or not
	int cfi;

	/// The F and K bits in the CCE packet (see appendix B in the RFC 4019)
	unsigned char FK;

	/// The number of times the checksum coverage field did not change
	int coverage_equal_count;
	/// The number of times the checksum coverage field may be inferred
	int coverage_inferred_count;
	/// Temporary variables related to the checksum coverage field
	int tmp_coverage;

	/// The number of CCE() packets sent by the compressor
	int sent_cce_only_count;
	/// The number of CCE(ON) packets sent by the compressor
	int sent_cce_on_count;
	 /// The number of CCE(OFF) packets sent by the compressor
	int sent_cce_off_count;

	/// The previous UDP-Lite header
	struct udphdr old_udp_lite;

	/// @brief UDP-Lite-specific temporary variables that are used during one
	///        single compression of packet
	struct udp_lite_tmp_variables tmp_variables;
};


#endif

