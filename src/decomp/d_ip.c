/**
 * @file d_ip.c
 * @brief ROHC decompression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "d_ip.h"


/**
 * @brief Define the decompression part of the IP-only profile as described
 *        in the RFC 3843.
 */
struct d_profile d_ip_profile =
{
	ROHC_PROFILE_IP,              /* profile ID (see 5 in RFC 3843) */
	"1.0",                        /* profile version */
	"IP / Decompressor",          /* profile description */
	d_generic_decode,             /* profile handlers */
	d_generic_decode_ir,
	d_generic_create,
	d_generic_destroy,
	d_generic_detect_ir_size,
	d_generic_detect_ir_dyn_size,
	d_generic_get_sn,
};

