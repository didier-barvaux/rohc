/**
 * @file d_rtp.h
 * @brief ROHC decompression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef D_RTP_H
#define D_RTP_H

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>

#include "d_generic.h"
#include "d_udp.h"
#include "ts_sc_decomp.h"


/**
 * @brief Define the RTP part of the decompression profile context.
 * 
 * This object must be used with the generic part of the decompression
 * context d_generic_context.
 *
 * @see d_generic_context
 */
struct d_rtp_context
{
	/// Whether the UDP checksum field is encoded in the ROHC packet or not
	int udp_checksum_present;

	/// The LSB-encoded Timestamp
	struct d_lsb_decode ts;

	/// Timestamp
	unsigned int timestamp;

	/// The field received to decode TS
	int ts_received;

	/// The size of the field received to decode TS
	int ts_received_size;

	/// Padding field
	int rp;

	/// Extension field
	int rx;

	/// Payload Type field
	int pt;

	/// RTP Marker
	int m;

	/// The structure to decompress TS_SRIDE
	struct ts_sc_decomp ts_sc;
};


/*
 * Public function prototypes.
 */

unsigned int rtp_detect_ir_size(struct d_context *context,
				unsigned char *packet,
                                unsigned int plen,
                                int second_byte,
                                int profile_id);

unsigned int rtp_detect_ir_dyn_size(unsigned char *first_byte,
                                    unsigned int plen,
                                    int largecid,
                                    struct d_context *context,
				    unsigned char *packet);

int rtp_decode_static_rtp(struct d_generic_context *context,
                          const unsigned char *packet,
                          unsigned int length,
                          unsigned char *dest);

int rtp_decode_dynamic_rtp(struct d_generic_context *context,
                           const unsigned char *packet,
                           unsigned int length,
                           unsigned char *dest);

int rtp_build_uncompressed_rtp(struct d_generic_context *context,
                               struct d_generic_changes *active,
                               unsigned char *dest,
                               int payload_size);
int rtp_get_static_part(void);

#endif

