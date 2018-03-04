/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013 Viveris Technologies
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
 * @file d_uncompressed.c
 * @brief ROHC decompression context for the uncompressed profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_decomp.h"
#include "rohc_decomp_internals.h"
#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "crc.h"
#include "rohc_decomp_detect_packet.h" /* for rohc_decomp_packet_is_ir() */

#include <string.h>


/*
 * Private structures
 */

/** The bits extracted for Uncompressed decompression profile */
struct rohc_uncomp_extr_bits
{
	bool first_byte_used;  /**< Whether the first byte is saved or not */
	uint8_t first_byte;    /**< The first payload byte */
};


/** The decoded values for the Uncompressed decompression profile */
struct rohc_uncomp_decoded
{
	bool first_byte_used;  /**< Whether the first byte is saved or not */
	uint8_t first_byte;    /**< The first payload byte */
};


/*
 * Prototypes of private functions
 */

static bool uncomp_new_context(const struct rohc_decomp_ctxt *const context,
                               void **const persist_ctxt,
                               struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static void uncomp_free_context(void *const persist_ctxt,
                                const struct rohc_decomp_volat_ctxt *const volat_ctxt)
	__attribute__((nonnull(2)));

static rohc_packet_t uncomp_detect_pkt_type(const struct rohc_decomp_ctxt *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool uncomp_parse_pkt(const struct rohc_decomp_ctxt *const context,
                             const struct rohc_buf rohc_packet,
                             const size_t large_cid_len,
                             rohc_packet_t *const packet_type,
                             struct rohc_decomp_crc *const extr_crc,
                             struct rohc_uncomp_extr_bits *const extr_bits,
                             size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 4, 5, 6, 7)));

static bool uncomp_parse_ir(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_buf rohc_packet,
                            const size_t large_cid_len,
                            struct rohc_decomp_crc *const extr_crc,
                            struct rohc_uncomp_extr_bits *const extr_bits,
                            size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 4, 5, 6)));

static bool uncomp_parse_normal(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_buf rohc_packet,
                                const size_t large_cid_len,
                                struct rohc_decomp_crc *const extr_crc,
                                struct rohc_uncomp_extr_bits *const extr_bits,
                                size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 4, 5, 6)));

static rohc_status_t uncomp_decode_bits(const struct rohc_decomp_ctxt *const context,
                                        const struct rohc_uncomp_extr_bits *const extr_bits,
                                        const size_t payload_len,
                                        struct rohc_uncomp_decoded *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static rohc_status_t uncomp_build_hdrs(const struct rohc_decomp *const decomp,
                                       const struct rohc_decomp_ctxt *const context,
                                       const rohc_packet_t packet_type,
                                       const struct rohc_decomp_crc *const extr_crc,
                                       const struct rohc_uncomp_decoded *const decoded,
                                       const size_t payload_len,
                                       struct rohc_buf *const uncomp_hdrs,
                                       size_t *const uncomp_hdrs_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5, 7, 8)));

static void uncomp_update_ctxt(struct rohc_decomp_ctxt *const context,
                               const struct rohc_uncomp_decoded *const decoded,
                               const size_t payload_len,
                               bool *const do_change_mode)
	__attribute__((nonnull(1, 2, 4)));

static bool uncomp_attempt_repair(const struct rohc_decomp *const decomp,
                                  const struct rohc_decomp_ctxt *const context,
                                  const struct rohc_ts pkt_arrival_time,
                                  struct rohc_decomp_crc_corr_ctxt *const crc_corr,
                                  struct rohc_uncomp_extr_bits *const extr_bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

static uint32_t uncomp_get_sn(const struct rohc_decomp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1), pure));


/*
 * Definitions of private functions
 */

/**
 * @brief Create the Uncompressed volatile and persistent parts of the context
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context            The decompression context
 * @param[out] persist_ctxt  The persistent part of the decompression context
 * @param[out] volat_ctxt    The volatile part of the decompression context
 * @return                   true if the Uncompressed context was successfully
 *                           created, false if a problem occurred
 */
static bool uncomp_new_context(const struct rohc_decomp_ctxt *const context,
                               void **const persist_ctxt,
                               struct rohc_decomp_volat_ctxt *const volat_ctxt)
{
	assert(context->profile->id == ROHC_PROFILE_UNCOMPRESSED);

	/* persistent part */
	*persist_ctxt = NULL;

	/* volatile part */
	volat_ctxt->crc.type = ROHC_CRC_TYPE_NONE;
	volat_ctxt->crc.bits_nr = 0;
	volat_ctxt->extr_bits = malloc(sizeof(struct rohc_uncomp_extr_bits));
	if(volat_ctxt->extr_bits == NULL)
	{
		rohc_decomp_warn(context, "failed to allocate memory for the volatile part "
		                 "of the Uncompressed decompression profile");
		goto error;
	}
	volat_ctxt->decoded_values = malloc(sizeof(struct rohc_uncomp_decoded));
	if(volat_ctxt->decoded_values == NULL)
	{
		rohc_decomp_warn(context, "failed to allocate memory for the volatile part "
		                 "of the Uncompressed decompression profile");
		goto free_extr_bits;
	}

	return true;

free_extr_bits:
	free(volat_ctxt->extr_bits);
error:
	return false;
}


/**
 * @brief Destroy profile-specific data, nothing to destroy for the
 *        uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param persist_ctxt  The persistent part of the decompression context
 * @param volat_ctxt    The volatile part of the decompression context
 */
static void uncomp_free_context(void *const persist_ctxt,
                                const struct rohc_decomp_volat_ctxt *const volat_ctxt)
{
	assert(persist_ctxt == NULL);
	free(volat_ctxt->extr_bits);
	free(volat_ctxt->decoded_values);
}


/**
 * @brief Detect the type of ROHC packet for the Uncompressed profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
static rohc_packet_t uncomp_detect_pkt_type(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len __attribute__((unused)))
{
	rohc_packet_t type;

	if(rohc_decomp_packet_is_ir(rohc_packet, rohc_length))
	{
		type = ROHC_PACKET_IR;
	}
	else
	{
		type = ROHC_PACKET_NORMAL;
	}

	return type;
}


/**
 * @brief Parse one IR or Normal packet for the Uncompressed profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context              The decompression context
 * @param rohc_packet          The ROHC packet to parse
 * @param large_cid_len        The length of the optional large CID field
 * @param[in,out] packet_type  IN:  The type of the ROHC packet to parse
 *                             OUT: The type of the parsed ROHC packet
 * @param[out] extr_crc        The CRC bits extracted from the ROHC packet
 * @param[out] extr_bits       The bits extracted from the ROHC packet
 * @param[out] rohc_hdr_len    The length of the ROHC header (in bytes)
 * @return                     true if parsing was successful,
 *                             false if packet was malformed
 */
static bool uncomp_parse_pkt(const struct rohc_decomp_ctxt *const context,
                             const struct rohc_buf rohc_packet,
                             const size_t large_cid_len,
                             rohc_packet_t *const packet_type,
                             struct rohc_decomp_crc *const extr_crc,
                             struct rohc_uncomp_extr_bits *const extr_bits,
                             size_t *const rohc_hdr_len)
{
	bool status;

	if((*packet_type) == ROHC_PACKET_IR)
	{
		status = uncomp_parse_ir(context, rohc_packet, large_cid_len,
		                         extr_crc, extr_bits, rohc_hdr_len);
	}
	else if((*packet_type) == ROHC_PACKET_NORMAL)
	{
		status = uncomp_parse_normal(context, rohc_packet, large_cid_len,
		                             extr_crc, extr_bits, rohc_hdr_len);
	}
	else
	{
		rohc_decomp_warn(context, "unsupported ROHC packet type %u", (*packet_type));
		status = false;
	}

	return status;
}


/**
 * @brief Parse one IR packet for the Uncompressed profile
 *
 * @param context            The decompression context
 * @param rohc_packet        The ROHC packet to decode
 * @param large_cid_len      The length of the optional large CID field
 * @param[out] extr_crc      The CRC extracted from the ROHC packet
 * @param[out] extr_bits     The bits extracted from the ROHC packet
 * @param[out] rohc_hdr_len  The length of the ROHC header (in bytes)
 * @return                   true if parsing was successful,
 *                           false if packet was malformed
 */
static bool uncomp_parse_ir(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_buf rohc_packet,
                            const size_t large_cid_len,
                            struct rohc_decomp_crc *const extr_crc,
                            struct rohc_uncomp_extr_bits *const extr_bits,
                            size_t *const rohc_hdr_len)
{
	struct rohc_buf rohc_remain_data = rohc_packet;

	(*rohc_hdr_len) = 0;

	/* IR packet does not need to save its first byte into the volatile part
	 * of the context */
	extr_bits->first_byte_used = false;

	/* packet must large enough for:
	 * IR type + (large CID + ) Profile ID + CRC */
	if(rohc_remain_data.len < (1 + large_cid_len + 2))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu bytes)",
		                 rohc_remain_data.len);
		goto error;
	}

	/* skip the IR type, optional large CID bytes, and Profile ID */
	rohc_buf_pull(&rohc_remain_data, large_cid_len + 2);
	(*rohc_hdr_len) += large_cid_len + 2;

	/* parse CRC */
	extr_crc->type = ROHC_CRC_TYPE_NONE;
	extr_crc->bits = GET_BIT_0_7(rohc_buf_data(rohc_remain_data));
	extr_crc->bits_nr = 8;
	rohc_decomp_debug(context, "CRC-8 found in packet = 0x%02x", extr_crc->bits);
	rohc_buf_pull(&rohc_remain_data, 1);
	(*rohc_hdr_len)++;

	return true;

error:
	return false;
}


/**
 * @brief Parse one Normal packet for the Uncompressed profile
 *
 * @param context            The decompression context
 * @param rohc_packet        The ROHC packet to decode
 * @param large_cid_len      The length of the optional large CID field
 * @param[out] extr_crc      The CRC extracted from the ROHC packet
 * @param[out] extr_bits     The bits extracted from the ROHC packet
 * @param[out] rohc_hdr_len  The length of the ROHC header (in bytes)
 * @return                   true if parsing was successful,
 *                           false if packet was malformed
 */
static bool uncomp_parse_normal(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_buf rohc_packet,
                                const size_t large_cid_len,
                                struct rohc_decomp_crc *const extr_crc,
                                struct rohc_uncomp_extr_bits *const extr_bits,
                                size_t *const rohc_hdr_len)
{
	struct rohc_buf rohc_remain_data = rohc_packet;

	(*rohc_hdr_len) = 0;

	/* the normal packet does not contain a CRC */
	extr_crc->type = ROHC_CRC_TYPE_NONE;
	extr_crc->bits_nr = 0;

	/* state must not be No Context */
	if(context->state == ROHC_DECOMP_STATE_NC)
	{
		rohc_decomp_warn(context, "cannot receive Normal packets in No Context "
		                 "state");
		goto error;
	}

	/* check if the ROHC packet is large enough for the first byte, the
	 * optional large CID field, and at least one more byte of data */
	if(rohc_remain_data.len < (1 + large_cid_len + 1))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu bytes)",
		                 rohc_remain_data.len);
		goto error;
	}

	/* save the first byte of the ROHC packet into the volatile part of the
	 * context (please note that the ROHC header length will be too large by one
	 * because of that, not great, but hey it's uncompressed profile anyway) */
	extr_bits->first_byte = GET_BIT_0_7(rohc_buf_data(rohc_remain_data));
	extr_bits->first_byte_used = true;
	rohc_buf_pull(&rohc_remain_data, 1);
	(*rohc_hdr_len)++;

	/* skip the optional large CID field */
	rohc_buf_pull(&rohc_remain_data, large_cid_len);
	(*rohc_hdr_len) += large_cid_len;

	return true;

error:
	return false;
}


/**
 * @brief Decode values from extracted bits for the Uncompressed profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context       The decompression context
 * @param extr_bits     The bits extracted from the ROHC packet
 * @param payload_len   The length of the packet payload (in bytes)
 * @param[out] decoded  The corresponding decoded values
 * @return              ROHC_STATUS_OK (decoding is always successful)
 */
static rohc_status_t uncomp_decode_bits(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                        const struct rohc_uncomp_extr_bits *const extr_bits,
                                        const size_t payload_len __attribute__((unused)),
                                        struct rohc_uncomp_decoded *const decoded)
{
	/* copy the first byte of the normal packet to be able to build the
	 * uncompressed packet */
	decoded->first_byte_used = extr_bits->first_byte_used;
	decoded->first_byte = extr_bits->first_byte;

	return ROHC_STATUS_OK;
}


/**
 * @brief Build the uncompressed headers for the Uncompressed profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp                The ROHC decompressor
 * @param context               The decompression context
 * @param packet_type           The type of ROHC packet
 * @param extr_crc              The CRC bits extracted from the ROHC header
 * @param decoded               The values decoded from ROHC header
 * @param payload_len           The length of the packet payload (in bytes)
 * @param[out] uncomp_hdrs      The uncompressed headers being built
 * @param[out] uncomp_hdrs_len  The length of the uncompressed headers written
 *                              into the buffer
 * @return                      Possible values:
 *                               \li ROHC_STATUS_OK if headers are built
 *                                   successfully,
 *                               \li ROHC_STATUS_OUTPUT_TOO_SMALL if
 *                                   \e uncomp_packet is too small
 */
static rohc_status_t uncomp_build_hdrs(const struct rohc_decomp *const decomp __attribute__((unused)),
                                       const struct rohc_decomp_ctxt *const context,
                                       const rohc_packet_t packet_type,
                                       const struct rohc_decomp_crc *const extr_crc __attribute__((unused)),
                                       const struct rohc_uncomp_decoded *const decoded,
                                       const size_t payload_len __attribute__((unused)),
                                       struct rohc_buf *const uncomp_hdrs,
                                       size_t *const uncomp_hdrs_len)
{
	(*uncomp_hdrs_len) = 0;

	if(decoded->first_byte_used)
	{
		/* copy the first byte of the ROHC packet to the decompressed packet */
		assert(packet_type == ROHC_PACKET_NORMAL);
		if(rohc_buf_avail_len(*uncomp_hdrs) < 1)
		{
			rohc_decomp_warn(context, "uncompressed packet too small (%zu bytes "
			                 "max) for the first byte of the payload",
			                 rohc_buf_avail_len(*uncomp_hdrs));
			goto error_output_too_small;
		}
		rohc_buf_byte(*uncomp_hdrs) = decoded->first_byte;
		uncomp_hdrs->len++;
		(*uncomp_hdrs_len)++;
	}

	return ROHC_STATUS_OK;

error_output_too_small:
	return ROHC_STATUS_OUTPUT_TOO_SMALL;
}


/**
 * @brief Update the decompression context with the infos of current packet
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context              The decompression context
 * @param decoded              The decoded values to update in the context
 * @param payload_len          The length of the packet payload (in bytes)
 * @param[out] do_change_mode  Whether the profile context wants to change
 *                             its operational mode or not
 */
static void uncomp_update_ctxt(struct rohc_decomp_ctxt *const context __attribute__((unused)),
                               const struct rohc_uncomp_decoded *const decoded __attribute__((unused)),
                               const size_t payload_len __attribute__((unused)),
                               bool *const do_change_mode __attribute__((unused)))
{
	/* nothing to update */
}


/**
 * @brief Attempt a packet/context repair upon CRC failure
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp             The ROHC decompressor
 * @param context            The decompression context
 * @param pkt_arrival_time   The arrival time of the ROHC packet that caused
 *                           the CRC failure
 * @param[in,out] crc_corr   The context for corrections upon CRC failures
 * @param[in,out] extr_bits  The bits extracted from the ROHC header
 * @return                   true if repair is possible, false if not
 */
static bool uncomp_attempt_repair(const struct rohc_decomp *const decomp __attribute__((unused)),
                                  const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                  const struct rohc_ts pkt_arrival_time __attribute__((unused)),
                                  struct rohc_decomp_crc_corr_ctxt *const crc_corr __attribute__((unused)),
                                  struct rohc_uncomp_extr_bits *const extr_bits __attribute__((unused)))
{
	/* CRC failure cannot happen with Uncompressed profile since Normal packets
	 * do not have a CRC */
	assert(0);
	return false;
}


/**
 * @brief Get the reference SN value of the context. Always return 0 for the
 *        uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference SN value
 */
static uint32_t uncomp_get_sn(const struct rohc_decomp_ctxt *const context __attribute__((unused)))
{
	return 0;
}


/**
 * @brief Define the decompression part of the Uncompressed profile as
 *        described in the RFC 3095.
 */
const struct rohc_decomp_profile d_uncomp_profile =
{
	.id              = ROHC_PROFILE_UNCOMPRESSED, /* profile ID (RFC3095 §8) */
	.msn_max_bits    = 0, /* no MSN */
	.new_context     = uncomp_new_context,
	.free_context    = uncomp_free_context,
	.detect_pkt_type = uncomp_detect_pkt_type,
	.parse_pkt       = (rohc_decomp_parse_pkt_t) uncomp_parse_pkt,
	.decode_bits     = (rohc_decomp_decode_bits_t) uncomp_decode_bits,
	.build_hdrs      = (rohc_decomp_build_hdrs_t) uncomp_build_hdrs,
	.update_ctxt     = (rohc_decomp_update_ctxt_t) uncomp_update_ctxt,
	.attempt_repair  = (rohc_decomp_attempt_repair_t) uncomp_attempt_repair,
	.get_sn          = uncomp_get_sn,
};

