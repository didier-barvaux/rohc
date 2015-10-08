/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2014 Viveris Technologies
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
 * @file rohc_decomp.h
 * @brief ROHC decompression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 */

#ifndef ROHC_DECOMP_H
#define ROHC_DECOMP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <rohc/rohc.h>
#include <rohc/rohc_packets.h>
#include <rohc/rohc_traces.h>
#include <rohc/rohc_buf.h>


/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
#  define ROHC_EXPORT __declspec(dllexport)
#else
#  define ROHC_EXPORT
#endif


/*
 * Declare the private ROHC decompressor structure that is defined inside the
 * library.
 */

struct rohc_decomp;



/*
 * Public structures and types
 */


/**
 * @brief The ROHC decompressor states
 *
 * The different ROHC operation states at decompressor as defined in section
 * 4.3.2 of RFC 3095.
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_get_state_descr
 */
typedef enum
{
	/** Unknown decompressor state */
	ROHC_DECOMP_STATE_UNKNOWN = 0,
	/** The No Context state */
	ROHC_DECOMP_STATE_NC = 1,
	/** The Static Context state */
	ROHC_DECOMP_STATE_SC = 2,
	/** The Full Context state */
	ROHC_DECOMP_STATE_FC = 3,
} rohc_decomp_state_t;


/**
 * @brief Some information about the last decompressed packet
 *
 * The structure is used by the \ref rohc_decomp_get_last_packet_info function
 * to store some information about the last decompressed packet.
 *
 * Versioning works as follow:
 *  - The \e version_major field defines the compatibility level. If the major
 *    number given by user does not match the one expected by the library,
 *    an error is returned.
 *  - The \e version_minor field defines the extension level. If the minor
 *    number given by user does not match the one expected by the library,
 *    only the fields supported in that minor version will be filled by
 *    \ref rohc_decomp_get_last_packet_info.
 *
 * Notes for developers:
 *  - Increase the major version if a field is removed.
 *  - Increase the major version if a field is added at the beginning or in
 *    the middle of the structure.
 *  - Increase the minor version if a field is added at the very end of the
 *    structure.
 *  - The version_major and version_minor fields must be located at the very
 *    beginning of the structure.
 *  - The structure must be packed.
 *
 * Supported versions:
 *  - Major 0 / Minor 0 contains: version_major, version_minor, context_mode,
 *    context_state, profile_id, nr_lost_packets, nr_misordered_packets, and
 *    is_duplicated
 *  - Major 0 / Minor = 1 added: corrected_crc_failures,
 *    corrected_sn_wraparounds, corrected_wrong_sn_updates, and packet_type
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_get_last_packet_info
 */
typedef struct
{
	/** The major version of this structure */
	unsigned short version_major;
	/** The minor version of this structure */
	unsigned short version_minor;
	/** The mode of the last context used by the compressor */
	rohc_mode_t context_mode;
	/** The state of the last context used by the compressor */
	rohc_decomp_state_t context_state;
	/** The profile ID of the last context used by the compressor */
	int profile_id;
	/** The number of (possible) lost packet(s) before last packet */
	unsigned long nr_lost_packets;
	/** The number of packet(s) before the last packet if late */
	unsigned long nr_misordered_packets;
	/** Is last packet a (possible) duplicated packet? */
	bool is_duplicated;

	/* added in 0.1 */
	/** The number of successful corrections upon CRC failure */
	unsigned long corrected_crc_failures;
	/** The number of successful corrections of SN wraparound upon CRC failure */
	unsigned long corrected_sn_wraparounds;
	/** The number of successful corrections of incorrect SN updates upon CRC
	 *  failure */
	unsigned long corrected_wrong_sn_updates;
	/** The type of the last decompressed ROHC packet */
	rohc_packet_t packet_type;

} __attribute__((packed)) rohc_decomp_last_packet_info_t;


/**
 * @brief Some general information about the decompressor
 *
 * The structure is used by the \ref rohc_decomp_get_general_info function
 * to store some general information about the decompressor.
 *
 * Versioning works as follow:
 *  - The \e version_major field defines the compatibility level. If the major
 *    number given by user does not match the one expected by the library,
 *    an error is returned.
 *  - The \e version_minor field defines the extension level. If the minor
 *    number given by user does not match the one expected by the library,
 *    only the fields supported in that minor version will be filled by
 *    \ref rohc_decomp_get_general_info.
 *
 * Notes for developers:
 *  - Increase the major version if a field is removed.
 *  - Increase the major version if a field is added at the beginning or in
 *    the middle of the structure.
 *  - Increase the minor version if a field is added at the very end of the
 *    structure.
 *  - The version_major and version_minor fields must be located at the very
 *    beginning of the structure.
 *  - The structure must be packed.
 *
 * Supported versions:
 *  - major 0 and minor = 0 contains: version_major, version_minor,
 *    contexts_nr, packets_nr, comp_bytes_nr, and uncomp_bytes_nr.
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_get_general_info
 */
typedef struct
{
	/** The major version of this structure */
	unsigned short version_major;
	/** The minor version of this structure */
	unsigned short version_minor;
	/** The number of contexts used by the decompressor */
	size_t contexts_nr;
	/** The number of packets processed by the decompressor */
	unsigned long packets_nr;
	/** The number of compressed bytes received by the decompressor */
	unsigned long comp_bytes_nr;
	/** The number of uncompressed bytes produced by the decompressor */
	unsigned long uncomp_bytes_nr;
} __attribute__((packed)) rohc_decomp_general_info_t;


/**
 * @brief The different features of the ROHC decompressor
 *
 * Features for the ROHC decompressor control whether mechanisms defined as
 * optional by RFCs are enabled or not. They can be set or unset with the
 * function \ref rohc_decomp_set_features.
 *
 * @ingroup rohc_decomp
 *
 * @see rohc_decomp_set_features
 */
typedef enum
{
	/** No feature at all */
	ROHC_DECOMP_FEATURE_NONE         = 0,
	/** Attempt packet repair in case of CRC failure */
	ROHC_DECOMP_FEATURE_CRC_REPAIR   = (1 << 0),
	/** Be compatible with 1.6.x versions */
	ROHC_DECOMP_FEATURE_COMPAT_1_6_x = (1 << 1),
	/** Dump content of packets in traces (beware: performance impact) */
	ROHC_DECOMP_FEATURE_DUMP_PACKETS = (1 << 3),

} rohc_decomp_features_t;



/*
 * Functions related to decompressor:
 */

struct rohc_decomp * ROHC_EXPORT rohc_decomp_new2(const rohc_cid_type_t cid_type,
                                                  const rohc_cid_t max_cid,
                                                  const rohc_mode_t mode)
	__attribute__((warn_unused_result));

void ROHC_EXPORT rohc_decomp_free(struct rohc_decomp *const decomp);

rohc_status_t ROHC_EXPORT rohc_decompress3(struct rohc_decomp *const decomp,
                                           const struct rohc_buf rohc_packet,
                                           struct rohc_buf *const uncomp_packet,
                                           struct rohc_buf *const rcvd_feedback,
                                           struct rohc_buf *const feedback_send)
	__attribute__((warn_unused_result));



/*
 * Functions related to statistics:
 */

const char * ROHC_EXPORT rohc_decomp_get_state_descr(const rohc_decomp_state_t state)
	__attribute__((warn_unused_result, const));

bool ROHC_EXPORT rohc_decomp_get_general_info(const struct rohc_decomp *const decomp,
                                              rohc_decomp_general_info_t *const info)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_get_last_packet_info(const struct rohc_decomp *const decomp,
                                                  rohc_decomp_last_packet_info_t *const info)
	__attribute__((warn_unused_result));


/*
 * Functions related to user parameters
 */

/* CID */

bool ROHC_EXPORT rohc_decomp_get_cid_type(const struct rohc_decomp *const decomp,
                                          rohc_cid_type_t *const cid_type)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_get_max_cid(const struct rohc_decomp *const decomp,
                                         size_t *const max_cid)
	__attribute__((warn_unused_result));

/* MRRU */

bool ROHC_EXPORT rohc_decomp_set_mrru(struct rohc_decomp *const decomp,
                                      const size_t mrru)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_get_mrru(const struct rohc_decomp *const decomp,
                                      size_t *const mrru)
	__attribute__((warn_unused_result));

/* pRTT */

bool ROHC_EXPORT rohc_decomp_set_prtt(struct rohc_decomp *const decomp,
                                      const size_t prtt)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_get_prtt(const struct rohc_decomp *const decomp,
                                      size_t *const prtt)
	__attribute__((warn_unused_result));

/* feedback rate-limiting */

bool ROHC_EXPORT rohc_decomp_set_rate_limits(struct rohc_decomp *const decomp,
                                             const size_t k, const size_t n,
                                             const size_t k_1, const size_t n_1,
                                             const size_t k_2, const size_t n_2)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_get_rate_limits(const struct rohc_decomp *const decomp,
                                             size_t *const k, size_t *const n,
                                             size_t *const k_1, size_t *const n_1,
                                             size_t *const k_2, size_t *const n_2)
	__attribute__((warn_unused_result));

/* decompression library features */

bool ROHC_EXPORT rohc_decomp_set_features(struct rohc_decomp *const decomp,
                                          const rohc_decomp_features_t features)
	__attribute__((warn_unused_result));


/*
 * Functions related to decompression profiles
 */

bool ROHC_EXPORT rohc_decomp_profile_enabled(const struct rohc_decomp *const decomp,
                                             const rohc_profile_t profile)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_enable_profile(struct rohc_decomp *const decomp,
                                            const rohc_profile_t profile)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_disable_profile(struct rohc_decomp *const decomp,
                                             const rohc_profile_t profile)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_enable_profiles(struct rohc_decomp *const decomp,
                                             ...)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_decomp_disable_profiles(struct rohc_decomp *const decomp,
                                              ...)
	__attribute__((warn_unused_result));


/*
 * Functions related to traces
 */

bool ROHC_EXPORT rohc_decomp_set_traces_cb2(struct rohc_decomp *const decomp,
                                            rohc_trace_callback2_t callback,
                                            void *const priv_ctxt)
	__attribute__((warn_unused_result));


#undef ROHC_EXPORT /* do not pollute outside this header */

#ifdef __cplusplus
}
#endif

#endif /* ROHC_DECOMP_H */

