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
 * @file rohc_comp.h
 * @brief ROHC compression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 */

#ifndef COMP_H
#define COMP_H

#include "rohc.h"
#include "rohc_packets.h"
#include "rohc_traces.h"

#include <stdlib.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif


/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
	#define ROHC_EXPORT __declspec(dllexport)
#else
	#define ROHC_EXPORT 
#endif


/*
 * Declare the private ROHC compressor structure that is defined inside the
 * library.
 */

struct rohc_comp;


/*
 * Public structures and types
 */


/**
 * @brief The different ROHC compressor states
 *
 * See 4.3.1 in the RFC 3095.
 *
 * If you add a new compressor state, please also add the corresponding
 * textual description in \ref rohc_comp_get_state_descr.
 */
typedef enum
{
	/** The Initialization and Refresh (IR) state */
	IR = 1,
	/** The First Order (FO) state */
	FO = 2,
	/** The Second Order (SO) state */
	SO = 3,
} rohc_c_state;


/**
 * @brief Some information about the last compressed packet
 *
 * Non-extensible version of rohc_comp_last_packet_info2_t
 */
typedef struct
{
	/** The mode of the last context used by the compressor */
	rohc_mode context_mode;
	/** The state of the last context used by the compressor */
	rohc_c_state context_state;
	/** The type of ROHC packet created for the last compressed packet */
	rohc_packet_t packet_type;
	/** The uncompressed size (in bytes) of the last compressed packet */
	unsigned long total_last_uncomp_size;
	/** The uncompressed size (in bytes) of the last compressed header */
	unsigned long header_last_uncomp_size;
	/** The compressed size (in bytes) of the last compressed packet */
	unsigned long total_last_comp_size;
	/** The compressed size (in bytes) of the last compressed header */
	unsigned long header_last_comp_size;
} rohc_comp_last_packet_info_t;


/**
 * @brief Some information about the last compressed packet
 *
 * Extensible version of rohc_comp_last_packet_info_t. Versioning works
 * as follow:
 *  - The 'version_major' field defines the compatibility level. If the major
 *    number given by user does not match the one expected by the library,
 *    an error is returned.
 *  - The 'version_minor' field defines the extension level. If the minor
 *    number given by user does not match the one expected by the library,
 *    only the fields supported in that minor version will be filled by
 *    \ref rohc_comp_get_last_packet_info2.
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
 *  - Major = 0:
 *     - Minor = 0:
 *        version_major
 *        version_minor
 *        context_id
 *        is_context_init
 *        context_mode
 *        context_state
 *        context_used
 *        profile_id
 *        packet_type
 *        total_last_uncomp_size
 *        header_last_uncomp_size
 *        total_last_comp_size
 *        header_last_comp_size
 */
typedef struct
{
	/** The major version of this structure */
	unsigned short version_major;
	/** The minor version of this structure */
	unsigned short version_minor;
	/** The Context ID (CID) */
	unsigned int context_id;
	/** Whether the context was initialized (created/re-used) by the packet */
	bool is_context_init;
	/** The mode of the last context used by the compressor */
	rohc_mode context_mode;
	/** The state of the last context used by the compressor */
	rohc_c_state context_state;
	/** Whether the last context used by the compressor is still in use */
	bool context_used;
	/** The profile ID of the last context used by the compressor */
	int profile_id;
	/** The type of ROHC packet created for the last compressed packet */
	rohc_packet_t packet_type;
	/** The uncompressed size (in bytes) of the last compressed packet */
	unsigned long total_last_uncomp_size;
	/** The uncompressed size (in bytes) of the last compressed header */
	unsigned long header_last_uncomp_size;
	/** The compressed size (in bytes) of the last compressed packet */
	unsigned long total_last_comp_size;
	/** The compressed size (in bytes) of the last compressed header */
	unsigned long header_last_comp_size;
} __attribute__((packed)) rohc_comp_last_packet_info2_t;


/**
 * @brief Some general information about the compressor
 *
 * Versioning works as follow:
 *  - The 'version_major' field defines the compatibility level. If the major
 *    number given by user does not match the one expected by the library,
 *    an error is returned.
 *  - The 'version_minor' field defines the extension level. If the minor
 *    number given by user does not match the one expected by the library,
 *    only the fields supported in that minor version will be filled by
 *    \ref rohc_comp_get_general_info.
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
 *  - Major = 0:
 *     - Minor = 0:
 *        version_major
 *        version_minor
 */
typedef struct
{
	/** The major version of this structure */
	unsigned short version_major;
	/** The minor version of this structure */
	unsigned short version_minor;
	/** The number of contexts used by the compressor */
	size_t contexts_nr;
	/** The number of packets processed by the compressor */
	unsigned long packets_nr;
	/** The number of uncompressed bytes received by the compressor */
	unsigned long uncomp_bytes_nr;
	/** The number of compressed bytes produced by the compressor */
	unsigned long comp_bytes_nr;
} __attribute__((packed)) rohc_comp_general_info_t;


/**
 * @brief The prototype of the RTP detection callback
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @param rtp_private  A pointer to a memory area to be used by the callback
 *                     function.
 * @return             true if the packet is an RTP packet, false otherwise
 */
typedef bool (*rohc_rtp_detection_callback_t)(const unsigned char *const ip,
                                              const unsigned char *const udp,
                                              const unsigned char *const payload,
                                              const unsigned int payload_size,
                                              void *const rtp_private)
	__attribute__((nonnull(1, 2, 3), warn_unused_result));


/** The prototype of the callback for random numbers */
typedef int (*rohc_comp_random_cb_t) (const struct rohc_comp *const comp,
                                      void *const user_context)
	__attribute__((nonnull(1)));


/*
 * Prototypes of main public functions related to ROHC compression
 */

struct rohc_comp * ROHC_EXPORT rohc_alloc_compressor(int max_cid,
                                                     int jam_use,
                                                     int adapt_size,
                                                     int encap_size);
void ROHC_EXPORT rohc_free_compressor(struct rohc_comp *comp);

bool ROHC_EXPORT rohc_comp_set_traces_cb(struct rohc_comp *const comp,
                                         rohc_trace_callback_t callback)
	__attribute__((nonnull(1, 2), warn_unused_result));

bool ROHC_EXPORT rohc_comp_set_random_cb(struct rohc_comp *const comp,
                                         rohc_comp_random_cb_t callback,
                                         void *const user_context)
	__attribute__((nonnull(1, 2)));

int ROHC_EXPORT rohc_compress(struct rohc_comp *comp,
                              unsigned char *ibuf,
                              int isize,
                              unsigned char *obuf,
                              int osize)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_compress2() instead");

int ROHC_EXPORT rohc_compress2(struct rohc_comp *const comp,
                               const unsigned char *const uncomp_packet,
                               const size_t uncomp_packet_len,
                               unsigned char *const rohc_packet,
                               const size_t rohc_packet_max_len,
                               size_t *const rohc_packet_len)
	__attribute__((nonnull(1, 2, 4, 6), warn_unused_result));

int ROHC_EXPORT rohc_comp_get_segment(struct rohc_comp *const comp,
                                      unsigned char *const segment,
                                      const size_t max_len,
                                      size_t *const len)
	__attribute__((nonnull(1, 2, 4), warn_unused_result));

bool rohc_comp_force_contexts_reinit(struct rohc_comp *const comp)
	__attribute__((nonnull(1), warn_unused_result));


/*
 * Prototypes of public functions related to user interaction
 */

int ROHC_EXPORT rohc_c_is_enabled(struct rohc_comp *comp);
int ROHC_EXPORT rohc_c_using_small_cid(struct rohc_comp *comp);

void ROHC_EXPORT rohc_activate_profile(struct rohc_comp *comp, int profile);

void ROHC_EXPORT rohc_c_set_header(struct rohc_comp *compressor, int value);

void ROHC_EXPORT rohc_c_set_mrru(struct rohc_comp *compressor, int value)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_set_mrru() instead");
bool ROHC_EXPORT rohc_comp_set_mrru(struct rohc_comp *const comp,
                                    const size_t mrru)
	__attribute__((nonnull(1), warn_unused_result));
bool ROHC_EXPORT rohc_comp_get_mrru(const struct rohc_comp *const comp,
                                    size_t *const mrru)
	__attribute__((nonnull(1, 2), warn_unused_result));

void ROHC_EXPORT rohc_c_set_max_cid(struct rohc_comp *compressor, int value);
bool ROHC_EXPORT rohc_comp_get_max_cid(const struct rohc_comp *const comp,
                                       size_t *const max_cid)
	__attribute__((nonnull(1, 2), warn_unused_result));

void ROHC_EXPORT rohc_c_set_large_cid(struct rohc_comp *compressor, int value);
bool ROHC_EXPORT rohc_comp_get_cid_type(const struct rohc_comp *const comp,
                                        rohc_cid_type_t *const cid_type)
	__attribute__((nonnull(1, 2), warn_unused_result));

void ROHC_EXPORT rohc_c_set_enable(struct rohc_comp *compressor, int value);

/* RTP stream detection through UDP ports */
bool ROHC_EXPORT rohc_comp_add_rtp_port(struct rohc_comp *const comp,
                                        const unsigned int port)
	__attribute__((nonnull(1), warn_unused_result));
bool ROHC_EXPORT rohc_comp_remove_rtp_port(struct rohc_comp *const comp,
                                           const unsigned int port)
	__attribute__((nonnull(1), warn_unused_result));
bool ROHC_EXPORT rohc_comp_reset_rtp_ports(struct rohc_comp *const comp)
	__attribute__((nonnull(1), warn_unused_result));

/* RTP stream detection through callback */
bool ROHC_EXPORT rohc_comp_set_rtp_detection_cb(struct rohc_comp *const comp,
                                                rohc_rtp_detection_callback_t callback,
                                                void *const rtp_private)
	__attribute__((nonnull(1), warn_unused_result));


/*
 * Prototypes of public functions related to ROHC feedback
 */

void ROHC_EXPORT c_piggyback_feedback(struct rohc_comp *comp,
                                      unsigned char *packet,
                                      int size)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_piggyback_feedback() instead");
bool ROHC_EXPORT rohc_comp_piggyback_feedback(struct rohc_comp *const comp,
                                              const unsigned char *const feedback,
                                              const size_t size)
	__attribute__((nonnull(1, 2), warn_unused_result));
void ROHC_EXPORT c_deliver_feedback(struct rohc_comp *comp,
                                    unsigned char *feedback,
                                    int size);
int ROHC_EXPORT rohc_feedback_flush(struct rohc_comp *comp,
                                    unsigned char *obuf,
                                    int osize);
bool ROHC_EXPORT rohc_feedback_remove_locked(struct rohc_comp *const comp)
	__attribute__((nonnull(1), warn_unused_result));
bool ROHC_EXPORT rohc_feedback_unlock(struct rohc_comp *const comp)
	__attribute__((nonnull(1), warn_unused_result));

/* Configure robustness to packet loss/damage */
bool ROHC_EXPORT rohc_comp_set_wlsb_window_width(struct rohc_comp *const comp,
                                                 const size_t width)
	__attribute__((nonnull(1), warn_unused_result));
bool ROHC_EXPORT rohc_comp_set_periodic_refreshes(struct rohc_comp *const comp,
																  const size_t ir_timeout,
																  const size_t fo_timeout)
	__attribute__((nonnull(1), warn_unused_result));


/*
 * Prototypes of public functions related to ROHC compression statistics
 */

int ROHC_EXPORT rohc_c_info(char *buffer)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_general_info() instead");
int ROHC_EXPORT rohc_c_statistics(struct rohc_comp *comp,
                                  unsigned int indent,
                                  char *buffer)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_general_info() instead");
int ROHC_EXPORT rohc_c_context(struct rohc_comp *comp,
                               int cid,
                               unsigned int indent,
                               char *buffer)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_general_info() instead");
int ROHC_EXPORT rohc_comp_get_last_packet_info(const struct rohc_comp *const comp,
                                               rohc_comp_last_packet_info_t *const info)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_last_packet_info2() instead");


bool ROHC_EXPORT rohc_comp_get_general_info(const struct rohc_comp *const comp,
                                            rohc_comp_general_info_t *const info)
	__attribute__((nonnull(1, 2), warn_unused_result));

bool ROHC_EXPORT rohc_comp_get_last_packet_info2(const struct rohc_comp *const comp,
                                                 rohc_comp_last_packet_info2_t *const info);

const char * ROHC_EXPORT rohc_comp_get_state_descr(const rohc_c_state state);


#undef ROHC_EXPORT /* do not pollute outside this header */

#endif

