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
 * @file d_generic.c
 * @brief ROHC generic decompression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author The hackers from ROHC for Linux
 * @author David Moreau from TAS
 */

#include "d_generic.h"
#include "d_rtp.h"
#include "config.h" /* for RTP_BIT_TYPE and ROHC_EXTRA_DEBUG definition */
#include "rohc_traces_internal.h"
#include "rohc_time.h"
#include "rohc_debug.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "rohc_bit_ops.h"
#include "rohc_decomp_internals.h"
#include "comp_list.h"
#include "decode.h"
#include "wlsb.h"
#include "sdvl.h"
#include "crc.h"

#include <assert.h>


/*
 * Definitions of private constants and macros
 */


/*
 * Private function prototypes for parsing the static and dynamic parts
 * of the IR and IR-DYN headers
 */

static int parse_static_part_ip(const struct d_context *const context,
                                const unsigned char *const packet,
                                const size_t length,
                                struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int parse_static_part_ipv4(const struct d_context *const context,
                                  const unsigned char *packet,
                                  const size_t length,
                                  struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int parse_static_part_ipv6(const struct d_context *const context,
                                  const unsigned char *packet,
                                  const size_t length,
                                  struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int parse_dynamic_part_ip(const struct d_context *const context,
                                 const unsigned char *const packet,
                                 const size_t length,
                                 struct rohc_extr_ip_bits *const bits,
                                 struct list_decomp *const list_decomp)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));
static int parse_dynamic_part_ipv4(const struct d_context *const context,
                                   const unsigned char *packet,
                                   const size_t length,
                                   struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int parse_dynamic_part_ipv6(const struct d_context *const context,
                                   const unsigned char *packet,
                                   const size_t length,
                                   struct rohc_extr_ip_bits *const bits,
                                   struct list_decomp *const list_decomp)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));


/*
 * Private function prototypes for parsing the different UO* headers
 */

static bool parse_packet(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_packet,
                         const size_t rohc_length,
                         const size_t large_cid_len,
                         rohc_packet_t *const packet_type,
                         struct rohc_extr_bits *const bits,
                         size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));

static bool parse_ir(const struct rohc_decomp *const decomp,
                     const struct d_context *const context,
                     const unsigned char *const rohc_packet,
                     const size_t rohc_length,
                     const size_t large_cid_len,
                     rohc_packet_t *const packet_type,
                     struct rohc_extr_bits *const bits,
                     size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));

static bool parse_irdyn(const struct rohc_decomp *const decomp,
                        const struct d_context *const context,
                        const unsigned char *const rohc_packet,
                        const size_t rohc_length,
                        const size_t large_cid_len,
                        rohc_packet_t *const packet_type,
                        struct rohc_extr_bits *const bits,
                        size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));

static bool parse_uo0(const struct rohc_decomp *const decomp,
                      const struct d_context *const context,
                      const unsigned char *const rohc_packet,
                      const size_t rohc_length,
                      const size_t large_cid_len,
                      rohc_packet_t *const packet_type,
                      struct rohc_extr_bits *const bits,
                      size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));

static bool parse_uo1(const struct rohc_decomp *const decomp,
                      const struct d_context *const context,
                      const unsigned char *const rohc_packet,
                      const size_t rohc_length,
                      const size_t large_cid_len,
                      rohc_packet_t *const packet_type,
                      struct rohc_extr_bits *const bits,
                      size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));
static bool parse_uo1rtp(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_packet,
                         const size_t rohc_length,
                         const size_t large_cid_len,
                         rohc_packet_t *const packet_type,
                         struct rohc_extr_bits *const bits,
                         size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));
static bool parse_uo1id(const struct rohc_decomp *const decomp,
                        const struct d_context *const context,
                        const unsigned char *const rohc_packet,
                        const size_t rohc_length,
                        const size_t large_cid_len,
                        rohc_packet_t *const packet_type,
                        struct rohc_extr_bits *const bits,
                        size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));
static bool parse_uo1ts(const struct rohc_decomp *const decomp,
                        const struct d_context *const context,
                        const unsigned char *const rohc_packet,
                        const size_t rohc_length,
                        const size_t large_cid_len,
                        rohc_packet_t *const packet_type,
                        struct rohc_extr_bits *const bits,
                        size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));

static bool parse_uor2(const struct rohc_decomp *const decomp,
                       const struct d_context *const context,
                       const unsigned char *const rohc_packet,
                       const size_t rohc_length,
                       const size_t large_cid_len,
                       rohc_packet_t *const packet_type,
                       struct rohc_extr_bits *const bits,
                       size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));
static bool parse_uor2rtp(const struct rohc_decomp *const decomp,
                          const struct d_context *const context,
                          const unsigned char *const rohc_packet,
                          const size_t rohc_length,
                          const size_t large_cid_len,
                          rohc_packet_t *const packet_type,
                          struct rohc_extr_bits *const bits,
                          size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));
static int parse_uor2rtp_once(const struct rohc_decomp *const decomp,
                              const struct d_context *const context,
                              const unsigned char *const rohc_packet,
                              const size_t rohc_length,
                              const size_t large_cid_len,
                              const rohc_packet_t packet_type,
                              uint8_t outer_rnd,
                              uint8_t inner_rnd,
                              struct rohc_extr_bits *const bits,
                              size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 9, 10)));
static bool parse_uor2id(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_packet,
                         const size_t rohc_length,
                         const size_t large_cid_len,
                         rohc_packet_t *const packet_type,
                         struct rohc_extr_bits *const bits,
                         size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));
static int parse_uor2id_once(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const unsigned char *const rohc_packet,
                             const size_t rohc_length,
                             const size_t large_cid_len,
                             const rohc_packet_t packet_type,
                             uint8_t outer_rnd,
                             uint8_t inner_rnd,
                             struct rohc_extr_bits *const bits,
                             size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 9, 10)));
static bool parse_uor2ts(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_packet,
                         const size_t rohc_length,
                         const size_t large_cid_len,
                         rohc_packet_t *const packet_type,
                         struct rohc_extr_bits *const bits,
                         size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6, 7, 8)));
static int parse_uor2ts_once(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const unsigned char *const rohc_packet,
                             const size_t rohc_length,
                             const size_t large_cid_len,
                             const rohc_packet_t packet_type,
                             uint8_t outer_rnd,
                             uint8_t inner_rnd,
                             struct rohc_extr_bits *const bits,
                             size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 9, 10)));

static bool parse_uo_remainder(const struct rohc_decomp *const decomp,
                               const struct d_context *const context,
                               const unsigned char *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_extr_bits *const bits,
                               size_t *const rohc_hdr_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));


/*
 * Private function prototypes for parsing the different extensions
 */

static uint8_t parse_extension_type(const unsigned char *const rohc_ext)
	__attribute__((warn_unused_result, nonnull(1), pure));
static int parse_extension0(const struct rohc_decomp *const decomp,
                            const struct d_context *const context,
                            const unsigned char *const rohc_data,
                            const size_t rohc_data_len,
                            const rohc_packet_t packet_type,
                            const ip_header_pos_t innermost_ip_hdr,
                            struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 7)));
static int parse_extension1(const struct rohc_decomp *const decomp,
                            const struct d_context *const context,
                            const unsigned char *const rohc_data,
                            const size_t rohc_data_len,
                            const rohc_packet_t packet_type,
                            const ip_header_pos_t innermost_ip_hdr,
                            struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 7)));
static int parse_extension2(const struct rohc_decomp *const decomp,
                            const struct d_context *const context,
                            const unsigned char *const rohc_data,
                            const size_t rohc_data_len,
                            const rohc_packet_t packet_type,
                            const ip_header_pos_t innermost_ip_hdr,
                            struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 7)));


/*
 * Private function prototypes for decoding compressed lists
 */

static int rohc_list_decode(struct list_decomp *const decomp,
                            const unsigned char *const packet,
                            const size_t packet_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_decode_type_0(struct list_decomp *const decomp,
                                   const unsigned char *const packet,
                                   const size_t packet_len,
                                   const int gen_id,
                                   const int ps,
                                   const int m)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_decode_type_1(struct list_decomp *const decomp,
                                   const unsigned char *const packet,
                                   const size_t packet_len,
                                   const int gen_id,
                                   const int ps,
                                   const int xi_1)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_decode_type_2(struct list_decomp *const decomp,
                                   const unsigned char *const packet,
                                   const size_t packet_len,
                                   const int gen_id,
                                   const int ps)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_decode_type_3(struct list_decomp *const decomp,
                                   const unsigned char *const packet,
                                   const size_t packet_len,
                                   const int gen_id,
                                   const int ps,
                                   const int xi_1)
	__attribute__((warn_unused_result, nonnull(1, 2)));


/*
 * Private function prototypes for building the uncompressed headers
 */

static int build_uncomp_hdrs(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const rohc_packet_t packet_type,
                             const struct rohc_decoded_values decoded,
                             const size_t payload_len,
                             const rohc_crc_type_t crc_type,
                             const uint8_t crc_packet,
                             unsigned char *uncomp_hdrs,
                             size_t *const uncomp_hdrs_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 8, 9)));
static size_t build_uncomp_ip(const struct d_context *const context,
                              const struct rohc_decoded_ip_values decoded,
                              unsigned char *const dest,
                              const size_t payload_size,
                              const struct list_decomp *const list_decomp)
	__attribute__((warn_unused_result, nonnull(1, 3)));
static size_t build_uncomp_ipv4(const struct d_context *const context,
                                const struct rohc_decoded_ip_values decoded,
                                unsigned char *const dest,
                                const size_t payload_size)
	__attribute__((warn_unused_result, nonnull(1, 3)));
static size_t build_uncomp_ipv6(const struct d_context *const context,
                                const struct rohc_decoded_ip_values decoded,
                                unsigned char *const dest,
                                const size_t payload_size,
                                const struct list_decomp *const list_decomp)
	__attribute__((warn_unused_result, nonnull(1, 3, 5)));


/*
 * Private function prototypes for decoding the extracted bits
 */

static bool decode_values_from_bits(const struct rohc_decomp *const decomp,
                                    struct d_context *const context,
                                    const struct rohc_extr_bits bits,
                                    struct rohc_decoded_values *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static bool decode_ip_values_from_bits(const struct rohc_decomp *const decomp,
                                       const struct d_context *const context,
                                       const struct d_generic_changes *const ctxt,
                                       const struct ip_id_offset_decode *const ip_id_decode,
                                       const uint32_t decoded_sn,
                                       const struct rohc_extr_ip_bits bits,
                                       const char *const descr,
                                       struct rohc_decoded_ip_values *const decoded)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 7, 8)));



/*
 * Private function prototypes for list compression
 */

static bool rohc_list_is_gen_id_known(const struct list_decomp *const decomp,
                                      const unsigned int gen_id)
	__attribute__((warn_unused_result, nonnull(1)));

static uint8_t rohc_get_bit(const unsigned char byte, const size_t pos)
	__attribute__((warn_unused_result, const));

static bool check_ip6_item(const struct list_decomp *const decomp,
                           const size_t index_table)
	__attribute__((warn_unused_result, nonnull(1)));

static void list_decomp_ipv6_destroy_table(struct list_decomp *const decomp)
	__attribute__((nonnull(1)));

static size_t rohc_build_ip6_extension(const struct list_decomp *const decomp,
                                       const uint8_t ip_nh_type,
                                       unsigned char *const dest)
	__attribute__((warn_unused_result, nonnull(1, 3)));

static bool create_ip6_item(const unsigned char *const data,
                            const size_t length,
                            const size_t index_table,
                            struct list_decomp *const decomp)
	__attribute__((warn_unused_result, nonnull(1, 4)));

static void ip6_d_init_table(struct list_decomp *const decomp)
	__attribute__((nonnull(1)));

static int get_ip6_ext_size(const unsigned char *const data,
                            const size_t data_len)
	__attribute__((warn_unused_result, nonnull(1)));


/*
 * Private function prototypes for miscellaneous functions
 */

static bool check_ir_crc(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_hdr,
                         const size_t rohc_hdr_len,
                         const size_t add_cid_len,
                         const size_t large_cid_len,
                         const uint8_t crc_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static bool check_uncomp_crc(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const unsigned char *const outer_ip_hdr,
                             const unsigned char *const inner_ip_hdr,
                             const unsigned char *const next_header,
                             const rohc_crc_type_t crc_type,
                             const uint8_t crc_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

static bool attempt_repair(const struct rohc_decomp *const decomp,
                           const struct d_context *const context,
                           struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static bool is_sn_wraparound(const struct rohc_timestamp cur_arrival_time,
                             const struct rohc_timestamp arrival_times[ROHC_MAX_ARRIVAL_TIMES],
                             const size_t arrival_times_nr,
                             const size_t arrival_times_index,
                             const size_t k,
                             const rohc_lsb_shift_t p)
	__attribute__((warn_unused_result, pure));

static void update_context(const struct d_context *const context,
                           const struct rohc_decoded_values decoded)
	__attribute__((nonnull(1)));

static void stats_add_decomp_success(struct d_context *const context,
                                     const size_t comp_hdr_len,
                                     const size_t uncomp_hdr_len)
	__attribute__((nonnull(1)));

static void reset_extr_bits(const struct d_generic_context *const g_context,
                            struct rohc_extr_bits *const bits)
	__attribute__((nonnull(1, 2)));



/*
 * Definitions of public functions
 */

/**
 * @brief Create the generic decompression context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context         The decompression context
 * @param trace_callback  The function to call for printing traces
 * @param profile_id      The ID of the associated decompression profile
 * @return                The newly-created generic decompression context
 */
void * d_generic_create(const struct d_context *const context,
                        rohc_trace_callback_t trace_callback,
                        const int profile_id)
{
	struct d_generic_context *g_context;

	/* allocate memory for the generic context */
	g_context = malloc(sizeof(struct d_generic_context));
	if(g_context == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "no memory for the generic decompression context\n");
		goto quit;
	}
	memset(g_context, 0, sizeof(struct d_generic_context));

	/* create the Offset IP-ID decoding context for outer IP header */
	g_context->outer_ip_id_offset_ctxt = ip_id_offset_new();
	if(g_context->outer_ip_id_offset_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the Offset IP-ID decoding context "
		           "for outer IP header\n");
		goto free_context;
	}

	/* create the Offset IP-ID decoding context for inner IP header */
	g_context->inner_ip_id_offset_ctxt = ip_id_offset_new();
	if(g_context->inner_ip_id_offset_ctxt == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "failed to create the Offset IP-ID decoding context "
		           "for inner IP header\n");
		goto free_outer_ip_id_offset_ctxt;
	}

	g_context->outer_ip_changes = malloc(sizeof(struct d_generic_changes));
	if(g_context->outer_ip_changes == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the outer IP header changes\n");
		goto free_inner_ip_id_offset_ctxt;
	}
	memset(g_context->outer_ip_changes, 0, sizeof(struct d_generic_changes));

	g_context->inner_ip_changes = malloc(sizeof(struct d_generic_changes));
	if(g_context->inner_ip_changes == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the inner IP header changes\n");
		goto free_outer_ip_changes;
	}
	memset(g_context->inner_ip_changes, 0, sizeof(struct d_generic_changes));

	g_context->list_decomp1 = malloc(sizeof(struct list_decomp));
	if(g_context->list_decomp1 == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the list decompressor 1\n");
		goto free_inner_ip_changes;
	}
	memset(g_context->list_decomp1, 0, sizeof(struct list_decomp));
	ip6_d_init_table(g_context->list_decomp1);
	g_context->list_decomp1->free_table = list_decomp_ipv6_destroy_table;
	g_context->list_decomp1->encode_extension = rohc_build_ip6_extension;
	g_context->list_decomp1->check_item = check_ip6_item;
	g_context->list_decomp1->create_item = create_ip6_item;
	g_context->list_decomp1->get_ext_size = get_ip6_ext_size;
	g_context->list_decomp1->trace_callback = trace_callback;
	g_context->list_decomp1->profile_id = profile_id;

	g_context->list_decomp2 = malloc(sizeof(struct list_decomp));
	if(g_context->list_decomp2 == NULL)
	{
		rohc_error(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		           "cannot allocate memory for the list decompressor 2\n");
		goto free_decomp1;
	}
	memset(g_context->list_decomp2, 0, sizeof(struct list_decomp));
	ip6_d_init_table(g_context->list_decomp2);
	g_context->list_decomp2->free_table = list_decomp_ipv6_destroy_table;
	g_context->list_decomp2->encode_extension = rohc_build_ip6_extension;
	g_context->list_decomp2->check_item = check_ip6_item;
	g_context->list_decomp2->create_item = create_ip6_item;
	g_context->list_decomp2->get_ext_size = get_ip6_ext_size;
	g_context->list_decomp2->trace_callback = trace_callback;
	g_context->list_decomp2->profile_id = profile_id;

	/* no default next header */
	g_context->next_header_proto = 0;

	/* default CRC computation */
	g_context->compute_crc_static = compute_crc_static;
	g_context->compute_crc_dynamic = compute_crc_dynamic;

	/* at the beginning, no attempt to correct CRC failure */
	g_context->crc_corr = ROHC_DECOMP_CRC_CORR_SN_NONE;
	g_context->correction_counter = 0;
	/* arrival times for correction upon CRC failure */
	memset(g_context->arrival_times, 0, sizeof(struct rohc_timestamp) * 10);
	g_context->arrival_times_nr = 0;
	g_context->arrival_times_index = 0;
	g_context->cur_arrival_time.sec = 0;
	g_context->cur_arrival_time.nsec = 0;

	return g_context;

free_decomp1:
	zfree(g_context->list_decomp1);
free_inner_ip_changes:
	zfree(g_context->inner_ip_changes);
free_outer_ip_changes:
	zfree(g_context->outer_ip_changes);
free_inner_ip_id_offset_ctxt:
	ip_id_offset_free(g_context->inner_ip_id_offset_ctxt);
free_outer_ip_id_offset_ctxt:
	ip_id_offset_free(g_context->outer_ip_id_offset_ctxt);
free_context:
	zfree(g_context);
quit:
	return NULL;
}


/**
 * @brief Destroy the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
void d_generic_destroy(void *const context)
{
	struct d_generic_context *g_context;
	int i;

	assert(context != NULL);
	g_context = (struct d_generic_context *) context;

	/* destroy Offset IP-ID decoding contexts */
	ip_id_offset_free(g_context->outer_ip_id_offset_ctxt);
	ip_id_offset_free(g_context->inner_ip_id_offset_ctxt);

	/* destroy the information about the IP headers */
	assert(g_context->outer_ip_changes != NULL);
	zfree(g_context->outer_ip_changes);
	assert(g_context->inner_ip_changes != NULL);
	zfree(g_context->inner_ip_changes);

	/* destroy list decompression for outer IP header */
	assert(g_context->list_decomp1 != NULL);
	g_context->list_decomp1->free_table(g_context->list_decomp1);
	for(i = 0; i < LIST_COMP_WINDOW; i++)
	{
		if(g_context->list_decomp1->list_table[i] != NULL)
		{
			list_destroy(g_context->list_decomp1->list_table[i]);
		}
	}
	zfree(g_context->list_decomp1);

	/* destroy list decompression for inner IP header */
	assert(g_context->list_decomp2 != NULL);
	g_context->list_decomp2->free_table(g_context->list_decomp2);
	for(i = 0; i < LIST_COMP_WINDOW; i++)
	{
		if(g_context->list_decomp2->list_table[i] != NULL)
		{
			list_destroy(g_context->list_decomp2->list_table[i]);
		}
	}
	zfree(g_context->list_decomp2);

	/* destroy profile-specific part */
	if(g_context->specific != NULL)
	{
		zfree(g_context->specific);
	}

	/* destroy generic context itself */
	free(g_context);
}


/**
 * @brief Initialize the tables IPv6 extension in decompressor
 *
 * @param decomp The list decompressor
 */
static void ip6_d_init_table(struct list_decomp *decomp)
{
	/* insert HBH type in table */
	decomp->based_table[0].type = HBH;
	decomp->based_table[0].length = 0;
	decomp->based_table[0].data = NULL;
	decomp->trans_table[0].known = 0;
	decomp->trans_table[0].item = &decomp->based_table[0];
	/* insert DEST type in table */
	decomp->based_table[1].type = DEST;
	decomp->based_table[1].length = 0;
	decomp->based_table[1].data = NULL;
	decomp->trans_table[1].known = 0;
	decomp->trans_table[1].item = &decomp->based_table[1];
	/* insert RTHDR type in table */
	decomp->based_table[2].type = RTHDR;
	decomp->based_table[2].length = 0;
	decomp->based_table[2].data = NULL;
	decomp->trans_table[2].known = 0;
	decomp->trans_table[2].item = &decomp->based_table[2];
	/* insert AHHDR type in table */
	decomp->based_table[3].type = AH;
	decomp->based_table[3].length = 0;
	decomp->based_table[3].data = NULL;
	decomp->trans_table[3].known = 0;
	decomp->trans_table[3].item = &decomp->based_table[3];
}


/**
 * @brief Free the based table of the list decompressor
 * @param decomp The list decompressor
 */
static void list_decomp_ipv6_destroy_table(struct list_decomp *decomp)
{
	int i;
	for(i = 0; i < 4; i++)
	{
		if(decomp->based_table[i].data != NULL)
		{
			zfree(decomp->based_table[i].data);
		}
	}
}


/**
 * @brief Decompress the compressed list in given packet
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The remaining length of the packet to decode (in bytes)
 * @return            The size of the compressed list in packet in case of
 *                    success, -1 in case of failure
 */
static int rohc_list_decode(struct list_decomp *decomp,
                            const unsigned char *packet,
                            size_t packet_len)
{
	int et; // encoding type
	int ps;
	int gen_id;
	int m;
	uint8_t xi_1;
	int ret;
	size_t read_length = 0;

	assert(decomp != NULL);
	assert(packet != NULL);

	/* check for minimal size (1 byte) */
	if(packet_len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for compressed list (only %zd bytes "
		             "while at least 1 byte is required)\n", packet_len);
		goto error;
	}

	if(GET_BIT_0_7(packet) == 0)
	{
		rd_list_debug(decomp, "no extension list found\n");
		decomp->is_present = false;
		packet++;
		read_length++;
		packet_len--;
	}
	else
	{
		decomp->is_present = true;

		/* is there enough data in packet for the ET/PS/m/XI1 and gen_id fields ? */
		if(packet_len < 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "packet too small for compressed list (only %zd bytes "
			             "while at least 2 bytes are required)\n", packet_len);
			goto error;
		}

		/* parse ET, PS, and m/XI1 fields */
		m = GET_BIT_0_3(packet);
		xi_1 = m; /* m and XI 1 are the same field */
		et = GET_BIT_6_7(packet);
		ps = GET_REAL(GET_BIT_4(packet));
		packet++;
		read_length++;
		packet_len--;
		rd_list_debug(decomp, "ET = %d, PS = %d, m = XI 1 = %d\n", m, et, ps);

		/* parse gen_id */
		gen_id = GET_BIT_0_7(packet);
		packet++;
		read_length++;
		packet_len--;
		rd_list_debug(decomp, "gen_id = 0x%02x\n", gen_id);

		/* decode the compressed list according to its type */
		switch(et)
		{
			case 0:
				ret = rohc_list_decode_type_0(decomp, packet, packet_len,
				                              gen_id, ps, m);
				break;
			case 1:
				ret = rohc_list_decode_type_1(decomp, packet, packet_len,
				                              gen_id, ps, xi_1);
				break;
			case 2:
				ret = rohc_list_decode_type_2(decomp, packet, packet_len,
				                              gen_id, ps);
				break;
			case 3:
				ret = rohc_list_decode_type_3(decomp, packet, packet_len,
				                              gen_id, ps, xi_1);
				break;
			default:
				/* should not happen */
				rohc_error(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
				           "unknown type of compressed list (ET = %u)\n", et);
				assert(0);
				goto error;
		}
		if(ret < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "failed to decode compressed list type %d\n", et);
			goto error;
		}
		if(ret > packet_len)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "too many bytes read: %d bytes read in a %zd-byte "
			             "packet\n", ret, packet_len);
			goto error;
		}
		read_length += ret;
		packet_len -= ret;
	}

	return read_length;

error:
	return -1;
}


/**
 * @brief Check if the given gen_id is known, ie. present in list table
 *
 * @param decomp  The list decompressor
 * @param gen_id  The gen_id to check for
 * @return        true if successful, false otherwise
 */
static bool rohc_list_is_gen_id_known(const struct list_decomp *const decomp,
                                      const unsigned int gen_id)
{
	unsigned int i;

	assert(decomp != NULL);
	assert(decomp->list_table != NULL);

	for(i = 0; i < LIST_COMP_WINDOW; i++)
	{
		if(decomp->list_table[i] != NULL && decomp->list_table[i]->gen_id == gen_id)
		{
			/* entry found */
			return true;
		}
	}

	/* entry not found */
	return false;
}


/**
 * @brief Check if the item is correct in IPv6 table
 *
 * @param decomp       The list decompressor
 * @param index_table  The index of the item to check the presence
 * @return             true if item is found, false if not
 */
static bool check_ip6_item(const struct list_decomp *const decomp,
                           const size_t index_table)
{
	if(index_table > MAX_ITEM)
	{
		rd_list_debug(decomp, "no item in based table at position %zu\n",
		              index_table);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Create an IPv6 item extension list
 *
 * @param data         The data in the item
 * @param length       The length of the item
 * @param index_table  The index of the item in based table
 * @param decomp       The list decompressor
 * @return             true in case of success, false otherwise
*/
static bool create_ip6_item(const unsigned char *const data,
                            const size_t length,
                            const size_t index_table,
                            struct list_decomp *const decomp)
{
	assert(decomp != NULL);

	/* check minimal length for Next Header and Length fields */
	if(length < 2)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for Next Header and Length fields: "
		             "only %zd bytes available while at least 2 bytes are "
		             "required\n", length);
		goto error;
	}

	decomp->based_table[index_table].length = length;
	decomp->trans_table[index_table].known = 1;

	if(decomp->based_table[index_table].data != NULL)
	{
		zfree(decomp->based_table[index_table].data);
	}

	decomp->based_table[index_table].data = malloc(length);
	if(decomp->based_table[index_table].data == NULL)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "failed to allocate memory for new IPv6 item\n");
		goto error;
	}
	memcpy(decomp->based_table[index_table].data, data, length);

	return true;

error:
	decomp->based_table[index_table].data = NULL;
	decomp->based_table[index_table].length = 0;
	decomp->trans_table[index_table].known = 0;
	return false;
}


/**
 * @brief Decode an extension list type 0
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The length (in bytes) of the packet to decompress
 * @param gen_id      The id of the current list
 * @param ps          The ps field
 * @param m           The m field
 * @return            \li In case of success, the number of bytes read in the given
 *                        packet, ie. the length of the compressed list
 *                    \li -1 in case of failure
 */
static int rohc_list_decode_type_0(struct list_decomp *const decomp,
                                   const unsigned char *packet,
                                   size_t packet_len,
                                   const int gen_id,
                                   const int ps,
                                   const int m)
{
	size_t packet_read_length = 0;
	size_t xi_length; /* the length (in bytes) of the XI list */
	unsigned int xi_index; /* the index of the current XI in XI list */
	size_t item_read_length; /* the amount of bytes currently read in the item field */
	bool new_list;

	/* is the transmitted list a new one (ie. unknown gen_id) ? */
	new_list = !rohc_list_is_gen_id_known(decomp, gen_id);

	if(new_list) //new list
	{
		rd_list_debug(decomp, "creation of a new list\n");
		decomp->counter_list++;
		decomp->counter = 0;
		decomp->ref_ok = 0;
		if(decomp->counter_list >= LIST_COMP_WINDOW)
		{
			decomp->counter_list = 0;
		}
		if(decomp->list_table[decomp->counter_list] != NULL)
		{
			rohc_list_empty(decomp->list_table[decomp->counter_list]);
		}
		else
		{
			rd_list_debug(decomp, "creating compression list %d\n",
			              decomp->counter_list);
			decomp->list_table[decomp->counter_list] = list_create();
			if(decomp->list_table[decomp->counter_list] == NULL)
			{
				rohc_error(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
				           "cannot allocate memory for the compression list\n");
				goto error;
			}
			decomp->list_table[decomp->counter_list]->gen_id = gen_id;
		}
		decomp->counter++;
	}
	else if(decomp->counter < L)
	{
		decomp->counter++;
		if(decomp->counter == L)
		{
			assert(decomp->list_table[decomp->counter_list] != NULL);
			decomp->ref_list = decomp->list_table[decomp->counter_list];
			decomp->ref_ok = 1;
		}
	}
	rd_list_debug(decomp, "new value of decompressor list counter: %d\n",
	              decomp->counter);

	/* determine the length (in bytes) of the XI list */
	if(!ps)
	{
		/* 4-bit XIs */
		if((m % 2) == 0)
		{
			/* even number of XI fields */
			xi_length = m / 2;
		}
		else
		{
			/* odd number of XI fields, there are 4 bits of padding */
			xi_length = (m + 1) / 2;
		}
	}
	else
	{
		/* 8-bit XIs */
		xi_length = m;
	}

	/* is there enough room in packet for all the XI list ? */
	if(packet_len < xi_length)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for m = %d XI items (only %zd bytes "
		             "while at least %zd bytes are required)\n", m, packet_len,
		             xi_length);
		goto error;
	}

	/* creation of the list from the m XI items */
	item_read_length = 0;
	for(xi_index = 0; xi_index < m; xi_index++)
	{
		unsigned int xi_x_value; /* the value of the X field in one XI field */
		unsigned int xi_index_value; /* the value of the Index field in one XI field */

		if(!ps)
		{
			/* 4-bit XI */
			if((xi_index % 2) == 0)
			{
				/* 4-bit XI is stored in MSB */
				xi_x_value = GET_BIT_7(packet + xi_index / 2);
				xi_index_value = GET_BIT_4_6(packet);
			}
			else
			{
				/* 4-bit XI is stored in LSB */
				xi_x_value = GET_BIT_3(packet + xi_index / 2);
				xi_index_value = GET_BIT_0_2(packet);
			}
			if(!decomp->check_item(decomp, xi_index_value))
			{
				goto error;
			}

			/* is there a corresponding item in packet after the XI list ? */
			if(xi_x_value)
			{
				int item_length; /* the length (in bytes) of the item related to XI */

				/* is there enough room in packet for at least one byte of
				 * the item? */
				if(packet_len <= (xi_length + item_read_length))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "packet too small for at least 1 byte of item "
					             "for XI #%u (only %zd bytes available while more "
					             "than %zd bytes are required)\n", xi_index,
					             packet_len, xi_length + item_read_length);
					goto error;
				}

				/* X bit set in XI, so retrieve the related item in ROHC header */
				item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
				                                   packet_len - xi_length - item_read_length);
				if(item_length < 0)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "failed to determine the length of list item "
					             "referenced by XI #%d\n", xi_index);
					goto error;
				}

				/* is there enough room in packet for the full item? */
				if(packet_len < (xi_length + item_read_length + item_length))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "packet too small for the full item of XI #%u "
					             "(only %zd bytes available while at least "
					             "%zd bytes are required)\n", xi_index, packet_len,
					             xi_length + item_read_length + item_length);
					goto error;
				}

				if(new_list)
				{
					bool is_created =
						decomp->create_item(packet + xi_length + item_read_length,
						                    item_length, xi_index_value, decomp);
					if(!is_created)
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "failed to create new IPv6 item\n");
						goto error;
					}
				}

				/* skip the item in ROHC header */
				item_read_length += item_length;
			}
			else
			{
				/* X bit not set in XI, so item is not provided in ROHC header,
				   it must already be known by decompressor */
				if(!decomp->trans_table[xi_index_value].known)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "list item with index #%u referenced by XI "
					             "#%d is not known yet\n", xi_index_value, xi_index);
					goto error;
				}
			}
		}
		else
		{
			/* 8-bit XI */
			xi_x_value = GET_BIT_7(packet + xi_index);
			xi_index_value = GET_BIT_0_6(packet + xi_index);
			if(!decomp->check_item(decomp, xi_index_value))
			{
				goto error;
			}

			/* is there a corresponding item in packet after the XI list ? */
			if(xi_x_value)
			{
				int item_length; /* the length (in bytes) of the item related to XI */

				/* is there enough room in packet for at least one byte of
				 * the item? */
				if(packet_len <= (xi_length + item_read_length))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "packet too small for at least 1 byte of item "
					             "for XI #%u (only %zd bytes available while more "
					             "than %zd bytes are required)\n", xi_index,
					             packet_len, xi_length + item_read_length);
					goto error;
				}

				/* X bit set in XI, so retrieve the related item in ROHC header */
				item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
				                                   packet_len - xi_length - item_read_length);
				if(item_length < 0)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "failed to determine the length of list item "
					             "referenced by XI #%d\n", xi_index);
					goto error;
				}

				/* is there enough room in packet for the full item? */
				if(packet_len < (xi_length + item_read_length + item_length))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "packet too small for the full item of XI #%u "
					             "(only %zd bytes available while at least "
					             "%zd bytes are required)\n", xi_index, packet_len,
					             xi_length + item_read_length + item_length);
					goto error;
				}

				if(new_list)
				{
					bool is_created =
						decomp->create_item(packet + xi_length + item_read_length,
						                    item_length, xi_index_value, decomp);
					if(!is_created)
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "failed to create new IPv6 item\n");
						goto error;
					}
				}

				/* skip the item in ROHC header */
				item_read_length += item_length;
			}
			else
			{
				/* X bit not set in XI, so item is not provided in ROHC header,
				   it must already be known by decompressor */
				if(!decomp->trans_table[xi_index_value].known)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "list item with index #%u referenced by XI "
					             "#%d is not known yet\n", xi_index_value, xi_index);
					goto error;
				}
			}
		}

		if(new_list)
		{
			rd_list_debug(decomp, "insert a new item of type 0x%02x in list\n",
			              decomp->based_table[xi_index_value].type);
			if(!list_add_at_index(decomp->list_table[decomp->counter_list],
			                      &(decomp->based_table[xi_index_value]),
			                      xi_index, xi_index_value))
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
				             "failed to insert new item transmitted in "
				             "ROHC header at position #%d in new list\n", xi_index);
				goto error;
			}
		}
	}

	/* ensure that in case of an odd number of 4-bit XIs, the 4 bits of padding
	   are set to 0 */
	if(ps == 0 && (m % 2) != 0)
	{
		const uint8_t xi_padding = GET_BIT_0_3(packet + xi_length - 1);
		if(xi_padding != 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "sender does not conform to ROHC standards: when an "
			             "odd number of 4-bit XIs is used, the last 4 bits of the "
			             "XI list should be set to 0\n, not 0x%x\n", xi_padding);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}
	}

	/* skip the XI list and the item list */
	packet_read_length += xi_length + item_read_length;
	packet_len -= xi_length + item_read_length;

#if ROHC_EXTRA_DEBUG == 1
	{
		struct list_elt *elt;
		int i;

		/* print current list after reception */
		rd_list_debug(decomp, "current list (gen_id = %d) after reception:\n",
		              decomp->list_table[decomp->counter_list]->gen_id);
		i = 0;
		while((elt = list_get_elt_by_index(decomp->list_table[decomp->counter_list], i)) != NULL)
		{
			rd_list_debug(decomp, "   IPv6 extension of type 0x%02x / %d\n",
			              elt->item->type, elt->item->type);
			i++;
		}
	}
#endif

	return packet_read_length;

error:
	return -1;
}


/**
 * @brief Decode an extension list type 1
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The length (in bytes) of the packet to decompress
 * @param gen_id      The id of the current list
 * @param ps          The ps field
 * @param xi_1        The XI 1 field if PS = 1 (4-bit XI)
 * @return            \li In case of success, the number of bytes read in the
 *                        given packet, ie. the length of the compressed list
 *                    \li -1 in case of failure
 *
 * @todo factorize some code with \ref rohc_list_decode_type_3
 */
static int rohc_list_decode_type_1(struct list_decomp *const decomp,
                                   const unsigned char *packet,
                                   size_t packet_len,
                                   const int gen_id,
                                   const int ps,
                                   const int xi_1)
{
	size_t packet_read_length = 0;
	unsigned char mask[2]; /* insertion bit mask on 1-2 bytes */
	size_t mask_length; /* the length (in bits) of the insertion mask */
	size_t k; /* the number of ones in insertion mask and the number of elements in XI list */
	size_t xi_length; /* the length (in bytes) of the XI list */
	int xi_index; /* the index of the current XI in XI list */
	size_t item_read_length; /* the amount of bytes currently read in the item field */
	struct list_elt *elt;
	unsigned int ref_id;
	size_t ref_list_size;
	size_t ref_list_cur_pos; /* current position in reference list */
	bool new_list; /* whether we receive a new list or a known one */
	int i;

	assert(decomp != NULL);
	assert(packet != NULL);
	assert(ps == 0 || ps == 1);

	/* init mask[1] to avoid a false warning of GCC */
	mask[1] = 0x00;

	/* in case of 8-bit XI, the XI 1 field should be set to 0 */
	if(ps && xi_1 != 0)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "sender does not conform to ROHC standards: when 8-bit "
		             "XIs are used, the 4-bit XI 1 field should be set to 0, "
		             "not 0x%x\n", xi_1);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}

	/* is there enough data in packet for the ref_id and minimal insertion
	   bit mask fields ? */
	if(packet_len < 2)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for ref_id and minimal insertion bit "
		             "mask fields (only %zd bytes while at least 2 bytes are "
		             "required)\n", packet_len);
		goto error;
	}

	/* is the transmitted list a new one (ie. unknown gen_id) ? */
	new_list = !rohc_list_is_gen_id_known(decomp, gen_id);

	/* parse ref_id */
	ref_id = GET_BIT_0_7(packet);
	packet++;
	packet_read_length++;
	packet_len--;
	rd_list_debug(decomp, "ref_id = 0x%02x\n", ref_id);
	if(!rohc_list_is_gen_id_known(decomp, ref_id))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "unknown ID 0x%02x given for reference list\n", ref_id);
		goto error;
	}

	/* update the list table */
	if(decomp->ref_list == NULL || decomp->ref_list->gen_id != ref_id)
	{
		rd_list_debug(decomp, "reference list changed (gen_id %d -> gen_id %d) "
		              "since last packet, update list table in consequence\n",
		              decomp->ref_list == NULL ? -1 : decomp->ref_list->gen_id,
		              ref_id);
		for(i = 0; i < LIST_COMP_WINDOW; i++)
		{
			if(decomp->list_table[i] != NULL)
			{
				if(decomp->list_table[i]->gen_id < ref_id)
				{
					rohc_list_empty(decomp->list_table[i]);
				}
				else if(decomp->list_table[i]->gen_id == ref_id)
				{
					decomp->ref_list = decomp->list_table[i];
				}
			}
		}
	}
	assert(decomp->ref_list != NULL);

#if ROHC_EXTRA_DEBUG == 1
	/* print current list before update */
	rd_list_debug(decomp, "current list (gen_id = %d) before update:\n",
	              decomp->list_table[decomp->counter_list]->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(decomp->list_table[decomp->counter_list], i)) != NULL)
	{
		rd_list_debug(decomp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}
#endif

	if(new_list)
	{
		struct c_list *list;

		decomp->ref_ok = 0;
		decomp->counter = 0;
		rd_list_debug(decomp, "creation of a new list\n");
		decomp->counter_list++;
		if(decomp->counter_list >= LIST_COMP_WINDOW)
		{
			decomp->counter_list = 0;
		}
		if(decomp->list_table[decomp->counter_list] == decomp->ref_list)
		{
			decomp->counter_list++;
		}
		list = decomp->list_table[decomp->counter_list];
		if(list != NULL && list->first_elt != NULL)
		{
			rohc_list_empty(list);
		}
		else
		{
			rd_list_debug(decomp, "creating compression list %d\n",
			              decomp->counter_list);
			decomp->list_table[decomp->counter_list] = list_create();
			if(decomp->list_table[decomp->counter_list] == NULL)
			{
				rohc_error(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
				           "cannot allocate memory for the compression list\n");
				goto error;
			}
			decomp->list_table[decomp->counter_list]->gen_id = gen_id;
		}
	}

	/* determine the number of bits set to 1 in the insertion bit mask */
	k = 0;
	mask[0] = *packet;
	packet++;
	rd_list_debug(decomp, "insertion bit mask (first byte) = 0x%02x\n", mask[0]);

	for(i = 6; i >= 0; i--)
	{
		if(rohc_get_bit(mask[0], i))
		{
			k++;
		}
	}
	if(GET_REAL(GET_BIT_7(mask)) == 1)
	{
		/* 15-bit mask */
		if(packet_len < 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "packet too small for a 2-byte insertion bit mask "
			             "(only %zd bytes available)\n", packet_len);
			goto error;
		}
		mask_length = 15;
		mask[1] = *packet;
		packet++;
		rd_list_debug(decomp, "insertion bit mask (second byte) = 0x%02x\n", mask[1]);

		for(i = 7; i >= 0; i--)
		{
			if(rohc_get_bit(mask[1], i))
			{
				k++;
			}
		}

		/* skip the insertion mask */
		packet_read_length += 2;
		packet_len -= 2;
	}
	else
	{
		/* 7-bit mask */
		rd_list_debug(decomp, "no second byte of insertion bit mask\n");
		mask_length = 7;

		/* skip the insertion mask */
		packet_read_length++;
		packet_len--;
	}

	/* determine the length (in bytes) of the XI list */
	if(ps == 0)
	{
		/* 4-bit XI */
		if((k - 1) % 2 == 0)
		{
			/* odd number of 4-bit XI fields and first XI field stored in
			   first byte of header, so last byte is full */
			xi_length = (k - 1) / 2;
		}
		else
		{
			/* even number of 4-bit XI fields and first XI field stored in
			   first byte of header, so last byte is not full */
			xi_length = (k - 1) / 2 + 1;
		}
	}
	else
	{
		/* 8-bit XI */
		xi_length = k;
	}

	/* is there enough room in packet for all the XI list ? */
	if(packet_len < xi_length)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for k = %zd XI items (only %zd bytes "
		             "while at least %zd bytes are required)\n",
		             k, packet_len, xi_length);
		goto error;
	}

	/* insert of new items in the list */
	xi_index = 0;
	item_read_length = 0;
	ref_list_cur_pos = 0;
	ref_list_size = list_get_size(decomp->ref_list);
	for(i = 0; i < mask_length; i++)
	{
		int new_item_to_insert;

		/* retrieve the corresponding bit in the insertion mask */
		if(i < 7)
		{
			/* bit is located in first byte of insertion mask */
			new_item_to_insert = rohc_get_bit(mask[0], 6 - i);
		}
		else
		{
			/* bit is located in 2nd byte of insertion mask */
			new_item_to_insert = rohc_get_bit(mask[1], 14 - i);
		}

		/* insert item if required */
		if(!new_item_to_insert)
		{
			/* take the next item from reference list (if there no more item in
			   reference list, do nothing) */
			if(new_list && ref_list_cur_pos < ref_list_size)
			{
				rd_list_debug(decomp, "insert item from reference list "
				              "(index %zd) into current list (index %d)\n",
				              ref_list_cur_pos, i);
				elt = list_get_elt_by_index(decomp->ref_list, ref_list_cur_pos);
				if(!list_add_at_index(decomp->list_table[decomp->counter_list],
				                      elt->item, i, elt->index_table))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "failed to insert item from reference list "
					             "(index %zd) into current list (index %d)\n",
					             ref_list_cur_pos, i);
					goto error;
				}

				/* skip item in reference list */
				ref_list_cur_pos++;
			}
		}
		else
		{
			unsigned int xi_x_value; /* the value of the X field in one XI field */
			unsigned int xi_index_value; /* the value of the Index field in one XI field */
			int item_length; /* the length (in bytes) of the item related to XI */

			/* new item to insert in list, parse the related XI field */
			if(!ps)
			{
				/* ROHC header contains 4-bit XIs */

				/* which type of XI do we parse ? first one, odd one or even one ? */
				if(xi_index == 0)
				{
					/* first XI is stored in the first byte of the header */

					/* parse XI field */
					xi_x_value = GET_BIT_3(&xi_1);
					xi_index_value = GET_BIT_0_2(&xi_1);
					if(!decomp->check_item(decomp, xi_index_value))
					{
						goto error;
					}

					/* parse the corresponding item if present */
					if(xi_x_value)
					{
						/* is there enough room in packet for at least one byte
						 * of the item? */
						if(packet_len <= (xi_length + item_read_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for at least 1 byte of "
							             "item for XI #%u (only %zd bytes available "
							             "while more than %zd bytes are required)\n",
							             xi_index, packet_len,
							             xi_length + item_read_length);
							goto error;
						}

						/* X bit set in XI, so retrieve the related item in ROHC header */
						item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
						                                   packet_len - xi_length - item_read_length);
						if(item_length < 0)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "failed to determine the length of list item "
							             "referenced by XI #%d\n", xi_index);
							goto error;
						}

						/* is there enough room in packet for the full item? */
						if(packet_len < (xi_length + item_read_length + item_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for the full item of "
							             "XI #%u (only %zd bytes available while at "
							             "least %zd bytes are required)\n", xi_index,
							             packet_len, xi_length + item_read_length +
							             item_length);
							goto error;
						}

						if(new_list)
						{
							bool is_created =
								decomp->create_item(packet + xi_length + item_read_length,
								                    item_length, xi_index_value, decomp);
							if(!is_created)
							{
								rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
								             "failed to create new IPv6 item\n");
								goto error;
							}
						}

						/* skip the item in ROHC header */
						item_read_length += item_length;
					}
					else
					{
						/* X bit not set in XI, so item is not provided in ROHC header,
						   it must already be known by decompressor */
						if(!decomp->trans_table[xi_index_value].known)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "list item with index #%u referenced "
							             "by XI #%d is not known yet\n",
							             xi_index_value, xi_index);
							goto error;
						}
					}
				}
				else if((xi_index % 2) != 0)
				{
					/* handle odd XI, ie. XI stored in MSB */

					/* parse XI field */
					xi_x_value = GET_BIT_7(packet + (xi_index - 1) / 2);
					xi_index_value = GET_BIT_4_6(packet + (xi_index - 1) / 2);
					if(!decomp->check_item(decomp, xi_index_value))
					{
						goto error;
					}

					/* parse the corresponding item if present */
					if(xi_x_value)
					{
						/* is there enough room in packet for at least one byte
						 * of the item? */
						if(packet_len <= (xi_length + item_read_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for at least 1 byte of "
							             "item for XI #%u (only %zd bytes available "
							             "while more than %zd bytes are required)\n",
							             xi_index, packet_len,
							             xi_length + item_read_length);
							goto error;
						}

						/* X bit set in XI, so retrieve the related item in ROHC header */
						item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
						                                   packet_len - xi_length - item_read_length);
						if(item_length < 0)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "failed to determine the length of list item "
							             "referenced by XI #%d\n", xi_index);
							goto error;
						}

						/* is there enough room in packet for the full item? */
						if(packet_len < (xi_length + item_read_length + item_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for the full item of "
							             "XI #%u (only %zd bytes available while at "
							             "least %zd bytes are required)\n", xi_index,
							             packet_len, xi_length + item_read_length +
							             item_length);
							goto error;
						}

						if(new_list)
						{
							bool is_created =
								decomp->create_item(packet + xi_length + item_read_length,
								                    item_length, xi_index_value, decomp);
							if(!is_created)
							{
								rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
								             "failed to create new IPv6 item\n");
								goto error;
							}
						}

						/* skip the item in ROHC header */
						item_read_length += item_length;
					}
					else
					{
						/* X bit not set in XI, so item is not provided in ROHC header,
						   it must already be known by decompressor */
						assert(xi_index_value < MAX_ITEM);
						if(!decomp->trans_table[xi_index_value].known)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "list item with index #%u referenced "
							             "by XI #%d is not known yet\n",
							             xi_index_value, xi_index);
							goto error;
						}
					}
				}
				else
				{
					/* handle even XI, ie. XI stored in LSB */

					/* parse XI field */
					xi_x_value = GET_BIT_3(packet + (xi_index - 1) / 2);
					xi_index_value = GET_BIT_0_2(packet + (xi_index - 1) / 2);
					if(!decomp->check_item(decomp, xi_index_value))
					{
						goto error;
					}

					/* parse the corresponding item if present */
					if(xi_x_value)
					{
						/* is there enough room in packet for at least one byte
						 * of the item? */
						if(packet_len <= (xi_length + item_read_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for at least 1 byte of "
							             "item for XI #%u (only %zd bytes available "
							             "while more than %zd bytes are required)\n",
							             xi_index, packet_len,
							             xi_length + item_read_length);
							goto error;
						}

						/* X bit set in XI, so retrieve the related item in ROHC header */
						item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
						                                   packet_len - xi_length - item_read_length);
						if(item_length < 0)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "failed to determine the length of list item "
							             "referenced by XI #%d\n", xi_index);
							goto error;
						}

						/* is there enough room in packet for the full item? */
						if(packet_len < (xi_length + item_read_length + item_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for the full item of "
							             "XI #%u (only %zd bytes available while at "
							             "least %zd bytes are required)\n", xi_index,
							             packet_len, xi_length + item_read_length +
							             item_length);
							goto error;
						}

						if(new_list)
						{
							bool is_created =
								decomp->create_item(packet + xi_length + item_read_length,
								                    item_length, xi_index_value, decomp);
							if(!is_created)
							{
								rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
								             "failed to create new IPv6 item\n");
								goto error;
							}
						}

						/* skip the item in ROHC header */
						item_read_length += item_length;
					}
					else
					{
						/* X bit not set in XI, so item is not provided in ROHC header,
						   it must already be known by decompressor */
						assert(xi_index_value < MAX_ITEM);
						if(!decomp->trans_table[xi_index_value].known)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "list item with index #%u referenced "
							             "by XI #%d is not known yet\n",
							             xi_index_value, xi_index);
							goto error;
						}
					}
				}
			}
			else
			{
				/* ROHC header contains 8-bit XIs */

				/* parse XI field */
				xi_x_value = GET_BIT_3(packet + xi_index);
				xi_index_value = GET_BIT_0_2(packet + xi_index);
				if(!decomp->check_item(decomp, xi_index))
				{
					goto error;
				}

				/* parse the corresponding item if present */
				if(xi_x_value)
				{
					/* is there enough room in packet for at least one byte of
					 * the item? */
					if(packet_len <= (xi_length + item_read_length))
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "packet too small for at least 1 byte of item "
						             "for XI #%u (only %zd bytes available while "
						             "more than %zd bytes are required)\n",
						             xi_index, packet_len,
						             xi_length + item_read_length);
						goto error;
					}

					/* X bit set in XI, so retrieve the related item in ROHC header */
					item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
					                                   packet_len - xi_length - item_read_length);
					if(item_length < 0)
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "failed to determine the length of list item "
						             "referenced by XI #%d\n", xi_index);
						goto error;
					}

					/* is there enough room in packet for the full item? */
					if(packet_len < (xi_length + item_read_length + item_length))
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "packet too small for the full item of XI #%u "
						             "(only %zd bytes available while at least "
						             "%zd bytes are required)\n", xi_index,
						             packet_len, xi_length + item_read_length +
						             item_length);
						goto error;
					}

					if(new_list)
					{
						bool is_created =
							decomp->create_item(packet + xi_length + item_read_length,
							                    item_length, xi_index_value, decomp);
						if(!is_created)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "failed to create new IPv6 item\n");
							goto error;
						}
					}

					/* skip the item in ROHC header */
					item_read_length += item_length;
				}
				else
				{
					/* X bit not set in XI, so item is not provided in ROHC header,
					   it must already be known by decompressor */
					assert(xi_index_value < MAX_ITEM);
					if(!decomp->trans_table[xi_index_value].known)
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "list item with index #%u referenced "
						             "by XI #%d is not known yet\n",
						             xi_index_value, xi_index);
						goto error;
					}
				}
			}

			if(new_list)
			{
				rd_list_debug(decomp, "insert new item #%d into current list "
				              "(index %d)\n", xi_index, i);
				if(!list_add_at_index(decomp->list_table[decomp->counter_list],
				                      &(decomp->based_table[xi_index_value]),
				                      i, xi_index_value))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "failed to insert new item #%d into current list "
					             "(index %d)\n", xi_index, i);
					goto error;
				}
			}

			/* skip the XI we have just parsed */
			xi_index++;
		}
	}

	/* ensure that in case of an even number of 4-bit XIs, the 4 bits of padding
	   are set to 0 */
	if(ps == 0 && (k % 2) == 0)
	{
		const uint8_t xi_padding = GET_BIT_0_3(packet + xi_length - 1);
		if(xi_padding != 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "sender does not conform to ROHC standards: when an "
			             "even number of 4-bit XIs is used, the last 4 bits of the "
			             "XI list should be set to 0\n, not 0x%x\n", xi_padding);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}
	}

	/* skip the XI list and the item list */
	packet_read_length += xi_length + item_read_length;
	packet_len -= xi_length + item_read_length;

#if ROHC_EXTRA_DEBUG == 1
	/* print current list after update */
	rd_list_debug(decomp, "current list (gen_id = %d) after update:\n",
	              decomp->list_table[decomp->counter_list]->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(decomp->list_table[decomp->counter_list], i)) != NULL)
	{
		rd_list_debug(decomp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}
#endif

	/* does the received list becomes the new reference list ? */
	if(decomp->counter < L)
	{
		decomp->ref_ok = 0;
		decomp->counter++;
		if(decomp->counter == L)
		{
			assert(decomp->list_table[decomp->counter_list] != NULL);
			rd_list_debug(decomp, "received list (gen_id = %d) now becomes the "
			              "reference list\n",
			              decomp->list_table[decomp->counter_list]->gen_id);
			decomp->ref_list = decomp->list_table[decomp->counter_list];
			decomp->ref_ok = 1;
		}
	}

	return packet_read_length;

error:
	return -1;
}


/**
 * @brief Decode an extension list type 2
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The length (in bytes) of the packet to decompress
 * @param gen_id      The id of the current list
 * @param ps          The ps field
 * @return            \li In case of success, the number of bytes read in the given
 *                        packet, ie. the length of the compressed list
 *                    \li -1 in case of failure
 *
 * @todo factorize some code with \ref rohc_list_decode_type_3
 */
static int rohc_list_decode_type_2(struct list_decomp *const decomp,
                                   const unsigned char *packet,
                                   size_t packet_len,
                                   const int gen_id,
                                   const int ps)
{
	size_t packet_read_length = 0;
	unsigned char mask[2]; /* removal bit mask on 1-2 bytes */
	size_t mask_length; /* the length (in bits) of the removal mask */
	struct list_elt *elt;
	unsigned int ref_id;
	bool new_list;
	int i;

	/* init mask[1] to avoid a false warning of GCC */
	mask[1] = 0x00;

	/* is there enough data in packet for the ref_id and minimal removal
	   bit mask fields ? */
	if(packet_len < 2)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for ref_id and minimal removal bit "
		             "mask fields (only %zd bytes while at least 2 bytes are "
		             "required)\n", packet_len);
		goto error;
	}

	/* is the transmitted list a new one (ie. unknown gen_id) ? */
	new_list = !rohc_list_is_gen_id_known(decomp, gen_id);

	/* parse ref_id */
	ref_id = GET_BIT_0_7(packet);
	packet++;
	packet_read_length++;
	packet_len--;
	rd_list_debug(decomp, "ref_id = 0x%02x\n", ref_id);
	if(!rohc_list_is_gen_id_known(decomp, ref_id))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "unknown ID 0x%02x given for reference list\n", ref_id);
		goto error;
	}

	/* update the list table */
	if(decomp->ref_list == NULL || decomp->ref_list->gen_id != ref_id)
	{
		rd_list_debug(decomp, "reference list changed (gen_id %d -> gen_id %d) "
		              "since last packet, update list table in consequence\n",
		              decomp->ref_list == NULL ? -1 : decomp->ref_list->gen_id,
		              ref_id);
		for(i = 0; i < LIST_COMP_WINDOW; i++)
		{
			if(decomp->list_table[i] != NULL)
			{
				if(decomp->list_table[i]->gen_id < ref_id)
				{
					rohc_list_empty(decomp->list_table[i]);
				}
				else if(decomp->list_table[i]->gen_id == ref_id)
				{
					decomp->ref_list = decomp->list_table[i];
				}
			}
		}
	}
	assert(decomp->ref_list != NULL);

#if ROHC_EXTRA_DEBUG == 1
	/* print reference list before update */
	rd_list_debug(decomp, "reference list (gen_id = %d) used as base:\n",
	              decomp->ref_list->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(decomp->ref_list, i)) != NULL)
	{
		rd_list_debug(decomp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}
#endif

	/* determine the length removal bit mask */
	mask[0] = *packet;
	packet++;
	rd_list_debug(decomp, "removal bit mask (first byte) = 0x%02x\n", mask[0]);
	if(GET_REAL(GET_BIT_7(mask)) == 1)
	{
		/* 15-bit mask */
		if(packet_len < 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "packet too small for a 2-byte removal bit mask "
			             "(only %zd bytes available)\n", packet_len);
			goto error;
		}
		mask_length = 15;
		mask[1] = *packet;
		packet++;
		rd_list_debug(decomp, "removal bit mask (second byte) = 0x%02x\n", mask[1]);

		/* skip the removal mask */
		packet_read_length += 2;
		packet_len -= 2;
	}
	else
	{
		/* 7-bit mask */
		rd_list_debug(decomp, "no second byte of removal bit mask\n");
		mask_length = 7;

		/* skip the removal mask */
		packet_read_length++;
		packet_len--;
	}

	/* re-use known list or create of the new list if it is not already known */
	if(!new_list)
	{
		rd_list_debug(decomp, "re-use list with gen_id = %d found in context\n",
		              gen_id);
	}
	else
	{
		struct c_list *list;
		size_t new_list_len;
		size_t ref_list_size;

		rd_list_debug(decomp, "creation of a new list with gen_id = %d\n", gen_id);

		decomp->ref_ok = 0;
		decomp->counter = 0;
		decomp->counter_list = (decomp->counter_list + 1) % LIST_COMP_WINDOW;
		if(decomp->list_table[decomp->counter_list] == decomp->ref_list)
		{
			decomp->counter_list++;
		}
		list = decomp->list_table[decomp->counter_list];
		if(list != NULL && list->first_elt != NULL)
		{
			rohc_list_empty(list);
		}
		else
		{
			rd_list_debug(decomp, "creating compression list at index %d in "
			              "list table\n", decomp->counter_list);
			decomp->list_table[decomp->counter_list] = list_create();
			if(decomp->list_table[decomp->counter_list] == NULL)
			{
				rohc_error(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
				           "cannot allocate memory for the compression list\n");
				goto error;
			}
			decomp->list_table[decomp->counter_list]->gen_id = gen_id;
		}

		new_list_len = 0;
		ref_list_size = list_get_size(decomp->ref_list);
		for(i = 0; i < mask_length; i++)
		{
			int item_to_remove;

			/* retrieve the corresponding bit in the removal mask */
			if(i < 7)
			{
				/* bit is located in first byte of removal mask */
				item_to_remove = rohc_get_bit(mask[0], 6 - i);
			}
			else
			{
				/* bit is located in 2nd byte of insertion mask */
				item_to_remove = rohc_get_bit(mask[1], 14 - i);
			}

			/* remove item if required */
			if(item_to_remove)
			{
				/* skip item only if reference list is large enough */
				if(i < ref_list_size)
				{
					rd_list_debug(decomp, "skip item at index %d of reference "
					              "list\n", i);
				}
			}
			else
			{
				rd_list_debug(decomp, "take item at index %d of reference list "
				              "as item at index %zd of current list\n", i,
				              new_list_len);

				/* check that reference list is large enough */
				if(i >= ref_list_size)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "reference list is too short: item at index %d "
					             "requested while list contains only %zd items\n",
					             i, ref_list_size);
					goto error;
				}

				/* retrieve item from reference list and insert it in current list */
				elt = list_get_elt_by_index(decomp->ref_list, i);
				if(!list_add_at_index(decomp->list_table[decomp->counter_list],
				                      elt->item, new_list_len, elt->index_table))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "failed to insert item at index %zd "
					             "in current list\n", new_list_len);
					goto error;
				}

				new_list_len++;
			}
		}
	}

#if ROHC_EXTRA_DEBUG == 1
	/* print current list after update */
	rd_list_debug(decomp, "current list (gen_id = %d) decoded:\n",
	              decomp->list_table[decomp->counter_list]->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(decomp->list_table[decomp->counter_list], i)) != NULL)
	{
		rd_list_debug(decomp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}
#endif

	/* does the received list becomes the new reference list ? */
	if(decomp->counter < L)
	{
		decomp->ref_ok = 0;
		decomp->counter++;
		if(decomp->counter == L)
		{
			assert(decomp->list_table[decomp->counter_list] != NULL);
			rd_list_debug(decomp, "received list (gen_id = %d) now becomes the "
			              "reference list\n",
			              decomp->list_table[decomp->counter_list]->gen_id);
			decomp->ref_list = decomp->list_table[decomp->counter_list];
			decomp->ref_ok = 1;
		}
	}

	rd_list_debug(decomp, "new value of decompressor list counter: %d\n",
	              decomp->counter);

	return packet_read_length;

error:
	return -1;
}


/**
 * @brief Get the size (in bytes) of the extension
 *
 * @param data      The extension data
 * @param data_len  The length (in bytes) of the extension data
 * @return          The size of the extension in case of success,
 *                  -1 otherwise
 */
static int get_ip6_ext_size(const unsigned char *data, const size_t data_len)
{
	if(data_len < 2)
	{
		/* too few data for extension: at least 2 bytes of data are required */
		goto error;
	}

	return (data[1] + 1) * 8;

error:
	return -1;
}


/**
 * @brief Decode an extension list type 3
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The length (in bytes) of the packet to decompress
 * @param gen_id      The id of the current list
 * @param ps          The ps field
 * @param xi_1        The XI 1 field if PS = 1 (4-bit XI)
 * @return            \li In case of success, the number of bytes read in the given
 *                        packet, ie. the length of the compressed list
 *                    \li -1 in case of failure
 *
 * @todo factorize some code with \ref rohc_list_decode_type_1
 * @todo factorize some code with \ref rohc_list_decode_type_2
 */
static int rohc_list_decode_type_3(struct list_decomp *const decomp,
                                   const unsigned char *packet,
                                   size_t packet_len,
                                   const int gen_id,
                                   const int ps,
                                   const int xi_1)
{
	size_t packet_read_length = 0;
	unsigned char rem_mask[2]; /* removal bit mask on 1-2 bytes */
	unsigned char ins_mask[2]; /* insertion bit mask on 1-2 bytes */
	size_t rem_mask_length; /* the length (in bits) of the removal mask */
	size_t ins_mask_length; /* the length (in bits) of the insertion mask */
	size_t k; /* the number of ones in insertion mask and the number of elements in XI list */
	size_t xi_length; /* the length (in bytes) of the XI list */
	int xi_index; /* the index of the current XI in XI list */
	size_t item_read_length; /* the amount of bytes currently read in the item field */
	struct list_elt *elt;
	unsigned int ref_id;
	struct c_list removal_list; /* list after removal scheme but before insertion scheme */
	size_t removal_list_cur_pos; /* current position in list after removal */
	size_t removal_list_size; /* size of list after removal */
	bool new_list;
	int i;

	/* init rem_mask[1], ins_mask[1] and removal_list_size to avoid a false
	 * warning of GCC */
	rem_mask[1] = 0x00;
	ins_mask[1] = 0x00;
	removal_list_size = 0;

	/* in case of 8-bit XI, the XI 1 field should be set to 0 */
	if(ps && xi_1 != 0)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "sender does not conform to ROHC standards: when 8-bit "
		             "XIs are used, the 4-bit XI 1 field should be set to 0, "
		             "not 0x%x\n", xi_1);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}

	/* is there enough data in packet for the ref_id and minimal removal
	   bit mask fields ? */
	if(packet_len < 2)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for ref_id and minimal removal bit "
		             "mask fields (only %zd bytes while at least 1 bytes are "
		             "required)\n", packet_len);
		goto error;
	}

	/* is the transmitted list a new one (ie. unknown gen_id) ? */
	new_list = !rohc_list_is_gen_id_known(decomp, gen_id);

	/* parse ref_id */
	ref_id = GET_BIT_0_7(packet);
	packet++;
	packet_read_length++;
	packet_len--;
	rd_list_debug(decomp, "ref_id = 0x%02x\n", ref_id);
	if(!rohc_list_is_gen_id_known(decomp, ref_id))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "unknown ID 0x%02x given for reference list\n", ref_id);
		goto error;
	}

	/* update the list table */
	if(decomp->ref_list == NULL || decomp->ref_list->gen_id != ref_id)
	{
		rd_list_debug(decomp, "reference list changed (gen_id %d -> gen_id %d) "
		              "since last packet, update list table in consequence\n",
		              decomp->ref_list == NULL ? -1 : decomp->ref_list->gen_id,
		              ref_id);
		for(i = 0; i < LIST_COMP_WINDOW; i++)
		{
			if(decomp->list_table[i] != NULL)
			{
				if(decomp->list_table[i]->gen_id < ref_id)
				{
					rohc_list_empty(decomp->list_table[i]);
				}
				else if(decomp->list_table[i]->gen_id == ref_id)
				{
					decomp->ref_list = decomp->list_table[i];
				}
			}
		}
	}
	assert(decomp->ref_list != NULL);

#if ROHC_EXTRA_DEBUG == 1
	/* print reference list before update */
	rd_list_debug(decomp, "reference list (gen_id = %d) used as base:\n",
	              decomp->ref_list->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(decomp->ref_list, i)) != NULL)
	{
		rd_list_debug(decomp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}
#endif

	if(new_list)
	{
		decomp->ref_ok = 0;
		decomp->counter = 0;
		rd_list_debug(decomp, "creation of a new list\n");
		decomp->counter_list++;
		if(decomp->counter_list >= LIST_COMP_WINDOW)
		{
			decomp->counter_list = 0;
		}
		if(decomp->list_table[decomp->counter_list] == decomp->ref_list)
		{
			decomp->counter_list++;
		}
		if(decomp->list_table[decomp->counter_list] != NULL &&
		   decomp->list_table[decomp->counter_list]->first_elt != NULL)
		{
			rohc_list_empty(decomp->list_table[decomp->counter_list]);
		}
		else
		{
			rd_list_debug(decomp, "creating compression list %d\n",
			              decomp->counter_list);
			decomp->list_table[decomp->counter_list] = list_create();
			if(decomp->list_table[decomp->counter_list] == NULL)
			{
				rohc_error(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
				           "cannot allocate memory for the compression list\n");
				goto error;
			}
			rd_list_debug(decomp, "gen_id = %d \n", gen_id);
			decomp->list_table[decomp->counter_list]->gen_id = gen_id;
		}

		/* create a list for intermediate result after removal scheme but
		   before insertion scheme */
		removal_list.gen_id = gen_id;
		removal_list.first_elt = NULL;
	}

	/*
	 * Removal scheme
	 */

	/* determine the length removal bit mask */
	rem_mask[0] = *packet;
	packet++;
	rd_list_debug(decomp, "removal bit mask (first byte) = 0x%02x\n", rem_mask[0]);
	if(GET_REAL(GET_BIT_7(rem_mask)) == 1)
	{
		/* 15-bit mask */
		if(packet_len < 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "packet too small for a 2-byte removal bit mask "
			             "(only %zd bytes available)\n", packet_len);
			goto error;
		}
		rem_mask_length = 15;
		rem_mask[1] = *packet;
		packet++;
		rd_list_debug(decomp, "removal bit mask (second byte) = 0x%02x\n", rem_mask[1]);

		/* skip the removal mask */
		packet_read_length += 2;
		packet_len -= 2;
	}
	else
	{
		/* 7-bit mask */
		rd_list_debug(decomp, "no second byte of removal bit mask\n");
		rem_mask_length = 7;

		/* skip the removal mask */
		packet_read_length++;
		packet_len--;
	}

	/* re-use known list or create of the new list if it is not already known */
	if(!new_list)
	{
		rd_list_debug(decomp, "re-use list with gen_id = %d found in context\n",
		              gen_id);
	}
	else
	{
		size_t new_list_len = 0;
		size_t ref_list_size;

		ref_list_size = list_get_size(decomp->ref_list);
		for(i = 0; i < rem_mask_length; i++)
		{
			int item_to_remove;

			/* retrieve the corresponding bit in the removal mask */
			if(i < 7)
			{
				/* bit is located in first byte of removal mask */
				item_to_remove = rohc_get_bit(rem_mask[0], 6 - i);
			}
			else
			{
				/* bit is located in 2nd byte of insertion mask */
				item_to_remove = rohc_get_bit(rem_mask[1], 14 - i);
			}

			/* remove item if required */
			if(item_to_remove)
			{
				/* skip item only if reference list is large enough */
				if(i < ref_list_size)
				{
					rd_list_debug(decomp, "skip item at index %d of reference "
					              "list\n", i);
				}
			}
			else
			{
				rd_list_debug(decomp, "take item at index %d of reference list "
				              "as item at index %zd of current list\n", i,
				              new_list_len);

				/* check that reference list is large enough */
				if(i >= ref_list_size)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "reference list is too short: item at index %d "
					             "requested while list contains only %zd items\n",
					             i, ref_list_size);
					goto error;
				}

				/* retrieve item from reference list and insert it in current list */
				elt = list_get_elt_by_index(decomp->ref_list, i);
				if(!list_add_at_index(&removal_list, elt->item, new_list_len,
				                      elt->index_table))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "failed to insert element at position #%zd "
					             "in current list\n", new_list_len + 1);
					goto error;
				}

				new_list_len++;
			}
		}

#if ROHC_EXTRA_DEBUG == 1
		/* print current list after removal scheme */
		rd_list_debug(decomp, "current list (gen_id = %d) after removal scheme:\n",
		              removal_list.gen_id);
		i = 0;
		while((elt = list_get_elt_by_index(&removal_list, i)) != NULL)
		{
			rd_list_debug(decomp, "   IPv6 extension of type 0x%02x / %d\n",
			              elt->item->type, elt->item->type);
			i++;
		}
#endif
	}

	/*
	 * Insertion scheme
	 */

	/* is there enough data in packet for minimal insertion bit mask field ? */
	if(packet_len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for minimal insertion bit mask field "
		             "(only %zd bytes while at least 1 byte is required)\n", packet_len);
		goto error;
	}

	/* determine the number of bits set to 1 in the insertion bit mask */
	k = 0;
	ins_mask[0] = *packet;
	packet++;
	rd_list_debug(decomp, "insertion bit mask (first byte) = 0x%02x\n", ins_mask[0]);

	for(i = 6; i >= 0; i--)
	{
		if(rohc_get_bit(ins_mask[0], i))
		{
			k++;
		}
	}
	if(GET_REAL(GET_BIT_7(ins_mask)) == 1)
	{
		/* 15-bit mask */
		if(packet_len < 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "packet too small for a 2-byte insertion bit mask "
			             "(only %zd bytes available)\n", packet_len);
			goto error;
		}
		ins_mask_length = 15;
		ins_mask[1] = *packet;
		packet++;
		rd_list_debug(decomp, "insertion bit mask (second byte) = 0x%02x\n",
		              ins_mask[1]);

		for(i = 7; i >= 0; i--)
		{
			if(rohc_get_bit(ins_mask[1], i))
			{
				k++;
			}
		}

		/* skip the insertion mask */
		packet_read_length += 2;
		packet_len -= 2;
	}
	else
	{
		/* 7-bit mask */
		rd_list_debug(decomp, "no second byte of insertion bit mask\n");
		ins_mask_length = 7;

		/* skip the insertion mask */
		packet_read_length++;
		packet_len--;
	}

	/* determine the length (in bytes) of the XI list */
	if(ps == 0)
	{
		/* 4-bit XI */
		if((k - 1) % 2 == 0)
		{
			/* odd number of 4-bit XI fields and first XI field stored in
			   first byte of header, so last byte is full */
			xi_length = (k - 1) / 2;
		}
		else
		{
			/* even number of 4-bit XI fields and first XI field stored in
			   first byte of header, so last byte is not full */
			xi_length = (k - 1) / 2 + 1;
		}
	}
	else
	{
		/* 8-bit XI */
		xi_length = k;
	}

	/* is there enough room in packet for all the XI list ? */
	if(packet_len < xi_length)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
		             "packet too small for k = %zd XI items (only %zd bytes "
		             "while at least %zd bytes are required)\n", k, packet_len,
		             xi_length);
		goto error;
	}

	/* create current list with reference list and new provided items */
	xi_index = 0;
	item_read_length = 0;
	removal_list_cur_pos = 0;
	if(new_list)
	{
		removal_list_size = list_get_size(&removal_list);
	}
	for(i = 0; i < ins_mask_length; i++)
	{
		int new_item_to_insert;

		/* retrieve the corresponding bit in the insertion mask */
		if(i < 7)
		{
			/* bit is located in first byte of insertion mask */
			new_item_to_insert = rohc_get_bit(ins_mask[0], 6 - i);
		}
		else
		{
			/* bit is located in 2nd byte of insertion mask */
			new_item_to_insert = rohc_get_bit(ins_mask[1], 14 - i);
		}

		/* insert item if required */
		if(!new_item_to_insert)
		{
			/* take the next item from reference list (if there no more item in
			   reference list, do nothing) */
			if(new_list && removal_list_cur_pos < removal_list_size)
			{
				/* new list, insert the item from reference list */
				rd_list_debug(decomp, "insert item from reference list "
				              "(index %zd) into current list (index %d)\n",
				              removal_list_cur_pos, i);
				elt = list_get_elt_by_index(&removal_list, removal_list_cur_pos);
				if(!list_add_at_index(decomp->list_table[decomp->counter_list],
				                      elt->item, i, elt->index_table))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "failed to insert item from reference list "
					             "(index %zd) into current list (index %d)\n",
					             removal_list_cur_pos, i);
					goto error;
				}

				/* skip item in reference list */
				removal_list_cur_pos++;
			}
		}
		else
		{
			unsigned int xi_x_value; /* the value of the X field in one XI field */
			unsigned int xi_index_value; /* the value of the Index field in one XI field */
			int item_length; /* the length (in bytes) of the item related to XI */

			/* new item to insert in list, parse the related XI field */
			if(!ps)
			{
				/* ROHC header contains 4-bit XIs */

				/* which type of XI do we parse ? first one, odd one or even one ? */
				if(xi_index == 0)
				{
					/* first XI is stored in the first byte of the header */

					/* parse XI field */
					xi_x_value = GET_BIT_3(&xi_1);
					xi_index_value = GET_BIT_0_2(&xi_1);
					if(!decomp->check_item(decomp, xi_index_value))
					{
						goto error;
					}

					/* parse the corresponding item if present */
					if(xi_x_value)
					{
						/* is there enough room in packet for at least one byte
						 * of the item? */
						if(packet_len <= (xi_length + item_read_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for at least 1 byte of "
							             "item for XI #%u (only %zd bytes available "
							             "while more than %zd bytes are required)\n",
							             xi_index, packet_len,
							             xi_length + item_read_length);
							goto error;
						}

						/* X bit set in XI, so retrieve the related item in ROHC header */
						item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
						                                   packet_len - xi_length - item_read_length);
						if(item_length < 0)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "failed to determine the length of list item "
							             "referenced by XI #%d\n", xi_index);
							goto error;
						}

						/* is there enough room in packet for the full item? */
						if(packet_len < (xi_length + item_read_length + item_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for the full item of "
							             "XI #%u (only %zd bytes available while at "
							             "least %zd bytes are required)\n", xi_index,
							             packet_len, xi_length + item_read_length +
							             item_length);
							goto error;
						}

						if(new_list)
						{
							bool is_created;

							rd_list_debug(decomp, "record transmitted item #%d in "
							              "context (index %u)\n", xi_index,
							              xi_index_value);
							is_created =
								decomp->create_item(packet + xi_length + item_read_length,
								                    item_length, xi_index_value, decomp);
							if(!is_created)
							{
								rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
								             "failed to create new IPv6 item\n");
								goto error;
							}
						}

						/* skip the item in ROHC header */
						item_read_length += item_length;
					}
					else
					{
						/* X bit not set in XI, so item is not provided in ROHC header,
						   it must already be known by decompressor */
						assert(xi_index_value < MAX_ITEM);
						if(!decomp->trans_table[xi_index_value].known)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "list item with index #%u referenced "
							             "by XI #%d is not known yet\n",
							             xi_index_value, xi_index);
							goto error;
						}
					}
				}
				else if((xi_index % 2) != 0)
				{
					/* handle odd XI, ie. XI stored in MSB */

					/* parse XI field */
					xi_x_value = GET_BIT_7(packet + (xi_index - 1) / 2);
					xi_index_value = GET_BIT_4_6(packet + (xi_index - 1) / 2);
					if(!decomp->check_item(decomp, xi_index_value))
					{
						goto error;
					}

					/* parse the corresponding item if present */
					if(xi_x_value)
					{
						/* is there enough room in packet for at least one byte
						 * of the item? */
						if(packet_len <= (xi_length + item_read_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for at least 1 byte of "
							             "item for XI #%u (only %zd bytes available "
							             "while more than %zd bytes are required)\n",
							             xi_index, packet_len,
							             xi_length + item_read_length);
							goto error;
						}

						/* X bit set in XI, so retrieve the related item in ROHC header */
						item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
						                                   packet_len - xi_length - item_read_length);
						if(item_length < 0)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "failed to determine the length of list item "
							             "referenced by XI #%d\n", xi_index);
							goto error;
						}

						/* is there enough room in packet for the full item? */
						if(packet_len < (xi_length + item_read_length + item_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for the full item of "
							             "XI #%u (only %zd bytes available while at "
							             "least %zd bytes are required)\n", xi_index,
							             packet_len, xi_length + item_read_length +
							             item_length);
							goto error;
						}

						if(new_list)
						{
							bool is_created;

							rd_list_debug(decomp, "record transmitted item #%d in "
							              "context with index %u\n", xi_index,
							              xi_index_value);
							is_created =
								decomp->create_item(packet + xi_length + item_read_length,
								                    item_length, xi_index_value, decomp);
							if(!is_created)
							{
								rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
								             "failed to create new IPv6 item\n");
								goto error;
							}
						}

						/* skip the item in ROHC header */
						item_read_length += item_length;
					}
					else
					{
						/* X bit not set in XI, so item is not provided in ROHC header,
						   it must already be known by decompressor */
						assert(xi_index_value < MAX_ITEM);
						if(!decomp->trans_table[xi_index_value].known)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "list item with index #%u referenced "
							             "by XI #%d is not known yet\n",
							             xi_index_value, xi_index);
							goto error;
						}
					}
				}
				else
				{
					/* handle even XI, ie. XI stored in LSB */

					/* parse XI field */
					xi_x_value = GET_BIT_3(packet + (xi_index - 1) / 2);
					xi_index_value = GET_BIT_0_2(packet + (xi_index - 1) / 2);
					if(!decomp->check_item(decomp, xi_index_value))
					{
						goto error;
					}

					/* parse the corresponding item if present */
					if(xi_x_value)
					{
						/* is there enough room in packet for at least one byte
						 * of the item? */
						if(packet_len <= (xi_length + item_read_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for at least 1 byte of "
							             "item for XI #%u (only %zd bytes available "
							             "while more than %zd bytes are required)\n",
							             xi_index, packet_len,
							             xi_length + item_read_length);
							goto error;
						}

						/* X bit set in XI, so retrieve the related item in ROHC header */
						item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
						                                   packet_len - xi_length - item_read_length);
						if(item_length < 0)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "failed to determine the length of list item "
							             "referenced by XI #%d\n", xi_index);
							goto error;
						}

						/* is there enough room in packet for the full item? */
						if(packet_len < (xi_length + item_read_length + item_length))
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "packet too small for the full item of "
							             "XI #%u (only %zd bytes available while at "
							             "least %zd bytes are required)\n", xi_index,
							             packet_len, xi_length + item_read_length +
							             item_length);
							goto error;
						}

						if(new_list)
						{
							bool is_created;

							rd_list_debug(decomp, "record transmitted item #%d in "
							              "context with index %u\n", xi_index,
							              xi_index_value);
							is_created =
								decomp->create_item(packet + xi_length + item_read_length,
								                    item_length, xi_index_value, decomp);
							if(!is_created)
							{
								rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
								             "failed to create new IPv6 item\n");
								goto error;
							}
						}

						/* skip the item in ROHC header */
						item_read_length += item_length;
					}
					else
					{
						/* X bit not set in XI, so item is not provided in ROHC header,
						   it must already be known by decompressor */
						assert(xi_index_value < MAX_ITEM);
						if(!decomp->trans_table[xi_index_value].known)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "list item with index #%u referenced "
							             "by XI #%d is not known yet\n",
							             xi_index_value, xi_index);
							goto error;
						}
					}
				}
			}
			else
			{
				/* ROHC header contains 8-bit XIs */

				/* parse XI field */
				xi_x_value = GET_BIT_3(packet + xi_index);
				xi_index_value = GET_BIT_0_2(packet + xi_index);
				if(!decomp->check_item(decomp, xi_index_value))
				{
					goto error;
				}

				/* parse the corresponding item if present */
				if(xi_x_value)
				{
					/* is there enough room in packet for at least one byte of
					 * the item? */
					if(packet_len <= (xi_length + item_read_length))
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "packet too small for at least 1 byte of item "
						             "for XI #%u (only %zd bytes available while "
						             "more than %zd bytes are required)\n",
						             xi_index, packet_len,
						             xi_length + item_read_length);
						goto error;
					}

					/* X bit set in XI, so retrieve the related item in ROHC header */
					item_length = decomp->get_ext_size(packet + xi_length + item_read_length,
					                                   packet_len - xi_length - item_read_length);
					if(item_length < 0)
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "failed to determine the length of list item "
						             "referenced by XI #%d\n", xi_index);
						goto error;
					}

					/* is there enough room in packet for the full item? */
					if(packet_len < (xi_length + item_read_length + item_length))
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "packet too small for the full item of XI #%u "
						             "(only %zd bytes available while at least "
						             "%zd bytes are required)\n", xi_index,
						             packet_len, xi_length + item_read_length +
						             item_length);
						goto error;
					}

					if(new_list)
					{
						bool is_created;

						rd_list_debug(decomp, "record transmitted item #%d in "
						              "context with index %u\n", xi_index,
						              xi_index_value);
						is_created =
							decomp->create_item(packet + xi_length + item_read_length,
							                    item_length, xi_index_value, decomp);
						if(!is_created)
						{
							rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
							             "failed to create new IPv6 item\n");
							goto error;
						}
					}

					/* skip the item in ROHC header */
					item_read_length += item_length;
				}
				else
				{
					/* X bit not set in XI, so item is not provided in ROHC header,
					   it must already be known by decompressor */
					if(!decomp->trans_table[xi_index_value].known)
					{
						rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
						             "list item with index #%u referenced "
						             "by XI #%d is not known yet\n",
						             xi_index_value, xi_index);
						goto error;
					}
				}
			}

			if(new_list)
			{
				rd_list_debug(decomp, "insert new item from context (index %u) "
				              "into current list (index %d)\n", xi_index_value, i);
				if(!list_add_at_index(decomp->list_table[decomp->counter_list],
				                      &(decomp->based_table[xi_index_value]),
				                      i, xi_index_value))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
					             "failed to insert new item from context "
					             "(index %u) into current list (index %d)\n",
					             xi_index_value, i);
					goto error;
				}
			}

			/* skip the XI we have just parsed */
			xi_index++;
		}
	}

	/* ensure that in case of an even number of 4-bit XIs, the 4 bits of padding
	   are set to 0 */
	if(ps == 0 && (k % 2) == 0)
	{
		const uint8_t xi_padding = GET_BIT_0_3(packet + xi_length - 1);
		if(xi_padding != 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			             "sender does not conform to ROHC standards: when an "
			             "even number of 4-bit XIs is used, the last 4 bits of the "
			             "XI list should be set to 0\n, not 0x%x\n", xi_padding);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}
	}

	/* skip the XI list and the item list */
	packet_read_length += xi_length + item_read_length;
	packet_len -= xi_length + item_read_length;

#if ROHC_EXTRA_DEBUG == 1
	/* print current list after insertion scheme */
	rd_list_debug(decomp, "current list (gen_id = %d) decoded:\n",
	              decomp->list_table[decomp->counter_list]->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(decomp->list_table[decomp->counter_list], i)) != NULL)
	{
		rd_list_debug(decomp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}
#endif

	/* does the received list becomes the new reference list ? */
	if(decomp->counter < L)
	{
		decomp->ref_ok = 0;
		decomp->counter++;
		if(decomp->counter == L)
		{
			assert(decomp->list_table[decomp->counter_list] != NULL);
			rd_list_debug(decomp, "received list (gen_id = %d) now becomes the "
			              "reference list\n",
			              decomp->list_table[decomp->counter_list]->gen_id);
			decomp->ref_list = decomp->list_table[decomp->counter_list];
			decomp->ref_ok = 1;
		}
	}

	rd_list_debug(decomp, "new value of decompressor list counter: %d\n",
	              decomp->counter);

	return packet_read_length;

error:
	return -1;
}


/**
 * @brief Get the bit in the given byte at the given position
 *
 * @param byte   The byte to analyse
 * @param pos    The position between 0 and 7
 * @return       The requested bit
 */
static uint8_t rohc_get_bit(const unsigned char byte, const size_t pos)
{
	uint8_t bit;

	switch(pos)
	{
		case 0:
			bit = GET_BIT_0(&byte);
			break;
		case 1:
			bit = GET_BIT_1(&byte) >> 1;
			break;
		case 2:
			bit = GET_BIT_2(&byte) >> 2;
			break;
		case 3:
			bit = GET_BIT_3(&byte) >> 3;
			break;
		case 4:
			bit = GET_BIT_4(&byte) >> 4;
			break;
		case 5:
			bit = GET_BIT_5(&byte) >> 5;
			break;
		case 6:
			bit = GET_BIT_6(&byte) >> 6;
			break;
		case 7:
			bit = GET_BIT_7(&byte) >> 7;
			break;
		default:
			/* there is no such bit in a byte */
			assert(0); /* should not happen */
			bit = 0;
			break;
	}

	return bit;
}


/**
 * @brief Parse one IR, IR-DYN, UO-0, UO-1*, or UOR-2* packet
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the ROHC header
 * @param rohc_hdr_len   OUT: The size of the ROHC header
 * @return               true if packet is successfully parsed, false otherwise
 *
 * @see parse_ir
 * @see parse_irdyn
 * @see parse_uo0
 * @see parse_uo1
 * @see parse_uo1rtp
 * @see parse_uo1id
 * @see parse_uo1ts
 * @see parse_uor2
 * @see parse_uor2rtp
 * @see parse_uor2id
 * @see parse_uor2ts
 */
static bool parse_packet(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_packet,
                         const size_t rohc_length,
                         const size_t large_cid_len,
                         rohc_packet_t *const packet_type,
                         struct rohc_extr_bits *const bits,
                         size_t *const rohc_hdr_len)
{
	bool (*parse) (const struct rohc_decomp *const decomp,
	               const struct d_context *const context,
	               const unsigned char *const rohc_packet,
	               const size_t rohc_length,
	               const size_t large_cid_len,
	               rohc_packet_t *const packet_type,
	               struct rohc_extr_bits *const bits,
	               size_t *const rohc_hdr_len);

	assert(decomp != NULL);
	assert(context != NULL);
	assert(rohc_packet != NULL);
	assert(packet_type != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	/* what function to call for parsing the packet? */
	switch(*packet_type)
	{
		case ROHC_PACKET_IR:
		{
			parse = parse_ir;
			break;
		}
		case ROHC_PACKET_IR_DYN:
		{
			parse = parse_irdyn;
			break;
		}
		case ROHC_PACKET_UO_0:
		{
			parse = parse_uo0;
			break;
		}
		case ROHC_PACKET_UO_1:
		{
			parse = parse_uo1;
			break;
		}
		case ROHC_PACKET_UO_1_RTP:
		{
			parse = parse_uo1rtp;
			break;
		}
		case ROHC_PACKET_UO_1_ID:
		{
			parse = parse_uo1id;
			break;
		}
		case ROHC_PACKET_UO_1_TS:
		{
			parse = parse_uo1ts;
			break;
		}
		case ROHC_PACKET_UOR_2:
		{
			parse = parse_uor2;
			break;
		}
		case ROHC_PACKET_UOR_2_RTP:
		{
			parse = parse_uor2rtp;
			break;
		}
		case ROHC_PACKET_UOR_2_TS:
		{
			parse = parse_uor2ts;
			break;
		}
		case ROHC_PACKET_UOR_2_ID:
		{
			parse = parse_uor2id;
			break;
		}
		default:
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "unknown packet type (%d)\n", *packet_type);
			goto error;
		}
	}

	/* let's parse the packet! */
	return parse(decomp, context, rohc_packet, rohc_length, large_cid_len,
	             packet_type, bits, rohc_hdr_len);

error:
	return false;
}


/**
 * @brief Parse one IR packet
 *
 * \verbatim

 IR packet (5.7.7.1):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  |         Add-CID octet         |  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   1   0 | D |
    +---+---+---+---+---+---+---+---+
    |                               |
 3  /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
 4  |            Profile            |  1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              |  1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  |         Static chain          |  variable length
    |                               |
    +---+---+---+---+---+---+---+---+
    |                               |
 7  |         Dynamic chain         |  present if D = 1, variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 8  |             SN                |  2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    |                               |
    |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the IR header
 * @param rohc_hdr_len   OUT: The size of the IR header
 * @return               true if IR is successfully parsed, false otherwise
 */
static bool parse_ir(const struct rohc_decomp *const decomp,
                     const struct d_context *const context,
                     const unsigned char *const rohc_packet,
                     const size_t rohc_length,
                     const size_t large_cid_len,
                     rohc_packet_t *const packet_type,
                     struct rohc_extr_bits *const bits,
                     size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context = context->specific;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* helper variables for values returned by functions */
	bool dynamic_present;
	int size;

	assert(g_context != NULL);
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);
	bits->crc_type = ROHC_CRC_TYPE_NONE;

	/* packet must large enough for:
	 * IR type + (large CID + ) Profile ID + CRC */
	if(rohc_remain_len < (1 + large_cid_len + 2))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* is the dynamic flag set ? */
	dynamic_present = !!GET_BIT_0(rohc_remain_data);

	/* skip the IR type, optional large CID bytes, and Profile ID */
	rohc_remain_data += large_cid_len + 2;
	rohc_remain_len -= large_cid_len + 2;
	*rohc_hdr_len += large_cid_len + 2;

	/* parse CRC */
	bits->crc = GET_BIT_0_7(rohc_remain_data);
	bits->crc_nr = 8;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* decode the static part of the outer header */
	size = parse_static_part_ip(context, rohc_remain_data, rohc_remain_len,
	                            &bits->outer_ip);
	if(size == -1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "cannot parse the outer IP static part\n");
		goto error;
	}
	rohc_remain_data += size;
	rohc_remain_len -= size;
	*rohc_hdr_len += size;

	/* check for IP version switch during context re-use */
	if(context->num_recv_packets > 1 &&
	   bits->outer_ip.version != ip_get_version(&g_context->outer_ip_changes->ip))
	{
		rohc_decomp_debug(context, "outer IP version mismatch (packet = %d, "
		                  "context = %d) -> context is being reused\n",
		                  bits->outer_ip.version,
		                  ip_get_version(&g_context->outer_ip_changes->ip));
		bits->is_context_reused = true;
	}

	/* check for the presence of a second IP header */
	assert(bits->outer_ip.proto_nr == 8);
	if(bits->outer_ip.proto == ROHC_IPPROTO_IPIP ||
	   bits->outer_ip.proto == ROHC_IPPROTO_IPV6)
	{
		rohc_decomp_debug(context, "second IP header detected\n");

		/* check for 1 to 2 IP headers switch during context re-use */
		if(context->num_recv_packets > 1 && !g_context->multiple_ip)
		{
			rohc_decomp_debug(context, "number of IP headers mismatch (packet "
			                  "= 2, context = 1) -> context is being reused\n");
			bits->is_context_reused = true;
		}

		/* update context */
		g_context->multiple_ip = 1;
	}
	else
	{
		/* check for 2 to 1 IP headers switch during context re-use */
		if(context->num_recv_packets > 1 && g_context->multiple_ip)
		{
			rohc_decomp_debug(context, "number of IP headers mismatch (packet "
			                  "= 1, context = 2) -> context is being reused\n");
			bits->is_context_reused = true;
		}

		/* update context */
		g_context->multiple_ip = 0;
	}

	/* decode the static part of the inner IP header
	 * if multiple IP headers */
	if(g_context->multiple_ip)
	{
		size = parse_static_part_ip(context, rohc_remain_data, rohc_remain_len,
		                            &bits->inner_ip);
		if(size == -1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot parse the inner IP static part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		*rohc_hdr_len += size;

		/* check for IP version switch during context re-use */
		if(context->num_recv_packets > 1 &&
		   bits->inner_ip.version != ip_get_version(&g_context->inner_ip_changes->ip))
		{
			rohc_decomp_debug(context, "inner IP version mismatch (packet = %d, "
			                  "context = %d) -> context is being reused\n",
			                  bits->inner_ip.version,
			                  ip_get_version(&g_context->inner_ip_changes->ip));
			bits->is_context_reused = true;
		}
	}

	/* parse the static part of the next header header if necessary */
	if(g_context->parse_static_next_hdr != NULL)
	{
		size = g_context->parse_static_next_hdr(context, rohc_remain_data,
		                                        rohc_remain_len, bits);
		if(size == -1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot parse the next header static part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		*rohc_hdr_len += size;
	}

	/* decode the dynamic part of the ROHC packet */
	if(dynamic_present)
	{
		/* decode the dynamic part of the outer IP header */
		size = parse_dynamic_part_ip(context, rohc_remain_data, rohc_remain_len,
		                             &bits->outer_ip,
		                             g_context->list_decomp1);
		if(size == -1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot parse the outer IP dynamic part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		*rohc_hdr_len += size;

		/* decode the dynamic part of the inner IP header */
		if(g_context->multiple_ip)
		{
			size = parse_dynamic_part_ip(context, rohc_remain_data, rohc_remain_len,
			                             &bits->inner_ip,
			                             g_context->list_decomp2);
			if(size == -1)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "cannot parse the inner IP dynamic part\n");
				goto error;
			}
			rohc_remain_data += size;
			rohc_remain_len -= size;
			*rohc_hdr_len += size;
		}

		/* parse the dynamic part of the next header header if necessary */
		if(g_context->parse_dyn_next_hdr != NULL)
		{
			size = g_context->parse_dyn_next_hdr(context, rohc_remain_data,
			                                     rohc_remain_len, bits);
			if(size == -1)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "cannot parse the next header dynamic part\n");
				goto error;
			}
			rohc_remain_data += size;
			rohc_remain_len -= size;
			*rohc_hdr_len += size;
		}
	}
	else if(context->state != ROHC_DECOMP_STATE_FC)
	{
		/* in 'Static Context' or 'No Context' state and the packet does not
		 * contain a dynamic part */
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "receive IR packet without a dynamic part, but not "
		             "in Full Context state\n");
		goto error;
	}

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* IR packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse the IP static part of a ROHC packet.
 *
 * See 5.7.7.3 and 5.7.7.4 in RFC 3095 for details.
 *
 * @param context     The decompression context
 * @param packet      The ROHC packet to parse
 * @param length      The length of the ROHC packet
 * @param bits        OUT: The bits extracted from the IP static part
 * @return            The number of bytes read in the ROHC packet,
 *                    -1 in case of failure
 */
static int parse_static_part_ip(const struct d_context *const context,
                                const unsigned char *const packet,
                                const size_t length,
                                struct rohc_extr_ip_bits *const bits)
{
	int read; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the IP version */
	if(length < 1)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zu)\n", length);
		goto error;
	}

	/* retrieve the IP version */
	bits->version = GET_BIT_4_7(packet);

	/* reject non IPv4/IPv6 packets */
	if(bits->version != IPV4 && bits->version != IPV6)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "unsupported IP version (%d)\n", bits->version);
		goto error;
	}

	/* decode the static part of the IP header depending on the IP version */
	if(bits->version == IPV4)
	{
		read = parse_static_part_ipv4(context, packet, length, bits);
	}
	else /* IPV6 */
	{
		read = parse_static_part_ipv6(context, packet, length, bits);
	}

	return read;

error:
	return -1;
}


/**
 * @brief Parse the IPv4 static part of a ROHC packet.
 *
 * See 5.7.7.4 in RFC 3095 for details.
 *
 * @param context  The decompression context
 * @param packet   The ROHC packet to parse
 * @param length   The length of the ROHC packet
 * @param bits     OUT: The bits extracted from the IPv4 static part
 * @return         The number of bytes read in the ROHC packet,
 *                 -1 in case of failure
 */
static int parse_static_part_ipv4(const struct d_context *const context,
                                  const unsigned char *packet,
                                  const size_t length,
                                  struct rohc_extr_ip_bits *const bits)
{
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the IPv4 static part */
	if(length < 10)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zu)\n", length);
		goto error;
	}

	/* IP version already read by \ref parse_static_part_ip */
	rohc_decomp_debug(context, "IP Version = %d\n", bits->version);
	packet++;
	read++;

	/* read the protocol number */
	bits->proto = GET_BIT_0_7(packet);
	bits->proto_nr = 8;
	rohc_decomp_debug(context, "Protocol = 0x%02x\n", bits->proto);
	packet++;
	read++;

	/* read the source IP address */
	memcpy(bits->saddr, packet, 4);
	bits->saddr_nr = 32;
	rohc_decomp_debug(context, "Source Address = " IPV4_ADDR_FORMAT "\n",
	                  IPV4_ADDR_RAW(bits->saddr));
	packet += 4;
	read += 4;

	/* read the destination IP address */
	memcpy(bits->daddr, packet, 4);
	bits->daddr_nr = 32;
	rohc_decomp_debug(context, "Destination Address = " IPV4_ADDR_FORMAT "\n",
	                  IPV4_ADDR_RAW(bits->daddr));
	packet += 4;
	read += 4;

	return read;

error:
	return -1;
}


/**
 * @brief Parse the IPv6 static part of a ROHC packet.
 *
 * See 5.7.7.3 in RFC 3095 for details.
 *
 * @param context  The decompression context
 * @param packet   The ROHC packet to parse
 * @param length   The length of the ROHC packet
 * @param bits     OUT: The bits extracted from the IPv6 static part
 * @return         The number of bytes read in the ROHC packet,
 *                 -1 in case of failure
 */
static int parse_static_part_ipv6(const struct d_context *const context,
                                  const unsigned char *packet,
                                  const size_t length,
                                  struct rohc_extr_ip_bits *const bits)
{
	int read = 0; /* number of bytes read from the packet */

	assert(context != NULL);
	assert(packet != NULL);
	assert(bits != NULL);

	/* check the minimal length to decode the IPv6 static part */
	if(length < 36)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zu)\n", length);
		goto error;
	}

	/* IP version already read by \ref parse_static_part_ip */
	rohc_decomp_debug(context, "IP Version = %d\n", bits->version);

	/* read the flow label */
	bits->flowid = (GET_BIT_0_3(packet) << 16) |
	               (GET_BIT_0_7(packet + 1) << 8) |
	               GET_BIT_0_7(packet + 2);
	bits->flowid_nr = 20;
	rohc_decomp_debug(context, "Flow Label = 0x%05x\n", bits->flowid);
	packet += 3;
	read += 3;

	/* read the next header value */
	bits->proto = GET_BIT_0_7(packet);
	bits->proto_nr = 8;
	rohc_decomp_debug(context, "Next Header = 0x%02x\n", bits->proto);
	packet++;
	read++;

	/* read the source IP address */
	memcpy(bits->saddr, packet, 16);
	bits->saddr_nr = 128;
	rohc_decomp_debug(context, "Source Address = " IPV6_ADDR_FORMAT "\n",
	                  IPV6_ADDR_RAW(bits->saddr));
	packet += 16;
	read += 16;

	/* read the destination IP address */
	memcpy(bits->daddr, packet, 16);
	bits->daddr_nr = 128;
	rohc_decomp_debug(context, "Destination Address = " IPV6_ADDR_FORMAT "\n",
	                  IPV6_ADDR_RAW(bits->daddr));
	packet += 16;
	read += 16;

	return read;

error:
	return -1;
}


/**
 * @brief Parse the IP dynamic part of a ROHC packet.
 *
 * See 5.7.7.3 and 5.7.7.4 in RFC 3095 for details.
 *
 * @param context     The decompression context
 * @param packet      The ROHC packet to parse
 * @param length      The length of the ROHC packet
 * @param bits        OUT: The bits extracted from the IP dynamic part
 * @param list_decomp The list decompressor (only for IPv6)
 * @return            The number of bytes read in the ROHC packet,
 *                    -1 in case of failure
 */
static int parse_dynamic_part_ip(const struct d_context *const context,
                                 const unsigned char *const packet,
                                 const size_t length,
                                 struct rohc_extr_ip_bits *const bits,
                                 struct list_decomp *const list_decomp)
{
	int read; /* number of bytes read from the packet */

	/* decode the dynamic part of the IP header depending on the IP version */
	if(bits->version == IPV4)
	{
		read = parse_dynamic_part_ipv4(context, packet, length, bits);
	}
	else /* IPV6 */
	{
		read = parse_dynamic_part_ipv6(context, packet, length, bits, list_decomp);
	}

	return read;
}


/**
 * @brief Decode the IPv4 dynamic part of a ROHC packet.
 *
 * See 5.7.7.4 in RFC 3095 for details. Generic extension header list is not
 * managed yet.
 * See 3.3 in RFC 3843 for details on the Static IP Identifier (SID) flag.
 *
 * \verbatim

Dynamic part:

      +---+---+---+---+---+---+---+---+
      |        Type of Service        |
      +---+---+---+---+---+---+---+---+
      |         Time to Live          |
      +---+---+---+---+---+---+---+---+
      /        Identification         /   2 octets, sent verbatim
      +---+---+---+---+---+---+---+---+
      | DF|RND|NBO|SID|       0       |
      +---+---+---+---+---+---+---+---+
      / Generic extension header list /  variable length
      +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context  The decompression context
 * @param packet   The ROHC packet to decode
 * @param length   The length of the ROHC packet
 * @param bits     OUT: The bits extracted from the IP dynamic part
 * @return         The number of bytes read in the ROHC packet,
 *                 -1 in case of failure
 */
static int parse_dynamic_part_ipv4(const struct d_context *const context,
                                   const unsigned char *packet,
                                   const size_t length,
                                   struct rohc_extr_ip_bits *const bits)
{
	/* The size (in bytes) of the IPv4 dynamic part:
	 *
	 *   1 (TOS) + 1 (TTL) + 2 (IP-ID) + 1 (flags) + 1 (header list) = 6 bytes
	 *
	 * The size of the generic extension header list field is considered
	 * constant because generic extension header list is not supported yet and
	 * thus 1 byte of zero is used. */
	const size_t ipv4_dyn_size = 6;
	int read = 0; /* number of bytes read from the packet */

	/* check the minimal length to decode the IPv4 dynamic part */
	if(length < ipv4_dyn_size)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zu)\n", length);
		goto error;
	}

	/* read the TOS field */
	bits->tos = GET_BIT_0_7(packet);
	bits->tos_nr = 8;
	rohc_decomp_debug(context, "TOS = 0x%02x\n", bits->tos);
	packet++;
	read++;

	/* read the TTL field */
	bits->ttl = GET_BIT_0_7(packet);
	bits->ttl_nr = 8;
	rohc_decomp_debug(context, "TTL = 0x%02x\n", bits->ttl);
	packet++;
	read++;

	/* read the IP-ID field */
	bits->id = GET_NEXT_16_BITS(packet);
	bits->id_nr = 16;
	bits->is_id_enc = false;
	rohc_decomp_debug(context, "IP-ID = 0x%04x\n", bits->id);
	packet += 2;
	read += 2;

	/* read the DF flag */
	bits->df = GET_REAL(GET_BIT_7(packet));
	bits->df_nr = 1;

	/* read the RND flag */
	bits->rnd = GET_REAL(GET_BIT_6(packet));
	bits->rnd_nr = 1;

	/* read the NBO flag */
	bits->nbo = GET_REAL(GET_BIT_5(packet));
	bits->nbo_nr = 1;

	/* read the SID flag */
	bits->sid = GET_REAL(GET_BIT_4(packet));
	bits->sid_nr = 1;

	rohc_decomp_debug(context, "DF = %d, RND = %d, NBO = %d, SID = %d\n",
	                  bits->df, bits->rnd, bits->nbo, bits->sid);
	packet++;
	read++;

	/* generic extension header list is not managed yet,
	   ignore the byte which should be set to 0 */
	if(GET_BIT_0_7(packet) != 0x00)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "generic extension header list not supported yet\n");
		goto error;
	}
	packet++;
	read++;

	return read;

error:
	return -1;
}


/**
 * @brief Decode the IPv6 dynamic part of a ROHC packet.
 *
 * See 5.7.7.3 in RFC 3095 for details. Generic extension header list is not
 * managed yet.
 *
 * @param context      The decompression context
 * @param packet       The ROHC packet to decode
 * @param length       The length of the ROHC packet
 * @param bits         OUT: The bits extracted from the IP dynamic part
 * @param list_decomp  The list decompressor
 * @return             The number of bytes read in the ROHC packet,
 *                     -1 in case of failure
 */
static int parse_dynamic_part_ipv6(const struct d_context *const context,
                                   const unsigned char *packet,
                                   const size_t length,
                                   struct rohc_extr_ip_bits *const bits,
                                   struct list_decomp *const list_decomp)
{
	int read = 0; /* number of bytes read from the packet */
	int size_ext; /* length (in bytes) of the generic extension header list */

	/* check the minimal length to decode the IPv6 dynamic part */
	if(length < 2)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zu)\n", length);
		goto error;
	}

	/* read the TC field */
	bits->tos = GET_BIT_0_7(packet);
	bits->tos_nr = 8;
	rohc_decomp_debug(context, "TC = 0x%02x\n", bits->tos);
	packet++;
	read++;

	/* read the HL field */
	bits->ttl = GET_BIT_0_7(packet);
	bits->ttl_nr = 8;
	rohc_decomp_debug(context, "HL = 0x%02x\n", bits->ttl);
	packet++;
	read++;

	/* generic extension header list */
	size_ext = rohc_list_decode(list_decomp, packet, length - read);
	if(size_ext < 0)
	{
		rohc_warning(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to decode IPv6 extensions list\n");
		goto error;
	}
	rohc_decomp_debug(context, "IPv6 extensions list = %d bytes\n", size_ext);
	packet += size_ext;
	read += size_ext;

	return read;

error:
	return -1;
}


/**
 * @brief Decode one IR, IR-DYN or UO* packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * Steps:
 *  \li A. Parsing of ROHC base header, extension header and tail of header
 *  \li B. For IR and IR-DYN packet, check for correct compressed header (CRC)
 *  \li C. Decode extracted bits
 *  \li D. Build uncompressed headers (and check for correct decompression
 *         for UO* packets)
 *  \li E. Copy the payload (if any)
 *  \li F. Update the compression context
 *
 * Steps C and D may be repeated if packet or context repair is attempted
 * upon CRC failure.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param arrival_time   The time at which packet was received (0 if unknown,
 *                       or to disable time-related features in ROHC protocol)
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param add_cid_len    The length of the optional Add-CID field
 * @param large_cid_len  The length of the optional large CID field
 * @param uncomp_packet  OUT: The decoded IP packet
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @return               The length of the uncompressed IP packet
 *                       or ROHC_ERROR if an error occurs
 *                       or ROHC_ERROR_CRC if a CRC error occurs
 */
int d_generic_decode(struct rohc_decomp *const decomp,
                     struct d_context *const context,
                     const struct rohc_timestamp arrival_time,
                     const unsigned char *const rohc_packet,
                     const size_t rohc_length,
                     const size_t add_cid_len,
                     const size_t large_cid_len,
                     unsigned char *uncomp_packet,
                     rohc_packet_t *const packet_type)
{
	struct d_generic_context *const g_context = context->specific;

	/* extracted bits for SN, outer IP-ID, inner IP-ID, TS... */
	struct rohc_extr_bits bits;
	/* decoded values for SN, outer IP-ID, inner IP-ID, TS... */
	struct rohc_decoded_values decoded;

	/* length of the parsed ROHC header and of the uncompressed headers */
	size_t rohc_header_len;
	size_t uncomp_header_len;

	/* ROHC and uncompressed payloads (they are the same) */
	const unsigned char *payload_data;
	size_t payload_len;

	/* Whether to attempt packet correction or not */
	bool try_decoding_again;

	/* helper variables for values returned by functions */
	bool parsing_ok;
	bool decode_ok;
	int build_ret;

	assert((*packet_type) != ROHC_PACKET_UNKNOWN);

	/* remember the arrival time of the packet (used for repair upon CRC
	 * failure for example) */
	g_context->cur_arrival_time = arrival_time;


	/* A. Parsing of ROHC base header, extension header and tail of header */

	/* let's parse the packet! */
	parsing_ok = parse_packet(decomp, context,
	                          rohc_packet, rohc_length, large_cid_len,
	                          packet_type, &bits, &rohc_header_len);
	if(!parsing_ok)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse the %s header\n",
		             rohc_get_packet_descr(*packet_type));
		goto error;
	}

	/* ROHC base header and its optional extension is now fully parsed,
	 * remaining data is the payload */
	payload_data = rohc_packet + rohc_header_len;
	payload_len = rohc_length - rohc_header_len;
	rohc_decomp_debug(context, "ROHC payload (length = %zd bytes) starts at "
	                  "offset %zd\n", payload_len, rohc_header_len);


	/*
	 * B. Check for correct compressed header (CRC)
	 *
	 * Use the CRC on compressed headers to check whether IR header was
	 * correctly received. The optional Add-CID is part of the CRC.
	 */

	if((*packet_type) == ROHC_PACKET_IR || (*packet_type) == ROHC_PACKET_IR_DYN)
	{
		const bool crc_ok = check_ir_crc(decomp, context,
		                                 rohc_packet - add_cid_len,
		                                 add_cid_len + rohc_header_len,
		                                 large_cid_len, add_cid_len, bits.crc);
		if(!crc_ok)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "CRC detected a transmission failure for IR packet\n");
			rohc_dump_packet(decomp->trace_callback, ROHC_TRACE_DECOMP,
			                 ROHC_TRACE_WARNING, "IR headers",
			                 rohc_packet - add_cid_len,
			                 rohc_header_len + add_cid_len);
			goto error_crc;
		}

		/* reset the correction attempt */
		g_context->correction_counter = 0;
	}


	try_decoding_again = false;
	do
	{
		if(try_decoding_again)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "CID %zu: CRC repair: try decoding packet again with new "
			             "assumptions\n", context->cid);
		}


		/* C. Decode extracted bits
		 *
		 * All bits are now extracted from the packet, let's decode them.
		 */

		decode_ok = decode_values_from_bits(decomp, context, bits, &decoded);
		if(!decode_ok)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to decode values from bits extracted from ROHC "
			             "header\n");
			goto error;
		}


		/* D. Build uncompressed headers & check for correct decompression
		 *
		 * All fields are now decoded, let's build the uncompressed headers.
		 *
		 * Use the CRC on decompressed headers to check whether decompression was
		 * correct.
		 */

		/* build the uncompressed headers */
		build_ret = build_uncomp_hdrs(decomp, context, *packet_type, decoded,
		                              payload_len, bits.crc_type, bits.crc,
		                              uncomp_packet, &uncomp_header_len);
		if(build_ret == ROHC_OK)
		{
			/* uncompressed headers successfully built and CRC is correct,
			 * no need to try decoding with different values */
			uncomp_packet += uncomp_header_len;

			if(g_context->crc_corr == ROHC_DECOMP_CRC_CORR_SN_NONE)
			{
				rohc_decomp_debug(context, "CRC is correct\n");
			}
			else
			{
				rohc_decomp_debug(context, "CID %zu: CRC repair: CRC is correct\n",
				                  context->cid);
				try_decoding_again = false;
			}
		}
		else if(build_ret != ROHC_ERROR_CRC)
		{
			/* uncompressed headers cannot be built, stop decoding */
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "CID %zu: failed to build uncompressed headers\n",
			             context->cid);
			rohc_dump_packet(decomp->trace_callback, ROHC_TRACE_DECOMP,
			                 ROHC_TRACE_WARNING, "compressed headers",
			                 rohc_packet, rohc_header_len);
			goto error;
		}
		else
		{
			/* uncompressed headers successfully built but CRC is incorrect,
			 * try decoding with different values (repair) */

			/* CRC for IR and IR-DYN packets checked before, so cannot fail here */
			assert((*packet_type) != ROHC_PACKET_IR);
			assert((*packet_type) != ROHC_PACKET_IR_DYN);

			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "CID %zu: failed to build uncompressed headers (CRC "
			             "failure)\n", context->cid);

			/* attempt a context/packet repair */
			try_decoding_again = attempt_repair(decomp, context, &bits);

			/* report CRC failure if attempt is not possible */
			if(!try_decoding_again)
			{
				/* uncompressed headers successfully built, CRC is incorrect, repair
				 * was disabled or attempted without any success, so give up */
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "CID %zu: failed to build uncompressed headers "
				             "(CRC failure)\n", context->cid);
				rohc_dump_packet(decomp->trace_callback, ROHC_TRACE_DECOMP,
				                 ROHC_TRACE_WARNING, "compressed headers",
				                 rohc_packet, rohc_header_len);
				goto error_crc;
			}
		}
	}
	while(try_decoding_again);

	/* after CRC failure, if the SN value seems to be correctly guessed, we must
	 * wait for 3 CRC-valid packets before the correction is approved. Two
	 * packets are therefore thrown away. */
	if(g_context->crc_corr != ROHC_DECOMP_CRC_CORR_SN_NONE)
	{
		if(g_context->correction_counter > 1)
		{
			/* update context with decoded values even if we drop the packet */
			update_context(context, decoded);

			g_context->correction_counter--;
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "CID %zu: CRC repair: throw away packet, still %zu "
			             "CRC-valid packets required\n", context->cid,
			             g_context->correction_counter);

			goto error_crc;
		}
		else if(g_context->correction_counter == 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "CID %zu: CRC repair: correction is successful, "
			             "keep packet\n", context->cid);
			context->corrected_crc_failures++;
			switch(g_context->crc_corr)
			{
				case ROHC_DECOMP_CRC_CORR_SN_WRAP:
					context->corrected_sn_wraparounds++;
					break;
				case ROHC_DECOMP_CRC_CORR_SN_UPDATES:
					context->corrected_wrong_sn_updates++;
					break;
				case ROHC_DECOMP_CRC_CORR_SN_NONE:
				default:
					rohc_error(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					           "CID %zu: CRC repair: unsupported repair algorithm "
					           "%d\n", context->cid, g_context->crc_corr);
					break;
			}
			g_context->crc_corr = ROHC_DECOMP_CRC_CORR_SN_NONE;
			g_context->correction_counter--;
		}
	}


	/* E. Copy the payload (if any) */

	if((rohc_header_len + payload_len) != rohc_length)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC %s header (%zd bytes) and payload (%zd bytes) "
		             "do not match the full ROHC %s packet (%zu bytes)\n",
		             rohc_get_packet_descr(*packet_type), rohc_header_len,
		             payload_len, rohc_get_packet_descr(*packet_type),
		             rohc_length);
		goto error;
	}
	if(payload_len != 0)
	{
		memcpy(uncomp_packet, payload_data, payload_len);
	}
	rohc_decomp_debug(context, "uncompressed packet length = %zu bytes\n",
	                  uncomp_header_len + payload_len);


	/* F. Update the compression context
	 *
	 * Once CRC check is done, update the compression context with the values
	 * that were decoded earlier.
	 *
	 * TODO: check what fields shall be updated in the context
	 */

	/* we are either already in full context state or we can transit
	 * through it */
	if(context->state != ROHC_DECOMP_STATE_FC)
	{
		rohc_decomp_debug(context, "change from state %d to state %d\n",
		                  context->state, ROHC_DECOMP_STATE_FC);
		context->state = ROHC_DECOMP_STATE_FC;
	}

	/* tell compressor about the current decompressor's operating mode
	 * if they are different */
	if(bits.mode_nr > 0 && bits.mode != context->mode)
	{
		rohc_decomp_debug(context, "mode different in compressor (%d) and "
		                  "decompressor (%d)\n", bits.mode, context->mode);
		d_change_mode_feedback(decomp, context);
	}

	/* update context with decoded values */
	update_context(context, decoded);


	/* update statistics */
	stats_add_decomp_success(context, rohc_header_len, uncomp_header_len);

	/* decompression is successful, return length of uncompressed packet */
	return (uncomp_header_len + payload_len);

error:
	return ROHC_ERROR;
error_crc:
	return ROHC_ERROR_CRC;
}


/**
 * @brief Get the reference SN value of the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference SN value
 */
uint32_t d_generic_get_sn(const struct d_context *const context)
{
	const struct d_generic_context *const g_context = context->specific;
	return rohc_lsb_get_ref(g_context->sn_lsb_ctxt, ROHC_LSB_REF_0);
}


/**
 * @brief Parse one UO-0 header
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UO-0 (5.7.1)

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 0 |      SN       |    CRC    |
    +===+===+===+===+===+===+===+===+

 Part 4 is empty.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the UO-0 header
 * @param rohc_hdr_len   OUT: The size of the UO-0 header
 * @return               true if UO-0 is successfully parsed,
 *                       false otherwise
 */
static bool parse_uo0(const struct rohc_decomp *const decomp,
                      const struct d_context *const context,
                      const unsigned char *const rohc_packet,
                      const size_t rohc_length,
                      const size_t large_cid_len,
                      rohc_packet_t *const packet_type,
                      struct rohc_extr_bits *const bits,
                      size_t *const rohc_hdr_len)
{
	struct d_generic_context *const g_context = context->specific;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	assert(g_context != NULL);
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* check packet usage */
	if(context->state == ROHC_DECOMP_STATE_SC)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-0 packets cannot be received in Static Context "
		             "state\n");
		goto error;
	}

	/* check if the ROHC packet is large enough to parse parts 2 and 3 */
	if(rohc_remain_len < (1 + large_cid_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* check if the rohc packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len < (1 + large_cid_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "rohc packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 1-bit "0" + 4-bit SN + 3-bit CRC */
	assert(GET_BIT_7(rohc_remain_data) == 0);
	bits->sn = GET_BIT_3_6(rohc_remain_data);
	bits->sn_nr = 4;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	bits->crc_type = ROHC_CRC_TYPE_3;
	bits->crc = GET_BIT_0_2(rohc_remain_data);
	bits->crc_nr = 3;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: no remainder of base header for UO-0 packet */
	/* part 5: no extension for UO-0 packet */

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UO* remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO-0 packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one UO-1 header for non-RTP profiles
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UO-1 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |         IP-ID         |
    +===+===+===+===+===+===+===+===+
 4  |        SN         |    CRC    |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the UO-1 header
 * @param rohc_hdr_len   OUT: The size of the UO-1 header
 * @return               true if UO-1 is successfully parsed,
 *                       false otherwise
 */
static bool parse_uo1(const struct rohc_decomp *const decomp,
                      const struct d_context *const context,
                      const unsigned char *const rohc_packet,
                      const size_t rohc_length,
                      const size_t large_cid_len,
                      rohc_packet_t *const packet_type,
                      struct rohc_extr_bits *const bits,
                      size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* which IP header is the innermost IPv4 header with non-random IP-ID ? */
	ip_header_pos_t innermost_ipv4_non_rnd;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* determine which IP header is the innermost IPv4 header with
	 * value(RND) = 0 */
	if(g_context->multiple_ip && is_ipv4_non_rnd_pkt(bits->inner_ip))
	{
		/* inner IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_SECOND;
	}
	else if(is_ipv4_non_rnd_pkt(bits->outer_ip))
	{
		/* outer IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;
	}
	else
	{
		/* no IPv4 header with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
	}

	/* check packet usage */
	if(context->state == ROHC_DECOMP_STATE_SC)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-1 packet cannot be received in Static Context state\n");
		goto error;
	}
	if(context->profile->id == ROHC_PROFILE_RTP)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-1 packet cannot be used with RTP profile\n");
		assert(0);
		goto error;
	}
	if(innermost_ipv4_non_rnd == ROHC_IP_HDR_NONE)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "cannot use the UO-1 packet with no 'IPv4 "
		             "header with non-random IP-ID'\n");
		goto error;
	}

	/* check if the rohc packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len <= (1 + large_cid_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "rohc packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 2-bit "10" + 6-bit IP-ID */
	assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
	if(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST)
	{
		bits->outer_ip.id = GET_BIT_0_5(rohc_remain_data);
		bits->outer_ip.id_nr = 6;
		bits->outer_ip.is_id_enc = true;
		rohc_decomp_debug(context, "%zd IP-ID bits for IP header #%u = 0x%x\n",
		                  bits->outer_ip.id_nr, innermost_ipv4_non_rnd,
		                  bits->outer_ip.id);
	}
	else
	{
		bits->inner_ip.id = GET_BIT_0_5(rohc_remain_data);
		bits->inner_ip.id_nr = 6;
		bits->inner_ip.is_id_enc = true;
		rohc_decomp_debug(context, "%zd IP-ID bits for IP header #%u = 0x%x\n",
		                  bits->inner_ip.id_nr, innermost_ipv4_non_rnd,
		                  bits->inner_ip.id);
	}
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: 5-bit SN + 3-bit CRC */
	bits->sn = GET_BIT_3_7(rohc_remain_data);
	bits->sn_nr = 5;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	bits->crc_type = ROHC_CRC_TYPE_3;
	bits->crc = GET_BIT_0_2(rohc_remain_data);
	bits->crc_nr = 3;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: extension only for UO-1-ID packet */

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UO-1 remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO-1 packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one UO-1 header for RTP profile
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UO-1-RTP (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |          TS           |
    +===+===+===+===+===+===+===+===+
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 T: T = 0 indicates format UO-1-ID;
    T = 1 indicates format UO-1-TS.

 UO-1-RTP cannot be used if there is no IPv4 header in the context or
 if value(RND) and value(RND2) are both 1.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the UO-1-RTP header
 * @param rohc_hdr_len   OUT: The size of the UO-1-RTP header
 * @return               true if UO-1-RTP is successfully parsed,
 *                       false otherwise
 */
static bool parse_uo1rtp(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_packet,
                         const size_t rohc_length,
                         const size_t large_cid_len,
                         rohc_packet_t *const packet_type,
                         struct rohc_extr_bits *const bits,
                         size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* check packet usage */
	if(context->state == ROHC_DECOMP_STATE_SC)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-1-RTP packet cannot be received in Static Context "
		             "state\n");
		goto error;
	}
	if(context->profile->id != ROHC_PROFILE_RTP)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-1-RTP packet cannot be used with non-RTP profiles\n");
		assert(0);
		goto error;
	}

	/* check if the rohc packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len <= (1 + large_cid_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "rohc packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 2-bit "10" + 6-bit TS */
	assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
	bits->ts = GET_BIT_0_5(rohc_remain_data);
	bits->ts_nr = 6;
	rohc_decomp_debug(context, "%zd TS bits = 0x%x\n", bits->ts_nr, bits->ts);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: 1-bit M + 4-bit SN + 3-bit CRC */
	bits->rtp_m = GET_REAL(GET_BIT_7(rohc_remain_data));
	bits->rtp_m_nr = 1;
	rohc_decomp_debug(context, "1-bit RTP Marker (M) = %u\n", bits->rtp_m);
	bits->sn = GET_BIT_3_6(rohc_remain_data);
	bits->sn_nr = 4;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	bits->crc_type = ROHC_CRC_TYPE_3;
	bits->crc = GET_BIT_0_2(rohc_remain_data);
	bits->crc_nr = 3;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: extension only for UO-1-ID packet */

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UO-1-RTP remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO-1-RTP packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one UO-1-ID header for RTP profiles
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UO-1-ID (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |T=0|      IP-ID        |
    +===+===+===+===+===+===+===+===+
 4  | X |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 X: X = 0 indicates that no extension is present;
    X = 1 indicates that an extension is present.

 T: T = 0 indicates format UO-1-ID;
    T = 1 indicates format UO-1-TS.

 UO-1-ID cannot be used if there is no IPv4 header in the context or
 if value(RND) and value(RND2) are both 1.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param bits           OUT: The bits extracted from the UO-1-ID header
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param rohc_hdr_len   OUT: The size of the UO-1-ID header
 * @return               true if UO-1-ID is successfully parsed,
 *                       false otherwise
 */
static bool parse_uo1id(const struct rohc_decomp *const decomp,
                        const struct d_context *const context,
                        const unsigned char *const rohc_packet,
                        const size_t rohc_length,
                        const size_t large_cid_len,
                        rohc_packet_t *const packet_type,
                        struct rohc_extr_bits *const bits,
                        size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* which IP header is the innermost IPv4 header with non-random IP-ID ? */
	ip_header_pos_t innermost_ipv4_non_rnd;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* determine which IP header is the innermost IPv4 header with
	 * value(RND) = 0 */
	if(g_context->multiple_ip && is_ipv4_non_rnd_pkt(bits->inner_ip))
	{
		/* inner IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_SECOND;
	}
	else if(is_ipv4_non_rnd_pkt(bits->outer_ip))
	{
		/* outer IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;
	}
	else
	{
		/* no IPv4 header with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
	}

	/* check packet usage */
	if(context->state == ROHC_DECOMP_STATE_SC)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-1-ID packet cannot be received in Static Context "
		             "state\n");
		goto error;
	}
	if(context->profile->id != ROHC_PROFILE_RTP)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-1-ID packet cannot be used with non-RTP profiles\n");
		assert(0);
		goto error;
	}
	if(innermost_ipv4_non_rnd == ROHC_IP_HDR_NONE)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "cannot use the UO-1-ID packet with no 'IPv4 "
		             "header with non-random IP-ID'\n");
		goto error;
	}

	/* check if the rohc packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len <= (1 + large_cid_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "rohc packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 2-bit "10" + 1-bit "T=0" + 5-bit IP-ID */
	assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
	assert(GET_BIT_5(rohc_remain_data) == 0);
	if(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST)
	{
		bits->outer_ip.id = GET_BIT_0_4(rohc_remain_data);
		bits->outer_ip.id_nr = 5;
		bits->outer_ip.is_id_enc = true;
		rohc_decomp_debug(context, "%zd IP-ID bits for IP header #%u = 0x%x\n",
		                  bits->outer_ip.id_nr, innermost_ipv4_non_rnd,
		                  bits->outer_ip.id);
	}
	else
	{
		bits->inner_ip.id = GET_BIT_0_4(rohc_remain_data);
		bits->inner_ip.id_nr = 5;
		bits->inner_ip.is_id_enc = true;
		rohc_decomp_debug(context, "%zd IP-ID bits for IP header #%u = 0x%x\n",
		                  bits->inner_ip.id_nr, innermost_ipv4_non_rnd,
		                  bits->inner_ip.id);
	}
	rohc_decomp_debug(context, "%zd outer IP-ID bits = 0x%x\n",
	                  bits->outer_ip.id_nr, bits->outer_ip.id);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: 1-bit X + 4-bit SN + 3-bit CRC */
	bits->ext_flag = GET_REAL(GET_BIT_7(rohc_remain_data));
	rohc_decomp_debug(context, "1-bit extension (X) = %u\n", bits->ext_flag);
	bits->sn = GET_BIT_3_6(rohc_remain_data);
	bits->sn_nr = 4;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	bits->crc_type = ROHC_CRC_TYPE_3;
	bits->crc = GET_BIT_0_2(rohc_remain_data);
	bits->crc_nr = 3;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: extension only for UO-1-ID packet */
	if(bits->ext_flag == 0)
	{
		/* no extension */
		rohc_decomp_debug(context, "no extension in UO-1-ID packet\n");
	}
	else
	{
		rohc_ext_t ext_type;
		int ext_size;

		/* check if the ROHC packet is large enough to read extension type */
		if(rohc_remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small for extension (len = %zd)\n",
			             rohc_remain_len);
			goto error;
		}

		/* determine extension type */
		rohc_decomp_debug(context, "first byte of extension = 0x%02x\n",
		                  GET_BIT_0_7(rohc_remain_data));
		ext_type = parse_extension_type(rohc_remain_data);

		/* decode extension */
		switch(ext_type)
		{
			case ROHC_EXT_0:
			{
				/* decode extension 0 */
				ext_size = parse_extension0(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UO_1_ID,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_1:
			{
				/* decode extension 1 */
				ext_size = parse_extension1(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UO_1_ID,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_2:
			{
				/* decode extension 2 */
				ext_size = parse_extension2(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UO_1_ID,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_3:
			{
				/* decode the extension */
				ext_size = g_context->parse_extension3(decomp, context,
				                                       rohc_remain_data,
				                                       rohc_remain_len,
				                                       *packet_type, bits);

				break;
			}

			default:
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "unknown extension (0x%x)\n", ext_type);
				goto error;
			}
		}

		/* was the extension successfully parsed? */
		if(ext_size < 0)
		{
			assert(ext_size != -2); /* no need for reparse with UO-1-ID packet */
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode extension %u of the UO-1-ID packet\n",
			             ext_type);
			goto error;
		}

		/* now, skip the extension in the ROHC header */
		rohc_remain_data += ext_size;
		rohc_remain_len -= ext_size;
		*rohc_hdr_len += ext_size;
	}

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UO-1-ID remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO-1-ID packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one UO-1-TS header for RTP profiles
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UO-1-TS (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |T=1|        TS         |
    +===+===+===+===+===+===+===+===+
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 T: T = 0 indicates format UO-1-ID;
    T = 1 indicates format UO-1-TS.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the UO-1-TS header
 * @param rohc_hdr_len   OUT: The size of the UO-1-TS header
 * @return               true if UO-1-TS is successfully parsed,
 *                       false otherwise
 */
static bool parse_uo1ts(const struct rohc_decomp *const decomp,
                        const struct d_context *const context,
                        const unsigned char *const rohc_packet,
                        const size_t rohc_length,
                        const size_t large_cid_len,
                        rohc_packet_t *const packet_type,
                        struct rohc_extr_bits *const bits,
                        size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* check packet usage */
	if(context->state == ROHC_DECOMP_STATE_SC)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-1-TS packet cannot be received in Static Context "
		             "state\n");
		goto error;
	}
	if(context->profile->id != ROHC_PROFILE_RTP)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UO-1-TS packet cannot be used with non-RTP profiles\n");
		assert(0);
		goto error;
	}

	/* check if the rohc packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len <= (1 + large_cid_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "rohc packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 2-bit "10" + 1-bit "T=1" + 5-bit TS */
	assert(GET_BIT_6_7(rohc_remain_data) == 0x02);
	assert(GET_BIT_5(rohc_remain_data) != 0);
	bits->ts = GET_BIT_0_4(rohc_remain_data);
	bits->ts_nr = 5;
	rohc_decomp_debug(context, "%zd TS bits = 0x%x\n", bits->ts_nr, bits->ts);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: 1-bit M + 4-bit SN + 3-bit CRC */
	bits->rtp_m = GET_REAL(GET_BIT_7(rohc_remain_data));
	bits->rtp_m_nr = 1;
	rohc_decomp_debug(context, "1-bit RTP Marker (M) = %u\n", bits->rtp_m);
	bits->sn = GET_BIT_3_6(rohc_remain_data);
	bits->sn_nr = 4;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	bits->crc_type = ROHC_CRC_TYPE_3;
	bits->crc = GET_BIT_0_2(rohc_remain_data);
	bits->crc_nr = 3;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: extension only for UO-1-ID packet */

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UO-1-TS remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO-1-TS packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one UOR-2 header for non-RTP profiles
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UOR-2 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        SN         |
    +===+===+===+===+===+===+===+===+
 4  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.

 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the UOR-2 header
 * @param rohc_hdr_len   OUT: The size of the UOR-2 header
 * @return               true if UOR-2 is successfully parsed,
 *                       false otherwise
 */
static bool parse_uor2(const struct rohc_decomp *const decomp,
                       const struct d_context *const context,
                       const unsigned char *const rohc_packet,
                       const size_t rohc_length,
                       const size_t large_cid_len,
                       rohc_packet_t *const packet_type,
                       struct rohc_extr_bits *const bits,
                       size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* which IP header is the innermost IPv4 header with non-random IP-ID ? */
	ip_header_pos_t innermost_ipv4_non_rnd;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* determine which IP header is the innermost IPv4 header with
	 * value(RND) = 0 */
	if(g_context->multiple_ip && is_ipv4_non_rnd_pkt(bits->inner_ip))
	{
		/* inner IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_SECOND;
	}
	else if(is_ipv4_non_rnd_pkt(bits->outer_ip))
	{
		/* outer IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;
	}
	else
	{
		/* no IPv4 header with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
	}

	/* check packet usage */
	if(context->profile->id == ROHC_PROFILE_RTP)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UOR-2 packet cannot be used with RTP profile\n");
		assert(0);
		goto error;
	}

	/* check if the ROHC packet is large enough to parse parts 2, 3 and 4 */
	if(rohc_remain_len < (1 + large_cid_len + 1))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 3-bit "110" + 5-bit SN */
	assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
	bits->sn = GET_BIT_0_4(rohc_remain_data);
	bits->sn_nr = 5;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4: 7-bit CRC + 1-bit X (extension) flag */
	bits->crc_type = ROHC_CRC_TYPE_7;
	bits->crc = GET_BIT_0_6(rohc_remain_data);
	bits->crc_nr = 7;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	bits->ext_flag = GET_REAL(GET_BIT_7(rohc_remain_data));
	rohc_decomp_debug(context, "extension is present = %u\n", bits->ext_flag);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: Extension */
	if(bits->ext_flag == 0)
	{
		/* no extension */
		rohc_decomp_debug(context, "no extension to decode in UOR-2 packet\n");
	}
	else
	{
		rohc_ext_t ext_type;
		int ext_size;

		/* check if the ROHC packet is large enough to read extension type */
		if(rohc_remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small for extension (len = %zd)\n",
			             rohc_remain_len);
			goto error;
		}

		/* decode extension */
		rohc_decomp_debug(context, "first byte of extension = 0x%02x\n",
		                  GET_BIT_0_7(rohc_remain_data));
		ext_type = parse_extension_type(rohc_remain_data);
		switch(ext_type)
		{
			case ROHC_EXT_0:
			{
				/* check extension usage */
				if(innermost_ipv4_non_rnd == ROHC_IP_HDR_NONE)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					             "cannot use extension 0 for UOR-2 packet with "
					             "no IPv4 header that got a non-random IP-ID\n");
					goto error;
				}

				/* decode extension 0 */
				ext_size = parse_extension0(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_1:
			{
				/* check extension usage */
				if(innermost_ipv4_non_rnd == ROHC_IP_HDR_NONE)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					             "cannot use extension 1 for UOR-2 packet with no "
					             "IPv4 header that got a non-random IP-ID\n");
					goto error;
				}

				/* decode extension 1 */
				ext_size = parse_extension1(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_2:
			{
				/* check extension usage */
				if(!is_ipv4_non_rnd_pkt(bits->outer_ip) ||
				   !g_context->multiple_ip ||
				   !is_ipv4_non_rnd_pkt(bits->inner_ip))
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					             "cannot use extension 2 for UOR-2 packet with 0 "
					             "or 1 IPv4 header that got non-random IP-ID\n");
					goto error;
				}
				if(innermost_ipv4_non_rnd != ROHC_IP_HDR_NONE)
				{
					rohc_decomp_debug(context, "IP header #%d is the innermost "
					                  "IPv4 header with a non-random IP-ID\n",
					                  innermost_ipv4_non_rnd);
				}

				/* decode extension 2 */
				ext_size = parse_extension2(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_3:
			{
				/* decode the extension */
				ext_size = g_context->parse_extension3(decomp, context,
				                                       rohc_remain_data,
				                                       rohc_remain_len,
				                                       *packet_type, bits);
				break;
			}

			default:
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "unknown extension (0x%x)\n", ext_type);
				goto error;
			}
		}

		/* was the extension successfully parsed? */
		if(ext_size < 0)
		{
			assert(ext_size != -2); /* no need for reparse with UOR-2 packet */
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode extension %u of the UOR-2 packet\n",
			             ext_type);
			goto error;
		}

		/* now, skip the extension in the ROHC header */
		rohc_remain_data += ext_size;
		rohc_remain_len -= ext_size;
		*rohc_hdr_len += ext_size;
	}

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UO* remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UOR-2 packet was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one UOR-2 header for RTP profile (in 2 passes if needed)
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the UOR-2-RTP header
 * @param rohc_hdr_len   OUT: The size of the UOR-2-RTP header
 * @return               true if UOR-2-RTP is successfully parsed,
 *                       false otherwise
 *
 * @see parse_uor2rtp_once
 */
static bool parse_uor2rtp(const struct rohc_decomp *const decomp,
                          const struct d_context *const context,
                          const unsigned char *const rohc_packet,
                          const size_t rohc_length,
                          const size_t large_cid_len,
                          rohc_packet_t *const packet_type,
                          struct rohc_extr_bits *const bits,
                          size_t *const rohc_hdr_len)
{
	struct d_generic_context *const g_context = context->specific;

	/* forced values for outer and inner RND flags */
	uint8_t outer_rnd;
	uint8_t inner_rnd;

	int parsing;

	/* check packet usage */
	if(context->profile->id != ROHC_PROFILE_RTP)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UOR-2-RTP packet cannot be used with non-RTP profiles\n");
		assert(0);
		goto error;
	}

	/* for the first parsing, use the context values for the outer/inner RND
	 * flags, force them for reparse later if required */
	outer_rnd = g_context->outer_ip_changes->rnd;
	inner_rnd = g_context->inner_ip_changes->rnd;

	/* try parsing UOR-2-RTP packet with information from context */
	parsing = parse_uor2rtp_once(decomp, context, rohc_packet, rohc_length,
	                             large_cid_len, *packet_type,
	                             outer_rnd, inner_rnd, bits, rohc_hdr_len);
	if(parsing != ROHC_OK)
	{
		if(parsing != ROHC_NEED_REPARSE)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to parse the UOR-2-RTP header\n");
			goto error;
		}

		/* UOR-2* packet overrided some context values, so reparsing with new
		 * assumptions is required */
		rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		          "packet needs to be reparsed with different assumptions "
		          "for packet type\n");
#if RTP_BIT_TYPE
		assert(0);
#else

		/* determine the new RND values for outer and inner IP headers */
		if(g_context->multiple_ip &&
		   bits->inner_ip.rnd_nr > 0 &&
		   bits->inner_ip.rnd != g_context->inner_ip_changes->rnd)
		{
			/* inner RND flag changed */
			assert(bits->inner_ip.rnd_nr == 1);
			inner_rnd = bits->inner_ip.rnd;
		}
		else
		{
			/* inner RND flag did not change */
			inner_rnd = g_context->inner_ip_changes->rnd;
		}
		if(bits->outer_ip.rnd_nr > 0 &&
		   bits->outer_ip.rnd != g_context->outer_ip_changes->rnd)
		{
			/* outer RND flag changed */
			assert(bits->outer_ip.rnd_nr == 1);
			outer_rnd = bits->outer_ip.rnd;
		}
		else
		{
			/* inner RND flag did not change */
			outer_rnd = g_context->outer_ip_changes->rnd;
		}

		/* change packet type UOR-2-RTP -> UOR-2-ID/TS, then try parsing UOR-2*
		 * packet with information from packet */
		if(d_is_uor2_ts(rohc_packet, rohc_length, large_cid_len))
		{
			rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			          "change for packet UOR-2-TS (T = 1)\n");
			*packet_type = ROHC_PACKET_UOR_2_TS;
			parsing = parse_uor2ts_once(decomp, context, rohc_packet,
			                            rohc_length, large_cid_len, *packet_type,
			                            outer_rnd, inner_rnd, bits, rohc_hdr_len);
		}
		else
		{
			rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			          "change for packet UOR-2-ID (T = 0)\n");
			*packet_type = ROHC_PACKET_UOR_2_ID;
			parsing = parse_uor2id_once(decomp, context, rohc_packet,
			                            rohc_length, large_cid_len, *packet_type,
			                            outer_rnd, inner_rnd, bits, rohc_hdr_len);
		}
		if(parsing == ROHC_NEED_REPARSE)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "reparse required by the reparse, there is an internal "
			             "problem\n");
			assert(0);
			goto error;
		}
		else if(parsing != ROHC_OK)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to reparse the UOR-2 header\n");
			goto error;
		}
#endif /* RTP_BIT_TYPE */
	}

	return true;

error:
	return false;
}


/**
 * @brief Parse one UOR-2-RTP header for RTP profile
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UOR-2-RTP (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4a | TS| M |       SN              |
    +---+---+---+---+---+---+---+---+
 4b | X |            CRC            |
    +---+---+---+---+---+---+---+---+

 X: X = 0 indicates that no extension is present;
    X = 1 indicates that an extension is present.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    The type of ROHC packet to parse
 * @param outer_rnd      The forced value for outer RND (used for reparsing)
 * @param inner_rnd      The forced value for inner RND (used for reparsing)
 * @param bits           OUT: The bits extracted from the UOR-2-RTP header
 * @param rohc_hdr_len   OUT: The size of the UOR-2-RTP header
 * @return               ROHC_OK if UOR-2-RTP is successfully parsed,
 *                       ROHC_NEED_REPARSE if packet needs to be parsed again,
 *                       ROHC_ERROR otherwise
 */
static int parse_uor2rtp_once(const struct rohc_decomp *const decomp,
                              const struct d_context *const context,
                              const unsigned char *const rohc_packet,
                              const size_t rohc_length,
                              const size_t large_cid_len,
                              const rohc_packet_t packet_type,
                              uint8_t outer_rnd,
                              uint8_t inner_rnd,
                              struct rohc_extr_bits *const bits,
                              size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* which IP header is the innermost IPv4 header with non-random IP-ID ? */
	ip_header_pos_t innermost_ipv4_non_rnd;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* force extracted RND values (for reparsing) */
	if(bits->outer_ip.version == IPV4)
	{
		bits->outer_ip.rnd = outer_rnd & 0x1;
		bits->outer_ip.rnd_nr = 1;
	}
	if(g_context->multiple_ip && bits->inner_ip.version == IPV4)
	{
		bits->inner_ip.rnd = inner_rnd & 0x1;
		bits->inner_ip.rnd_nr = 1;
	}

	/* determine which IP header is the innermost IPv4 header with
	 * value(RND) = 0 */
	if(g_context->multiple_ip && is_ipv4_non_rnd_pkt(bits->inner_ip))
	{
		/* inner IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_SECOND;
	}
	else if(is_ipv4_non_rnd_pkt(bits->outer_ip))
	{
		/* outer IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;
	}
	else
	{
		/* no IPv4 header with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
	}

	/* check if the ROHC packet is large enough to parse parts 2, 3, 4, 4a */
	if(rohc_remain_len < (1 + large_cid_len + 2))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 3-bit "110" + 5-bit TS */
	assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
	bits->ts = GET_BIT_0_4(rohc_remain_data) << 1;
	bits->ts_nr = 5;
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4a: 1-bit TS + 1-bit M flag + 6-bit SN */
	bits->ts |= GET_REAL(GET_BIT_7(rohc_remain_data));
	bits->ts_nr += 1;
	rohc_decomp_debug(context, "%zd TS bits = 0x%x\n", bits->ts_nr, bits->ts);
	bits->rtp_m = GET_REAL(GET_BIT_6(rohc_remain_data));
	bits->rtp_m_nr = 1;
	rohc_decomp_debug(context, "M flag = %u\n", bits->rtp_m);
	bits->sn = GET_BIT_0_5(rohc_remain_data);
	bits->sn_nr = 6;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 4: 6-bit or 7-bit CRC + 1-bit X (extension) flag
	 *   if the RTP bit type feature is enabled at build time, CRC is one
	 *   bit less than in ROHC standard for RTP-specific UOR-2 packets */
#if RTP_BIT_TYPE
	/* UOR-2* contains a 6-bit CRC if RTP bit type feature is enabled */
	bits->crc_type = ROHC_CRC_TYPE_6;
	bits->crc = GET_BIT_0_5(rohc_remain_data);
	bits->crc_nr = 6;
#else
	/* UOR-2* contains a 7-bit CRC */
	bits->crc_type = ROHC_CRC_TYPE_7;
	bits->crc = GET_BIT_0_6(rohc_remain_data);
	bits->crc_nr = 7;
#endif
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	bits->ext_flag = GET_REAL(GET_BIT_7(rohc_remain_data));
	rohc_decomp_debug(context, "extension is present = %u\n", bits->ext_flag);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: Extension */
	if(bits->ext_flag == 0)
	{
		/* no extension */
		rohc_decomp_debug(context, "no extension to decode in UOR-2-RTP packet\n");
	}
	else
	{
		rohc_ext_t ext_type;
		int ext_size;

		/* check if the ROHC packet is large enough to read extension type */
		if(rohc_remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small for extension (len = %zd)\n",
			             rohc_remain_len);
			goto error;
		}

		/* decode extension */
		rohc_decomp_debug(context, "first byte of extension = 0x%02x\n",
		                  GET_BIT_0_7(rohc_remain_data));
		ext_type = parse_extension_type(rohc_remain_data);
		switch(ext_type)
		{
			case ROHC_EXT_0:
			{
				/* decode extension 0 */
				ext_size = parse_extension0(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_RTP,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_1:
			{
				/* decode extension 1 */
				ext_size = parse_extension1(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_RTP,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_2:
			{
				if(innermost_ipv4_non_rnd != ROHC_IP_HDR_NONE)
				{
					rohc_decomp_debug(context, "IP header #%d is the innermost "
					                  "IPv4 header with a non-random IP-ID\n",
					                  innermost_ipv4_non_rnd);
				}

				/* decode extension 2 */
				ext_size = parse_extension2(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_RTP,
				                            innermost_ipv4_non_rnd, bits);
				break;
			}

			case ROHC_EXT_3:
			{
				/* decode the extension */
				ext_size = g_context->parse_extension3(decomp, context,
				                                       rohc_remain_data,
				                                       rohc_remain_len,
				                                       packet_type, bits);
				break;
			}

			default:
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "unknown extension (0x%x)\n", ext_type);
				goto error;
			}
		}

		/* was the extension successfully parsed? */
		if(ext_size == -2)
		{
			assert(ext_type == ROHC_EXT_3);
			rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			          "packet needs to be reparsed because RND changed "
			          "in extension 3\n");
			goto reparse;
		}
		else if(ext_size < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode extension %u of the UOR-2-RTP packet\n",
			             ext_type);
			goto error;
		}

		/* now, skip the extension in the ROHC header */
		rohc_remain_data += ext_size;
		rohc_remain_len -= ext_size;
		*rohc_hdr_len += ext_size;
	}

	/* parts 6, 9, and 13: UO* remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UOR-2-RTP remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UOR-2-RTP packet was successfully parsed */
	return ROHC_OK;

reparse:
	return ROHC_NEED_REPARSE;
error:
	return ROHC_ERROR;
}


/**
 * @brief Parse one UOR-2-ID header for RTP profile (in 2 passes if needed)
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the UOR-2-ID header
 * @param rohc_hdr_len   OUT: The size of the UOR-2-ID header
 * @return               true if UOR-2-ID is successfully parsed,
 *                       false otherwise
 *
 * @see parse_uor2id_once
 */
static bool parse_uor2id(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_packet,
                         const size_t rohc_length,
                         const size_t large_cid_len,
                         rohc_packet_t *const packet_type,
                         struct rohc_extr_bits *const bits,
                         size_t *const rohc_hdr_len)
{
	struct d_generic_context *const g_context = context->specific;

	/* forced values for outer and inner RND flags */
	uint8_t outer_rnd;
	uint8_t inner_rnd;

	int parsing;

	/* check packet usage */
	if(context->profile->id != ROHC_PROFILE_RTP)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UOR-2-ID packet cannot be used with non-RTP profiles\n");
		assert(0);
		goto error;
	}

	/* for the first parsing, use the context values for the outer/inner RND
	 * flags, force them for reparse later if required */
	outer_rnd = g_context->outer_ip_changes->rnd;
	inner_rnd = g_context->inner_ip_changes->rnd;

	/* try parsing UOR-2-ID packet with information from context */
	parsing = parse_uor2id_once(decomp, context, rohc_packet, rohc_length,
	                            large_cid_len, *packet_type,
	                            outer_rnd, inner_rnd, bits, rohc_hdr_len);
	if(parsing != ROHC_OK)
	{
		if(parsing != ROHC_NEED_REPARSE)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to parse the UOR-2-ID header\n");
			goto error;
		}

		/* UOR-2* packet overrided some context values, so reparsing with new
		 * assumptions is required */
		rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		          "packet needs to be reparsed with different assumptions "
		          "for packet type\n");
#if RTP_BIT_TYPE
		assert(0);
#else

		/* determine the new RND values for outer and inner IP headers */
		if(g_context->multiple_ip &&
		   bits->inner_ip.rnd_nr > 0 &&
		   bits->inner_ip.rnd != g_context->inner_ip_changes->rnd)
		{
			/* inner RND flag changed */
			assert(bits->inner_ip.rnd_nr == 1);
			inner_rnd = bits->inner_ip.rnd;
		}
		else
		{
			/* inner RND flag did not change */
			inner_rnd = g_context->inner_ip_changes->rnd;
		}
		if(bits->outer_ip.rnd_nr > 0 &&
		   bits->outer_ip.rnd != g_context->outer_ip_changes->rnd)
		{
			/* outer RND flag changed */
			assert(bits->outer_ip.rnd_nr == 1);
			outer_rnd = bits->outer_ip.rnd;
		}
		else
		{
			/* inner RND flag did not change */
			outer_rnd = g_context->outer_ip_changes->rnd;
		}

		/* change packet type UOR-2-ID -> UOR-2-RTP, then try parsing UOR-2*
		 * packet with information from packet */
		rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		          "change for packet UOR-2-RTP\n");
		*packet_type = ROHC_PACKET_UOR_2_RTP;
		parsing = parse_uor2rtp_once(decomp, context, rohc_packet, rohc_length,
		                             large_cid_len, *packet_type,
		                             outer_rnd, inner_rnd, bits, rohc_hdr_len);
		if(parsing == ROHC_NEED_REPARSE)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "reparse required by the reparse, there is an internal "
			             "problem\n");
			assert(0);
			goto error;
		}
		else if(parsing != ROHC_OK)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to reparse the UOR-2 header\n");
			goto error;
		}
#endif /* RTP_BIT_TYPE */
	}

	return true;

error:
	return false;
}


/**
 * @brief Parse one UOR-2-ID header for RTP profile
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UOR-2-ID (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |      IP-ID        |
    +===+===+===+===+===+===+===+===+
 4a |T=0| M |          SN           |
    +---+---+---+---+---+---+---+---+
 4b | X |           CRC             |
    +---+---+---+---+---+---+---+---+

 X: X = 0 indicates that no extension is present;
    X = 1 indicates that an extension is present.

 T: T = 0 indicates format UOR-2-ID;
    T = 1 indicates format UOR-2-TS.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    The type of ROHC packet to parse
 * @param outer_rnd      The forced value for outer RND (used for reparsing)
 * @param inner_rnd      The forced value for inner RND (used for reparsing)
 * @param bits           OUT: The bits extracted from the UOR-2-ID header
 * @param rohc_hdr_len   OUT: The size of the UOR-2-ID header
 * @return               ROHC_OK if UOR-2-ID is successfully parsed,
 *                       ROHC_NEED_REPARSE if packet needs to be parsed again,
 *                       ROHC_ERROR otherwise
 *
 * @see parse_uor2id
 */
static int parse_uor2id_once(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const unsigned char *const rohc_packet,
                             const size_t rohc_length,
                             const size_t large_cid_len,
                             const rohc_packet_t packet_type,
                             uint8_t outer_rnd,
                             uint8_t inner_rnd,
                             struct rohc_extr_bits *const bits,
                             size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* which IP header is the innermost IPv4 header with non-random IP-ID ? */
	ip_header_pos_t innermost_ipv4_non_rnd;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* force extracted RND values (for reparsing) */
	if(bits->outer_ip.version == IPV4)
	{
		bits->outer_ip.rnd = outer_rnd & 0x1;
		bits->outer_ip.rnd_nr = 1;
	}
	if(g_context->multiple_ip && bits->inner_ip.version == IPV4)
	{
		bits->inner_ip.rnd = inner_rnd & 0x1;
		bits->inner_ip.rnd_nr = 1;
	}

	/* determine which IP header is the innermost IPv4 header with
	 * value(RND) = 0 */
	if(g_context->multiple_ip && is_ipv4_non_rnd_pkt(bits->inner_ip))
	{
		/* inner IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_SECOND;
	}
	else if(is_ipv4_non_rnd_pkt(bits->outer_ip))
	{
		/* outer IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;
	}
	else
	{
		/* no IPv4 header with non-random IP-ID */
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "cannot use the UOR-2-ID packet with no 'IPv4 "
		             "header with non-random IP-ID'\n");
		goto error;
	}

	/* check if the ROHC packet is large enough to parse parts 2, 3, 4, 4a */
	if(rohc_remain_len < (1 + large_cid_len + 2))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 3-bit "110" + 5-bit IP-ID */
	assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
	if(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST)
	{
		bits->outer_ip.id = GET_BIT_0_4(rohc_remain_data);
		bits->outer_ip.id_nr = 5;
		bits->outer_ip.is_id_enc = true;
		rohc_decomp_debug(context, "%zd IP-ID bits for IP header #%u = 0x%x\n",
		                  bits->outer_ip.id_nr, innermost_ipv4_non_rnd,
		                  bits->outer_ip.id);
	}
	else
	{
		bits->inner_ip.id = GET_BIT_0_4(rohc_remain_data);
		bits->inner_ip.id_nr = 5;
		bits->inner_ip.is_id_enc = true;
		rohc_decomp_debug(context, "%zd IP-ID bits for IP header #%u = 0x%x\n",
		                  bits->inner_ip.id_nr, innermost_ipv4_non_rnd,
		                  bits->inner_ip.id);
	}
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4a: 1-bit T flag (ignored) + 1-bit M flag + 6-bit SN */
	bits->rtp_m = GET_REAL(GET_BIT_6(rohc_remain_data));
	bits->rtp_m_nr = 1;
	rohc_decomp_debug(context, "M flag = %u\n", bits->rtp_m);
	bits->sn = GET_BIT_0_5(rohc_remain_data);
	bits->sn_nr = 6;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 4: 6-bit or 7-bit CRC + 1-bit X (extension) flag
	 *   if the RTP bit type feature is enabled at build time, CRC is one
	 *   bit less than in ROHC standard for RTP-specific UOR-2 packets */
#if RTP_BIT_TYPE
	/* UOR-2* contains a 6-bit CRC if RTP bit type feature is enabled */
	bits->crc_type = ROHC_CRC_TYPE_6;
	bits->crc = GET_BIT_0_5(rohc_remain_data);
	bits->crc_nr = 6;
#else
	/* UOR-2* contains a 7-bit CRC */
	bits->crc_type = ROHC_CRC_TYPE_7;
	bits->crc = GET_BIT_0_6(rohc_remain_data);
	bits->crc_nr = 7;
#endif
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	bits->ext_flag = GET_REAL(GET_BIT_7(rohc_remain_data));
	rohc_decomp_debug(context, "extension is present = %u\n", bits->ext_flag);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: Extension */
	if(bits->ext_flag == 0)
	{
		/* no extension */
		rohc_decomp_debug(context, "no extension to decode in UOR-2* packet\n");
	}
	else
	{
		rohc_ext_t ext_type;
		int ext_size;

		/* check if the ROHC packet is large enough to read extension type */
		if(rohc_remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small for extension (len = %zd)\n",
			             rohc_remain_len);
			goto error;
		}

		/* decode extension */
		rohc_decomp_debug(context, "first byte of extension = 0x%02x\n",
		                  GET_BIT_0_7(rohc_remain_data));
		ext_type = parse_extension_type(rohc_remain_data);
		switch(ext_type)
		{
			case ROHC_EXT_0:
			{
				/* decode extension 0 */
				ext_size = parse_extension0(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_ID,
				                            innermost_ipv4_non_rnd, bits);
				break;
			}

			case ROHC_EXT_1:
			{
				/* decode extension 1 */
				ext_size = parse_extension1(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_ID,
				                            innermost_ipv4_non_rnd, bits);
				break;
			}

			case ROHC_EXT_2:
			{
				rohc_decomp_debug(context, "IP header #%d is the innermost "
				                  "IPv4 header with a non-random IP-ID\n",
				                  innermost_ipv4_non_rnd);

				/* decode extension 2 */
				ext_size = parse_extension2(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_ID,
				                            innermost_ipv4_non_rnd, bits);

				break;
			}

			case ROHC_EXT_3:
			{
				/* decode the extension */
				ext_size = g_context->parse_extension3(decomp, context,
				                                       rohc_remain_data,
				                                       rohc_remain_len,
				                                       packet_type, bits);

				break;
			}

			default:
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "unknown extension (0x%x)\n", ext_type);
				goto error;
			}
		}

		/* was the extension successfully parsed? */
		if(ext_size == -2)
		{
			assert(ext_type == ROHC_EXT_3);
			rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			          "packet needs to be reparsed because RND changed "
			          "in extension 3\n");
			goto reparse;
		}
		else if(ext_size < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode extension %u of the UOR-2-ID packet\n",
			             ext_type);
			goto error;
		}

		/* now, skip the extension in the ROHC header */
		rohc_remain_data += ext_size;
		rohc_remain_len -= ext_size;
		*rohc_hdr_len += ext_size;
	}

	/* parts 6, 9, and 13: UOR-2-ID remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UOR-2-ID remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UOR-2-ID packet was successfully parsed */
	return ROHC_OK;

reparse:
	return ROHC_NEED_REPARSE;
error:
	return ROHC_ERROR;
}


/**
 * @brief Parse one UOR-2-TS header for RTP profile (in 2 passes if needed)
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the UOR-2-TS header
 * @param rohc_hdr_len   OUT: The size of the UOR-2-TS header
 * @return               true if UOR-2-TS is successfully parsed,
 *                       false otherwise
 *
 * @see parse_uor2ts_once
 */
static bool parse_uor2ts(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_packet,
                         const size_t rohc_length,
                         const size_t large_cid_len,
                         rohc_packet_t *const packet_type,
                         struct rohc_extr_bits *const bits,
                         size_t *const rohc_hdr_len)
{
	struct d_generic_context *const g_context = context->specific;

	/* forced values for outer and inner RND flags */
	uint8_t outer_rnd;
	uint8_t inner_rnd;

	int parsing;

	/* check packet usage */
	if(context->profile->id != ROHC_PROFILE_RTP)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "UOR-2-TS packet cannot be used with non-RTP profiles\n");
		assert(0);
		goto error;
	}

	/* for the first parsing, use the context values for the outer/inner RND
	 * flags, force them for reparse later if required */
	outer_rnd = g_context->outer_ip_changes->rnd;
	inner_rnd = g_context->inner_ip_changes->rnd;

	/* try parsing UOR-2-TS packet with information from context */
	parsing = parse_uor2ts_once(decomp, context, rohc_packet, rohc_length,
	                            large_cid_len, *packet_type,
	                            outer_rnd, inner_rnd, bits, rohc_hdr_len);
	if(parsing != ROHC_OK)
	{
		if(parsing != ROHC_NEED_REPARSE)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to parse the UOR-2-TS header\n");
			goto error;
		}

		/* UOR-2* packet overrided some context values, so reparsing with new
		 * assumptions is required */
		rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		          "packet needs to be reparsed with different assumptions "
		          "for packet type\n");
#if RTP_BIT_TYPE
		assert(0);
#else

		/* determine the new RND values for outer and inner IP headers */
		if(g_context->multiple_ip &&
		   bits->inner_ip.rnd_nr > 0 &&
		   bits->inner_ip.rnd != g_context->inner_ip_changes->rnd)
		{
			/* inner RND flag changed */
			assert(bits->inner_ip.rnd_nr == 1);
			inner_rnd = bits->inner_ip.rnd;
		}
		else
		{
			/* inner RND flag did not change */
			inner_rnd = g_context->inner_ip_changes->rnd;
		}
		if(bits->outer_ip.rnd_nr > 0 &&
		   bits->outer_ip.rnd != g_context->outer_ip_changes->rnd)
		{
			/* outer RND flag changed */
			assert(bits->outer_ip.rnd_nr == 1);
			outer_rnd = bits->outer_ip.rnd;
		}
		else
		{
			/* inner RND flag did not change */
			outer_rnd = g_context->outer_ip_changes->rnd;
		}

		/* change packet type UOR-2-ID -> UOR-2-RTP, then try parsing UOR-2*
		 * packet with information from packet */
		rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		          "change for packet UOR-2-RTP\n");
		*packet_type = ROHC_PACKET_UOR_2_RTP;
		parsing = parse_uor2rtp_once(decomp, context, rohc_packet, rohc_length,
		                             large_cid_len, *packet_type,
		                             outer_rnd, inner_rnd, bits, rohc_hdr_len);
		if(parsing == ROHC_NEED_REPARSE)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "reparse required by the reparse, there is an internal "
			             "problem\n");
			assert(0);
			goto error;
		}
		else if(parsing != ROHC_OK)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to reparse the UOR-2 header\n");
			goto error;
		}
#endif /* RTP_BIT_TYPE */
	}

	return true;

error:
	return false;
}


/**
 * @brief Parse one UOR-2-TS header for RTP profile
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

 UOR-2-TS (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4a |T=1| M |          SN           |
    +---+---+---+---+---+---+---+---+
 4b | X |           CRC             |
    +---+---+---+---+---+---+---+---+

 X: X = 0 indicates that no extension is present;
    X = 1 indicates that an extension is present.

 T: T = 0 indicates format UOR-2-ID;
    T = 1 indicates format UOR-2-TS.

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1 and 3 are parsed in parent functions.
 * Parts 6, 9, and 13 are parsed in sub-function.
 * Parts 2, 4, and 5 are parsed in this function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    The type of ROHC packet to parse
 * @param outer_rnd      The forced value for outer RND (used for reparsing)
 * @param inner_rnd      The forced value for inner RND (used for reparsing)
 * @param bits           OUT: The bits extracted from the UOR-2-TS header
 * @param rohc_hdr_len   OUT: The size of the UOR-2-TS header
 * @return               ROHC_OK if UOR-2-TS is successfully parsed,
 *                       ROHC_NEED_REPARSE if packet needs to be parsed again,
 *                       ROHC_ERROR otherwise
 *
 * @see parse_uor2ts
 */
static int parse_uor2ts_once(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const unsigned char *const rohc_packet,
                             const size_t rohc_length,
                             const size_t large_cid_len,
                             const rohc_packet_t packet_type,
                             uint8_t outer_rnd,
                             uint8_t inner_rnd,
                             struct rohc_extr_bits *const bits,
                             size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;
	size_t rohc_remainder_len;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* which IP header is the innermost IPv4 header with non-random IP-ID ? */
	ip_header_pos_t innermost_ipv4_non_rnd;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);

	/* force extracted RND values (for reparsing) */
	if(bits->outer_ip.version == IPV4)
	{
		bits->outer_ip.rnd = outer_rnd & 0x1;
		bits->outer_ip.rnd_nr = 1;
	}
	if(g_context->multiple_ip && bits->inner_ip.version == IPV4)
	{
		bits->inner_ip.rnd = inner_rnd & 0x1;
		bits->inner_ip.rnd_nr = 1;
	}

	/* determine which IP header is the innermost IPv4 header with
	 * value(RND) = 0 */
	if(g_context->multiple_ip && is_ipv4_non_rnd_pkt(bits->inner_ip))
	{
		/* inner IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_SECOND;
	}
	else if(is_ipv4_non_rnd_pkt(bits->outer_ip))
	{
		/* outer IP header is IPv4 with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;
	}
	else
	{
		/* no IPv4 header with non-random IP-ID */
		innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
	}

	/* check if the ROHC packet is large enough to parse parts 2, 3, 4, 4a */
	if(rohc_remain_len < (1 + large_cid_len + 2))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* part 2: 3-bit "110" + 5-bit TS */
	assert(GET_BIT_5_7(rohc_remain_data) == 0x06);
	bits->ts = GET_BIT_0_4(rohc_remain_data);
	bits->ts_nr = 5;
	rohc_decomp_debug(context, "%zd TS bits = 0x%x\n", bits->ts_nr, bits->ts);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 3: skip large CID (handled elsewhere) */
	rohc_remain_data += large_cid_len;
	rohc_remain_len -= large_cid_len;
	*rohc_hdr_len += large_cid_len;

	/* part 4a: 1-bit T flag (ignored) + 1-bit M flag + 6-bit SN */
	bits->rtp_m = GET_REAL(GET_BIT_6(rohc_remain_data));
	bits->rtp_m_nr = 1;
	rohc_decomp_debug(context, "M flag = %u\n", bits->rtp_m);
	bits->sn = GET_BIT_0_5(rohc_remain_data);
	bits->sn_nr = 6;
	bits->is_sn_enc = true;
	rohc_decomp_debug(context, "%zd SN bits = 0x%x\n", bits->sn_nr, bits->sn);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 4: 6-bit or 7-bit CRC + 1-bit X (extension) flag
	 *   if the RTP bit type feature is enabled at build time, CRC is one
	 *   bit less than in ROHC standard for RTP-specific UOR-2 packets */
#if RTP_BIT_TYPE
	/* UOR-2* contains a 6-bit CRC if RTP bit type feature is enabled */
	bits->crc_type = ROHC_CRC_TYPE_6;
	bits->crc = GET_BIT_0_5(rohc_remain_data);
	bits->crc_nr = 6;
#else
	/* UOR-2* contains a 7-bit CRC */
	bits->crc_type = ROHC_CRC_TYPE_7;
	bits->crc = GET_BIT_0_6(rohc_remain_data);
	bits->crc_nr = 7;
#endif
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	bits->ext_flag = GET_REAL(GET_BIT_7(rohc_remain_data));
	rohc_decomp_debug(context, "extension is present = %u\n", bits->ext_flag);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* part 5: Extension */
	if(bits->ext_flag == 0)
	{
		/* no extension */
		rohc_decomp_debug(context, "no extension to decode in UOR-2* packet\n");
	}
	else
	{
		rohc_ext_t ext_type;
		int ext_size;

		/* check if the ROHC packet is large enough to read extension type */
		if(rohc_remain_len < 1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small for extension (len = %zd)\n",
			             rohc_remain_len);
			goto error;
		}

		/* decode extension */
		rohc_decomp_debug(context, "first byte of extension = 0x%02x\n",
		                  GET_BIT_0_7(rohc_remain_data));
		ext_type = parse_extension_type(rohc_remain_data);
		switch(ext_type)
		{
			case ROHC_EXT_0:
			{
				/* decode extension 0 */
				ext_size = parse_extension0(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_TS,
				                            innermost_ipv4_non_rnd, bits);
				break;
			}

			case ROHC_EXT_1:
			{
				/* check extension usage */
				if(innermost_ipv4_non_rnd == ROHC_IP_HDR_NONE)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					             "cannot use extension 1 for the UOR-2-TS packet "
					             "with no IPv4 header that got non-random IP-ID\n");
					goto error;
				}

				/* decode extension 1 */
				ext_size = parse_extension1(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_TS,
				                            innermost_ipv4_non_rnd, bits);
				break;
			}

			case ROHC_EXT_2:
			{
				/* check extension usage */
				if(innermost_ipv4_non_rnd == ROHC_IP_HDR_NONE)
				{
					rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
					             "cannot use extension 2 for the UOR-2-TS packet "
					             "with no IPv4 header that got non-random IP-ID\n");
					goto error;
				}
				else
				{
					rohc_decomp_debug(context, "IP header #%d is the innermost "
					                  "IPv4 header with a non-random IP-ID\n",
					                  innermost_ipv4_non_rnd);
				}

				/* decode extension 2 */
				ext_size = parse_extension2(decomp, context,
				                            rohc_remain_data, rohc_remain_len,
				                            ROHC_PACKET_UOR_2_TS,
				                            innermost_ipv4_non_rnd, bits);
				break;
			}

			case ROHC_EXT_3:
			{
				/* decode the extension */
				ext_size = g_context->parse_extension3(decomp, context,
				                                       rohc_remain_data,
				                                       rohc_remain_len,
				                                       packet_type, bits);
				break;
			}

			default:
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "unknown extension (0x%x)\n", ext_type);
				goto error;
			}
		}

		/* was the extension successfully parsed? */
		if(ext_size == -2)
		{
			assert(ext_type == ROHC_EXT_3);
			rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			          "packet needs to be reparsed because RND changed "
			          "in extension 3\n");
			goto reparse;
		}
		else if(ext_size < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode extension %u of the UOR-2-TS packet\n",
			             ext_type);
			goto error;
		}

		/* now, skip the extension in the ROHC header */
		rohc_remain_data += ext_size;
		rohc_remain_len -= ext_size;
		*rohc_hdr_len += ext_size;
	}

	/* parts 6, 9, and 13: UOR-2-TS remainder */
	if(!parse_uo_remainder(decomp, context, rohc_remain_data, rohc_remain_len,
	                       bits, &rohc_remainder_len))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to parse UOR-2-TS remainder\n");
		goto error;
	}
	rohc_remain_data += rohc_remainder_len;
	rohc_remain_len -= rohc_remainder_len;
	*rohc_hdr_len += rohc_remainder_len;

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UOR-2-TS packet was successfully parsed */
	return ROHC_OK;

reparse:
	return ROHC_NEED_REPARSE;
error:
	return ROHC_ERROR;
}


/**
 * @brief Parse the remainder of the UO* header
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :   remainder of base header    :                    |
 4  /     see below for details     /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported.
 * Parts 1, 2, 3, 4, and 5 are parsed in parent functions.
 * Parts 6 and 9 are parsed in this function.
 * Part 13 is parsed in profile-specific function.
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param bits           OUT: The bits extracted from the UO* header
 * @param rohc_hdr_len   OUT: The size of the UO* header
 * @return               true if UO* is successfully parsed, false otherwise
 */
static bool parse_uo_remainder(const struct rohc_decomp *const decomp,
                               const struct d_context *const context,
                               const unsigned char *const rohc_packet,
                               const size_t rohc_length,
                               struct rohc_extr_bits *const bits,
                               size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	assert(context != NULL);
	g_context = context->specific;
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* part 6: extract 16 outer IP-ID bits in case the outer IP-ID is random */
	if(is_ipv4_rnd_pkt(bits->outer_ip))
	{
		/* outer IP-ID is random, read its full 16-bit value and ignore any
		   previous bits we may have read (they should be filled with zeroes) */

		/* check if the ROHC packet is large enough to read the outer IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small for random outer IP-ID bits "
			             "(len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* sanity check: all bits that are above 16 bits should be zero */
		if(bits->outer_ip.id_nr > 0 && bits->outer_ip.id != 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "bad packet format: outer IP-ID bits from the base ROHC "
			             "header shall be filled with zeroes but 0x%x was found\n",
			             bits->outer_ip.id);
		}

		/* retrieve the full outer IP-ID value */
		bits->outer_ip.id = rohc_ntoh16(GET_NEXT_16_BITS(rohc_remain_data));
		bits->outer_ip.id_nr = 16;
		bits->outer_ip.is_id_enc = true;

		rohc_decomp_debug(context, "replace any existing outer IP-ID bits with "
		                  "with the ones found at the end of the UO* packet "
		                  "(0x%x on %zd bits)\n", bits->outer_ip.id,
		                  bits->outer_ip.id_nr);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		*rohc_hdr_len += 2;
	}

	/* parts 7 and 8: not supported */

	/* part 9: extract 16 inner IP-ID bits in case the inner IP-ID is random */
	if(g_context->multiple_ip && is_ipv4_rnd_pkt(bits->inner_ip))
	{
		/* inner IP-ID is random, read its full 16-bit value and ignore any
		   previous bits we may have read (they should be filled with zeroes) */

		/* check if the ROHC packet is large enough to read the inner IP-ID */
		if(rohc_remain_len < 2)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "ROHC packet too small for random inner IP-ID bits "
			             "(len = %zd)\n", rohc_remain_len);
			goto error;
		}

		/* sanity check: all bits that are above 16 bits should be zero */
		if(bits->inner_ip.id_nr > 0 && bits->inner_ip.id != 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "bad packet format: inner IP-ID bits from the base ROHC "
			             "header shall be filled with zeroes but 0x%x was found\n",
			             bits->inner_ip.id);
		}

		/* retrieve the full inner IP-ID value */
		bits->inner_ip.id = rohc_ntoh16(GET_NEXT_16_BITS(rohc_remain_data));
		bits->inner_ip.id_nr = 16;
		bits->inner_ip.is_id_enc = true;

		rohc_decomp_debug(context, "replace any existing inner IP-ID bits "
		                  "with the ones found at the end of the UO* packet "
		                  "(0x%x on %zd bits)\n", bits->inner_ip.id,
		                  bits->inner_ip.id_nr);

		rohc_remain_data += 2;
		rohc_remain_len -= 2;
		*rohc_hdr_len += 2;
	}

	/* parts 10, 11 and 12: not supported */

	/* part 13: decode the tail of UO* packet */
	if(g_context->parse_uo_remainder != NULL)
	{
		int size;

		size = g_context->parse_uo_remainder(context, rohc_remain_data,
		                                     rohc_remain_len, bits);
		if(size < 0)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode the remainder of UO* packet\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		*rohc_hdr_len += size;
	}

	/* sanity checks */
	assert((*rohc_hdr_len) <= rohc_length);

	/* UO* remainder was successfully parsed */
	return true;

error:
	return false;
}


/**
 * @brief Parse one IR-DYN packet
 *
 * \verbatim

 IR-DYN packet (5.7.7.2):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         : if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   0   0   0 | IR-DYN packet type
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /     0-2 octets of CID info    / 1-2 octets if for large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
 4  |            Profile            | 1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              | 1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /         Dynamic chain         / variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 7  |             SN                | 2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    :                               :
    /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet to decode
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @param packet_type    IN:  The type of the ROHC packet to parse
 *                       OUT: The type of the parsed ROHC packet
 * @param bits           OUT: The bits extracted from the IR-DYN header
 * @param rohc_hdr_len   OUT: The size of the IR-DYN header
 * @return               true if IR-DYN is successfully parsed, false otherwise
 */
static bool parse_irdyn(const struct rohc_decomp *const decomp,
                        const struct d_context *const context,
                        const unsigned char *const rohc_packet,
                        const size_t rohc_length,
                        const size_t large_cid_len,
                        rohc_packet_t *const packet_type,
                        struct rohc_extr_bits *const bits,
                        size_t *const rohc_hdr_len)
{
	struct d_generic_context *g_context = context->specific;

	/* remaining ROHC data not parsed yet and the length of the ROHC headers
	   (will be computed during parsing) */
	const unsigned char *rohc_remain_data;
	size_t rohc_remain_len;

	/* helper variables for values returned by functions */
	int size;

	assert(g_context != NULL);
	assert(rohc_packet != NULL);
	assert(bits != NULL);
	assert(rohc_hdr_len != NULL);

	rohc_remain_data = rohc_packet;
	rohc_remain_len = rohc_length;
	*rohc_hdr_len = 0;

	/* reset all extracted bits */
	reset_extr_bits(g_context, bits);
	bits->crc_type = ROHC_CRC_TYPE_NONE;

	/* packet must large enough for:
	 * IR-DYN type + (large CID + ) Profile ID + CRC */
	if(rohc_remain_len < (1 + large_cid_len + 2))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_remain_len);
		goto error;
	}

	/* skip the IR-DYN type, optional large CID bytes, and Profile ID */
	rohc_remain_data += large_cid_len + 2;
	rohc_remain_len -= large_cid_len + 2;
	*rohc_hdr_len += large_cid_len + 2;

	/* parse CRC */
	bits->crc = GET_BIT_0_7(rohc_remain_data);
	bits->crc_nr = 8;
	rohc_decomp_debug(context, "CRC-%zd found in packet = 0x%02x\n",
	                  bits->crc_nr, bits->crc);
	rohc_remain_data++;
	rohc_remain_len--;
	(*rohc_hdr_len)++;

	/* decode the dynamic part of the outer IP header */
	size = parse_dynamic_part_ip(context, rohc_remain_data, rohc_remain_len,
	                             &bits->outer_ip,
	                             g_context->list_decomp1);
	if(size == -1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "cannot decode the outer IP dynamic part\n");
		goto error;
	}
	rohc_remain_data += size;
	rohc_remain_len -= size;
	*rohc_hdr_len += size;

	/* decode the dynamic part of the inner IP header */
	if(g_context->multiple_ip)
	{
		size = parse_dynamic_part_ip(context, rohc_remain_data, rohc_remain_len,
		                             &bits->inner_ip,
		                             g_context->list_decomp2);
		if(size == -1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode the inner IP dynamic part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		*rohc_hdr_len += size;
	}

	/* parse the dynamic part of the next header if necessary */
	if(g_context->parse_dyn_next_hdr != NULL)
	{
		size = g_context->parse_dyn_next_hdr(context, rohc_remain_data,
		                                     rohc_remain_len, bits);
		if(size == -1)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "cannot decode the next header dynamic part\n");
			goto error;
		}
		rohc_remain_data += size;
		rohc_remain_len -= size;
		*rohc_hdr_len += size;
	}

	return true;

error:
	return false;
}


/**
 * @brief Parse the extension 0 of the UO-1-ID or UOR-2* packet
 *
 * Bits extracted:
 *  - 3 bits of SN
 *  - UOR-2: 3 bits of innermost non-random IP-ID
 *  - UOR-2-ID: 3 bits of innermost non-random IP-ID
 *  - UOR-2-RTP: 3 bits of TS
 *  - UOR-2-TS: 3 bits of TS
 *  - UO-1-ID: 3 bits of innermost non-random IP-ID
 *
 * @param decomp            The ROHC decompressor
 * @param context           The decompression context
 * @param rohc_data         The ROHC data to parse
 * @param rohc_data_len     The length of the ROHC data to parse
 * @param packet_type       The type of ROHC packet
 * @param innermost_ip_hdr  The innermost IPv4 header with non-random IP-ID
 * @param bits              IN: the bits already found in base header
 *                          OUT: the bits found in the extension header 0
 * @return                  The data length read from the ROHC packet,
 *                          -1 in case of error
 */
static int parse_extension0(const struct rohc_decomp *const decomp,
                            const struct d_context *const context,
                            const unsigned char *const rohc_data,
                            const size_t rohc_data_len,
                            const rohc_packet_t packet_type,
                            const ip_header_pos_t innermost_ip_hdr,
                            struct rohc_extr_bits *const bits)
{
	const size_t rohc_ext0_len = 1;

	assert(rohc_data != NULL);
	assert(bits != NULL);

	rohc_decomp_debug(context, "decode %s extension 0\n",
	                  rohc_get_packet_descr(packet_type));

	/* check the minimal length to decode the extension 0 */
	if(rohc_data_len < 1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_data_len);
		goto error;
	}

	/* parse 3 bits of SN */
	APPEND_SN_BITS(ROHC_EXT_0, bits, GET_BIT_3_5(rohc_data), 3);

	/* parse the IP-ID or TS bits */
	switch(packet_type)
	{
		case ROHC_PACKET_UOR_2:
		case ROHC_PACKET_UOR_2_ID:
		case ROHC_PACKET_UO_1_ID:
		{
			/* sanity check */
			assert(innermost_ip_hdr == ROHC_IP_HDR_FIRST ||
			       innermost_ip_hdr == ROHC_IP_HDR_SECOND);
			/* parse 3 bits of the innermost IP-ID */
			if(innermost_ip_hdr == ROHC_IP_HDR_FIRST)
			{
				APPEND_OUTER_IP_ID_BITS(ROHC_EXT_0, bits,
				                        GET_BIT_0_2(rohc_data), 3);
			}
			else
			{
				APPEND_INNER_IP_ID_BITS(ROHC_EXT_0, bits,
				                        GET_BIT_0_2(rohc_data), 3);
			}
			break;
		}

		case ROHC_PACKET_UOR_2_RTP:
		case ROHC_PACKET_UOR_2_TS:
		{
			/* read 3 bits of TS */
			APPEND_TS_BITS(ROHC_EXT_0, bits, GET_BIT_0_2(rohc_data), 3);
			break;
		}

		default:
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "bad packet type (%d)\n", packet_type);
			goto error;
		}
	}

	return rohc_ext0_len;

error:
	return -1;
}


/**
 * @brief Parse the extension 1 of the UO-1-ID or UOR-2* packet
 *
 * Bits extracted:
 *  - 3 bits of SN
 *  - UOR-2: 11 bits of innermost IP-ID
 *  - UOR-2-RTP: 11 bits of TS
 *  - UOR-2-TS: 3 bits of TS / 8 bits of innermost IP-ID
 *  - UOR-2-ID: 3 bits of innermost IP-ID / 8 bits of TS
 *  - UO-1-ID: 3 bits of innermost IP-ID / 8 bits of TS
 *
 * @param decomp            The ROHC decompressor
 * @param context           The decompression context
 * @param rohc_data         The ROHC data to parse
 * @param rohc_data_len     The length of the ROHC data to parse
 * @param packet_type       The type of ROHC packet
 * @param innermost_ip_hdr  The innermost IPv4 header with non-random IP-ID
 * @param bits              IN: the bits already found in base header
 *                          OUT: the bits found in the extension header 1
 * @return                  The data length read from the ROHC packet,
 *                          -1 in case of error
 */
static int parse_extension1(const struct rohc_decomp *const decomp,
                            const struct d_context *const context,
                            const unsigned char *const rohc_data,
                            const size_t rohc_data_len,
                            const rohc_packet_t packet_type,
                            const ip_header_pos_t innermost_ip_hdr,
                            struct rohc_extr_bits *const bits)
{
	const size_t rohc_ext1_len = 2;

	rohc_decomp_debug(context, "decode %s extension 1\n",
	                  rohc_get_packet_descr(packet_type));

	/* check the minimal length to decode the extension 1 */
	if(rohc_data_len < 2)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_data_len);
		goto error;
	}

	/* parse 3 bits of SN */
	APPEND_SN_BITS(ROHC_EXT_1, bits, GET_BIT_3_5(rohc_data), 3);

	/* parse the IP-ID and/or TS bits */
	switch(packet_type)
	{
		case ROHC_PACKET_UOR_2:
		{
			/* sanity check */
			assert(innermost_ip_hdr == ROHC_IP_HDR_FIRST ||
			       innermost_ip_hdr == ROHC_IP_HDR_SECOND);
			/* parse 11 bits of the innermost IP-ID */
			if(innermost_ip_hdr == ROHC_IP_HDR_FIRST)
			{
				APPEND_OUTER_IP_ID_BITS(ROHC_EXT_1, bits,
				                        (GET_BIT_0_2(rohc_data) << 8) |
				                        GET_BIT_0_7(rohc_data + 1), 11);
			}
			else
			{
				APPEND_INNER_IP_ID_BITS(ROHC_EXT_1, bits,
				                        (GET_BIT_0_2(rohc_data) << 8) |
				                        GET_BIT_0_7(rohc_data + 1), 11);
			}
			break;
		}

		case ROHC_PACKET_UOR_2_RTP:
		{
			/* parse 11 bits of TS */
			APPEND_TS_BITS(ROHC_EXT_1, bits,
			               (GET_BIT_0_2(rohc_data) << 8) |
			               GET_BIT_0_7(rohc_data + 1), 11);
			break;
		}

		case ROHC_PACKET_UOR_2_TS:
		{
			/* sanity check */
			assert(innermost_ip_hdr == ROHC_IP_HDR_FIRST ||
			       innermost_ip_hdr == ROHC_IP_HDR_SECOND);
			/* parse 3 bits of TS */
			APPEND_TS_BITS(ROHC_EXT_1, bits, GET_BIT_0_2(rohc_data), 3);
			/* parse 8 bits of the innermost IP-ID */
			if(innermost_ip_hdr == ROHC_IP_HDR_FIRST)
			{
				APPEND_OUTER_IP_ID_BITS(ROHC_EXT_1, bits,
				                        GET_BIT_0_7(rohc_data + 1), 8);
			}
			else
			{
				APPEND_INNER_IP_ID_BITS(ROHC_EXT_1, bits,
				                        GET_BIT_0_7(rohc_data + 1), 8);
			}
			break;
		}

		case ROHC_PACKET_UOR_2_ID:
		case ROHC_PACKET_UO_1_ID:
		{
			/* sanity check */
			assert(innermost_ip_hdr == ROHC_IP_HDR_FIRST ||
			       innermost_ip_hdr == ROHC_IP_HDR_SECOND);
			/* parse 3 bits of the innermost IP-ID */
			if(innermost_ip_hdr == ROHC_IP_HDR_FIRST)
			{
				APPEND_OUTER_IP_ID_BITS(ROHC_EXT_1, bits,
				                        GET_BIT_0_2(rohc_data), 3);
			}
			else
			{
				APPEND_INNER_IP_ID_BITS(ROHC_EXT_1, bits,
				                        GET_BIT_0_2(rohc_data), 3);
			}
			/* parse 8 bits of TS */
			APPEND_TS_BITS(ROHC_EXT_1, bits, GET_BIT_0_7(rohc_data + 1), 8);
			break;
		}

		default:
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "bad packet type (%d)\n", packet_type);
			goto error;
		}
	}

	return rohc_ext1_len;

error:
	return -1;
}


/**
 * @brief Parse the extension 2 of the UO-1-ID or UOR-2* packet
 *
 * Bits extracted:
 *  - 3 bits of SN
 *  - UOR-2: 11 bits of outer IP-ID / 8 bits of inner IP-ID
 *  - UOR-2-RTP: 19 bits of TS
 *  - UOR-2-TS: 11 bits of TS / 8 bits of the innermost IP-ID
 *  - UOR-2-ID: 8 bits of TS / 11 bits of the innermost IP-ID
 *  - UO-1-ID: 8 bits of TS / 11 bits of the innermost IP-ID
 *
 * @param decomp            The ROHC decompressor
 * @param context           The decompression context
 * @param rohc_data         The ROHC data to parse
 * @param rohc_data_len     The length of the ROHC data to parse
 * @param packet_type       The type of ROHC packet
 * @param innermost_ip_hdr  The innermost IPv4 header with non-random IP-ID
 * @param bits              IN: the bits already found in base header
 *                          OUT: the bits found in the extension header 2
 * @return                  The data length read from the ROHC packet,
 *                          -1 in case of error
 */
static int parse_extension2(const struct rohc_decomp *const decomp,
                            const struct d_context *const context,
                            const unsigned char *const rohc_data,
                            const size_t rohc_data_len,
                            const rohc_packet_t packet_type,
                            const ip_header_pos_t innermost_ip_hdr,
                            struct rohc_extr_bits *const bits)
{
	const size_t rohc_ext2_len = 3;

	assert(rohc_data != NULL);
	assert(bits != NULL);

	rohc_decomp_debug(context, "decode %s extension 2\n",
	                  rohc_get_packet_descr(packet_type));

	/* check the minimal length to decode the extension 2 */
	if(rohc_data_len < 3)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "ROHC packet too small (len = %zd)\n", rohc_data_len);
		goto error;
	}

	/* parse 3 bits of SN */
	APPEND_SN_BITS(ROHC_EXT_2, bits, GET_BIT_3_5(rohc_data), 3);

	/* parse the outer IP-ID, outer IP-ID and/or TS bits */
	switch(packet_type)
	{
		case ROHC_PACKET_UOR_2:
		{
			/* parse 11 bits of outer IP-ID */
			APPEND_OUTER_IP_ID_BITS(ROHC_EXT_2, bits,
			                        (GET_BIT_0_2(rohc_data) << 8) |
			                        GET_BIT_0_7(rohc_data + 1), 11);
			/* parse 8 bits of inner IP-ID */
			APPEND_INNER_IP_ID_BITS(ROHC_EXT_2, bits,
			                        GET_BIT_0_7(rohc_data + 2), 8);
			break;
		}

		case ROHC_PACKET_UOR_2_RTP:
		{
			/* parse 19 bits of TS */
			APPEND_TS_BITS(ROHC_EXT_2, bits,
			               ((GET_BIT_0_2(rohc_data) << 16) & 0x70000) |
			               ((GET_BIT_0_7(rohc_data + 1) << 8) & 0xff00) |
			               (GET_BIT_0_7(rohc_data + 2) & 0xff), 19);
			break;
		}

		case ROHC_PACKET_UOR_2_TS:
		{
			/* sanity check */
			assert(innermost_ip_hdr == ROHC_IP_HDR_FIRST ||
			       innermost_ip_hdr == ROHC_IP_HDR_SECOND);
			/* parse 11 bits of TS */
			APPEND_TS_BITS(ROHC_EXT_2, bits,
			               (GET_BIT_0_2(rohc_data) << 8) |
			               GET_BIT_0_7(rohc_data + 1), 11);
			/* parse 8 bits of the innermost IP-ID */
			if(innermost_ip_hdr == ROHC_IP_HDR_FIRST)
			{
				APPEND_OUTER_IP_ID_BITS(ROHC_EXT_2, bits,
				                        GET_BIT_0_7(rohc_data + 2), 8);
			}
			else
			{
				APPEND_INNER_IP_ID_BITS(ROHC_EXT_2, bits,
				                        GET_BIT_0_7(rohc_data + 2), 8);
			}
			break;
		}

		case ROHC_PACKET_UOR_2_ID:
		case ROHC_PACKET_UO_1_ID:
		{
			/* sanity check */
			assert(innermost_ip_hdr == ROHC_IP_HDR_FIRST ||
			       innermost_ip_hdr == ROHC_IP_HDR_SECOND);
			/* parse 11 bits of the innermost IP-ID */
			if(innermost_ip_hdr == ROHC_IP_HDR_FIRST)
			{
				APPEND_OUTER_IP_ID_BITS(ROHC_EXT_2, bits,
				                        (GET_BIT_0_2(rohc_data) << 8) |
				                        GET_BIT_0_7(rohc_data + 1), 11);
			}
			else
			{
				APPEND_INNER_IP_ID_BITS(ROHC_EXT_2, bits,
				                        (GET_BIT_0_2(rohc_data) << 8) |
				                        GET_BIT_0_7(rohc_data + 1), 11);
			}
			/* parse 8 bits of TS */
			APPEND_TS_BITS(ROHC_EXT_2, bits, GET_BIT_0_7(rohc_data + 2), 8);
			break;
		}

		default:
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "bad packet type (%d)\n", packet_type);
			goto error;
		}
	}

	return rohc_ext2_len;

error:
	return -1;
}


/**
 * @brief Find out which extension is carried by the UOR-2 packet.
 *
 * @param rohc_ext  The ROHC UOR-2 packet
 * @return          The UOR-2 extension type among:
 *                    \li ROHC_EXT_0
 *                    \li ROHC_EXT_1
 *                    \li ROHC_EXT_2
 *                    \li ROHC_EXT_3
 */
static uint8_t parse_extension_type(const unsigned char *const rohc_ext)
{
	return GET_BIT_6_7(rohc_ext);
}


/**
 * @brief Build the uncompressed headers
 *
 * @todo check for uncomp_hdrs size before writing into it
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param packet_type     The type of ROHC packet
 * @param decoded         The values decoded from ROHC header
 * @param payload_len     The length of the packet payload
 * @param crc_type        The type of CRC
 * @param crc_packet      The CRC extracted from the ROHC header
 * @param uncomp_hdrs     OUT: The buffer to store the uncompressed headers
 * @param uncomp_hdrs_len OUT: The length of the uncompressed headers written
 *                             into the buffer
 * @return                ROHC_OK if headers are built successfully,
 *                        ROHC_ERROR_CRC if the headers do not match the CRC,
 *                        ROHC_ERROR for other errors
 */
static int build_uncomp_hdrs(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const rohc_packet_t packet_type,
                             const struct rohc_decoded_values decoded,
                             const size_t payload_len,
                             const rohc_crc_type_t crc_type,
                             const uint8_t crc_packet,
                             unsigned char *uncomp_hdrs,
                             size_t *const uncomp_hdrs_len)
{
	struct d_generic_context *g_context;
	unsigned char *outer_ip_hdr;
	unsigned char *inner_ip_hdr;
	unsigned char *next_header;
	unsigned int size;

	assert(decomp != NULL);
	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(uncomp_hdrs != NULL);
	assert(uncomp_hdrs_len != NULL);

	*uncomp_hdrs_len = 0;

	/* build the IP headers */
	if(g_context->multiple_ip)
	{
		size_t inner_ip_hdr_len;
		size_t inner_ip_ext_hdrs_len;

		/* determine the length of the inner IP header */
		if(decoded.inner_ip.version == IPV4)
		{
			inner_ip_hdr_len = sizeof(struct ipv4_hdr);
		}
		else
		{
			inner_ip_hdr_len = sizeof(struct ipv6_hdr);
		}
		rohc_decomp_debug(context, "length of inner IP header = %zd bytes\n",
		                  inner_ip_hdr_len);

		/* determine the length of extension headers of the inner IP header */
		inner_ip_ext_hdrs_len = 0;
		if(g_context->list_decomp2->is_present)
		{
			struct c_list *inner_ip_ext_hdrs_list;
			size_t i;

			if(g_context->list_decomp2->ref_ok)
			{
				inner_ip_ext_hdrs_list = g_context->list_decomp2->ref_list;
			}
			else
			{
				inner_ip_ext_hdrs_list =
					g_context->list_decomp2->list_table[g_context->list_decomp2->counter_list];
			}
			for(i = 0; i < list_get_size(inner_ip_ext_hdrs_list); i++)
			{
				struct list_elt *elt;
				elt = list_get_elt_by_index(inner_ip_ext_hdrs_list, i);
				inner_ip_ext_hdrs_len += elt->item->length;
			}
		}
		rohc_decomp_debug(context, "length of extension headers for inner IP "
		                  "header = %zd bytes\n", inner_ip_ext_hdrs_len);

		rohc_decomp_debug(context, "length of transport header = %u bytes\n",
		                  g_context->outer_ip_changes->next_header_len);

		/* build the outer IP header */
		size = build_uncomp_ip(context, decoded.outer_ip, uncomp_hdrs,
		                       inner_ip_hdr_len + inner_ip_ext_hdrs_len +
		                       g_context->outer_ip_changes->next_header_len +
		                       payload_len,
		                       g_context->list_decomp1);
		outer_ip_hdr = uncomp_hdrs;
		uncomp_hdrs += size;
		*uncomp_hdrs_len += size;

		/* build the inner IP header */
		size = build_uncomp_ip(context, decoded.inner_ip, uncomp_hdrs,
		                       g_context->inner_ip_changes->next_header_len +
		                       payload_len,
		                       g_context->list_decomp2);
		inner_ip_hdr = uncomp_hdrs;
		uncomp_hdrs += size;
		*uncomp_hdrs_len += size;
	}
	else
	{
		rohc_decomp_debug(context, "length of transport header = %u bytes\n",
		                  g_context->outer_ip_changes->next_header_len);

		/* build the single IP header */
		size = build_uncomp_ip(context, decoded.outer_ip, uncomp_hdrs,
		                       g_context->outer_ip_changes->next_header_len +
		                       payload_len,
		                       g_context->list_decomp1);
		outer_ip_hdr = uncomp_hdrs;
		inner_ip_hdr = NULL;
		uncomp_hdrs += size;
		*uncomp_hdrs_len += size;
	}

	/* build the next header if present */
	next_header = uncomp_hdrs;
	if(g_context->build_next_header != NULL)
	{
		size = g_context->build_next_header(context, decoded,
		                                    uncomp_hdrs, payload_len);
		uncomp_hdrs += size;
		*uncomp_hdrs_len += size;
	}

	/* compute CRC on uncompressed headers if asked */
	if(crc_type != ROHC_CRC_TYPE_NONE)
	{
		bool crc_ok;

		crc_ok = check_uncomp_crc(decomp, context,
		                          outer_ip_hdr, inner_ip_hdr, next_header,
		                          crc_type, crc_packet);
		if(!crc_ok)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "CRC detected a decompression failure for packet "
			             "of type %s in state %s and mode %s\n",
			             rohc_get_packet_descr(packet_type),
			             rohc_decomp_get_state_descr(context->state),
			             rohc_get_mode_descr(context->mode));
			rohc_dump_packet(decomp->trace_callback, ROHC_TRACE_DECOMP,
			                 ROHC_TRACE_WARNING, "uncompressed headers",
			                 outer_ip_hdr, *uncomp_hdrs_len);
			goto error_crc;
		}
	}

	return ROHC_OK;

error_crc:
	return ROHC_ERROR_CRC;
#if 0 /* TODO: handle cases where uncomp_hdrs is too short */
error:
	return ROHC_ERROR;
#endif
}


/**
 * @brief Build an uncompressed IP header.
 *
 * @param context      The decompression context
 * @param decoded      The decoded IPv4 fields
 * @param dest         The buffer to store the IP header (MUST be at least
 *                     of sizeof(struct ipv4_hdr) or sizeof(struct ipv6_hdr)
 *                     bytes depending on the IP version)
 * @param payload_size The length of the IP payload
 * @param list_decomp  The list decompressor (IPv6 only)
 * @return             The length of the IP header
 */
static size_t build_uncomp_ip(const struct d_context *const context,
                              const struct rohc_decoded_ip_values decoded,
                              unsigned char *const dest,
                              const size_t payload_size,
                              const struct list_decomp *const list_decomp)
{
	size_t length;

	if(decoded.version == IPV4)
	{
		length = build_uncomp_ipv4(context, decoded, dest, payload_size);
	}
	else
	{
		length = build_uncomp_ipv6(context, decoded, dest, payload_size, list_decomp);
	}

	return length;
}


/**
 * @brief Build an uncompressed IPv4 header.
 *
 * @param context      The decompression context
 * @param decoded      The decoded IPv4 fields
 * @param dest         The buffer to store the IPv4 header (MUST be at least
 *                     of sizeof(struct ipv4_hdr) bytes)
 * @param payload_size The length of the IPv4 payload
 * @return             The length of the IPv4 header
 */
static size_t build_uncomp_ipv4(const struct d_context *const context,
                                const struct rohc_decoded_ip_values decoded,
                                unsigned char *const dest,
                                const size_t payload_size)
{
	struct ipv4_hdr *const ip = (struct ipv4_hdr *) dest;

	/* static-known fields */
	ip->ihl = 5;

	/* static fields */
	ip->version = decoded.version;
	ip->protocol = decoded.proto;
	memcpy(&ip->saddr, decoded.saddr, 4);
	memcpy(&ip->daddr, decoded.daddr, 4);

	/* dynamic fields */
	ip->tos = decoded.tos;
	ip->id = rohc_hton16(decoded.id);
	if(!decoded.nbo)
	{
		ip->id = swab16(ip->id);
	}
	ip->frag_off = 0;
	IPV4_SET_DF(ip, decoded.df);
	ip->ttl = decoded.ttl;

	/* inferred fields */
	ip->tot_len = rohc_hton16(payload_size + ip->ihl * 4);
	rohc_decomp_debug(context, "Total Length = 0x%04x (IHL * 4 + %zu)\n",
	                  rohc_ntoh16(ip->tot_len), payload_size);
	ip->check = 0;
	ip->check = ip_fast_csum(dest, ip->ihl);
	rohc_decomp_debug(context, "IP checksum = 0x%04x\n",
	                  rohc_ntoh16(ip->check));

	return sizeof(struct ipv4_hdr);
}


/**
 * @brief Build an uncompressed IPv6 header.
 *
 * @param context      The decompression context
 * @param decoded      The decoded IPv6 fields
 * @param dest         The buffer to store the IPv6 header (MUST be at least
 *                     of sizeof(struct ipv6_hdr) bytes)
 * @param payload_size The length of the IPv6 payload
 * @param list_decomp  The list decompressor
 * @return             The length of the IPv6 header
 */
static size_t build_uncomp_ipv6(const struct d_context *const context,
                                const struct rohc_decoded_ip_values decoded,
                                unsigned char *const dest,
                                const size_t payload_size,
                                const struct list_decomp *const list_decomp)
{
	struct ipv6_hdr *const ip = (struct ipv6_hdr *) dest;
	size_t ext_size;

	/* static fields */
	IPV6_SET_VERSION(ip, decoded.version);
	IPV6_SET_FLOW_LABEL(ip, decoded.flowid);
	ip->ip6_nxt = decoded.proto;
	memcpy(&ip->ip6_src, decoded.saddr, 16);
	memcpy(&ip->ip6_dst, decoded.daddr, 16);

	/* if there are extension headers, set Next Header in base header
	 * according to the first one */
	if(list_decomp->is_present)
	{
		const struct c_list *list;
		if(list_decomp->ref_ok)
		{
			list = list_decomp->ref_list;
		}
		else
		{
			list = list_decomp->list_table[list_decomp->counter_list];
		}
		if(list_get_size(list) > 0)
		{
			ip->ip6_nxt = (uint8_t) list->first_elt->item->type;
			rohc_decomp_debug(context, "set Next Header in IPv6 base header to "
			                  "0x%02x because of IPv6 extension header\n",
			                  ip->ip6_nxt);
		}
	}

	/* dynamic fields */
	IPV6_SET_TC(ip, decoded.tos);
	ip->ip6_hlim = decoded.ttl;

	/* extension list */
	if(list_decomp->is_present)
	{
		ext_size = list_decomp->encode_extension(list_decomp, decoded.proto,
		                                         dest + sizeof(struct ipv6_hdr));
	}
	else
	{
		/* no extension header */
		ext_size = 0;
	}

	/* inferred fields */
	ip->ip6_plen = rohc_hton16(payload_size + ext_size);
	rohc_decomp_debug(context, "Payload Length = 0x%04x (extensions = %zu "
	                  "bytes, payload = %zu bytes)\n",
	                  rohc_ntoh16(ip->ip6_plen), ext_size, payload_size);

	return sizeof(struct ipv6_hdr) + ext_size;
}


/**
 * @brief Check whether the CRC on IR or IR-DYN header is correct or not
 *
 * The CRC for IR/IR-DYN headers is always CRC-8. It is computed on the
 * whole compressed header (payload excluded, but any CID bits included).
 *
 * @param decomp          The ROHC decompressor
 * @param context         The decompression context
 * @param rohc_hdr        The compressed IR or IR-DYN header
 * @param rohc_hdr_len    The length (in bytes) of the compressed header
 * @param add_cid_len     The length of the optional Add-CID field
 * @param large_cid_len   The length of the optional large CID field
 * @param crc_packet      The CRC extracted from the ROHC header
 * @return                true if the CRC is correct, false otherwise
 */
static bool check_ir_crc(const struct rohc_decomp *const decomp,
                         const struct d_context *const context,
                         const unsigned char *const rohc_hdr,
                         const size_t rohc_hdr_len,
                         const size_t add_cid_len,
                         const size_t large_cid_len,
                         const uint8_t crc_packet)
{
	const unsigned char *crc_table;
	const rohc_crc_type_t crc_type = ROHC_CRC_TYPE_8;
	const unsigned char crc_zero[] = { 0x00 };
	unsigned int crc_comp; /* computed CRC */

	assert(decomp != NULL);
	assert(rohc_hdr != NULL);
	assert(rohc_hdr_len > 3);

	crc_table = decomp->crc_table_8;

	/* ROHC header before CRC field:
	 * optional Add-CID + IR type + Profile ID + optional large CID */
	crc_comp = crc_calculate(crc_type, rohc_hdr,
	                         add_cid_len + 2 + large_cid_len,
	                         CRC_INIT_8, crc_table);

	/* zeroed CRC field */
	crc_comp = crc_calculate(crc_type, crc_zero, 1, crc_comp, crc_table);

	/* ROHC header after CRC field */
	crc_comp = crc_calculate(crc_type,
	                         rohc_hdr + add_cid_len + 2 + large_cid_len + 1,
	                         rohc_hdr_len - add_cid_len - 2 - large_cid_len - 1,
	                         crc_comp, crc_table);

	rohc_decomp_debug(context, "CRC-%d on compressed ROHC header = 0x%x\n",
	                  crc_type, crc_comp);

	/* does the computed CRC match the one in packet? */
	if(crc_comp != crc_packet)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "CRC failure (computed = 0x%02x, packet = 0x%02x)\n",
		             crc_comp, crc_packet);
		goto error;
	}

	/* computed CRC matches the one in packet */
	return true;

error:
	return false;
}


/**
 * @brief Check whether the CRC on uncompressed header is correct or not
 *
 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
 *       if the CRC-STATIC fields did not change.
 *
 * @param decomp        The ROHC decompressor
 * @param context       The decompression context
 * @param outer_ip_hdr  The outer IP header
 * @param inner_ip_hdr  The inner IP header if it exists, NULL otherwise
 * @param next_header   The transport header, eg. UDP
 * @param crc_type      The type of CRC
 * @param crc_packet    The CRC extracted from the ROHC header
 * @return              true if the CRC is correct, false otherwise
 */
static bool check_uncomp_crc(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const unsigned char *const outer_ip_hdr,
                             const unsigned char *const inner_ip_hdr,
                             const unsigned char *const next_header,
                             const rohc_crc_type_t crc_type,
                             const uint8_t crc_packet)
{
	struct d_generic_context *g_context;
	const unsigned char *crc_table;
	unsigned int crc_computed;

	assert(decomp != NULL);
	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(outer_ip_hdr != NULL);
	assert(next_header != NULL);
	assert(crc_type != ROHC_CRC_TYPE_NONE);

	/* determine the initial value and the pre-computed table for the CRC */
	switch(crc_type)
	{
		case ROHC_CRC_TYPE_2:
			crc_computed = CRC_INIT_2;
			crc_table = decomp->crc_table_2;
			break;
		case ROHC_CRC_TYPE_3:
			crc_computed = CRC_INIT_3;
			crc_table = decomp->crc_table_3;
			break;
		case ROHC_CRC_TYPE_6:
			crc_computed = CRC_INIT_6;
			crc_table = decomp->crc_table_6;
			break;
		case ROHC_CRC_TYPE_7:
			crc_computed = CRC_INIT_7;
			crc_table = decomp->crc_table_7;
			break;
		case ROHC_CRC_TYPE_8:
			crc_computed = CRC_INIT_8;
			crc_table = decomp->crc_table_8;
			break;
		default:
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "unknown CRC type %d\n", crc_type);
			assert(0);
			goto error;
	}

	/* compute the CRC from built uncompressed headers */
	crc_computed = g_context->compute_crc_static(outer_ip_hdr, inner_ip_hdr,
	                                             next_header, crc_type,
	                                             crc_computed, crc_table);
	crc_computed = g_context->compute_crc_dynamic(outer_ip_hdr, inner_ip_hdr,
	                                              next_header, crc_type,
	                                              crc_computed, crc_table);
	rohc_decomp_debug(context, "CRC-%d on uncompressed header = 0x%x\n",
	                  crc_type, crc_computed);

	/* does the computed CRC match the one in packet? */
	if(crc_computed != crc_packet)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "CRC failure (computed = 0x%02x, packet = 0x%02x)\n",
		             crc_computed, crc_packet);
		goto error;
	}

	/* computed CRC matches the one in packet */
	return true;

error:
	return false;
}


/**
 * @brief Attempt a packet/context repair upon CRC failure
 *
 * @param decomp         The ROHC decompressor
 * @param context        The decompression context
 * @param bits           OUT: The bits extracted from the UO-0 header
 * @return               true if repair is possible, false if not
 */
static bool attempt_repair(const struct rohc_decomp *const decomp,
                           const struct d_context *const context,
                           struct rohc_extr_bits *const bits)
{
	struct d_generic_context *const g_context = context->specific;
	const uint32_t sn_ref_0 = rohc_lsb_get_ref(g_context->sn_lsb_ctxt,
	                                           ROHC_LSB_REF_0);
	const uint32_t sn_ref_minus_1 = rohc_lsb_get_ref(g_context->sn_lsb_ctxt,
	                                                 ROHC_LSB_REF_MINUS_1);
	bool attempt_repair = false;

	/* do not try to repair packet/context if feature is disabled */
	if((decomp->features & ROHC_DECOMP_FEATURE_CRC_REPAIR) == 0)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "CID %zu: CRC repair: feature disabled\n", context->cid);
		goto skip;
	}

	/* do not try to repair packet/context if repair is already in action */
	if(g_context->crc_corr != ROHC_DECOMP_CRC_CORR_SN_NONE)
	{
		goto skip;
	}

	/* no correction attempt shall be already running */
	assert(g_context->correction_counter == 0);

	/* try to guess the correct SN value in case of failure */
	rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
	             "CID %zu: CRC repair: attempt to correct SN\n", context->cid);

	/* step b of RFC3095, §5.3.2.2.4. Correction of SN LSB wraparound:
	 *   When decompression fails, the decompressor computes the time
	 *   elapsed between the arrival of the previous, correctly decompressed
	 *   packet and the current packet.
	 *
	 * step c of RFC3095, §5.3.2.2.4. Correction of SN LSB wraparound:
	 *   If wraparound has occurred, INTERVAL will correspond to at least
	 *   2^k inter-packet times, where k is the number of SN bits in the
	 *   current header. */
	if(is_sn_wraparound(g_context->cur_arrival_time, g_context->arrival_times,
	                    g_context->arrival_times_nr,
	                    g_context->arrival_times_index, bits->sn_nr,
	                    lsb_get_p(g_context->sn_lsb_ctxt)))
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "CID %zu: CRC repair: CRC failure seems to be caused "
		             "by a sequence number LSB wraparound\n", context->cid);

		g_context->crc_corr = ROHC_DECOMP_CRC_CORR_SN_WRAP;

		/* step d of RFC3095, §5.3.2.2.4. Correction of SN LSB wraparound:
		 *   add 2^k to the reference SN and attempts to decompress the
		 *   packet using the new reference SN */
		bits->sn_ref_offset = (1 << bits->sn_nr);
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "CID %zu: CRC repair: try adding 2^k = 2^%zu = %u to "
		             "reference SN (ref 0 = %u)\n", context->cid, bits->sn_nr,
		             bits->sn_ref_offset, sn_ref_0);
	}
	else if(sn_ref_0 != sn_ref_minus_1)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "CID %zu: CRC repair: CRC failure seems to be caused "
		             "by an incorrect SN update\n", context->cid);

		g_context->crc_corr = ROHC_DECOMP_CRC_CORR_SN_UPDATES;

		/* step d of RFC3095, §5.3.2.2.5. Repair of incorrect SN updates:
		 *   If the header generated in b. does not pass the CRC test, and the
		 *   SN (SN curr2) generated when using ref -1 as the reference is
		 *   different from SN curr1, an additional decompression attempt is
		 *   performed based on SN curr2 as the decompressed SN. */
		bits->sn_ref_type = ROHC_LSB_REF_MINUS_1;
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "CID %zu: CRC repair: try using ref -1 (%u) as reference "
		             "SN instead of ref 0 (%u)\n", context->cid, sn_ref_minus_1,
		             sn_ref_0);
	}
	else
	{
		/* step e of RFC3095, §5.3.2.2.5. Repair of incorrect SN updates:
		 *   If the decompressed header generated in b. does not pass the CRC
		 *   test and SN curr2 is the same as SN curr1, an additional
		 *   decompression attempt is not useful and is not attempted. */
		goto skip;
	}

	/* packet/context correction is going to be attempted, 3 packets with
	 * correct CRC are required to accept the correction */
	g_context->correction_counter = 3;
	attempt_repair = true;

skip:
	return attempt_repair;
}


/**
 * @brief Is SN wraparound possible?
 *
 * According to RFC3095, §5.3.2.2.4, step c, SN wraparound is possible if the
 * inter-packet interval of the current packet is at least 2^k times the
 * nominal inter-packet interval (with k the number of SN bits in the current
 * header).
 *
 * However SN wraparound may happen sooner depending on the shift parameter p
 * of the W-LSB algorithm. If p is large, the interpretation interval is shifted
 * on the left: the positive part of the interpretation interval is smaller.
 * Less (lost) packets are needed to cause a wraparound.
 *
 * The 'width of the positive part of the interpretation interval' (2^k - p) is
 * used instead of the 'width of the full interpretation interval' (2^k).
 *
 * A -10% marge is taken to handle problems due to clock precision.
 *
 * @param cur_arrival_time     The arrival time of the current packet
 * @param arrival_times        The arrival times for the last packets
 * @param arrival_times_nr     The number of arrival times for last packets
 * @param arrival_times_index  The index for the arrival time of the next
 *                             packet
 * @param k                    The number of bits for SN
 * @param p                    The shift parameter p for SN
 * @return                     Whether SN wraparound is possible or not
 */
static bool is_sn_wraparound(const struct rohc_timestamp cur_arrival_time,
                             const struct rohc_timestamp arrival_times[ROHC_MAX_ARRIVAL_TIMES],
                             const size_t arrival_times_nr,
                             const size_t arrival_times_index,
                             const size_t k,
                             const rohc_lsb_shift_t p)
{
	const size_t arrival_times_index_last =
		(arrival_times_index + ROHC_MAX_ARRIVAL_TIMES - 1) % ROHC_MAX_ARRIVAL_TIMES;
	uint64_t cur_interval; /* in microseconds */
	uint64_t avg_interval; /* in microseconds */
	uint64_t min_interval; /* in microseconds */

	/* cannot use correction for SN wraparound if no arrival time was given
	 * for the current packet, or if too few packets were received yet */
	if((cur_arrival_time.sec == 0 && cur_arrival_time.nsec == 0) ||
	   arrival_times_nr < ROHC_MAX_ARRIVAL_TIMES)
	{
		goto error;
	}

	/* compute inter-packet arrival time for current packet */
	cur_interval = rohc_time_interval(arrival_times[arrival_times_index_last],
	                                  cur_arrival_time);

	/* compute average inter-packet arrival time for last packets */
	avg_interval = rohc_time_interval(arrival_times[arrival_times_index],
	                                  arrival_times[arrival_times_index_last]);
	avg_interval /= ROHC_MAX_ARRIVAL_TIMES - 1;

	/* compute the minimum inter-packet interval that the current interval
	 * shall exceed so that SN wraparound is detected */
	if(rohc_interval_compute_p(k, p) >= (1 << k))
	{
		goto error;
	}
	min_interval = ((1 << k) - rohc_interval_compute_p(k, p)) * avg_interval;

	/* substract 10% to handle problems related to clock precision */
	min_interval -= min_interval * 10 / 100;

	/* enough time elapsed for SN wraparound? */
	return (cur_interval >= min_interval);

error:
	return false;
}


/**
 * @brief Build an extension list in IPv6 header
 *
 * @param decomp      The list decompressor
 * @param ip_nh_type  The Next Header value of the base IPv6 header
 * @param dest        The buffer to store the IPv6 header
 * @return            The size of the list
 */
static size_t rohc_build_ip6_extension(const struct list_decomp *const decomp,
                                       const uint8_t ip_nh_type,
                                       unsigned char *const dest)
{
	const struct c_list *list;
	size_t size = 0; // size of the list

	assert(decomp != NULL);
	assert(dest != NULL);

	/* determine which list to use for building IPv6 extension headers */
	if(decomp->ref_ok)
	{
		rd_list_debug(decomp, "use reference list to build IPv6 extension "
		              "headers\n");
		list = decomp->ref_list;
	}
	else
	{
		rd_list_debug(decomp, "use list #%d to build IPv6 extension headers\n",
		              decomp->counter_list);
		list = decomp->list_table[decomp->counter_list];
	}
	assert(list != NULL);

	/* copy IPv6 extension headers if any */
	if(list->first_elt != NULL)
	{
		size_t length; // number of element in reference list
		size_t i;

		length = list_get_size(list);
		for(i = 0; i < length; i++)
		{
			uint8_t nh_type;
			const struct list_elt *elt;
			size_t size_data; // size of one of the extension

			// next header
			elt = list_get_elt_by_index(list, i);
			if(elt->next_elt != NULL)
			{
				/* not last extension header, use next extension header type */
				nh_type = elt->next_elt->item->type;
			}
			else
			{
				/* last extension header, use given IP next header type */
				nh_type = ip_nh_type;
			}
			dest[size] = nh_type & 0xff;

			// length
			size_data = elt->item->length;
			dest[size + 1] = ((size_data / 8) - 1) & 0xff;

			// data
			memcpy(dest + size + 2, elt->item->data + 2, size_data - 2);
			size += size_data;

			rd_list_debug(decomp, "build one %zu-byte IPv6 extension header with "
			              "Next Header 0x%02x\n", size_data, nh_type);
		}
	}

	return size;
}


/**
 * @brief Decode values from extracted bits
 *
 * The following values are decoded:
 *  - SN
 *  - fields related to the outer IP header
 *  - fields related to the inner IP header (if it exists)
 *
 * Other fields may be decoded by the profile-specific callback named
 * decode_values_from_bits.
 *
 * @param decomp   The ROHC decompressor
 * @param context  The decompression context
 * @param bits     The extracted bits
 * @param decoded  OUT: The corresponding decoded values
 * @return         true if decoding is successful, false otherwise
 */
static bool decode_values_from_bits(const struct rohc_decomp *const decomp,
                                    struct d_context *const context,
                                    const struct rohc_extr_bits bits,
                                    struct rohc_decoded_values *const decoded)
{
	struct d_generic_context *g_context;
	bool decode_ok;

	assert(context != NULL);
	assert(context->profile != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;
	assert(decoded != NULL);

	/* decode SN */
	if(!bits.is_sn_enc)
	{
		/* take packet value unchanged */
		assert(bits.sn_nr == 16 || bits.sn_nr == 32);
		decoded->sn = bits.sn;
	}
	else
	{
		/* decode SN from packet bits and context */
		decode_ok = rohc_lsb_decode(g_context->sn_lsb_ctxt, bits.sn_ref_type,
		                            bits.sn_ref_offset, bits.sn, bits.sn_nr,
		                            lsb_get_p(g_context->sn_lsb_ctxt),
		                            &decoded->sn);
		if(!decode_ok)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to decode %zd SN bits 0x%x\n",
			             bits.sn_nr, bits.sn);
			goto error;
		}
	}
	rohc_decomp_debug(context, "decoded SN = %u / 0x%x (nr bits = %zd, "
	                  "bits = %u / 0x%x)\n", decoded->sn, decoded->sn,
	                  bits.sn_nr, bits.sn, bits.sn);

	/* warn if value(SN) is not context(SN) + 1 */
	if(context->num_recv_packets > 1 && !bits.is_context_reused)
	{
		uint32_t sn_context;
		uint32_t expected_next_sn;

		/* get context(SN) */
		sn_context = context->profile->get_sn(context);

		/* compute the next SN value we expect in packet */
		if(context->profile->id == ROHC_PROFILE_ESP)
		{
			/* ESP profile handles 32-bit SN values */
			if(sn_context == 0xffffffff)
			{
				expected_next_sn = 0;
			}
			else
			{
				expected_next_sn = sn_context + 1;
			}
		}
		else
		{
			/* other profiles handle 16-bit SN values */
			if(sn_context == 0xffff)
			{
				expected_next_sn = 0;
			}
			else
			{
				expected_next_sn = sn_context + 1;
			}
		}

		/* do we decoded the expected SN? */
		if(decoded->sn == sn_context)
		{
			/* same SN: duplicated packet detected! */
			rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			          "packet seems to be a duplicated packet (SN = 0x%x)\n",
			          sn_context);
			context->nr_lost_packets = 0;
			context->nr_misordered_packets = 0;
			context->is_duplicated = true;
		}
		else if(decoded->sn > expected_next_sn)
		{
			/* bigger SN: some packets were lost or failed to be decompressed */
			rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			          "%u packets seem to have been lost, damaged, or failed "
			          "to be decompressed (SN jumped from 0x%x to 0x%x)\n",
			          decoded->sn - expected_next_sn, sn_context, decoded->sn);
			context->nr_lost_packets = decoded->sn - expected_next_sn;
			context->nr_misordered_packets = 0;
			context->is_duplicated = false;
		}
		else if(decoded->sn < expected_next_sn)
		{
			/* smaller SN: order was changed on the network channel */
			rohc_info(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			          "packet seems to come late (SN jumped back from 0x%x "
			          "to 0x%x)\n", sn_context, decoded->sn);
			context->nr_lost_packets = 0;
			context->nr_misordered_packets = expected_next_sn - decoded->sn;
			context->is_duplicated = false;
		}
		else
		{
			/* SN is as expected */
			context->nr_lost_packets = 0;
			context->nr_misordered_packets = 0;
			context->is_duplicated = false;
		}
	}
	else
	{
		/* no SN reference to detect SN duplicates or SN jumps */
		context->nr_lost_packets = 0;
		context->nr_misordered_packets = 0;
		context->is_duplicated = false;
	}

	/* decode fields related to the outer IP header */
	decode_ok = decode_ip_values_from_bits(decomp, context,
	                                       g_context->outer_ip_changes,
	                                       g_context->outer_ip_id_offset_ctxt,
	                                       decoded->sn, bits.outer_ip,
	                                       "outer", &decoded->outer_ip);
	if(!decode_ok)
	{
		rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
		             "failed to decode bits extracted for outer IP header\n");
		goto error;
	}

	/* decode fields related to the inner IP header (if it exists) */
	if(g_context->multiple_ip)
	{
		decode_ok = decode_ip_values_from_bits(decomp, context,
		                                       g_context->inner_ip_changes,
		                                       g_context->inner_ip_id_offset_ctxt,
		                                       decoded->sn, bits.inner_ip,
		                                       "inner", &decoded->inner_ip);
		if(!decode_ok)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to decode bits extracted for inner IP header\n");
			goto error;
		}
	}

	/* decode fields of next header if required */
	if(g_context->decode_values_from_bits != NULL)
	{
		decode_ok = g_context->decode_values_from_bits(context, bits, decoded);
		if(!decode_ok)
		{
			rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
			             "failed to decode fields of the next header\n");
			goto error;
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Decode IP values from extracted bits
 *
 * @param decomp        The ROHC decompressor
 * @param context       The decompression context
 * @param ctxt          The decompression context for the IP header
 * @param ip_id_decode  The context for decoding IP-ID offset
 * @param decoded_sn    The SN that was decoded
 * @param bits          The IP bits extracted from ROHC header (all headers
 *                      included: static/dynamic chains, UO* base header,
 *                      UO* extension header, UO* remainder header)
 * @param descr         The description of the IP header
 * @param decoded       OUT: The corresponding decoded IP values
 * @return              true if decoding is successful, false otherwise
 */
static bool decode_ip_values_from_bits(const struct rohc_decomp *const decomp,
                                       const struct d_context *const context,
                                       const struct d_generic_changes *const ctxt,
                                       const struct ip_id_offset_decode *const ip_id_decode,
                                       const uint32_t decoded_sn,
                                       const struct rohc_extr_ip_bits bits,
                                       const char *const descr,
                                       struct rohc_decoded_ip_values *const decoded)
{
	assert(ctxt != NULL);
	assert(decoded != NULL);

	/* IP version (always present in extracted bits) */
	decoded->version = bits.version;

	/* TOS/TC */
	if(bits.tos_nr > 0)
	{
		/* take value from base header */
		decoded->tos = bits.tos;
	}
	else
	{
		/* keep context value */
		decoded->tos = ip_get_tos(&ctxt->ip);
	}
	rohc_decomp_debug(context, "decoded %s TOS/TC = %d\n", descr, decoded->tos);

	/* TTL/HL */
	if(bits.ttl_nr > 0)
	{
		/* take value from base header */
		decoded->ttl = bits.ttl;
	}
	else
	{
		/* keep context value */
		decoded->ttl = ip_get_ttl(&ctxt->ip);
	}
	rohc_decomp_debug(context, "decoded %s TTL/HL = %d\n", descr, decoded->ttl);

	/* protocol/NH */
	if(bits.proto_nr > 0)
	{
		/* take value from base header */
		decoded->proto = bits.proto;
	}
	else
	{
		/* keep context value */
		decoded->proto = ip_get_protocol(&ctxt->ip);
	}
	rohc_decomp_debug(context, "decoded %s protocol/NH = %d\n", descr,
	                  decoded->proto);

	/* version specific fields */
	if(decoded->version == IPV4)
	{
		/* NBO flag */
		if(bits.nbo_nr > 0)
		{
			/* take value from base header */
			decoded->nbo = bits.nbo;
		}
		else
		{
			/* keep context value */
			decoded->nbo = ctxt->nbo;
		}
		rohc_decomp_debug(context, "decoded %s NBO = %d\n", descr, decoded->nbo);

		/* RND flag */
		if(bits.rnd_nr > 0)
		{
			/* take value from base header */
			decoded->rnd = bits.rnd;
		}
		else
		{
			/* keep context value */
			decoded->rnd = ctxt->rnd;
		}
		rohc_decomp_debug(context, "decoded %s RND = %d\n", descr, decoded->rnd);

		/* SID flag */
		if(bits.sid_nr > 0)
		{
			/* take value from base header */
			decoded->sid = bits.sid;
		}
		else
		{
			/* keep context value */
			decoded->sid = ctxt->sid;
		}
		rohc_decomp_debug(context, "decoded %s SID = %d\n", descr, decoded->sid);

		/* IP-ID */
		if(!bits.is_id_enc)
		{
			/* IR/IR-DYN packets transmit the IP-ID verbatim, so convert to
			 * host byte order only if nbo=1 */
			assert(bits.id_nr == 16);
			decoded->id = bits.id;
			if(bits.nbo)
			{
				decoded->id = rohc_ntoh16(bits.id);
			}
			else
			{
#if WORDS_BIGENDIAN == 1
				decoded->id = swab16(bits.id);
#else
				decoded->id = bits.id;
#endif
			}
		}
		else if(decoded->rnd)
		{
			/* take packet value unchanged if random */
			assert(bits.id_nr == 16);
			decoded->id = bits.id;

			if(decoded->sid)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "%s IP-ID got both RND and SID flags!\n", descr);
				goto error;
			}
		}
		else if(decoded->sid)
		{
			/* the IP-ID of the IPv4 header is constant: retrieve the value
			 * that is stored in the context */
			decoded->id = ipv4_get_id(&ctxt->ip);
		}
		else
		{
			/* the IP-ID of the IPv4 header changed in a predictable way:
			 * decode its new value with the help of the decoded SN and the
			 * least-significant IP-ID bits transmitted in the ROHC header */
			int ret;
			ret = ip_id_offset_decode(ip_id_decode, bits.id, bits.id_nr,
			                          decoded_sn, &decoded->id);
			if(ret != 1)
			{
				rohc_warning(decomp, ROHC_TRACE_DECOMP, context->profile->id,
				             "failed to decode %zd %s IP-ID bits 0x%x\n",
				             bits.id_nr, descr, bits.id);
				goto error;
			}
		}
		rohc_decomp_debug(context, "decoded %s IP-ID = 0x%04x (rnd = %d, "
		                  "nbo = %d, sid = %d, nr bits = %zd, bits = 0x%x)\n",
		                  descr, decoded->id, decoded->rnd, decoded->nbo,
		                  decoded->sid, bits.id_nr, bits.id);

		/* DF flag */
		if(bits.df_nr > 0)
		{
			/* take value from base header */
			decoded->df = bits.df;
		}
		else
		{
			/* keep context value */
			decoded->df = ipv4_get_df(&ctxt->ip);
		}
		rohc_decomp_debug(context, "decoded %s DF = %d\n", descr, decoded->df);

		/* source address */
		if(bits.saddr_nr > 0)
		{
			/* take value from base header */
			assert(bits.saddr_nr == 32);
			memcpy(decoded->saddr, bits.saddr, 4);
		}
		else
		{
			/* keep context value */
			const uint32_t saddr_ctxt = ipv4_get_saddr(&ctxt->ip);
			memcpy(decoded->saddr, &saddr_ctxt, 4);
		}
		rohc_decomp_debug(context, "decoded %s src address = " IPV4_ADDR_FORMAT
		                  "\n", descr, IPV4_ADDR_RAW(decoded->saddr));

		/* destination address */
		if(bits.daddr_nr > 0)
		{
			/* take value from base header */
			assert(bits.daddr_nr == 32);
			memcpy(decoded->daddr, bits.daddr, 4);
		}
		else
		{
			/* keep context value */
			const uint32_t daddr_ctxt = ipv4_get_daddr(&ctxt->ip);
			memcpy(decoded->daddr, &daddr_ctxt, 4);
		}
		rohc_decomp_debug(context, "decoded %s dst address = " IPV4_ADDR_FORMAT
		                  "\n", descr, IPV4_ADDR_RAW(decoded->daddr));
	}
	else /* IPV6 */
	{
		/* flow label */
		if(bits.flowid_nr > 0)
		{
			/* take value from base header */
			assert(bits.flowid_nr == 20);
			decoded->flowid = bits.flowid;
		}
		else
		{
			/* keep context value */
			decoded->flowid = ipv6_get_flow_label(&ctxt->ip);
		}
		rohc_decomp_debug(context, "decoded %s flow label = 0x%05x\n", descr,
		                  decoded->flowid);

		/* source address */
		if(bits.saddr_nr > 0)
		{
			/* take value from base header */
			assert(bits.saddr_nr == 128);
			memcpy(decoded->saddr, bits.saddr, 16);
		}
		else
		{
			/* keep context value */
			const struct ipv6_addr *saddr_ctxt = ipv6_get_saddr(&ctxt->ip);
			memcpy(decoded->saddr, saddr_ctxt, 16);
		}
		rohc_decomp_debug(context, "decoded %s src address = " IPV6_ADDR_FORMAT
		                  "\n", descr, IPV6_ADDR_RAW(decoded->saddr));

		/* destination address */
		if(bits.daddr_nr > 0)
		{
			/* take value from base header */
			assert(bits.daddr_nr == 128);
			memcpy(decoded->daddr, bits.daddr, 16);
		}
		else
		{
			/* keep context value */
			const struct ipv6_addr *daddr_ctxt = ipv6_get_daddr(&ctxt->ip);
			memcpy(decoded->daddr, daddr_ctxt, 16);
		}
		rohc_decomp_debug(context, "decoded %s dst address = " IPV6_ADDR_FORMAT
		                  "\n", descr, IPV6_ADDR_RAW(decoded->daddr));
	}

	return true;

error:
	return false;
}


/**
 * @brief Update context with decoded values
 *
 * The following decoded values are updated in context:
 *  - SN
 *  - static & dynamic fields of the outer IP header
 *  - static & dynamic fields of the inner IP header (if it exists)
 *  - fields for the next header (optional, depends on profile)
 *
 * @param context  The decompression context
 * @param decoded  The decoded values to update in the context
 */
static void update_context(const struct d_context *const context,
                           const struct rohc_decoded_values decoded)
{
	struct d_generic_context *g_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = context->specific;

	/* update SN */
	if(g_context->crc_corr == ROHC_DECOMP_CRC_CORR_SN_UPDATES &&
	   g_context->correction_counter == 3)
	{
		/* step f of RFC3095, 5.3.2.2.5. Repair of incorrect SN updates:
		 *   If the decompressed header generated in d. passes the CRC test,
		 *   ref -1 is not changed while ref 0 is set to SN curr2. */
		rohc_lsb_set_ref(g_context->sn_lsb_ctxt, decoded.sn, true);
	}
	else
	{
		/* nominal case and other repair algorithms replace both ref 0 and
		 * ref -1 */
		rohc_lsb_set_ref(g_context->sn_lsb_ctxt, decoded.sn, false);
	}

	/* update fields related to the outer IP header */
	ip_set_version(&g_context->outer_ip_changes->ip, decoded.outer_ip.version);
	ip_set_protocol(&g_context->outer_ip_changes->ip, decoded.outer_ip.proto);
	ip_set_tos(&g_context->outer_ip_changes->ip, decoded.outer_ip.tos);
	ip_set_ttl(&g_context->outer_ip_changes->ip, decoded.outer_ip.ttl);
	ip_set_saddr(&g_context->outer_ip_changes->ip, decoded.outer_ip.saddr);
	ip_set_daddr(&g_context->outer_ip_changes->ip, decoded.outer_ip.daddr);
	if(decoded.outer_ip.version == IPV4)
	{
		ipv4_set_id(&g_context->outer_ip_changes->ip, decoded.outer_ip.id);
		ip_id_offset_set_ref(g_context->outer_ip_id_offset_ctxt,
		                     decoded.outer_ip.id, decoded.sn);
		ipv4_set_df(&g_context->outer_ip_changes->ip, decoded.outer_ip.df);
		g_context->outer_ip_changes->nbo = decoded.outer_ip.nbo;
		g_context->outer_ip_changes->rnd = decoded.outer_ip.rnd;
		g_context->outer_ip_changes->sid = decoded.outer_ip.sid;
	}
	else /* IPV6 */
	{
		ipv6_set_flow_label(&g_context->outer_ip_changes->ip, decoded.outer_ip.flowid);
	}

	/* update fields related to the inner IP header (if any) */
	if(g_context->multiple_ip)
	{
		ip_set_version(&g_context->inner_ip_changes->ip, decoded.inner_ip.version);
		ip_set_protocol(&g_context->inner_ip_changes->ip, decoded.inner_ip.proto);
		ip_set_tos(&g_context->inner_ip_changes->ip, decoded.inner_ip.tos);
		ip_set_ttl(&g_context->inner_ip_changes->ip, decoded.inner_ip.ttl);
		ip_set_saddr(&g_context->inner_ip_changes->ip, decoded.inner_ip.saddr);
		ip_set_daddr(&g_context->inner_ip_changes->ip, decoded.inner_ip.daddr);
		if(decoded.inner_ip.version == IPV4)
		{
			ipv4_set_id(&g_context->inner_ip_changes->ip, decoded.inner_ip.id);
			ip_id_offset_set_ref(g_context->inner_ip_id_offset_ctxt,
			                     decoded.inner_ip.id, decoded.sn);
			ipv4_set_df(&g_context->inner_ip_changes->ip, decoded.inner_ip.df);
			g_context->inner_ip_changes->nbo = decoded.inner_ip.nbo;
			g_context->inner_ip_changes->rnd = decoded.inner_ip.rnd;
			g_context->inner_ip_changes->sid = decoded.inner_ip.sid;
		}
		else /* IPV6 */
		{
			ipv6_set_flow_label(&g_context->inner_ip_changes->ip, decoded.inner_ip.flowid);
		}
	}

	/* update arrival time */
	g_context->arrival_times[g_context->arrival_times_index] =
		g_context->cur_arrival_time;
	g_context->arrival_times_index =
		(g_context->arrival_times_index + 1) % ROHC_MAX_ARRIVAL_TIMES;
	g_context->arrival_times_nr =
		rohc_min(g_context->arrival_times_nr + 1, ROHC_MAX_ARRIVAL_TIMES);

	/* update context with decoded fields for next header if required */
	if(g_context->update_context != NULL)
	{
		g_context->update_context(context, decoded);
	}
}


/**
 * @brief Update statistics upon successful decompression
 *
 * @param context         The decompression context
 * @param comp_hdr_len    The length (in bytes) of the compressed header
 * @param uncomp_hdr_len  The length (in bytes) of the uncompressed header
 */
static void stats_add_decomp_success(struct d_context *const context,
                                     const size_t comp_hdr_len,
                                     const size_t uncomp_hdr_len)
{
	assert(context != NULL);
	context->header_compressed_size += comp_hdr_len;
	c_add_wlsb(context->header_16_compressed, 0, comp_hdr_len);
	context->header_uncompressed_size += uncomp_hdr_len;
	c_add_wlsb(context->header_16_uncompressed, 0, uncomp_hdr_len);
}


/**
 * @brief Reset the extracted bits for next parsing
 *
 * @param g_context  The generic decompression context
 * @param bits       OUT: The extracted bits to reset
 */
static void reset_extr_bits(const struct d_generic_context *const g_context,
                            struct rohc_extr_bits *const bits)
{
	assert(g_context != NULL);
	assert(bits != NULL);

	/* set every bits and sizes to 0 */
	memset(bits, 0, sizeof(struct rohc_extr_bits));

	/* by default, use ref 0 for LSB decoding (ref -1 will be used only for
	 * correction upon CRC failure) */
	bits->sn_ref_type = ROHC_LSB_REF_0;
	/* by default, do not apply any offset on reference SN (it will be applied
	 * only for correction upon CRC failure) */
	bits->sn_ref_offset = 0;

	/* by default context is not re-used */
	bits->is_context_reused = false;

	/* set IP version and NBO/RND flags for outer IP header */
	bits->outer_ip.version = ip_get_version(&g_context->outer_ip_changes->ip);
	bits->outer_ip.nbo = g_context->outer_ip_changes->nbo;
	bits->outer_ip.rnd = g_context->outer_ip_changes->rnd;
	bits->outer_ip.is_id_enc = true;

	/* set IP version and NBO/RND flags for inner IP header (if any) */
	if(g_context->multiple_ip)
	{
		bits->inner_ip.version = ip_get_version(&g_context->inner_ip_changes->ip);
		bits->inner_ip.nbo = g_context->inner_ip_changes->nbo;
		bits->inner_ip.rnd = g_context->inner_ip_changes->rnd;
		bits->inner_ip.is_id_enc = true;
	}

	/* According to RFC 3095 §5.7.5:
	 *
	 *   The TS field is scaled in all extensions, as it is in the base header,
	 *   except optionally when using Extension 3 where the Tsc flag can
	 *   indicate that the TS field is not scaled.
	 *
	 * So init the is_ts_scaled variable to true by default.
	 * \ref parse_extension3 will reset it to false if needed.
	 */
	bits->is_ts_scaled = true;
}

