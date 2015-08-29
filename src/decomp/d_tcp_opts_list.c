/*
 * Copyright 2012,2013,2014,2015 Didier Barvaux
 * Copyright 2013,2014 Viveris Technologies
 * Copyright 2012 WBX
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
 * @file   d_tcp_opts_list.c
 * @brief  Handle the list of TCP options for the TCP decompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "d_tcp_opts_list.h"

#include "d_tcp_defines.h"
#include "protocols/tcp.h"
#include "rohc_bit_ops.h"
#include "rohc_utils.h"
#include "schemes/tcp_sack.h"

#include "config.h" /* for ROHC_RFC_STRICT_DECOMPRESSOR */

#ifndef __KERNEL__
#  include <string.h>
#endif


struct d_tcp_opt_index /* TODO */
{
	bool used;
	uint8_t index;
	bool is_item_present;
};


struct d_tcp_opt /* TODO */
{
	uint8_t index;
	bool is_well_known;
	uint8_t kind;
	char descr[255];
	int (*parse_dynamic)(const struct rohc_decomp_ctxt *const context,
	                     const uint8_t *const data,
	                     const size_t data_len,
	                     struct d_tcp_opt_ctxt *const opt_ctxt)
		__attribute__((warn_unused_result, nonnull(1, 2, 4)));
	int (*parse_irregular)(const struct rohc_decomp_ctxt *const context,
	                       const uint8_t *const data,
	                       const size_t data_len,
	                       const uint8_t opt_index,
	                       struct d_tcp_opt_ctxt *const opt_ctxt)
		__attribute__((warn_unused_result, nonnull(1, 2, 5)));
	bool (*build)(const struct rohc_decomp_ctxt *const context,
	              const struct rohc_tcp_decoded_values *const decoded,
	              const struct d_tcp_opt_ctxt *const tcp_opt,
	              struct rohc_buf *const uncomp_packet,
	              size_t *const opt_len)
		__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));
};


static int d_tcp_opt_list_parse_indexes(const struct rohc_decomp_ctxt *const context,
                                        const uint8_t ps,
                                        const uint8_t m,
                                        const uint8_t *const indexes,
                                        const size_t indexes_max_len,
                                        const bool want_all_items_present,
                                        struct d_tcp_opt_index opt_indexes[ROHC_TCP_OPTS_MAX])
	__attribute__((warn_unused_result, nonnull(1, 4, 7)));

static int d_tcp_opt_list_parse_items(const struct rohc_decomp_ctxt *const context,
                                      const bool is_dynamic_chain,
                                      const uint8_t m,
                                      const struct d_tcp_opt_index opt_indexes[ROHC_TCP_OPTS_MAX],
                                      const uint8_t *const items,
                                      const size_t items_max_len,
                                      struct d_tcp_opts_ctxt *const tcp_opts)
	__attribute__((warn_unused_result, nonnull(1, 4, 5, 7)));

static int d_tcp_opt_list_parse_item(const struct rohc_decomp_ctxt *const context,
                                     const bool is_dynamic_chain,
                                     const struct d_tcp_opt_index opt_index,
                                     const uint8_t *const item,
                                     const size_t item_max_len,
                                     struct d_tcp_opt_ctxt opts_bits[MAX_TCP_OPTION_INDEX + 1])
	__attribute__((warn_unused_result, nonnull(1, 4, 6)));

static size_t d_tcp_opt_list_get_index_len(const uint8_t ps)
	__attribute__((warn_unused_result, const));

static size_t d_tcp_opt_list_get_indexes_len(const uint8_t ps, const uint8_t m)
	__attribute__((warn_unused_result, const));

static bool tcp_opt_is_well_known(const uint8_t idx)
	__attribute__((warn_unused_result, pure));

static int d_tcp_parse_nop_dyn(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const data,
                               const size_t data_len,
                               struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int d_tcp_parse_nop_irreg(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const data,
                                 const size_t data_len,
                                 const uint8_t opt_index,
                                 struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static bool d_tcp_build_nop(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_tcp_decoded_values *const decoded,
                            const struct d_tcp_opt_ctxt *const tcp_opt,
                            struct rohc_buf *const uncomp_packet,
                            size_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

static int d_tcp_parse_eol_dyn(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const data,
                               const size_t data_len,
                               struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int d_tcp_parse_eol_irreg(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const data,
                                 const size_t data_len,
                                 const uint8_t opt_index,
                                 struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static bool d_tcp_build_eol(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_tcp_decoded_values *const decoded,
                            const struct d_tcp_opt_ctxt *const tcp_opt,
                            struct rohc_buf *const uncomp_packet,
                            size_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

static int d_tcp_parse_mss_dyn(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const data,
                               const size_t data_len,
                               struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int d_tcp_parse_mss_irreg(const struct rohc_decomp_ctxt *const context,
                                 const uint8_t *const data,
                                 const size_t data_len,
                                 const uint8_t opt_index,
                                 struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static bool d_tcp_build_mss(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_tcp_decoded_values *const decoded,
                            const struct d_tcp_opt_ctxt *const tcp_opt,
                            struct rohc_buf *const uncomp_packet,
                            size_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

static int d_tcp_parse_ws_dyn(const struct rohc_decomp_ctxt *const context,
                              const uint8_t *const data,
                              const size_t data_len,
                              struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int d_tcp_parse_ws_irreg(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const data,
                                const size_t data_len,
                                const uint8_t opt_index,
                                struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static bool d_tcp_build_ws(const struct rohc_decomp_ctxt *const context,
                           const struct rohc_tcp_decoded_values *const decoded,
                           const struct d_tcp_opt_ctxt *const tcp_opt,
                           struct rohc_buf *const uncomp_packet,
                           size_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

static int d_tcp_parse_ts_dyn(const struct rohc_decomp_ctxt *const context,
                              const uint8_t *const data,
                              const size_t data_len,
                              struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int d_tcp_parse_ts_irreg(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const data,
                                const size_t data_len,
                                const uint8_t opt_index,
                                struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static bool d_tcp_build_ts(const struct rohc_decomp_ctxt *const context,
                           const struct rohc_tcp_decoded_values *const decoded,
                           const struct d_tcp_opt_ctxt *const tcp_opt,
                           struct rohc_buf *const uncomp_packet,
                           size_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

static int d_tcp_parse_sack_perm_dyn(const struct rohc_decomp_ctxt *const context,
                                     const uint8_t *const data,
                                     const size_t data_len,
                                     struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int d_tcp_parse_sack_perm_irreg(const struct rohc_decomp_ctxt *const context,
                                       const uint8_t *const data,
                                       const size_t data_len,
                                       const uint8_t opt_index,
                                       struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static bool d_tcp_build_sack_perm(const struct rohc_decomp_ctxt *const context,
                                  const struct rohc_tcp_decoded_values *const decoded,
                                  const struct d_tcp_opt_ctxt *const tcp_opt,
                                  struct rohc_buf *const uncomp_packet,
                                  size_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

static int d_tcp_parse_sack_dyn(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const data,
                                const size_t data_len,
                                struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int d_tcp_parse_sack_irreg(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *const data,
                                  const size_t data_len,
                                  const uint8_t opt_index,
                                  struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static bool d_tcp_build_sack(const struct rohc_decomp_ctxt *const context,
                             const struct rohc_tcp_decoded_values *const decoded,
                             const struct d_tcp_opt_ctxt *const tcp_opt,
                             struct rohc_buf *const uncomp_packet,
                             size_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));

static int d_tcp_parse_generic_dyn(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const data,
                                   const size_t data_len,
                                   struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));
static int d_tcp_parse_generic_irreg(const struct rohc_decomp_ctxt *const context,
                                     const uint8_t *const data,
                                     const size_t data_len,
                                     const uint8_t opt_index,
                                     struct d_tcp_opt_ctxt *const opt_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 2, 5)));
static bool d_tcp_build_generic(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_tcp_decoded_values *const decoded,
                                const struct d_tcp_opt_ctxt *const tcp_opt,
                                struct rohc_buf *const uncomp_packet,
                                size_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 5)));


/* TODO */
static struct d_tcp_opt d_tcp_opts[MAX_TCP_OPTION_INDEX + 1] =
{
	[TCP_INDEX_NOP]       = { TCP_INDEX_NOP, true, TCP_OPT_NOP,
	                          "No Operation (NOP)",
	                          d_tcp_parse_nop_dyn, d_tcp_parse_nop_irreg,
	                          d_tcp_build_nop },
	[TCP_INDEX_EOL]       = { TCP_INDEX_EOL, true, TCP_OPT_EOL,
	                          "End of Option List (EOL)",
	                          d_tcp_parse_eol_dyn, d_tcp_parse_eol_irreg,
	                          d_tcp_build_eol },
	[TCP_INDEX_MSS]       = { TCP_INDEX_MSS, true, TCP_OPT_MSS,
	                          "Maximum Segment Size (MSS)",
	                          d_tcp_parse_mss_dyn, d_tcp_parse_mss_irreg,
	                          d_tcp_build_mss },
	[TCP_INDEX_WS]        = { TCP_INDEX_WS, true, TCP_OPT_WS,
	                          "Window Scale (WS)",
	                          d_tcp_parse_ws_dyn, d_tcp_parse_ws_irreg,
	                          d_tcp_build_ws },
	[TCP_INDEX_TS]        = { TCP_INDEX_TS, true, TCP_OPT_TS,
	                          "Timestamps (TS)",
	                          d_tcp_parse_ts_dyn, d_tcp_parse_ts_irreg,
	                          d_tcp_build_ts },
	[TCP_INDEX_SACK_PERM] = { TCP_INDEX_SACK_PERM, true, TCP_OPT_SACK_PERM,
	                          "Selective Acknowledgment Permitted (SACK)",
	                          d_tcp_parse_sack_perm_dyn, d_tcp_parse_sack_perm_irreg,
	                          d_tcp_build_sack_perm },
	[TCP_INDEX_SACK]      = { TCP_INDEX_SACK, true, TCP_OPT_SACK,
	                          "Selective Acknowledgment (SACK)",
	                          d_tcp_parse_sack_dyn, d_tcp_parse_sack_irreg,
	                          d_tcp_build_sack },
	[TCP_INDEX_GENERIC7]  = { TCP_INDEX_GENERIC7, false, 0,
	                          "generic index 7",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
	[TCP_INDEX_GENERIC8]  = { TCP_INDEX_GENERIC8, false, 0,
	                          "generic index 8",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
	[TCP_INDEX_GENERIC9]  = { TCP_INDEX_GENERIC9, false, 0,
	                          "generic index 9",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
	[TCP_INDEX_GENERIC10] = { TCP_INDEX_GENERIC10, false, 0,
	                          "generic index 10",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
	[TCP_INDEX_GENERIC11] = { TCP_INDEX_GENERIC11, false, 0,
	                          "generic index 11",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
	[TCP_INDEX_GENERIC12] = { TCP_INDEX_GENERIC12, false, 0,
	                          "generic index 12",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
	[TCP_INDEX_GENERIC13] = { TCP_INDEX_GENERIC13, false, 0,
	                          "generic index 13",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
	[TCP_INDEX_GENERIC14] = { TCP_INDEX_GENERIC14, false, 0,
	                          "generic index 14",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
	[TCP_INDEX_GENERIC15] = { TCP_INDEX_GENERIC15, false, 0,
	                          "generic index 15",
	                          d_tcp_parse_generic_dyn, d_tcp_parse_generic_irreg,
	                          d_tcp_build_generic },
};


/* TODO */
int d_tcp_parse_tcp_opts_dyn(const struct rohc_decomp_ctxt *const context,
                             const uint8_t *const rohc_packet,
                             const size_t rohc_length,
                             const bool is_dynamic_chain,
                             struct d_tcp_opts_ctxt *const tcp_opts)
{
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	int ret;

	struct d_tcp_opt_index indexes[ROHC_TCP_OPTS_MAX] =
		{ { .used = 0, .index = 0, .is_item_present = 0 } };
	uint8_t reserved;
	uint8_t PS;
	uint8_t m;

	/* we need at least one byte to check whether TCP options are present or
	 * not */
	if(remain_len < 1)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: only %zu bytes available "
		                 "while at least 1 byte required for the first byte of TCP "
		                 "options", remain_len);
		goto error;
	}

	/* read number of XI item(s) in the compressed list */
	reserved = remain_data[0] & 0xe0;
	m = remain_data[0] & 0x0f;
	PS = GET_REAL(remain_data[0] & 0x10);
	if(reserved != 0)
	{
		rohc_decomp_debug(context, "malformed ROHC packet: malformed compressed "
		                  "list of TCP options: reserved bits must be zero, but "
		                  "first byte is 0x%02x", remain_data[0]);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}
	remain_data++;
	remain_len--;

	/* if TCP option list compression present */
	if(m == 0)
	{
		rohc_decomp_debug(context, "TCP list contains no option");
		goto skip;
	}

	/* parse list indexes */
	ret = d_tcp_opt_list_parse_indexes(context, PS, m, remain_data, remain_len,
	                                   is_dynamic_chain, indexes);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: failed to parse the list "
		                 "indexes for the compressed list of TCP options");
		goto error;
	}
	remain_data += ret;
	remain_len -= ret;

	/* parse list items */
	ret = d_tcp_opt_list_parse_items(context, is_dynamic_chain, m, indexes,
	                                 remain_data, remain_len, tcp_opts);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: failed to parse the list "
		                 "items for the compressed list of TCP options");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += ret;
#endif
	remain_len -= ret;

skip:
	return (rohc_length - remain_len);
error:
	return -1;
}


/* TODO */
int d_tcp_parse_tcp_opts_irreg(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const rohc_packet,
                               const size_t rohc_length,
                               struct d_tcp_opts_ctxt *const tcp_opts)
{
	const struct d_tcp_context *const tcp_context = context->persist_ctxt;
	const uint8_t *remain_data = rohc_packet;
	size_t remain_len = rohc_length;
	size_t i;
	int ret;

	for(i = 0; i < tcp_opts->nr; i++)
	{
		const uint8_t opt_index = tcp_opts->structure[i];
		struct d_tcp_opt_ctxt *const tcp_opt = &(tcp_opts->bits[opt_index]);
		uint8_t opt_type;

		assert(opt_index <= MAX_TCP_OPTION_INDEX);
		assert(tcp_opt->used);

		if(tcp_opts->expected_dynamic[i])
		{
			opt_type = tcp_opt->type;
			rohc_decomp_debug(context, "TCP irregular part: TCP option '%s' (%u) "
			                  "with index %u is not present",
			                  d_tcp_opts[opt_index].descr, opt_type, opt_index);
		}
		else
		{
			tcp_opt->type = tcp_context->tcp_opts.bits[opt_index].type;
			opt_type = tcp_opt->type;
			rohc_decomp_debug(context, "TCP irregular part: TCP option '%s' (%u) "
			                  "with index %u is present",
			                  d_tcp_opts[opt_index].descr, opt_type, opt_index);

			/* parse TCP option */
			ret = d_tcp_opts[opt_index].parse_irregular(context, remain_data,
			                                            remain_len, opt_index,
			                                            tcp_opt);
			if(ret < 0)
			{
				rohc_decomp_warn(context, "malformed ROHC packet: failed to parse item "
				                 "with index %u in the irregular chain", opt_index);
				goto error;
			}
			remain_data += ret;
			remain_len -= ret;

			/* now, option was found */
			tcp_opts->found[i] = true;
		}
	}

	return (rohc_length - remain_len);

error:
	return -1;
}


/* TODO */
static int d_tcp_opt_list_parse_indexes(const struct rohc_decomp_ctxt *const context,
                                        const uint8_t ps,
                                        const uint8_t m,
                                        const uint8_t *const indexes,
                                        const size_t indexes_max_len,
                                        const bool want_all_items_present,
                                        struct d_tcp_opt_index opt_indexes[ROHC_TCP_OPTS_MAX])
{
	size_t indexes_len;
	size_t index_pos;
	size_t i;

	/* compute the length of the indexes */
	indexes_len = d_tcp_opt_list_get_indexes_len(ps, m);
	rohc_decomp_debug(context, "TCP options list: %zu-bit XI fields are used on "
	                  "%zu bytes", d_tcp_opt_list_get_index_len(ps), indexes_len);

	/* enough remaining data for all indexes? */
	if(indexes_max_len < indexes_len)
	{
		rohc_decomp_warn(context, "ROHC packet is too small for compressed TCP "
		                 "options: %zu bytes available while at least %zu bytes "
		                 "required for the list indexes", indexes_max_len,
		                 indexes_len);
		goto error;
	}

	/* for all indexes in the list */
	for(i = 0, index_pos = 0; i < m && index_pos < indexes_len; i++)
	{
		bool is_item_present;
		uint8_t idx;

		if(ps == 0) /* 4-bit XI fields */
		{
			uint8_t value;

			if(i & 1) /* if odd position */
			{
				value = indexes[index_pos];
				index_pos++;
			}
			else
			{
				value = indexes[index_pos] >> 4;
			}
			is_item_present = GET_BOOL(GET_BIT_3(&value));
			idx = value & 0x07;
		}
		else /* 8-bit XI fields */
		{
			const uint8_t reserved = GET_BIT_4_6(indexes + index_pos);
			is_item_present = GET_BOOL(GET_BIT_7(indexes + index_pos));
			idx = indexes[index_pos] & 0x0f;
			if(reserved != 0)
			{
				rohc_decomp_debug(context, "malformed compressed list of TCP options: "
				                  "reserved bits of the 8-bit XI #%zu shall be zero, "
				                  "but XI is 0x%02x", i, indexes[index_pos]);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
				goto error;
#endif
			}
			index_pos++;
		}
		rohc_decomp_debug(context, "TCP options list: %zu-bit XI field #%zu: item "
		                  "with index %u is %s", d_tcp_opt_list_get_index_len(ps),
		                  i, idx, is_item_present ? "present" : "not present");

		if(want_all_items_present && !is_item_present)
		{
			rohc_decomp_warn(context, "malformed compressed list of TCP options: XI "
			                 "#%zu reports that item is not present while required "
			                 "in that kind of ROHC packet", i);
			goto error;
		}

		opt_indexes[i].used = true;
		opt_indexes[i].index = idx;
		opt_indexes[i].is_item_present = is_item_present;
	}

	/* check that the padding bits are zero in case of odd number of 4-bit XI fields */
	if(ps == 0 && (m % 2) != 0 && (indexes[index_pos] & 0x0f) != 0)
	{
		rohc_decomp_debug(context, "malformed compressed list of TCP options: the "
		                  "4-bit padding at the end of the %u 4-bit indexes shall "
		                  "be zero but it is 0x%x", m, indexes[index_pos] & 0x0f);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}

	return indexes_len;

error:
	return -1;
}


/* TODO */
static int d_tcp_opt_list_parse_items(const struct rohc_decomp_ctxt *const context,
                                      const bool is_dynamic_chain,
                                      const uint8_t m,
                                      const struct d_tcp_opt_index opt_indexes[ROHC_TCP_OPTS_MAX],
                                      const uint8_t *const items,
                                      const size_t items_max_len,
                                      struct d_tcp_opts_ctxt *const tcp_opts)
{
	const uint8_t *remain_data = items;
	size_t remain_len = items_max_len;
	uint8_t i;
	int ret;

	/* for all indexes in the list */
	for(i = 0; i < m; i++)
	{
		/* parse one list item */
		rohc_decomp_debug(context, "  TCP options list: XI #%u:", i);
		ret = d_tcp_opt_list_parse_item(context, is_dynamic_chain, opt_indexes[i],
		                                remain_data, remain_len, tcp_opts->bits);
		if(ret < 0)
		{
			rohc_decomp_warn(context, "malformed ROHC packet: failed to parse item "
			                 "of index #%u for the compressed list of TCP options", i);
			goto error;
		}
		remain_data += ret;
		remain_len -= ret;

		/* remember the structure of the list for parsing the irregular chain */
		tcp_opts->structure[i] = opt_indexes[i].index;
		tcp_opts->expected_dynamic[i] = opt_indexes[i].is_item_present;
		if(tcp_opts->expected_dynamic[i])
		{
			tcp_opts->found[i] = true;
		}
		tcp_opts->nr++;
	}

	return (items_max_len - remain_len);

error:
	return -1;
}


/* TODO */
static int d_tcp_opt_list_parse_item(const struct rohc_decomp_ctxt *const context,
                                     const bool is_dynamic_chain,
                                     const struct d_tcp_opt_index opt_index,
                                     const uint8_t *const item,
                                     const size_t item_max_len,
                                     struct d_tcp_opt_ctxt opts_bits[MAX_TCP_OPTION_INDEX + 1])
{
	struct d_tcp_opt_ctxt *const opt_bits = &(opts_bits[opt_index.index]);
	const uint8_t *remain_data = item;
	size_t remain_len = item_max_len;
	int ret;

	rohc_decomp_debug(context, "    item for index %u is %s", opt_index.index,
	                  (opt_index.is_item_present ? "present" : "absent"));

	if(!opt_index.is_item_present)
	{
		goto skip;
	}

	/* is option well-known? */
	if(tcp_opt_is_well_known(opt_index.index))
	{
		rohc_decomp_debug(context, "    parse the well-known TCP option '%s' (%u) "
		                  "with index %u in the %s",
		                  d_tcp_opts[opt_index.index].descr,
		                  d_tcp_opts[opt_index.index].kind, opt_index.index,
		                  is_dynamic_chain ? "dynamic chain" : "optional list");
		opt_bits->type = d_tcp_opts[opt_index.index].kind;
	}
	else
	{
		rohc_decomp_debug(context, "    parse the generic TCP option with index %u "
		                  "in the %s", opt_index.index, is_dynamic_chain ?
		                  "dynamic chain" : "optional list");
	}

	/* parse TCP option */
	ret = d_tcp_opts[opt_index.index].parse_dynamic(context, remain_data, remain_len,
	                                                opt_bits);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: failed to parse item "
		                 "with index %u in the %s chain", opt_index.index,
		                 is_dynamic_chain ? "dynamic chain" : "optional list");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += ret;
#endif
	remain_len -= ret;

	rohc_decomp_debug(context, "    %d bytes of TCP option of type 0x%02x (%u)",
	                  ret, opt_bits->type, opt_bits->type);

skip:
	/* last, make TCP index as used */
	opt_bits->used = true;
	return (item_max_len - remain_len);
error:
	return -1;
}


/* TODO */
static size_t d_tcp_opt_list_get_index_len(const uint8_t ps)
{
	assert(ps == 0 || ps == 1);
	return (ps == 0 ? 4U : 8U);
}


/* TODO */
static size_t d_tcp_opt_list_get_indexes_len(const uint8_t ps, const uint8_t m)
{
	assert(ps == 0 || ps == 1);
	assert(m <= MAX_TCP_OPTION_INDEX);
	return (ps == 0 ? ((m + 1) >> 1) : m);
}


/**
 * @brief Is the TCP option index a well-known index in the TCP profile
 *
 * @param idx  The index of the TCP option
 * @return     true if the index is a well-known index
 */
static bool tcp_opt_is_well_known(const uint8_t idx)
{
	assert(idx <= MAX_TCP_OPTION_INDEX);
	return d_tcp_opts[idx].is_well_known;
}


/* TODO */
static int d_tcp_parse_nop_dyn(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                               const uint8_t *const data __attribute__((unused)),
                               const size_t data_len __attribute__((unused)),
                               struct d_tcp_opt_ctxt *const opt_ctxt __attribute__((unused)))
{
	return 0;
}


/* TODO */
static int d_tcp_parse_nop_irreg(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                 const uint8_t *const data __attribute__((unused)),
                                 const size_t data_len __attribute__((unused)),
                                 const uint8_t opt_index __attribute__((unused)),
                                 struct d_tcp_opt_ctxt *const opt_ctxt __attribute__((unused)))
{
	return 0;
}


/* TODO */
static bool d_tcp_build_nop(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_tcp_decoded_values *const decoded __attribute__((unused)),
                            const struct d_tcp_opt_ctxt *const tcp_opt __attribute__((unused)),
                            struct rohc_buf *const uncomp_packet,
                            size_t *const opt_len)
{
	const size_t opt_nop_len = sizeof(uint8_t);

	if(rohc_buf_avail_len(*uncomp_packet) < opt_nop_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP NOP option", opt_nop_len);
		goto error;
	}
	rohc_buf_byte(*uncomp_packet) = TCP_OPT_NOP;
	uncomp_packet->len++;
	*opt_len = 1;

	return true;

error:
	return false;
}


/* TODO */
static int d_tcp_parse_eol_dyn(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const data,
                               const size_t data_len,
                               struct d_tcp_opt_ctxt *const opt_ctxt)
{
	const size_t eol_dyn_len = sizeof(uint8_t);
	const size_t max_opt_len = 0xff; /* TODO */
	size_t eol_uncomp_len;

	if(data_len < eol_dyn_len)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP option "
		                 "items: only %zu bytes available while at least %zu bytes "
		                 "required for EOL option", data_len, eol_dyn_len);
		goto error;
	}
	eol_uncomp_len = data[0] + 1;
	if(eol_uncomp_len > max_opt_len)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP option "
		                 "items: TCP EOL option is %zu-byte long according to ROHC "
		                 "packet, but maximum length is %zu bytes", eol_uncomp_len,
		                 max_opt_len);
		goto error;
	}
	rohc_decomp_debug(context, "    EOL option is repeated %zu times", eol_uncomp_len);
	opt_ctxt->data.eol.is_static = false;
	opt_ctxt->data.eol.len = eol_uncomp_len;

	return eol_dyn_len;

error:
	return -1;
}


/* TODO */
static int d_tcp_parse_eol_irreg(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                 const uint8_t *const data __attribute__((unused)),
                                 const size_t data_len __attribute__((unused)),
                                 const uint8_t opt_index __attribute__((unused)),
                                 struct d_tcp_opt_ctxt *const opt_ctxt __attribute__((unused)))
{
	opt_ctxt->data.eol.is_static = true;
	return 0;
}


/* TODO */
static bool d_tcp_build_eol(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_tcp_decoded_values *const decoded __attribute__((unused)),
                            const struct d_tcp_opt_ctxt *const tcp_opt,
                            struct rohc_buf *const uncomp_packet,
                            size_t *const opt_len)
{
	const size_t eol_len = tcp_opt->data.eol.len;
	size_t i;

	if(rohc_buf_avail_len(*uncomp_packet) < eol_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP EOL option", eol_len);
		goto error;
	}

	for(i = 0; i < eol_len; i++)
	{
		rohc_buf_byte_at(*uncomp_packet, i) = TCP_OPT_EOL;
	}
	uncomp_packet->len += eol_len;
	*opt_len = eol_len;

	return true;

error:
	return false;
}


/* TODO */
static int d_tcp_parse_mss_dyn(const struct rohc_decomp_ctxt *const context,
                               const uint8_t *const data,
                               const size_t data_len,
                               struct d_tcp_opt_ctxt *const opt_ctxt)
{
	const size_t mss_dyn_len = sizeof(uint16_t);

	if(data_len < mss_dyn_len)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP option "
		                 "items: only %zu bytes available while at least %zu bytes "
		                 "required for MSS option", data_len, mss_dyn_len);
		goto error;
	}
	opt_ctxt->data.mss.is_static = false;
	memcpy(&opt_ctxt->data.mss.value, data, mss_dyn_len);
	opt_ctxt->data.mss.value = rohc_ntoh16(opt_ctxt->data.mss.value);
	rohc_decomp_debug(context, "    TCP option MAXSEG = %u (0x%04x)",
	                  opt_ctxt->data.mss.value, opt_ctxt->data.mss.value);

	return mss_dyn_len;

error:
	return -1;
}


/* TODO */
static int d_tcp_parse_mss_irreg(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                 const uint8_t *const data __attribute__((unused)),
                                 const size_t data_len __attribute__((unused)),
                                 const uint8_t opt_index __attribute__((unused)),
                                 struct d_tcp_opt_ctxt *const opt_ctxt __attribute__((unused)))
{
	opt_ctxt->data.mss.is_static = true;
	return 0;
}


/* TODO */
static bool d_tcp_build_mss(const struct rohc_decomp_ctxt *const context,
                            const struct rohc_tcp_decoded_values *const decoded __attribute__((unused)),
                            const struct d_tcp_opt_ctxt *const tcp_opt,
                            struct rohc_buf *const uncomp_packet,
                            size_t *const opt_len)
{
	const size_t mss_len = 2 + sizeof(uint16_t);
	const uint16_t mss_value_nbo = rohc_hton16(tcp_opt->data.mss.value);

	if(rohc_buf_avail_len(*uncomp_packet) < mss_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP MSS option", mss_len);
		goto error;
	}

	rohc_buf_byte_at(*uncomp_packet, 0) = TCP_OPT_MSS;
	uncomp_packet->len++;
	rohc_buf_byte_at(*uncomp_packet, 1) = mss_len;
	uncomp_packet->len++;
	rohc_buf_append(uncomp_packet, (uint8_t *) &mss_value_nbo, sizeof(uint16_t));
	*opt_len = mss_len;

	return true;

error:
	return false;
}


/* TODO */
static int d_tcp_parse_ws_dyn(const struct rohc_decomp_ctxt *const context,
                              const uint8_t *const data,
                              const size_t data_len,
                              struct d_tcp_opt_ctxt *const opt_ctxt)
{
	const size_t ws_dyn_len = sizeof(uint8_t);

	if(data_len < ws_dyn_len)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP option "
		                 "items: only %zu bytes available while at least %zu bytes "
		                 "required for WS option", data_len, ws_dyn_len);
		goto error;
	}
	opt_ctxt->data.ws.is_static = false;
	opt_ctxt->data.ws.value = data[0];

	return ws_dyn_len;

error:
	return -1;
}


/* TODO */
static int d_tcp_parse_ws_irreg(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                const uint8_t *const data __attribute__((unused)),
                                const size_t data_len __attribute__((unused)),
                                const uint8_t opt_index __attribute__((unused)),
                                struct d_tcp_opt_ctxt *const opt_ctxt __attribute__((unused)))
{
	opt_ctxt->data.ws.is_static = true;
	return 0;
}


/* TODO */
static bool d_tcp_build_ws(const struct rohc_decomp_ctxt *const context,
                           const struct rohc_tcp_decoded_values *const decoded __attribute__((unused)),
                           const struct d_tcp_opt_ctxt *const tcp_opt,
                           struct rohc_buf *const uncomp_packet,
                           size_t *const opt_len)
{
	const size_t ws_len = 2 + sizeof(uint8_t);

	if(rohc_buf_avail_len(*uncomp_packet) < ws_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP WS option", ws_len);
		goto error;
	}

	rohc_buf_byte_at(*uncomp_packet, 0) = TCP_OPT_WS;
	rohc_buf_byte_at(*uncomp_packet, 1) = ws_len;
	rohc_buf_byte_at(*uncomp_packet, 2) = tcp_opt->data.ws.value;
	uncomp_packet->len += ws_len;
	*opt_len = ws_len;

	return true;

error:
	return false;
}


/* TODO */
static int d_tcp_parse_ts_dyn(const struct rohc_decomp_ctxt *const context,
                              const uint8_t *const data,
                              const size_t data_len,
                              struct d_tcp_opt_ctxt *const opt_ctxt)
{
	const struct tcp_option_timestamp *const opt_ts =
		(struct tcp_option_timestamp *) data;
	const size_t ts_field_len = sizeof(uint32_t);
	const size_t ts_dyn_len = 2 * ts_field_len;

	if(data_len < ts_dyn_len)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP option "
		                 "items: only %zu bytes available while at least %zu bytes "
		                 "required for TS option", data_len, ts_dyn_len);
		goto error;
	}

	opt_ctxt->data.ts.req.bits = rohc_ntoh32(opt_ts->ts);
	opt_ctxt->data.ts.req.bits_nr = 32;
	opt_ctxt->data.ts.rep.bits = rohc_ntoh32(opt_ts->ts_reply);
	opt_ctxt->data.ts.rep.bits_nr = 32;

	return ts_dyn_len;

error:
	return -1;
}


/* TODO */
static int d_tcp_parse_ts_irreg(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const data,
                                const size_t data_len,
                                const uint8_t opt_index __attribute__((unused)),
                                struct d_tcp_opt_ctxt *const opt_ctxt)
{
	const uint8_t *remain_data = data;
	size_t remain_len = data_len;
	size_t ts_len = 0;
	int ret;

	/* parse TS echo request */
	ret = d_tcp_ts_lsb_parse(context, remain_data, remain_len,
	                         &opt_ctxt->data.ts.req);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to parse TS echo request");
		goto error;
	}
	remain_data += ret;
	remain_len -= ret;
	ts_len += ret;

	/* parse TS echo reply */
	ret = d_tcp_ts_lsb_parse(context, remain_data, remain_len,
	                         &opt_ctxt->data.ts.rep);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "failed to parse TS echo reply");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	remain_data += ret;
	remain_len -= ret;
#endif
	ts_len += ret;

	return ts_len;

error:
	return -1;
}


/* TODO */
static bool d_tcp_build_ts(const struct rohc_decomp_ctxt *const context,
                           const struct rohc_tcp_decoded_values *const decoded,
                           const struct d_tcp_opt_ctxt *const tcp_opt __attribute__((unused)),
                           struct rohc_buf *const uncomp_packet,
                           size_t *const opt_len)
{
	const size_t ts_load_len = sizeof(struct tcp_option_timestamp);
	const size_t ts_len = 2 + ts_load_len;
	struct tcp_option_timestamp ts_load = {
		.ts = rohc_hton32(decoded->opt_ts_req),
		.ts_reply = rohc_hton32(decoded->opt_ts_rep)
	};

	if(rohc_buf_avail_len(*uncomp_packet) < ts_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP TS option", ts_len);
		goto error;
	}

	rohc_buf_byte_at(*uncomp_packet, 0) = TCP_OPT_TS;
	rohc_buf_byte_at(*uncomp_packet, 1) = ts_len;
	uncomp_packet->len += 2;
	rohc_buf_append(uncomp_packet, (uint8_t *) &ts_load, ts_load_len);
	*opt_len = ts_len;

	return true;

error:
	return false;
}


/* TODO */
static int d_tcp_parse_sack_perm_dyn(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                     const uint8_t *const data __attribute__((unused)),
                                     const size_t data_len __attribute__((unused)),
                                     struct d_tcp_opt_ctxt *const opt_ctxt __attribute__((unused)))
{
	return 0;
}


/* TODO */
static int d_tcp_parse_sack_perm_irreg(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                       const uint8_t *const data __attribute__((unused)),
                                       const size_t data_len __attribute__((unused)),
                                       const uint8_t opt_index __attribute__((unused)),
                                       struct d_tcp_opt_ctxt *const opt_ctxt __attribute__((unused)))
{
	return 0;
}


/* TODO */
static bool d_tcp_build_sack_perm(const struct rohc_decomp_ctxt *const context,
                                  const struct rohc_tcp_decoded_values *const decoded __attribute__((unused)),
                                  const struct d_tcp_opt_ctxt *const tcp_opt __attribute__((unused)),
                                  struct rohc_buf *const uncomp_packet,
                                  size_t *const opt_len)
{
	const size_t sack_perm_len = 2;

	if(rohc_buf_avail_len(*uncomp_packet) < sack_perm_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP SACK Permitted option", sack_perm_len);
		goto error;
	}

	rohc_buf_byte_at(*uncomp_packet, 0) = TCP_OPT_SACK_PERM;
	rohc_buf_byte_at(*uncomp_packet, 1) = sack_perm_len;
	uncomp_packet->len += sack_perm_len;
	*opt_len = sack_perm_len;

	return true;

error:
	return false;
}


/* TODO */
static int d_tcp_parse_sack_dyn(const struct rohc_decomp_ctxt *const context,
                                const uint8_t *const data,
                                const size_t data_len,
                                struct d_tcp_opt_ctxt *const opt_ctxt)
{
	int ret;

	ret = d_tcp_sack_parse(context, data, data_len, &opt_ctxt->data.sack);
	if(ret < 0)
	{
		rohc_decomp_warn(context, "malformed ROHC packet: malformed TCP option "
		                 "items: failed to parse TCP SACK option");
		goto error;
	}

	return ret;

error:
	return -1;
}


/* TODO */
static int d_tcp_parse_sack_irreg(const struct rohc_decomp_ctxt *const context,
                                  const uint8_t *const data,
                                  const size_t data_len,
                                  const uint8_t opt_index __attribute__((unused)),
                                  struct d_tcp_opt_ctxt *const opt_ctxt)
{
	return d_tcp_parse_sack_dyn(context, data, data_len, opt_ctxt);
}


/* TODO */
static bool d_tcp_build_sack(const struct rohc_decomp_ctxt *const context,
                             const struct rohc_tcp_decoded_values *const decoded,
                             const struct d_tcp_opt_ctxt *const tcp_opt __attribute__((unused)),
                             struct rohc_buf *const uncomp_packet,
                             size_t *const opt_len)
{
	const sack_block_t *const blocks = decoded->opt_sack_blocks.blocks;
	const size_t blocks_nr = decoded->opt_sack_blocks.blocks_nr;
	const size_t blocks_len = sizeof(sack_block_t) * blocks_nr;
	const size_t sack_len = 2 + blocks_len;

	if(rohc_buf_avail_len(*uncomp_packet) < sack_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP SACK option", sack_len);
		goto error;
	}

	rohc_buf_byte_at(*uncomp_packet, 0) = TCP_OPT_SACK;
	rohc_buf_byte_at(*uncomp_packet, 1) = sack_len;
	uncomp_packet->len += 2;
	rohc_buf_append(uncomp_packet, (uint8_t *) blocks, blocks_len);
	*opt_len = sack_len;

	return true;

error:
	return false;
}


/* TODO */
static int d_tcp_parse_generic_dyn(const struct rohc_decomp_ctxt *const context,
                                   const uint8_t *const data,
                                   const size_t data_len,
                                   struct d_tcp_opt_ctxt *const opt_ctxt)
{
	const size_t opt_hdr_len = ROHC_TCP_OPT_HDR_LEN;
	uint8_t opt_type;
	uint8_t opt_len;
	uint8_t opt_load_len;

	/* enough data for option type and length? */
	if(data_len < opt_hdr_len)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP option "
		                 "items: only %zu bytes available while at least %zu bytes "
		                 "required for TCP generic option", data_len, opt_hdr_len);
		goto error;
	}

	/* option type */
	opt_type = data[0];

	/* option_static flag */
	opt_ctxt->data.generic.option_static = GET_BOOL(GET_BIT_7(data + 1));

	/* option length */
	opt_len = data[1] & 0x7f;
	if(opt_len < opt_hdr_len)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP option "
		                 "items: TCP generic option length should be at least %zu "
		                 "bytes, but is only %u byte(s)", opt_hdr_len, opt_len);
		goto error;
	}
	opt_load_len = opt_len - opt_hdr_len;

	/* enough data for the whole option? */
	if(data_len < opt_len)
	{
		rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP option "
		                 "items: only %zu bytes available while at least %zu bytes "
		                 "required for TCP generic option", data_len, opt_hdr_len);
		goto error;
	}

	/* check if type or payload changed if index was already used */
	if(opt_ctxt->used)
	{
		if(opt_type != opt_ctxt->type) /* TODO */
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP "
			                 "option items: type of TCP generic option changed "
			                 "from %u to %u", opt_ctxt->type, opt_type);
			goto error;
		}
		if(opt_load_len != opt_ctxt->data.generic.load_len || /* TODO */
		   memcmp(data + opt_hdr_len, opt_ctxt->data.generic.load, opt_load_len) != 0)
		{
			rohc_decomp_warn(context, "malformed TCP dynamic part: malformed TCP "
			                 "option items: payload of TCP generic option changed");
			goto error;
		}
	}

	/* save the option type and payload */
	opt_ctxt->type = opt_type;
	opt_ctxt->data.generic.load_len = opt_load_len;
	memcpy(opt_ctxt->data.generic.load, data + opt_hdr_len, opt_load_len);
	rohc_decomp_debug(context, "    TCP option payload = %u bytes", opt_load_len);

	return opt_len;

error:
	return -1;
}


/* TODO */
static int d_tcp_parse_generic_irreg(const struct rohc_decomp_ctxt *const context,
                                     const uint8_t *const data,
                                     const size_t data_len,
                                     const uint8_t opt_index __attribute__((unused)),
                                     struct d_tcp_opt_ctxt *const opt_ctxt)
{
	const struct d_tcp_context *const tcp_context = context->persist_ctxt;
	const struct d_tcp_opt_ctxt *persist;
	size_t read = 0;

	assert(opt_index <= MAX_TCP_OPTION_INDEX);

	persist = &tcp_context->tcp_opts.bits[opt_index];

	/* TODO: in what case option_static could be set to 1 ? */
	if(persist->data.generic.option_static == 1)
	{
		/* TODO: handle generic_static_irregular() encoding */
		rohc_decomp_warn(context, "unsupported generic_static_irregular() encoding");
		goto error;
	}
	else if(persist->data.generic.option_static == 0)
	{
		uint8_t discriminator;

		if(data_len < 1)
		{
			rohc_decomp_warn(context, "malformed TCP irregular part: malformed "
			                 "TCP option items: at least 1 byte required for the "
			                 "discriminator of the generic option");
			goto error;
		}
		discriminator = data[0];
		read++;

		if(discriminator == 0x01)
		{
			/* TODO: handle generic_stable_irregular() */
			rohc_decomp_warn(context, "unsupported generic_stable_irregular() encoding");
			goto error;
		}
		else if(discriminator == 0x00)
		{
			/* generic_full_irregular() */
			const size_t opt_load_len = persist->data.generic.load_len;

			if(data_len < (read + opt_load_len))
			{
				rohc_decomp_warn(context, "malformed TCP irregular part: malformed "
				                 "TCP option items: TCP generic irregular option "
				                 "should be at least %zu byte(s), but is only %zu "
				                 "byte(s)", read + opt_load_len, data_len);
				goto error;
			}
			opt_ctxt->data.generic.load_len = opt_load_len;
			memcpy(opt_ctxt->data.generic.load, data + read, opt_load_len);
			read += opt_load_len;
			rohc_decomp_debug(context, "TCP generic option payload = %zu bytes", opt_load_len);
		}
	}

	return read;

error:
	return -1;
}


/* TODO */
static bool d_tcp_build_generic(const struct rohc_decomp_ctxt *const context,
                                const struct rohc_tcp_decoded_values *const decoded __attribute__((unused)),
                                const struct d_tcp_opt_ctxt *const tcp_opt,
                                struct rohc_buf *const uncomp_packet,
                                size_t *const opt_len)
{
	const uint8_t opt_type = tcp_opt->type;
	const size_t load_len = tcp_opt->data.generic.load_len;
	const size_t generic_len = 2 + load_len;

	if(rohc_buf_avail_len(*uncomp_packet) < generic_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP generic option of type %u", generic_len, opt_type);
		goto error;
	}

	rohc_buf_byte_at(*uncomp_packet, 0) = opt_type;
	rohc_buf_byte_at(*uncomp_packet, 1) = generic_len;
	uncomp_packet->len += 2;
	rohc_buf_append(uncomp_packet, tcp_opt->data.generic.load, load_len);
	*opt_len = generic_len;

	return true;

error:
	return false;
}


/* TODO */
bool d_tcp_build_tcp_opts(const struct rohc_decomp_ctxt *const context,
                          const struct rohc_tcp_decoded_values *const decoded,
                          struct rohc_buf *const uncomp_packet,
                          size_t *const opts_len)
{
	const uint8_t padding_bytes[sizeof(uint32_t) - 1] = { TCP_OPT_EOL };
	size_t opt_padding_len;
	size_t i;

	rohc_decomp_debug(context, "build TCP options");

	*opts_len = 0;

	for(i = 0; i < decoded->tcp_opts.nr; i++)
	{
		const uint8_t opt_index = decoded->tcp_opts.structure[i];
		const struct d_tcp_opt_ctxt *const tcp_opt =
			&(decoded->tcp_opts.bits[opt_index]);
		const uint8_t opt_type = tcp_opt->type;
		size_t opt_len;

		assert(tcp_opt->used);
		if(!decoded->tcp_opts.found[i])
		{
			rohc_decomp_warn(context, "failed to build TCP option #%zu: no "
			                 "information was transmitted for that option", i + 1);
			goto error;
		}

		rohc_decomp_debug(context, "  build TCP option #%zu '%s' (%u) with index %u",
		                  i + 1, tcp_opt_get_descr(opt_type), opt_type, opt_index);
		if(!d_tcp_opts[opt_index].build(context, decoded, tcp_opt, uncomp_packet,
		                                &opt_len))
		{
			rohc_decomp_warn(context, "failed to build TCP option #%zu with index "
			                 "%u and type %u", i + 1, opt_index, opt_type);
			goto error;
		}
		rohc_decomp_debug(context, "    => option is %zu-byte length", opt_len);
		rohc_buf_pull(uncomp_packet, opt_len);
		*opts_len += opt_len;
	}

	/* add padding after TCP options (they must be aligned on 32-bit words) */
	opt_padding_len = sizeof(uint32_t) - ((*opts_len) % sizeof(uint32_t));
	opt_padding_len %= sizeof(uint32_t);
	if(rohc_buf_avail_len(*uncomp_packet) < opt_padding_len)
	{
		rohc_decomp_warn(context, "output buffer too small for the %zu-byte "
		                 "TCP option padding", opt_padding_len);
		goto error;
	}
	rohc_decomp_debug(context, "  add %zu TCP EOL option(s) for padding",
	                  opt_padding_len);
	rohc_buf_append(uncomp_packet, padding_bytes, opt_padding_len);
	rohc_buf_pull(uncomp_packet, opt_padding_len);
	*opts_len += opt_padding_len;
	assert(((*opts_len) % sizeof(uint32_t)) == 0);

	rohc_decomp_debug(context, "  %zu TCP options built on %zu bytes",
	                  decoded->tcp_opts.nr + opt_padding_len, *opts_len);

	return true;

error:
	return false;
}

