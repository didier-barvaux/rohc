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
 * @file   c_tcp_opts_list.c
 * @brief  Handle the list of TCP options for the TCP compression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "c_tcp_opts_list.h"

#include "schemes/tcp_ts.h"
#include "schemes/tcp_sack.h"

#include <string.h>


/** The length of the table mapping for TCP options */
#define TCP_LIST_ITEM_MAP_LEN  16U


/** The definition of one TCP option for the compressor */
struct c_tcp_opt
{
	uint8_t index;        /**< The index of the option */
	bool is_well_known;   /**< Whether the option is well-known or not */
	uint8_t kind;         /**< The type of the option */
	char descr[255];      /**< A text description of the option */

	/** The function to code the list item for the TCP option */
	int (*build_list_item)(const struct rohc_comp_ctxt *const context,
	                       const struct tcphdr *const tcp,
	                       const uint8_t *const uncomp_opt,
	                       const uint8_t uncomp_opt_len,
	                       uint8_t *const comp_opt,
	                       const size_t comp_opt_max_len)
		__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));
};


static bool c_tcp_opt_get_type_len(const uint8_t *const opts_data,
                                   const size_t opts_len,
                                   uint8_t *const opt_type,
                                   uint8_t *const opt_len)
	__attribute__((warn_unused_result, nonnull(1, 3, 4)));

static bool c_tcp_opt_changed(const struct c_tcp_opts_ctxt *const opts_ctxt,
                              const uint8_t opt_idx,
                              const uint8_t *const pkt_opt,
                              const size_t pkt_opt_len)
	__attribute__((warn_unused_result, nonnull(1, 3)));

static void c_tcp_opt_record(struct c_tcp_opts_ctxt *const opts_ctxt,
                             const uint8_t opt_idx,
                             const uint8_t *const pkt_opt,
                             const size_t pkt_opt_len)
	__attribute__((nonnull(1, 3)));

static void c_tcp_opt_trace(const struct rohc_comp_ctxt *const context,
                            const uint8_t opt_type,
                            const uint8_t *const opt_data,
                            const size_t opt_len)
	__attribute__((nonnull(1, 3)));

static uint8_t c_tcp_get_opt_index(const struct rohc_comp_ctxt *const context,
                                   struct c_tcp_opts_ctxt *const opts_ctxt,
                                   const uint8_t opt_type,
                                   const bool indexes_in_use[MAX_TCP_OPTION_INDEX + 1])
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

static int c_tcp_opt_compute_ps(const uint8_t idx_max)
	__attribute__((warn_unused_result, const));

static size_t c_tcp_opt_compute_xi_len(const int ps, const size_t m)
	__attribute__((warn_unused_result, const));

static size_t c_tcp_opt_write_xi(const struct rohc_comp_ctxt *const context,
                                 uint8_t *const comp_opts,
                                 const int ps,
                                 const size_t opt_pos,
                                 const uint8_t opt_idx,
                                 const bool item_needed)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool c_tcp_is_list_item_needed(const struct rohc_comp_ctxt *const context,
                                      const rohc_chain_t chain_type,
                                      const uint8_t opt_idx,
                                      const uint8_t opt_type,
                                      const uint8_t opt_len,
                                      const uint8_t *const opt,
                                      const struct c_tcp_opts_ctxt *const opts_ctxt)
	__attribute__((warn_unused_result, nonnull(1, 6, 7)));

static int c_tcp_build_nop_list_item(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp,
                                     const uint8_t *const uncomp_opt,
                                     const uint8_t uncomp_opt_len,
                                     uint8_t *const comp_opt,
                                     const size_t comp_opt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int c_tcp_build_eol_list_item(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp,
                                     const uint8_t *const uncomp_opt,
                                     const uint8_t uncomp_opt_len,
                                     uint8_t *const comp_opt,
                                     const size_t comp_opt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int c_tcp_build_mss_list_item(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp,
                                     const uint8_t *const uncomp_opt,
                                     const uint8_t uncomp_opt_len,
                                     uint8_t *const comp_opt,
                                     const size_t comp_opt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int c_tcp_build_ws_list_item(const struct rohc_comp_ctxt *const context,
                                    const struct tcphdr *const tcp,
                                    const uint8_t *const uncomp_opt,
                                    const uint8_t uncomp_opt_len,
                                    uint8_t *const comp_opt,
                                    const size_t comp_opt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int c_tcp_build_ts_list_item(const struct rohc_comp_ctxt *const context,
                                    const struct tcphdr *const tcp,
                                    const uint8_t *const uncomp_opt,
                                    const uint8_t uncomp_opt_len,
                                    uint8_t *const comp_opt,
                                    const size_t comp_opt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int c_tcp_build_sack_perm_list_item(const struct rohc_comp_ctxt *const context,
                                           const struct tcphdr *const tcp,
                                           const uint8_t *const uncomp_opt,
                                           const uint8_t uncomp_opt_len,
                                           uint8_t *const comp_opt,
                                           const size_t comp_opt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int c_tcp_build_sack_list_item(const struct rohc_comp_ctxt *const context,
                                      const struct tcphdr *const tcp,
                                      const uint8_t *const uncomp_opt,
                                      const uint8_t uncomp_opt_len,
                                      uint8_t *const comp_opt,
                                      const size_t comp_opt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));

static int c_tcp_build_generic_list_item(const struct rohc_comp_ctxt *const context,
                                         const struct tcphdr *const tcp,
                                         const uint8_t *const uncomp_opt,
                                         const uint8_t uncomp_opt_len,
                                         uint8_t *const comp_opt,
                                         const size_t comp_opt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5)));


/* The definitions of all the TCP options supported by the compressor */
static struct c_tcp_opt c_tcp_opts[MAX_TCP_OPTION_INDEX + 1] =
{
	[TCP_INDEX_NOP]       = { TCP_INDEX_NOP, true, TCP_OPT_NOP,
	                          "No Operation (NOP)",
	                          c_tcp_build_nop_list_item },
	[TCP_INDEX_EOL]       = { TCP_INDEX_EOL, true, TCP_OPT_EOL,
	                          "End of Option List (EOL)",
	                          c_tcp_build_eol_list_item },
	[TCP_INDEX_MSS]       = { TCP_INDEX_MSS, true, TCP_OPT_MSS,
	                          "Maximum Segment Size (MSS)",
	                          c_tcp_build_mss_list_item },
	[TCP_INDEX_WS]        = { TCP_INDEX_WS, true, TCP_OPT_WS,
	                          "Window Scale (WS)",
	                          c_tcp_build_ws_list_item },
	[TCP_INDEX_TS]        = { TCP_INDEX_TS, true, TCP_OPT_TS,
	                          "Timestamps (TS)",
	                          c_tcp_build_ts_list_item },
	[TCP_INDEX_SACK_PERM] = { TCP_INDEX_SACK_PERM, true, TCP_OPT_SACK_PERM,
	                          "Selective Acknowledgment Permitted (SACK)",
	                          c_tcp_build_sack_perm_list_item },
	[TCP_INDEX_SACK]      = { TCP_INDEX_SACK, true, TCP_OPT_SACK,
	                          "Selective Acknowledgment (SACK)",
	                          c_tcp_build_sack_list_item },
	[TCP_INDEX_GENERIC7]  = { TCP_INDEX_GENERIC7, false, 0,
	                          "generic index 7",
	                          c_tcp_build_generic_list_item },
	[TCP_INDEX_GENERIC8]  = { TCP_INDEX_GENERIC8, false, 0,
	                          "generic index 8",
	                          c_tcp_build_generic_list_item },
	[TCP_INDEX_GENERIC9]  = { TCP_INDEX_GENERIC9, false, 0,
	                          "generic index 9",
	                          c_tcp_build_generic_list_item },
	[TCP_INDEX_GENERIC10] = { TCP_INDEX_GENERIC10, false, 0,
	                          "generic index 10",
	                          c_tcp_build_generic_list_item },
	[TCP_INDEX_GENERIC11] = { TCP_INDEX_GENERIC11, false, 0,
	                          "generic index 11",
	                          c_tcp_build_generic_list_item },
	[TCP_INDEX_GENERIC12] = { TCP_INDEX_GENERIC12, false, 0,
	                          "generic index 12",
	                          c_tcp_build_generic_list_item },
	[TCP_INDEX_GENERIC13] = { TCP_INDEX_GENERIC13, false, 0,
	                          "generic index 13",
	                          c_tcp_build_generic_list_item },
	[TCP_INDEX_GENERIC14] = { TCP_INDEX_GENERIC14, false, 0,
	                          "generic index 14",
	                          c_tcp_build_generic_list_item },
	[TCP_INDEX_GENERIC15] = { TCP_INDEX_GENERIC15, false, 0,
	                          "generic index 15",
	                          c_tcp_build_generic_list_item },
};


/**
 * @brief Table of TCP option index, from option Id
 *
 * See RFC4996 §6.3.4
 * Return item index of TCP option
 */
static int c_tcp_type2index[TCP_LIST_ITEM_MAP_LEN] =
{
	TCP_INDEX_EOL,             // TCP_OPT_EOL             0
	TCP_INDEX_NOP,             // TCP_OPT_NOP             1
	TCP_INDEX_MSS,             // TCP_OPT_MAXSEG          2
	TCP_INDEX_WS,              // TCP_OPT_WINDOW          3
	TCP_INDEX_SACK_PERM,       // TCP_OPT_SACK_PERMITTED  4
	TCP_INDEX_SACK,            // TCP_OPT_SACK            5
	-1,                        // TODO ?                  6
	-1,                        // TODO ?                  7
	TCP_INDEX_TS,              // TCP_OPT_TIMESTAMP       8
	-1,                        // TODO ?                  9
	-1,                        // TODO ?                 10
	-1,                        // TODO ?                 11
	-1,                        // TODO ?                 12
	-1,                        // TODO ?                 13
	-1,                        // TODO ?                 14
	-1                         // TODO ?                 15
};




/**
 * @brief Whether TCP options are acceptable for TCP profile or not
 *
 * TCP options are acceptable for the TCP profile if:
 *  - every TCP option is smaller than \e ROHC_TCP_OPT_MAX_LEN
 *  - the last TCP option is not truncated,
 *  - well-known TCP options got the expected length (see below),
 *  - no more than \e ROHC_TCP_OPTS_MAX options are present,
 *  - each TCP options is present only once (except EOL and NOP).
 *
 * The following well-known TCP options shall have expected lengths:
 *  - MSS shall be TCP_OLEN_MSS long,
 *  - WS shall be TCP_OLEN_WS long,
 *  - SACK Permitted shall be TCP_OLEN_SACK_PERM long,
 *  - SACK shall be 2 + N * 8 with N in range [1, 4]
 *  - TS shall be TCP_OLEN_TS long.
 *
 * @param comp         The ROHC compressor
 * @param opts         The beginning of the TCP options
 * @param data_offset  The length (in 32-bit words) of the full TCP header
 * @return             true if the TCP options are acceptable,
 *                     false if they are not
 *
 * @see ROHC_TCP_OPTS_MAX
 */
bool rohc_comp_tcp_are_options_acceptable(const struct rohc_comp *const comp,
                                          const uint8_t *const opts,
                                          const size_t data_offset)
{
	const size_t opts_len = data_offset * sizeof(uint32_t) - sizeof(struct tcphdr);
	uint8_t opt_types_count[TCP_OPT_MAX + 1] = { 0 };
	size_t opts_offset;
	size_t opt_pos;
	uint8_t opt_len;

	/* parse up to ROHC_TCP_OPTS_MAX TCP options */
	for(opt_pos = 0, opts_offset = 0;
	    opt_pos < ROHC_TCP_OPTS_MAX_PROTO && opts_offset < opts_len;
	    opt_pos++, opts_offset += opt_len)
	{
		uint8_t opt_type;

		/* get type and length of the next TCP option */
		if(!c_tcp_opt_get_type_len(opts + opts_offset, opts_len - opts_offset,
		                           &opt_type, &opt_len))
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "malformed TCP options: failed to parse option #%zu",
			           opt_pos + 1);
			goto bad_opts;
		}

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "TCP option %u found", opt_type);

		if(opt_len > ROHC_TCP_OPT_MAX_LEN)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "packet contains at least one %u-byte TCP option larger "
			           "than the internal maximum of %u bytes", opt_len,
			           ROHC_TCP_OPT_MAX_LEN);
			goto bad_opts;
		}

		if(opt_types_count[opt_type] >= 255)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "too many TCP options of type %u", opt_type);
			goto bad_opts;
		}
		opt_types_count[opt_type]++;

		/* TCP options shall occur at most once, except EOL and NOP */
		if(opt_type != TCP_OPT_EOL &&
		   opt_type != TCP_OPT_NOP &&
		   opt_types_count[opt_type] > 1)
		{
			rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
			           "malformed TCP options: TCP option '%s' (%u) should "
			           "occur at most once, but it was found at least %u times",
			           tcp_opt_get_descr(opt_type), opt_type,
			           opt_types_count[opt_type]);
			goto bad_opts;
		}

		/* check the well-known options in order to avoid using the TCP profile with
		 * malformed TCP packets */
		switch(opt_type)
		{
			case TCP_OPT_EOL:
			{
				const size_t max_eol_opt_len = (0xff + 8) / 8;
				size_t i;

				/* the TCP profile encodes the length of the EOL option in bits
				 * (minus the first 8 type bits) in a 8-bit field, so reject TCP
				 * packets with a large EOL option */
				if(opt_len > max_eol_opt_len)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "unexpected TCP header: %u-byte option EOL cannot be "
					           "compressed with the TCP profile (%zu bytes max)",
					           opt_len, max_eol_opt_len);
					goto bad_opts;
				}

				/* TCP option EOL bytes shall all be zeroes */
				for(i = 0; i < opt_len; i++)
				{
					if(opts[opts_offset + i] != TCP_OPT_EOL)
					{
						rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
						           "malformed TCP header: malformed option padding: "
						           "padding byte #%zu is 0x%02x while it should be 0x00",
						           i + 1, opts[opts_offset + i]);
						goto bad_opts;
					}
				}
				break;
			}
			case TCP_OPT_MSS:
			{
				if(opt_len != TCP_OLEN_MSS)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed TCP option #%zu: unexpected length for MSS "
					           "option: %u found in packet while %u expected",
					           opt_pos + 1, opt_len, TCP_OLEN_MSS);
					goto bad_opts;
				}
				break;
			}
			case TCP_OPT_WS:
			{
				if(opt_len != TCP_OLEN_WS)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed TCP option #%zu: unexpected length for WS "
					           "option: %u found in packet while %u expected",
					           opt_pos + 1, opt_len, TCP_OLEN_WS);
					goto bad_opts;
				}
				break;
			}
			case TCP_OPT_SACK_PERM:
			{
				if(opt_len != TCP_OLEN_SACK_PERM)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed TCP option #%zu: unexpected length for SACK "
					           "Permitted option: %u found in packet while %u expected",
					           opt_pos + 1, opt_len, TCP_OLEN_SACK_PERM);
					goto bad_opts;
				}
				break;
			}
			case TCP_OPT_SACK:
			{
				size_t sack_blocks_remain = (opt_len - 2) % sizeof(sack_block_t);
				size_t sack_blocks_nr = (opt_len - 2) / sizeof(sack_block_t);
				if(sack_blocks_remain != 0 ||
				   sack_blocks_nr == 0 ||
				   sack_blocks_nr > TCP_SACK_BLOCKS_MAX_NR)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed TCP option #%zu: unexpected length for "
					           "SACK option: %u found in packet while 2 + [1-4] "
					           "* %zu expected", opt_pos + 1, opt_len,
					           sizeof(sack_block_t));
					goto bad_opts;
				}
				break;
			}
			case TCP_OPT_TS:
			{
				if(opt_len != TCP_OLEN_TS)
				{
					rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
					           "malformed TCP option #%zu: unexpected length for TS "
					           "option: %u found in packet while %u expected",
					           opt_pos + 1, opt_len, TCP_OLEN_TS);
					goto bad_opts;
				}
				break;
			}
			default:
			{
				/* nothing to check for other options */
				break;
			}
		}
	}

	/* no more than ROHC_TCP_OPTS_MAX TCP options accepted by the TCP profile */
	if(opt_pos > ROHC_TCP_OPTS_MAX)
	{
		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "unexpected TCP header: too many TCP options: %zu "
		           "options found in packet but only %u options possible",
		           opt_pos, ROHC_TCP_OPTS_MAX);
		goto bad_opts;
	}

	return true;

bad_opts:
	return false;
}


/**
 * @brief Parse the uncompressed TCP options for changes
 *
 * @param context            The compression context
 * @param tcp                The TCP header
 * @param[in,out] opts_ctxt  The compression context for TCP options
 * @param[out] opts_len      The length (in bytes) of the TCP options
 * @return                   true if the TCP options were successfully parsed and
 *                           can be compressed, false otherwise
 */
bool tcp_detect_options_changes(struct rohc_comp_ctxt *const context,
                                const struct tcphdr *const tcp,
                                struct c_tcp_opts_ctxt *const opts_ctxt,
                                size_t *const opts_len)
{
	bool indexes_in_use[MAX_TCP_OPTION_INDEX + 1] = { false };
	uint8_t *opts;
	size_t opt_pos;
	uint8_t opt_len;
	size_t opts_offset;
	size_t opts_nr = 0;
	uint8_t opt_idx;

	assert(opts_ctxt->structure_nr <= ROHC_TCP_OPTS_MAX);

	opts_ctxt->tmp.do_list_struct_changed = false;
	opts_ctxt->tmp.do_list_static_changed = false;
	opts_ctxt->tmp.opt_ts_present = false;
	opts_ctxt->tmp.nr = 0;
	opts_ctxt->tmp.idx_max = 0;

	opts = ((uint8_t *) tcp) + sizeof(struct tcphdr);
	*opts_len = (tcp->data_offset << 2) - sizeof(struct tcphdr);

	rohc_comp_debug(context, "parse %zu-byte TCP options", *opts_len);

	for(opt_idx = TCP_INDEX_GENERIC7; opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
	{
		if(opts_ctxt->list[opt_idx].used)
		{
			if(opts_ctxt->list[opt_idx].age < UINT8_MAX)
			{
				opts_ctxt->list[opt_idx].age++;
			}
		}
	}

	for(opt_pos = 0, opts_offset = 0;
	    opt_pos < ROHC_TCP_OPTS_MAX && opts_offset < (*opts_len);
	    opt_pos++, opts_offset += opt_len)
	{
		uint8_t opt_type;

		/* get type and length of the next TCP option */
		if(!c_tcp_opt_get_type_len(opts + opts_offset, (*opts_len) - opts_offset,
		                           &opt_type, &opt_len))
		{
			rohc_comp_warn(context, "malformed TCP header: failed to parse "
			               "option #%zu", opt_pos + 1);
			goto error;
		}
		rohc_comp_debug(context, "  TCP option %u found", opt_type);
		rohc_comp_debug(context, "    option is %u-byte long", opt_len);

		if(opt_type == TCP_OPT_TS)
		{
			memcpy(&opts_ctxt->tmp.ts_req, opts + opts_offset + 2, sizeof(uint32_t));
			opts_ctxt->tmp.ts_req = rohc_ntoh32(opts_ctxt->tmp.ts_req);
			memcpy(&opts_ctxt->tmp.ts_reply, opts + opts_offset + 6, sizeof(uint32_t));
			opts_ctxt->tmp.ts_reply = rohc_ntoh32(opts_ctxt->tmp.ts_reply);
			opts_ctxt->tmp.opt_ts_present = true;
		}

		/* determine the index of the TCP option */
		opt_idx = c_tcp_get_opt_index(context, opts_ctxt, opt_type, indexes_in_use);
		indexes_in_use[opt_idx] = true;

		/* the EOL, MSS, and WS options are 'static options': they cannot be
		 * transmitted in irregular chain if their value changed, so the compressor
		 * needs to detect such changes and to select a packet type that can
		 * transmit their changes, ie. IR, IR-DYN, co_common, rnd_8 or seq_8 */
		if(opt_type == TCP_OPT_EOL || opt_type == TCP_OPT_MSS || opt_type == TCP_OPT_WS)
		{
			if(opts_ctxt->list[opt_idx].used &&
			   c_tcp_opt_changed(opts_ctxt, opt_idx, opts + opts_offset, opt_len))
			{
				rohc_comp_debug(context, "    static option changed of value");
				opts_ctxt->tmp.do_list_static_changed = true;
			}
		}

		/* was the option already used? */
		if(opts_ctxt->list[opt_idx].used)
		{
			rohc_comp_debug(context, "    option '%s' (%u) will use same "
			                "index %u as in previous packet",
			                tcp_opt_get_descr(opt_type), opt_type, opt_idx);
			/* option was grown old with all the others, make it grow young again */
			if(opts_ctxt->list[opt_idx].age > 0 && opts_ctxt->list[opt_idx].age < UINT8_MAX)
			{
				opts_ctxt->list[opt_idx].age--;
			}

			/* generic options cannot be transmitted in irregular chain if their
			 * length changed, so the compressor needs to detect such changes and
			 * to select a packet type that can transmit their changes, ie. IR,
			 * IR-DYN, co_common, rnd_8 or seq_8 */
			if(opt_idx >= TCP_INDEX_GENERIC7 &&
			   opt_len != opts_ctxt->list[opt_idx].data_len)
			{
				rohc_comp_debug(context, "    generic option changed of length (%u -> %u)",
				                opts_ctxt->list[opt_idx].data_len, opt_len);
				opts_ctxt->tmp.do_list_static_changed = true;
			}
		}
		else
		{
			/* now index is used by this option */
			opts_ctxt->list[opt_idx].used = true;
			opts_ctxt->list[opt_idx].type = opt_type;
			opts_ctxt->list[opt_idx].nr_trans = 0;
			opts_ctxt->list[opt_idx].age = 0;
			rohc_comp_debug(context, "    option '%s' (%u) will use new index %u",
			                tcp_opt_get_descr(opt_type), opt_type, opt_idx);
		}
		opts_ctxt->tmp.position2index[opt_pos] = opt_idx;
		opts_ctxt->tmp.nr++;
		if(opt_idx > opts_ctxt->tmp.idx_max)
		{
			opts_ctxt->tmp.idx_max = opt_idx;
		}

		/* was the TCP option present at the very same location in previous
		 * packet? */
		if(opt_pos >= opts_ctxt->structure_nr ||
		   opts_ctxt->structure[opt_pos] != opt_type)
		{
			rohc_comp_debug(context, "    option was not present at the very "
			                "same location in previous packet");
			opts_ctxt->tmp.do_list_struct_changed = true;
		}
		else
		{
			rohc_comp_debug(context, "    option was at the very same location "
			                "in previous packet");
		}

		/* record the structure of the current list TCP options in context */
		opts_ctxt->structure[opt_pos] = opt_type;
	}
	if(opt_pos >= ROHC_TCP_OPTS_MAX && opts_offset != (*opts_len))
	{
		rohc_comp_warn(context, "unexpected TCP header: too many TCP options: "
		               "%zu options found in packet but only %u options "
		               "possible", opt_pos, ROHC_TCP_OPTS_MAX);
		goto error;
	}
	opts_nr = opt_pos;

	/* fewer options than in previous packet? */
	for(opt_pos = opts_nr; opt_pos < opts_ctxt->structure_nr; opt_pos++)
	{
		rohc_comp_debug(context, "  TCP option %d is not present anymore",
		                opts_ctxt->structure[opt_pos]);
		opts_ctxt->tmp.do_list_struct_changed = true;
	}

	if(opts_ctxt->tmp.do_list_struct_changed)
	{
		/* the new structure has never been transmitted yet */
		rohc_comp_debug(context, "structure of TCP options list changed, "
		                "compressed list must be transmitted in the compressed "
		                "base header");
		opts_ctxt->structure_nr = opts_nr;
		opts_ctxt->structure_nr_trans = 0;
	}
	else if(opts_ctxt->tmp.do_list_static_changed)
	{
		/* changes on static options require list transmission */
		rohc_comp_debug(context, "structure of TCP options list is unchanged, "
		                "but at least one static option changed of value, so "
		                "compressed list must be transmitted in the compressed "
		                "base header");
		assert(opts_ctxt->structure_nr == opts_nr);
		opts_ctxt->structure_nr_trans = 0;
	}
	else if(opts_ctxt->structure_nr_trans < context->compressor->list_trans_nr)
	{
		/* the structure was transmitted but not enough times */
		rohc_comp_debug(context, "structure of TCP options list changed in "
		                "the last few packets, compressed list must be "
		                "transmitted at least %u times more in the compressed "
		                "base header", context->compressor->list_trans_nr -
		                opts_ctxt->structure_nr_trans);
		opts_ctxt->tmp.do_list_struct_changed = true;
		assert(opts_ctxt->structure_nr == opts_nr);
		opts_ctxt->structure_nr_trans++;
	}
	else
	{
		/* no transmission required */
		rohc_comp_debug(context, "structure of TCP options list is unchanged, "
		                "compressed list may be omitted from the compressed "
		                "base header, any content changes may be transmitted "
		                "in the irregular chain");
		assert(opts_ctxt->structure_nr == opts_nr);
	}

	/* use 4-bit XI or 8-bit XI ? */
	if(opts_ctxt->tmp.idx_max <= 7)
	{
		rohc_comp_debug(context, "compressed TCP options list will be able to "
		                "use 4-bit XI since the largest index is %u",
		                opts_ctxt->tmp.idx_max);
	}
	else
	{
		assert(opts_ctxt->tmp.idx_max <= MAX_TCP_OPTION_INDEX);
		rohc_comp_debug(context, "compressed TCP options list will use 8-bit "
		                "XI since the largest index is %u", opts_ctxt->tmp.idx_max);
	}

	return true;

error:
	return false;
}


/**
 * @brief Build the list of TCP options items
 *
 * The list of TCP options is used in:
 *  - the dynamic chain of the IR and IR-DYN packets,
 *  - the replicate chain of the IR-CR packets,
 *  - at the end of the rnd_8, seq_8, and co_common packets.
 *
 * @param context            The compression context
 * @param tcp                The TCP header
 * @param msn                The Master Sequence Number (MSN) of the packet to compress
 * @param chain_type         The TCP chain for which the list of items is
 * @param[in,out] opts_ctxt  The compression context for TCP options
 * @param[out] comp_opts     The compressed TCP options
 * @param comp_opts_max_len  The max remaining length in the ROHC buffer
 * @param[out] no_item_needed Whether no item was needed at all
 * @return                   The length (in bytes) of compressed TCP options
 *                           in case of success, -1 in case of failure
 */
int c_tcp_code_tcp_opts_list_item(const struct rohc_comp_ctxt *const context,
                                  const struct tcphdr *const tcp,
                                  const uint16_t msn,
                                  const rohc_chain_t chain_type,
                                  struct c_tcp_opts_ctxt *const opts_ctxt,
                                  uint8_t *const comp_opts,
                                  const size_t comp_opts_max_len,
                                  bool *const no_item_needed)
{
	const uint8_t *options = ((uint8_t *) tcp) + sizeof(struct tcphdr);
	const size_t data_offset_bytes = (tcp->data_offset << 2);
	const size_t options_length = data_offset_bytes - sizeof(struct tcphdr);

	uint8_t *xi_remain_data = comp_opts;
	size_t xi_remain_len = comp_opts_max_len;
	uint8_t *items_remain_data;
	size_t items_remain_len;

	const size_t m = opts_ctxt->tmp.nr;
	size_t opt_pos;
	uint8_t opt_len;
	size_t xis_len;
	int ps;

	size_t comp_opts_len = 0; /* no compressed option at the beginning */
	int ret;
	int i;

	(*no_item_needed) = true;

	assert(data_offset_bytes >= sizeof(struct tcphdr));

	/* dump TCP options */
	rohc_comp_dump_buf(context, "TCP options", options, options_length);

	/* what type of XI fields to use? */
	ps = c_tcp_opt_compute_ps(opts_ctxt->tmp.idx_max);
	assert(ps == 0 || ps == 1);

	/* is the ROHC buffer large enough to contain all the XI indexes? */
	xis_len = c_tcp_opt_compute_xi_len(ps, m);
	if(xi_remain_len < xis_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP options in the "
		               "CO header: %zu bytes required for XI fields, but only %zu "
		               "bytes available", xis_len, xi_remain_len);
		goto error;
	}
	rohc_comp_debug(context, "TCP options list: %u-bit XI indexes will be stored "
	                "on %zu bytes", (ps == 0 ? 4U : 8U), xis_len);

	/* list of items begins after the list of XI indexes */
	items_remain_data = xi_remain_data + xis_len;
	items_remain_len = xi_remain_len - xis_len;
	comp_opts_len += xis_len;

	/* set the number and type of XI fields */
	assert((m & 0x0f) == m);
	xi_remain_data[0] = (ps << 4) | m;
	xi_remain_data++;
	xi_remain_len--;

	/* see RFC4996 page 25-26 */
	for(i = options_length, opt_pos = 0;
	    i > 0 && opt_pos < m;
	    i -= opt_len, opt_pos++, options += opt_len)
	{
		const uint8_t opt_idx = opts_ctxt->tmp.position2index[opt_pos];
		bool item_needed;
		uint8_t opt_type;
		size_t comp_opt_len;

		/* the TCP option index shall be in use */
		assert(opts_ctxt->list[opt_idx].used);

		/* get type and length of the next TCP option */
		if(!c_tcp_opt_get_type_len(options, i, &opt_type, &opt_len))
		{
			rohc_comp_warn(context, "malformed TCP options: failed to parse "
			               "option #%zu", opt_pos + 1);
			goto error;
		}
		rohc_comp_debug(context, "TCP options list: compress option '%s' (%u)",
		                tcp_opt_get_descr(opt_type), opt_type);

		/* print a trace that describes the TCP option */
		c_tcp_opt_trace(context, opt_type, options, opt_len);

		/* do we need to transmit the item? */
		item_needed = c_tcp_is_list_item_needed(context, chain_type, opt_idx,
		                                        opt_type, opt_len, options, opts_ctxt);

		/* if item is transmitted, the option is new, changed now or changed a
		 * few packets back, so save the option in context */
		/* TODO: move at the very end of compression to avoid altering
		 *       context in case of compression failure */
		if(item_needed)
		{
			(*no_item_needed) = false;
			c_tcp_opt_record(opts_ctxt, opt_idx, options, opt_len);
		}

		/* write the XI field for the TCP option */
		{
			const size_t xi_len = c_tcp_opt_write_xi(context, xi_remain_data, ps,
			                                         opt_pos, opt_idx, item_needed);
			xi_remain_data += xi_len;
			xi_remain_len -= xi_len;
		}

		/* nothing more to do for the current option if item is not needed */
		if(!item_needed)
		{
			continue;
		}

		/* write the item field for the TCP option if transmission is needed */
		ret = c_tcp_opts[opt_idx].build_list_item(context, tcp, options, opt_len,
		                                          items_remain_data, items_remain_len);
		if(ret < 0)
		{
			rohc_comp_warn(context, "TCP options list: failed to build list item "
			               "for option '%s' with index %u",
			               c_tcp_opts[opt_idx].descr, opt_idx);
			goto error;
		}
		items_remain_data += ret;
		items_remain_len -= ret;
		comp_opt_len = ret;

		/* TCP option is transmitted towards decompressor once more */
		opts_ctxt->list[opt_idx].nr_trans++;
		opts_ctxt->tmp.is_list_item_present[opt_idx] = true;
		rohc_comp_debug(context, "TCP options list: option '%s' (%u) added "
			                "%zu bytes of item", tcp_opt_get_descr(opt_type),
			                opt_type, comp_opt_len);
		comp_opts_len += comp_opt_len;

		/* TODO: move at the very end of compression to avoid altering
		 *       context in case of compression failure */
		if(opt_type == TCP_OPT_TS)
		{
			const struct tcp_option_timestamp *const opt_ts =
				(struct tcp_option_timestamp *) (options + 2);
			opts_ctxt->is_timestamp_init = true;
			c_add_wlsb(&opts_ctxt->ts_req_wlsb, msn, rohc_ntoh32(opt_ts->ts));
			c_add_wlsb(&opts_ctxt->ts_reply_wlsb, msn, rohc_ntoh32(opt_ts->ts_reply));
		}
	}
	if(opt_pos >= ROHC_TCP_OPTS_MAX && i != 0)
	{
		rohc_comp_warn(context, "unexpected TCP header: too many TCP options: %zu "
		               "options found in packet but only %u options possible",
		               opt_pos, ROHC_TCP_OPTS_MAX);
		goto error;
	}

	rohc_comp_dump_buf(context, "TCP compressed options", comp_opts, comp_opts_len);

	return comp_opts_len;

error:
	return -1;
}


/**
 * @brief Build the list of TCP options for the irregular chain
 *
 * All the CO packets contains an irregular chain.
 *
 * @param context            The compression context
 * @param tcp                The TCP header
 * @param msn                The Master Sequence Number (MSN) of the packet to compress
 * @param[in,out] opts_ctxt  The compression context for TCP options
 * @param[out] comp_opts     The compressed TCP options
 * @param comp_opts_max_len  The max remaining length in the ROHC buffer
 * @return                   The length (in bytes) of compressed TCP options
 *                           in case of success, -1 in case of failure
 *
 * @todo TODO: defines 'options profiles' the same way as for decompressor
 */
int c_tcp_code_tcp_opts_irreg(const struct rohc_comp_ctxt *const context,
                              const struct tcphdr *const tcp,
                              const uint16_t msn,
                              struct c_tcp_opts_ctxt *const opts_ctxt,
                              uint8_t *const comp_opts,
                              const size_t comp_opts_max_len)
{
	uint8_t *rohc_remain_data = comp_opts;
	size_t rohc_remain_len = comp_opts_max_len;
	size_t comp_opts_len = 0;

	const uint8_t *const opts = ((uint8_t *) tcp) + sizeof(struct tcphdr);
	const size_t opts_len = (tcp->data_offset << 2) - sizeof(struct tcphdr);
	uint8_t opt_len;
	size_t opts_offset;
	size_t opt_pos;

	bool is_ok;
	int ret;

	rohc_comp_debug(context, "irregular chain: encode irregular content for all "
	                "TCP options");

	/* build the list of irregular encodings of TCP options */
	for(opt_pos = 0, opts_offset = 0;
	    opt_pos < ROHC_TCP_OPTS_MAX && opts_offset < opts_len;
	    opt_pos++, opts_offset += opt_len)
	{
		const uint8_t opt_idx = opts_ctxt->tmp.position2index[opt_pos];
		size_t comp_opt_len = 0;
		uint8_t opt_type;

		/* the TCP option index shall be in use */
		assert(opts_ctxt->list[opt_idx].used);

		/* get type and length of the next TCP option */
		if(!c_tcp_opt_get_type_len(opts + opts_offset, opts_len - opts_offset,
		                           &opt_type, &opt_len))
		{
			rohc_comp_warn(context, "malformed TCP options: failed to parse option "
			               "#%zu", opt_pos + 1);
			goto error;
		}

		/* don't put this option in the irregular chain if already present in the
		 * dynamic chain */
		if(opts_ctxt->tmp.is_list_item_present[opt_idx])
		{
			rohc_comp_debug(context, "irregular chain: do not encode irregular "
			                "content for TCP option %u because it is already "
			                "transmitted in the compressed list of TCP options",
			                opt_type);
			continue;
		}
		rohc_comp_debug(context, "irregular chain: encode irregular content for "
		                "TCP option %u", opt_type);

		/* encode the TCP option in its irregular form */
		if(opt_type == TCP_OPT_TS)
		{
			const struct tcp_option_timestamp *const opt_ts =
				(struct tcp_option_timestamp *) (opts + opts_offset + 2);
			size_t encoded_ts_lsb_len;

			/* encode TS with ts_lsb() */
			is_ok = c_tcp_ts_lsb_code(context, rohc_ntoh32(opt_ts->ts),
			                          opts_ctxt->tmp.nr_opt_ts_req_bits_minus_1,
			                          opts_ctxt->tmp.nr_opt_ts_req_bits_0x40000,
			                          opts_ctxt->tmp.nr_opt_ts_req_bits_0x4000000,
			                          rohc_remain_data, rohc_remain_len,
			                          &encoded_ts_lsb_len);
			if(!is_ok)
			{
				rohc_comp_warn(context, "irregular chain: failed to encode echo "
				               "request of TCP Timestamp option");
				goto error;
			}
			rohc_remain_data += encoded_ts_lsb_len;
			rohc_remain_len -= encoded_ts_lsb_len;
			comp_opt_len += encoded_ts_lsb_len;

			/* encode TS reply with ts_lsb()*/
			is_ok = c_tcp_ts_lsb_code(context, rohc_ntoh32(opt_ts->ts_reply),
			                          opts_ctxt->tmp.nr_opt_ts_reply_bits_minus_1,
			                          opts_ctxt->tmp.nr_opt_ts_reply_bits_0x40000,
			                          opts_ctxt->tmp.nr_opt_ts_reply_bits_0x4000000,
			                          rohc_remain_data, rohc_remain_len,
			                          &encoded_ts_lsb_len);
			if(!is_ok)
			{
				rohc_comp_warn(context, "irregular chain: failed to encode echo "
				               "reply of TCP Timestamp option");
				goto error;
			}
			rohc_remain_data += encoded_ts_lsb_len;
			rohc_remain_len -= encoded_ts_lsb_len;
			comp_opt_len += encoded_ts_lsb_len;

			/* TODO: move at the very end of compression to avoid altering
			 *       context in case of compression failure */
			opts_ctxt->is_timestamp_init = true;
			c_add_wlsb(&opts_ctxt->ts_req_wlsb, msn, rohc_ntoh32(opt_ts->ts));
			c_add_wlsb(&opts_ctxt->ts_reply_wlsb, msn, rohc_ntoh32(opt_ts->ts_reply));
		}
		else if(opt_type == TCP_OPT_SACK)
		{
			const sack_block_t *const sack_blocks =
				(sack_block_t *) (opts + opts_offset + 2);
			const bool is_sack_unchanged =
				!c_tcp_opt_changed(opts_ctxt, opt_idx, opts + opts_offset, opt_len);

			assert(opt_len > 2);
			ret = c_tcp_opt_sack_code(context, rohc_ntoh32(tcp->ack_num),
			                          sack_blocks, opt_len - 2, is_sack_unchanged,
			                          rohc_remain_data, rohc_remain_len);
			if(ret < 0)
			{
				rohc_comp_warn(context, "failed to encode TCP option SACK");
				goto error;
			}
			rohc_remain_data += ret;
			rohc_remain_len -= ret;
			comp_opt_len += ret;
		}
		else if(opt_type != TCP_OPT_EOL &&
		        opt_type != TCP_OPT_NOP &&
		        opt_type != TCP_OPT_MSS &&
		        opt_type != TCP_OPT_WS &&
		        opt_type != TCP_OPT_SACK_PERM)
		{
			/* generic encoding */
			/* TODO: in what case option_static could be set to 1 ? */

			uint8_t discriminator;
			size_t contents_len;

			if(c_tcp_opt_changed(opts_ctxt, opt_idx, opts + opts_offset,
			                     opt_len - opts_offset))
			{
				/* generic_full_irregular: the item that is assumed to change
				 * constantly. Length is not allowed to change here, since a length
				 * change is most likely to cause new NOPs or an EOL length change. */
				discriminator = 0x00;
				contents_len = opt_len - 2;
			}
			else
			{
				/* generic_stable_irregular: the item that can change, but currently
				 * is unchanged */
				discriminator = 0xff;
				contents_len = 0;
			}

			if(rohc_remain_len < (1 + contents_len))
			{
				rohc_comp_warn(context, "ROHC buffer too small for the TCP irregular "
				               "part: %zu bytes required for TCP generic option, but "
				               "only %zu bytes available", 1 + contents_len,
				               rohc_remain_len);
				goto error;
			}

			/* discriminator byte */
			rohc_remain_data[0] = discriminator;
			rohc_remain_data++;
			rohc_remain_len--;
			comp_opt_len++;

			/* option contents, if any */
			if(contents_len > 0)
			{
				memcpy(rohc_remain_data, opts + opts_offset + 2, contents_len);
				rohc_remain_data += contents_len;
				rohc_remain_len -= contents_len;
				comp_opt_len += contents_len;
			}
		}
		rohc_comp_debug(context, "irregular chain: added %zu bytes of irregular "
		                "content for TCP option %u", comp_opt_len, opt_type);
		comp_opts_len += comp_opt_len;

		/* save the option in context */
		/* TODO: move at the very end of compression to avoid altering
		 *       context in case of compression failure */
		c_tcp_opt_record(opts_ctxt, opt_idx, opts + opts_offset, opts_len - opts_offset);
	}

	return comp_opts_len;

error:
	return -1;
}


/**
 * @brief Get the type and length of the next TCP option
 *
 * @param opts_data       The remaining data in the TCP options
 * @param opts_len        The length of the remaining data in the TCP options
 * @param[out] opt_type   The type of the TCP option
 * @param[out] opt_len    The length (in bytes) of the TCP option
 * @return                true if one well-formed TCP option was found,
 *                        false if the TCP option is malformed
 */
static bool c_tcp_opt_get_type_len(const uint8_t *const opts_data,
                                   const size_t opts_len,
                                   uint8_t *const opt_type,
                                   uint8_t *const opt_len)
{
	/* option type */
	if(opts_len < 1)
	{
		goto error;
	}
	*opt_type = opts_data[0];

	/* option length */
	if((*opt_type) == TCP_OPT_NOP)
	{
		/* 1-byte TCP option NOP */
		*opt_len = 1;
	}
	else if((*opt_type) == TCP_OPT_EOL)
	{
		/* TCP option EOL consumes all the remaining bytes of options */
		*opt_len = opts_len;
	}
	else
	{
		/* multi-byte TCP options: check minimal length and get length */
		if(opts_len < 2)
		{
			goto error;
		}
		*opt_len = opts_data[1];
		if((*opt_len) < 2 || (*opt_len) > opts_len)
		{
			goto error;
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Does the TCP option changed since last packets?
 *
 * The TCP option changed if the packet TCP option do not match the TCP option
 * that was recorded in the compression context.
 *
 * @param opts_ctxt    The compression context of the TCP options
 * @param opt_idx      The index of the TCP option in the TCP compression context
 * @param pkt_opt      The TCP option as found in the TCP packet
 * @param pkt_opt_len  The length of the TCP option as found in the TCP packet
 * @return             true if the TCP option changed, false if it doesn't
 */
static bool c_tcp_opt_changed(const struct c_tcp_opts_ctxt *const opts_ctxt,
                              const uint8_t opt_idx,
                              const uint8_t *const pkt_opt,
                              const size_t pkt_opt_len)
{
	return (opts_ctxt->list[opt_idx].data_len != pkt_opt_len ||
	        memcmp(opts_ctxt->list[opt_idx].data.raw, pkt_opt, pkt_opt_len) != 0);
}


/**
 * @brief Record the TCP option in context
 *
 * @param[out] opts_ctxt  The TCP compression context
 * @param opt_idx         The index of the TCP option in the TCP compression context
 * @param pkt_opt         The TCP option as found in the TCP packet
 * @param pkt_opt_len     The length of the TCP option as found in the TCP packet
 */
static void c_tcp_opt_record(struct c_tcp_opts_ctxt *const opts_ctxt,
                             const uint8_t opt_idx,
                             const uint8_t *const pkt_opt,
                             const size_t pkt_opt_len)
{
	opts_ctxt->list[opt_idx].data_len = pkt_opt_len;
	memcpy(opts_ctxt->list[opt_idx].data.raw, pkt_opt, pkt_opt_len);
}


/**
 * @brief Print a trace for the given TCP option
 *
 * @param context   The compression context
 * @param opt_type  The type of the TCP option to print a trace for
 * @param opt_data  The data of the TCP option to print a trace for
 * @param opt_len   The length (in bytes) of the TCP option to print a trace for
 */
static void c_tcp_opt_trace(const struct rohc_comp_ctxt *const context,
                            const uint8_t opt_type,
                            const uint8_t *const opt_data,
                            const size_t opt_len)
{
	const char *const opt_descr = tcp_opt_get_descr(opt_type);

	switch(opt_type)
	{
		case TCP_OPT_EOL:
		{
			rohc_comp_debug(context, "TCP option %s (%zu bytes)", opt_descr,
			                opt_len);
			break;
		}
		case TCP_OPT_SACK:
		{
			const size_t sack_blocks_nr = (opt_len - 2) % sizeof(sack_block_t);
			rohc_comp_debug(context, "TCP option %s = %zu blocks", opt_descr,
			                sack_blocks_nr);
			break;
		}
		case TCP_OPT_TS:
		{
			const struct tcp_option_timestamp *const opt_ts =
				(struct tcp_option_timestamp *) (opt_data + 2);
			rohc_comp_debug(context, "TCP option %s = 0x%04x 0x%04x", opt_descr,
			                rohc_ntoh32(opt_ts->ts), rohc_ntoh32(opt_ts->ts_reply));
			break;
		}
		case TCP_OPT_MSS:
		{
			uint16_t mss_val;
			memcpy(&mss_val, opt_data + 2, 2);
			rohc_comp_debug(context, "TCP option %s = %u (0x%04x)", opt_descr,
			                rohc_ntoh16(mss_val), rohc_ntoh16(mss_val));
			break;
		}
		case TCP_OPT_WS:
		{
			rohc_comp_debug(context, "TCP option %s = %u", opt_descr, opt_data[2]);
			break;
		}
		case TCP_OPT_NOP:
		case TCP_OPT_SACK_PERM:
		{
			rohc_comp_debug(context, "TCP option %s", opt_descr);
			break;
		}
		default:
		{
			rohc_comp_debug(context, "TCP option %s (type %u)", opt_descr, opt_type);
			break;
		}
	}
}


/**
 * @brief Determine the index of the TCP option
 *
 * @param context            The compression context
 * @param[in,out] opts_ctxt  The compression context for TCP options
 * @param opt_type           The type of the option
 * @param indexes_in_use     What indexes are used by the current packet?
 * @return                   true if the TCP options were successfully parsed and
 *                           can be compressed, false otherwise
 */
static uint8_t c_tcp_get_opt_index(const struct rohc_comp_ctxt *const context,
                                   struct c_tcp_opts_ctxt *const opts_ctxt,
                                   const uint8_t opt_type,
                                   const bool indexes_in_use[MAX_TCP_OPTION_INDEX + 1])
{
	uint8_t opt_idx;

	if(opt_type < TCP_LIST_ITEM_MAP_LEN && c_tcp_type2index[opt_type] >= 0)
	{
		/* TCP option got a reserved index */
		opt_idx = c_tcp_type2index[opt_type];
		rohc_comp_debug(context, "    option '%s' (%u) will use reserved index %u",
		                tcp_opt_get_descr(opt_type), opt_type, opt_idx);
	}
	else /* TCP option doesn't have a reserved index */
	{
		int opt_idx_free = -1;

		/* find the index that was used for the same option in previous packets... */
		for(opt_idx = TCP_INDEX_GENERIC7;
		    opt_idx_free < 0 && opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
		{
			if(opts_ctxt->list[opt_idx].used &&
			   opts_ctxt->list[opt_idx].type == opt_type)
			{
				rohc_comp_debug(context, "    re-use index %u that was already "
				                "used for the same option previously", opt_idx);
				opt_idx_free = opt_idx;
			}
		}

		/* ... or use the first free index... */
		for(opt_idx = TCP_INDEX_GENERIC7;
		    opt_idx_free < 0 && opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
		{
			if(!opts_ctxt->list[opt_idx].used)
			{
				rohc_comp_debug(context, "    use free index %u that was never "
				                "used before", opt_idx);
				opt_idx_free = opt_idx;
			}
		}

		/* ... or recycle the oldest index (but not already recycled by the current
		 * packet, otherwise 2 options might get the same index) */
		if(opt_idx_free < 0)
		{
			uint8_t oldest_idx = 0;
			size_t oldest_idx_age = 0;

			for(opt_idx = TCP_INDEX_GENERIC7; opt_idx <= MAX_TCP_OPTION_INDEX; opt_idx++)
			{
				if(!indexes_in_use[opt_idx] &&
				   opts_ctxt->list[opt_idx].used &&
				   opts_ctxt->list[opt_idx].age > oldest_idx_age)
				{
					oldest_idx_age = opts_ctxt->list[opt_idx].age;
					oldest_idx = opt_idx;
				}
			}
			rohc_comp_debug(context, "    no free index, recycle index %u "
			                "because it is the oldest one", oldest_idx);
			opt_idx_free = oldest_idx;
			opts_ctxt->list[opt_idx_free].used = false;
		}
		opt_idx = opt_idx_free;
	}

	return opt_idx;
}


/**
 * @brief Determine PS for the compressed list of TCP options
 *
 * According to RFC6846, §6.3.3, PS indicates size of XI fields:
 *  \li PS = 0 indicates 4-bit XI fields;
 *  \li PS = 1 indicates 8-bit XI fields.
 *
 * The rational to choose is: use 4-bit XI fields if the largest option index
 * may fit in 4 bits, otherwise fallback on the 8-bit XI fields
 *
 * @param idx_max  The largest option index used in the compressed packet
 * @return         The PS value
 */
static int c_tcp_opt_compute_ps(const uint8_t idx_max)
{
	assert(idx_max <= MAX_TCP_OPTION_INDEX);
	return (idx_max <= 7 ? 0 : 1);
}


/**
 * @brief Determine the length of XI indexes for the list of TCP options
 *
 * The length of the XI indexes depends on the type of XI fields we use.
 * According to RFC6846, §6.3.3, PS indicates size of XI fields:
 *  \li PS = 0 indicates 4-bit XI fields;
 *  \li PS = 1 indicates 8-bit XI fields.
 *
 * The computed XI length includes the first byte that contain the reserved
 * bits, the PS flag and the number of XI indexes (m).
 *
 * @param ps  The PS value
 * @param m   The number of elements in the list
 * @return    The length (in bytes) of the XI indexes
 */
static size_t c_tcp_opt_compute_xi_len(const int ps, const size_t m)
{
	size_t xis_len = 1; /* first byte contains reserved bits, PS flag and m */

	assert(ps == 0 || ps == 1);
	assert(m <= ROHC_TCP_OPTS_MAX);

	/* XI length depends on the type of XI fields we use */
	if(ps == 1)
	{
		/* 8-bit XI fields */
		xis_len += m;
	}
	else
	{
		/* 4-bit XI fields with padding if needed */
		xis_len += (m + 1) / 2;
	}

	return xis_len;
}


/**
 * @brief Write the XI field for a TCP option
 *
 * The room available in \e comp_opts shall have been checked before calling
 * this function.
 *
 * @param context           The compression context
 * @param[in,out] comp_opts  The compressed options
 * @param ps                 0 to use 4-bit XI fields, or 1 to use 8-bit XI fields
 * @param opt_pos            The position of the TCP option in the list
 *                           (opt_pos starts at 0)
 * @param opt_idx            The index of the TCP option
 * @param item_needed        Whether the TCP option requires its related item
 *                           to be present or not
 * @return                   The number of bytes completed
 */
static size_t c_tcp_opt_write_xi(const struct rohc_comp_ctxt *const context,
                                 uint8_t *const comp_opts,
                                 const int ps,
                                 const size_t opt_pos,
                                 const uint8_t opt_idx,
                                 const bool item_needed)
{
	size_t completed_bytes_nr;

	if(ps == 0)
	{
		/* use 4-bit XI fields */
		assert(opt_idx <= 7);
		rohc_comp_debug(context, "TCP options list: 4-bit XI field #%zu: index %u "
		                "do%s transmit an item", opt_pos, opt_idx,
		                item_needed ? "" : " not");
		if(opt_pos & 1)
		{
			comp_opts[0] |= opt_idx;
			if(item_needed)
			{
				comp_opts[0] |= 0x08;
			}
			completed_bytes_nr = 1;
		}
		else
		{
			comp_opts[0] = opt_idx << 4;
			if(item_needed)
			{
				comp_opts[0] |= 0x08 << 4;
			}
			completed_bytes_nr = 0;
		}
	}
	else
	{
		/* use 8-bit XI fields */
		assert(ps == 1);
		assert(opt_idx <= MAX_TCP_OPTION_INDEX);
		rohc_comp_debug(context, "TCP options list: 8-bit XI field #%zu: index %u "
		                "do%s transmit an item", opt_pos, opt_idx,
		                item_needed ? "" : " not");
		comp_opts[0] = opt_idx;
		if(item_needed)
		{
			comp_opts[0] |= 0x80;
		}
		completed_bytes_nr = 1;
	}

	return completed_bytes_nr;
}


/**
 * @brief Shall the list item be transmitted or not?
 *
 * @param context           The compression context
 * @param chain_type        The TCP chain for which the list of items is
 * @param opt_idx           The compression index of the TCP option to compress
 * @param opt_type          The type of the TCP option to compress
 * @param opt_len           The length of the TCP option to compress
 * @param opt               The TCP option to compress
 * @param opts_ctxt         The compression context for TCP options
 * @return                  true if the list item shall be transmitted,
 *                          false if it shall not
 */
static bool c_tcp_is_list_item_needed(const struct rohc_comp_ctxt *const context,
                                      const rohc_chain_t chain_type,
                                      const uint8_t opt_idx,
                                      const uint8_t opt_type,
                                      const uint8_t opt_len,
                                      const uint8_t *const opt,
                                      const struct c_tcp_opts_ctxt *const opts_ctxt)
{
	bool item_needed;

	/* do we need to transmit the item? */
	if(chain_type == ROHC_CHAIN_DYNAMIC || chain_type == ROHC_CHAIN_REPLICATE)
	{
		/* items are required in dynamic chain, see RFC6846 §6.3.5 */
		rohc_comp_debug(context, "TCP options list: option '%s' is transmitted "
		                "because dynamic/replicate chains require all options to "
		                "be transmitted", tcp_opt_get_descr(opt_type));
		item_needed = true;
	}
	else if(chain_type == ROHC_CHAIN_CO &&
	        (opt_idx == TCP_INDEX_NOP || opt_idx == TCP_INDEX_SACK_PERM))
	{
		/* in CO headers, NOP and SACK Permitted options have empty items,
		 * so transmitting them is useless */
		rohc_comp_debug(context, "TCP options list: option '%s' is not transmitted "
		                "because transmitting an empty item is useless",
		                tcp_opt_get_descr(opt_type));
		item_needed = false;
	}
	else if(opts_ctxt->list[opt_idx].nr_trans == 0)
	{
		/* option has never been transmitted, item must be transmitted */
		rohc_comp_debug(context, "TCP options list: option '%s' is new",
		                tcp_opt_get_descr(opt_type));
		item_needed = true;
	}
	else if(c_tcp_opt_changed(opts_ctxt, opt_idx, opt, opt_len))
	{
		/* option was already transmitted but it changed since then,
		 * item must be transmitted again */
		rohc_comp_debug(context, "TCP options list: option '%s' changed",
		                tcp_opt_get_descr(opt_type));
		item_needed = true;
	}
	else if(opts_ctxt->list[opt_idx].nr_trans < context->compressor->list_trans_nr)
	{
		/* option was already transmitted and didn't change since then, but the
		 * compressor is not confident yet that decompressor got the list item */
		rohc_comp_debug(context, "TCP options list: option '%s' shall be "
		                "transmitted %u times more to gain transmission confidence",
		                tcp_opt_get_descr(opt_type),
		                context->compressor->list_trans_nr -
		                opts_ctxt->list[opt_idx].nr_trans);
		item_needed = true;
	}
	else
	{
		/* option was already transmitted and didn't change since then,
		 * item shall not be transmitted again */
		rohc_comp_debug(context, "TCP options list: option '%s' is unchanged and "
		                "was transmitted at least %u times",
		                tcp_opt_get_descr(opt_type),
		                context->compressor->list_trans_nr);
		item_needed = false;
	}

	return item_needed;
}


/**
 * @brief Build the list item for the TCP NOP option
 *
 * @param context           The compression context
 * @param tcp               The TCP header
 * @param uncomp_opt        The uncompressed TCP option to compress
 * @param uncomp_opt_len    The length of the uncompressed TCP option to compress
 * @param[out] comp_opt     The compressed TCP option
 * @param comp_opt_max_len  The max remaining length in the ROHC buffer
 * @return                  The length (in bytes) of compressed TCP option
 *                          in case of success, -1 in case of failure
 */
static int c_tcp_build_nop_list_item(const struct rohc_comp_ctxt *const context __attribute__((unused)),
                                     const struct tcphdr *const tcp __attribute__((unused)),
                                     const uint8_t *const uncomp_opt __attribute__((unused)),
                                     const uint8_t uncomp_opt_len __attribute__((unused)),
                                     uint8_t *const comp_opt __attribute__((unused)),
                                     const size_t comp_opt_max_len __attribute__((unused)))
{
	/* NOP list item is empty */
	return 0;
}


/**
 * @brief Build the list item for the TCP EOL option
 *
 * \verbatim

   pad_len =:= compressed_value(8, nbits-8) [ 8 ];

\endverbatim
 *
 * @param context           The compression context
 * @param tcp               The TCP header
 * @param uncomp_opt        The uncompressed TCP option to compress
 * @param uncomp_opt_len    The length of the uncompressed TCP option to compress
 * @param[out] comp_opt     The compressed TCP option
 * @param comp_opt_max_len  The max remaining length in the ROHC buffer
 * @return                  The length (in bytes) of compressed TCP option
 *                          in case of success, -1 in case of failure
 */
static int c_tcp_build_eol_list_item(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp __attribute__((unused)),
                                     const uint8_t *const uncomp_opt __attribute__((unused)),
                                     const uint8_t uncomp_opt_len,
                                     uint8_t *const comp_opt,
                                     const size_t comp_opt_max_len)
{
	const size_t pad_len_bits = (uncomp_opt_len - 1) * 8;
	const size_t comp_opt_len = 1;

	/* is the ROHC buffer large enough to contain the list item? */
	if(comp_opt_max_len < comp_opt_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP option EOL item: "
		               "%zu bytes required, but only %zu bytes available",
		               comp_opt_len, comp_opt_max_len);
		goto error;
	}

	/* a very large EOL option (eg. 40 bytes) cannot be encoded */
	if(pad_len_bits > 0xff)
	{
		rohc_comp_warn(context, "cannot build TCP option EOL item: unexpected "
		               "large number of %zu pad_len bits", pad_len_bits);
		goto error;
	}

	comp_opt[0] = pad_len_bits;

	return comp_opt_len;

error:
	return -1;
}


/**
 * @brief Build the list item for the TCP MSS option
 *
 * \verbatim

   mss =:= irregular(16) [ 16 ];

\endverbatim
 *
 * @param context           The compression context
 * @param tcp               The TCP header
 * @param uncomp_opt        The uncompressed TCP option to compress
 * @param uncomp_opt_len    The length of the uncompressed TCP option to compress
 * @param[out] comp_opt     The compressed TCP option
 * @param comp_opt_max_len  The max remaining length in the ROHC buffer
 * @return                  The length (in bytes) of compressed TCP option
 *                          in case of success, -1 in case of failure
 */
static int c_tcp_build_mss_list_item(const struct rohc_comp_ctxt *const context,
                                     const struct tcphdr *const tcp __attribute__((unused)),
                                     const uint8_t *const uncomp_opt,
                                     const uint8_t uncomp_opt_len __attribute__((unused)),
                                     uint8_t *const comp_opt,
                                     const size_t comp_opt_max_len)
{
	const size_t comp_opt_len = sizeof(uint16_t);

	/* is the ROHC buffer large enough to contain the list item? */
	if(comp_opt_max_len < comp_opt_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP option MSS item: "
		               "%zu bytes required, but only %zu bytes available",
		               comp_opt_len, comp_opt_max_len);
		goto error;
	}

	memcpy(comp_opt, uncomp_opt + 2, sizeof(uint16_t));

	return comp_opt_len;

error:
	return -1;
}


/**
 * @brief Build the list item for the TCP WS option
 *
 * \verbatim

   wscale =:= irregular(8) [ 8 ];

\endverbatim
 *
 * @param context           The compression context
 * @param tcp               The TCP header
 * @param uncomp_opt        The uncompressed TCP option to compress
 * @param uncomp_opt_len    The length of the uncompressed TCP option to compress
 * @param[out] comp_opt     The compressed TCP option
 * @param comp_opt_max_len  The max remaining length in the ROHC buffer
 * @return                  The length (in bytes) of compressed TCP option
 *                          in case of success, -1 in case of failure
 */
static int c_tcp_build_ws_list_item(const struct rohc_comp_ctxt *const context,
                                    const struct tcphdr *const tcp __attribute__((unused)),
                                    const uint8_t *const uncomp_opt,
                                    const uint8_t uncomp_opt_len __attribute__((unused)),
                                    uint8_t *const comp_opt,
                                    const size_t comp_opt_max_len)
{
	const size_t comp_opt_len = 1;

	/* is the ROHC buffer large enough to contain the list item? */
	if(comp_opt_max_len < comp_opt_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP option WS item: "
		               "%zu bytes required, but only %zu bytes available",
		               comp_opt_len, comp_opt_max_len);
		goto error;
	}

	comp_opt[0] = uncomp_opt[2];

	return comp_opt_len;

error:
	return -1;
}


/**
 * @brief Build the list item for the TCP TS option
 *
 * \verbatim

   tsval  =:= irregular(32) [ 32 ];
   tsecho =:= irregular(32) [ 32 ];

\endverbatim
 *
 * @param context           The compression context
 * @param tcp               The TCP header
 * @param uncomp_opt        The uncompressed TCP option to compress
 * @param uncomp_opt_len    The length of the uncompressed TCP option to compress
 * @param[out] comp_opt     The compressed TCP option
 * @param comp_opt_max_len  The max remaining length in the ROHC buffer
 * @return                  The length (in bytes) of compressed TCP option
 *                          in case of success, -1 in case of failure
 */
static int c_tcp_build_ts_list_item(const struct rohc_comp_ctxt *const context,
                                    const struct tcphdr *const tcp __attribute__((unused)),
                                    const uint8_t *const uncomp_opt,
                                    const uint8_t uncomp_opt_len __attribute__((unused)),
                                    uint8_t *const comp_opt,
                                    const size_t comp_opt_max_len)
{
	const size_t comp_opt_len = sizeof(struct tcp_option_timestamp);
	const struct tcp_option_timestamp *const opt_ts =
		(struct tcp_option_timestamp *) (uncomp_opt + 2);

	/* is the ROHC buffer large enough to contain the list item? */
	if(comp_opt_max_len < comp_opt_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the TCP option TS item: "
		               "%zu bytes required, but only %zu bytes available",
		               comp_opt_len, comp_opt_max_len);
		goto error;
	}

	memcpy(comp_opt, opt_ts, sizeof(struct tcp_option_timestamp));

	return comp_opt_len;

error:
	return -1;
}


/**
 * @brief Build the list item for the TCP SACK Permitted option
 *
 * @param context           The compression context
 * @param tcp               The TCP header
 * @param uncomp_opt        The uncompressed TCP option to compress
 * @param uncomp_opt_len    The length of the uncompressed TCP option to compress
 * @param[out] comp_opt     The compressed TCP option
 * @param comp_opt_max_len  The max remaining length in the ROHC buffer
 * @return                  The length (in bytes) of compressed TCP option
 *                          in case of success, -1 in case of failure
 */
static int c_tcp_build_sack_perm_list_item(const struct rohc_comp_ctxt *const context __attribute__((unused)),
                                           const struct tcphdr *const tcp __attribute__((unused)),
                                           const uint8_t *const uncomp_opt __attribute__((unused)),
                                           const uint8_t uncomp_opt_len __attribute__((unused)),
                                           uint8_t *const comp_opt __attribute__((unused)),
                                           const size_t comp_opt_max_len __attribute__((unused)))
{
	/* SACK Permitted list item is empty */
	return 0;
}


/**
 * @brief Build the list item for the TCP SACK option
 *
 * See RFC4996 page 67.
 *
 * @param context           The compression context
 * @param tcp               The TCP header
 * @param uncomp_opt        The uncompressed TCP option to compress
 * @param uncomp_opt_len    The length of the uncompressed TCP option to compress
 * @param[out] comp_opt     The compressed TCP option
 * @param comp_opt_max_len  The max remaining length in the ROHC buffer
 * @return                  The length (in bytes) of compressed TCP option
 *                          in case of success, -1 in case of failure
 */
static int c_tcp_build_sack_list_item(const struct rohc_comp_ctxt *const context,
                                      const struct tcphdr *const tcp,
                                      const uint8_t *const uncomp_opt,
                                      const uint8_t uncomp_opt_len,
                                      uint8_t *const comp_opt,
                                      const size_t comp_opt_max_len)
{
	const sack_block_t *const opt_sack = (sack_block_t *) (uncomp_opt + 2);
	const bool is_sack_unchanged = false; /* unchanged encoding is only supported
	                                         by irregular chain */

	assert(uncomp_opt_len > 2);
	return c_tcp_opt_sack_code(context, rohc_ntoh32(tcp->ack_num),
	                           opt_sack, uncomp_opt_len - 2, is_sack_unchanged,
	                           comp_opt, comp_opt_max_len);
}


/**
 * @brief Build the list item for the TCP generic option
 *
 * \verbatim

   type          =:= irregular(8)      [ 8 ];
   option_static =:= one_bit_choice    [ 1 ];
   length_lsb    =:= irregular(7)      [ 7 ];
   contents      =:=
     irregular(length_lsb.UVALUE*8-16) [ length_lsb.UVALUE*8-16 ];

\endverbatim
 *
 * @param context           The compression context
 * @param tcp               The TCP header
 * @param uncomp_opt        The uncompressed TCP option to compress
 * @param uncomp_opt_len    The length of the uncompressed TCP option to compress
 * @param[out] comp_opt     The compressed TCP option
 * @param comp_opt_max_len  The max remaining length in the ROHC buffer
 * @return                  The length (in bytes) of compressed TCP option
 *                          in case of success, -1 in case of failure
 */
static int c_tcp_build_generic_list_item(const struct rohc_comp_ctxt *const context,
                                         const struct tcphdr *const tcp __attribute__((unused)),
                                         const uint8_t *const uncomp_opt,
                                         const uint8_t uncomp_opt_len,
                                         uint8_t *const comp_opt,
                                         const size_t comp_opt_max_len)
{
	/* TODO: for what option option_static = 1 would be helpful? */
	const uint8_t max_opt_len_mask = 0x7f;
	const uint8_t option_static = 0;
	const uint8_t opt_type = uncomp_opt[0];
	const size_t comp_opt_len = uncomp_opt_len;

	/* the compressed generic option cannot handle very long options */
	if((uncomp_opt_len & max_opt_len_mask) != uncomp_opt_len)
	{
		rohc_comp_warn(context, "generic encoding scheme cannot handle TCP options "
		               "larger than %u bytes and option %u is %u bytes long",
		               max_opt_len_mask, opt_type, uncomp_opt_len);
		goto error;
	}

	/* is the ROHC buffer large enough to contain the generic encoding? */
	if(comp_opt_max_len < comp_opt_len)
	{
		rohc_comp_warn(context, "ROHC buffer too small for the generic encoding "
		               "for TCP option: %zu bytes required, but only %zu bytes "
		               "available", comp_opt_len, comp_opt_max_len);
		goto error;
	}

	/* copy the whole uncompressed option, then alter the length field to reduce
	 * it and include the static flag */
	memcpy(comp_opt, uncomp_opt, comp_opt_len);
	comp_opt[1] = (option_static << 7) | (uncomp_opt_len & 0x7f);

	return comp_opt_len;

error:
	return -1;
}

