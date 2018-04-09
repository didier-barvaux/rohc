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
 * @file   c_tcp_opts_list.h
 * @brief  Handle the list of TCP options for the TCP ompression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_TCP_OPTS_LIST_H
#define ROHC_COMP_TCP_OPTS_LIST_H

#include "rohc_comp_internals.h"
#include "protocols/tcp.h"
#include "protocols/rfc6846.h"

#include <stdint.h>
#include <stddef.h>


/**
 * @brief The compression context for one TCP option
 */
struct c_tcp_opt_ctxt
{
	/** The number of times the TCP option was transmitted */
	uint8_t nr_trans;
	/** Whether the option context is in use or not */
	bool used;
	/** The type of the TCP option */
	uint8_t type;
	uint8_t age;
	/** The length of the TCP option */
	uint8_t data_len;
	uint8_t unused[3];
/** The maximum size (in bytes) of one TCP option */
#define MAX_TCP_OPT_SIZE 40U
	/** The TCP option data */
	union
	{
		uint8_t raw[MAX_TCP_OPT_SIZE];
		sack_block_t sack_blocks[4];
		struct tcp_option_timestamp timestamp;
	} data;
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct c_tcp_opt_ctxt, data) % 8) == 0,
               "data in c_tcp_opt_ctxt should be aligned on 8 bytes");
_Static_assert((sizeof(struct c_tcp_opt_ctxt) % 8) == 0,
               "c_tcp_opt_ctxt length should be multiple of 8 bytes");
#endif


/** The temporary part of the compression context for TCP options */
struct c_tcp_opts_ctxt_tmp
{
	/** The value of the TCP option timestamp echo request (in HBO) */
	uint32_t ts_req;
	/** The value of the TCP option timestamp echo reply (in HBO) */
	uint32_t ts_reply;

	/** Whether the content of every TCP options was transmitted or not */
	bool is_list_item_present[MAX_TCP_OPTION_INDEX + 1];

	/** The mapping between option types and indexes */
	uint8_t position2index[ROHC_TCP_OPTS_MAX];

	/** The number of options in the list of TCP options */
	uint8_t nr;
	/* The maximum index value used for the list of TCP options */
	uint8_t idx_max;

	/** Whether the structure of the list of TCP options changed in the
	 * current packet */
	uint8_t do_list_struct_changed:1;
	/** Whether at least one of the static TCP options changed in the
	 * current packet */
	uint8_t do_list_static_changed:1;
	/** Whether the TCP option timestamp echo request is present in packet */
	uint8_t opt_ts_present:1;
	uint8_t unused:5;

	uint8_t unused2[5];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct c_tcp_opts_ctxt_tmp, ts_req) % 8) == 0,
               "ts_req in c_tcp_opts_ctxt_tmp should be aligned on 8 bytes");
_Static_assert((offsetof(struct c_tcp_opts_ctxt_tmp, is_list_item_present) % 8) == 0,
               "is_list_item_present in c_tcp_opts_ctxt_tmp should be aligned on 8 bytes");
_Static_assert((offsetof(struct c_tcp_opts_ctxt_tmp, position2index) % 8) == 0,
               "position2index in c_tcp_opts_ctxt_tmp should be aligned on 8 bytes");
_Static_assert((sizeof(struct c_tcp_opts_ctxt_tmp) % 8) == 0,
               "c_tcp_opts_ctxt_tmp length should be multiple of 8 bytes");
#endif


/** The compression context for TCP options */
struct c_tcp_opts_ctxt
{
	uint8_t structure[ROHC_TCP_OPTS_MAX];
	uint8_t structure_nr;
	struct c_tcp_opt_ctxt list[MAX_TCP_OPTION_INDEX + 1];

	struct c_wlsb ts_req_wlsb;
	struct c_wlsb ts_reply_wlsb;

	/** The temporary part of the context, shall be reset between 2 packets */
	struct c_tcp_opts_ctxt_tmp tmp;

	/** The number of times the structure of the list of TCP options was
	 * transmitted since it last changed */
	uint8_t structure_nr_trans;
	bool is_timestamp_init;
	uint8_t unused[6];
};

/* compiler sanity check for C11-compliant compilers and GCC >= 4.6 */
#if ((defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || \
     (defined(__GNUC__) && defined(__GNUC_MINOR__) && \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))))
_Static_assert((offsetof(struct c_tcp_opts_ctxt, structure) % 8) == 0,
               "structure in c_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct c_tcp_opts_ctxt, list) % 8) == 0,
               "list in c_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct c_tcp_opts_ctxt, ts_req_wlsb) % 8) == 0,
               "ts_req_wlsb in c_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct c_tcp_opts_ctxt, ts_reply_wlsb) % 8) == 0,
               "ts_reply_wlsb in c_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((offsetof(struct c_tcp_opts_ctxt, tmp) % 8) == 0,
               "tmp in c_tcp_opts_ctxt should be aligned on 8 bytes");
_Static_assert((sizeof(struct c_tcp_opts_ctxt) % 8) == 0,
               "c_tcp_opts_ctxt length should be multiple of 8 bytes");
#endif


bool rohc_comp_tcp_are_options_acceptable(const struct rohc_comp *const comp,
                                          const uint8_t *const opts,
                                          const size_t data_offset,
                                          struct rohc_pkt_hdrs *const uncomp_pkt_hdrs)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

void tcp_detect_options_changes(struct rohc_comp_ctxt *const context,
                                const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                struct c_tcp_opts_ctxt *const opts_ctxt)
	__attribute__((nonnull(1, 2, 3)));

int c_tcp_code_tcp_opts_list_item(const struct rohc_comp_ctxt *const context,
                                  const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                                  const uint16_t msn,
                                  const rohc_chain_t chain_type,
                                  struct c_tcp_opts_ctxt *const opts_ctxt,
                                  uint8_t *const comp_opts,
                                  const size_t comp_opts_max_len,
                                  bool *const no_item_needed)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6, 8)));

int c_tcp_code_tcp_opts_irreg(const struct rohc_comp_ctxt *const context,
                              const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                              const uint16_t msn,
                              struct c_tcp_opts_ctxt *const opts_ctxt,
                              uint8_t *const comp_opts,
                              const size_t comp_opts_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

#endif /* ROHC_COMP_TCP_OPTS_LIST_H */

