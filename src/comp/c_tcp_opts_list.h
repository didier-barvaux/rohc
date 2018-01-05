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
	/** Whether the option context is in use or not */
	bool used;
	/** The type of the TCP option */
	uint8_t type;
	/** The number of times the TCP option was transmitted */
	size_t nr_trans;
	size_t age;
	/** The length of the TCP option */
	size_t data_len;
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


/** The temporary part of the compression context for TCP options */
struct c_tcp_opts_ctxt_tmp
{
	/** Whether the structure of the list of TCP options changed in the
	 * current packet */
	bool do_list_struct_changed;
	/** Whether at least one of the static TCP options changed in the
	 * current packet */
	bool do_list_static_changed;
	/** Whether the content of every TCP options was transmitted or not */
	bool is_list_item_present[MAX_TCP_OPTION_INDEX + 1];

	/** The number of options in the list of TCP options */
	size_t nr;
	/** The mapping between option types and indexes */
	uint8_t position2index[ROHC_TCP_OPTS_MAX];
	/* The maximum index value used for the list of TCP options */
	uint8_t idx_max;

	/** Whether the TCP option timestamp echo request is present in packet */
	bool opt_ts_present;
	/** The value of the TCP option timestamp echo request (in HBO) */
	uint32_t ts_req;
	/** The value of the TCP option timestamp echo reply (in HBO) */
	uint32_t ts_reply;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo request with p = -1 */
	size_t nr_opt_ts_req_bits_minus_1;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo request with p = 0x40000 */
	size_t nr_opt_ts_req_bits_0x40000;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo request with p = 0x4000000 */
	size_t nr_opt_ts_req_bits_0x4000000;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo reply with p = -1 */
	size_t nr_opt_ts_reply_bits_minus_1;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo reply with p = 0x40000 */
	size_t nr_opt_ts_reply_bits_0x40000;
	/** The minimal number of bits required to encode the TCP option timestamp
	 *  echo reply with p = 0x4000000 */
	size_t nr_opt_ts_reply_bits_0x4000000;
};


/** The compression context for TCP options */
struct c_tcp_opts_ctxt
{
	/** The number of times the structure of the list of TCP options was
	 * transmitted since it last changed */
	size_t structure_nr_trans;
	size_t structure_nr;
	uint8_t structure[ROHC_TCP_OPTS_MAX];
	struct c_tcp_opt_ctxt list[MAX_TCP_OPTION_INDEX + 1];

	bool is_timestamp_init;
	struct c_wlsb ts_req_wlsb;
	struct c_wlsb ts_reply_wlsb;

	/** The temporary part of the context, shall be reset between 2 packets */
	struct c_tcp_opts_ctxt_tmp tmp;
};


bool rohc_comp_tcp_are_options_acceptable(const struct rohc_comp *const comp,
                                          const uint8_t *const opts,
                                          const size_t data_offset)
	__attribute__((warn_unused_result, nonnull(1, 2)));

bool tcp_detect_options_changes(struct rohc_comp_ctxt *const context,
                                const struct tcphdr *const tcp,
                                struct c_tcp_opts_ctxt *const opts_ctxt,
                                size_t *const opts_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

int c_tcp_code_tcp_opts_list_item(const struct rohc_comp_ctxt *const context,
                                  const struct tcphdr *const tcp,
                                  const uint16_t msn,
                                  const rohc_tcp_chain_t chain_type,
                                  struct c_tcp_opts_ctxt *const opts_ctxt,
                                  uint8_t *const comp_opts,
                                  const size_t comp_opts_max_len,
                                  bool *const no_item_needed)
	__attribute__((warn_unused_result, nonnull(1, 2, 5, 6, 8)));

int c_tcp_code_tcp_opts_irreg(const struct rohc_comp_ctxt *const context,
                              const struct tcphdr *const tcp,
                              const uint16_t msn,
                              struct c_tcp_opts_ctxt *const opts_ctxt,
                              uint8_t *const comp_opts,
                              const size_t comp_opts_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

#endif /* ROHC_COMP_TCP_OPTS_LIST_H */

