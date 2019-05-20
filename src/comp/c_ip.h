/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010,2014 Viveris Technologies
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
 * @file c_ip.h
 * @brief ROHC compression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_IP_H
#define ROHC_COMP_IP_H

#include "rohc_comp_rfc3095.h"

/*
 * Public function prototypes.
 */

rohc_packet_t c_ip_decide_FO_packet(const struct rohc_comp_ctxt *const context,
                                    const struct rfc3095_tmp_state *const changes)
	__attribute__((warn_unused_result, nonnull(1, 2)));
rohc_packet_t c_ip_decide_SO_packet(const struct rohc_comp_ctxt *const context,
                                    const struct rfc3095_tmp_state *const changes)
	__attribute__((warn_unused_result, nonnull(1, 2)));

uint32_t c_ip_get_next_sn(const struct rohc_comp_ctxt *const context,
                          const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs __attribute__((unused)))
	__attribute__((warn_unused_result, nonnull(1, 2), pure));

int c_ip_code_ir_remainder(const struct rohc_comp_ctxt *const context,
                           const struct rfc3095_tmp_state *const changes,
                           uint8_t *const dest,
                           const size_t dest_max_len,
                           const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

#endif

