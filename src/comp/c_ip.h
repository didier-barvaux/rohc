/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010,2014 Viveris Technologies
 *
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
 * @file c_ip.h
 * @brief ROHC compression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_IP_H
#define ROHC_COMP_IP_H

#include "c_generic.h"

/*
 * Public function prototypes.
 */

bool c_ip_check_context(const struct c_context *const context,
                        const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

rohc_packet_t c_ip_decide_FO_packet(const struct c_context *context);
rohc_packet_t c_ip_decide_SO_packet(const struct c_context *context);

uint32_t c_ip_get_next_sn(const struct c_context *const context,
                          const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

size_t c_ip_code_ir_remainder(const struct c_context *const context,
	                           unsigned char *const dest,
	                           const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2)));

#endif

