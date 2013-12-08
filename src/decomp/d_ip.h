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
 * @file d_ip.h
 * @brief ROHC decompression context for the IP-only profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_IP_H
#define ROHC_DECOMP_IP_H

#include "d_generic.h"


/*
 * Public function prototypes.
 */

rohc_packet_t ip_detect_packet_type(const struct rohc_decomp *const decomp,
                                    const struct d_context *const context,
                                    const uint8_t *const rohc_packet,
                                    const size_t rohc_length,
                                    const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

int ip_parse_dynamic_ip(const struct d_context *const context,
                        const uint8_t *packet,
                        const size_t length,
                        struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));

int ip_parse_extension3(const struct rohc_decomp *const decomp,
                        const struct d_context *const context,
                        const unsigned char *const rohc_data,
                        const size_t rohc_data_len,
                        const rohc_packet_t packet_type,
                        struct rohc_extr_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));

int parse_outer_header_flags(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const unsigned char *const flags,
                             const unsigned char *fields,
                             const size_t length,
                             struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 6)));

int parse_inner_header_flags(const struct rohc_decomp *const decomp,
                             const struct d_context *const context,
                             const unsigned char *const flags,
                             const unsigned char *fields,
                             const size_t length,
                             struct rohc_extr_ip_bits *const bits)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4, 6)));

#endif

