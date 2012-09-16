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
 * @author The hackers from ROHC for Linux
 */

#ifndef D_IP_H
#define D_IP_H

#include "d_generic.h"


/*
 * Public function prototypes.
 */

rohc_packet_t ip_detect_packet_type(struct rohc_decomp *decomp,
                                    struct d_context *context,
                                    const unsigned char *packet,
                                    const size_t rohc_length,
                                    const size_t large_cid_len);

int ip_parse_dynamic_ip(struct d_generic_context *context,
                        const unsigned char *packet,
                        unsigned int length,
                        struct rohc_extr_bits *const bits);

#endif

