/*
 * Copyright 2012,2013,2014,2015,2016 Didier Barvaux
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
 * @file   c_tcp_static.h
 * @brief  Handle the static chain of the TCP compression profile
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_TCP_STATIC_H
#define ROHC_COMP_TCP_STATIC_H

#include "rohc_comp_internals.h"
#include "rohc_buf.h"

#include <stdint.h>
#include <stdlib.h>

int tcp_code_static_part(struct rohc_comp_ctxt *const context,
                         const struct rohc_pkt_hdrs *const uncomp_pkt_hdrs,
                         uint8_t *const rohc_pkt,
                         const size_t rohc_pkt_max_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

#endif /* ROHC_COMP_TCP_STATIC_H */

