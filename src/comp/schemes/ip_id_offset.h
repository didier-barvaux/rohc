/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010 Viveris Technologies
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
 * @file   src/comp/schemes/ip_id_offset.h
 * @brief  Offset IP-ID encoding
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_IP_ID_OFFSET_H
#define ROHC_COMP_IP_ID_OFFSET_H

#include <stdint.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif

bool is_ip_id_increasing(const uint16_t old_id, const uint16_t new_id)
	__attribute__((warn_unused_result, const));

#endif

