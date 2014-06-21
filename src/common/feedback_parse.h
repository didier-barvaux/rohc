/*
 * Copyright 2011,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012 Viveris Technologies
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
 * @file   feedback_parse.h
 * @brief  Function to parse ROHC feedback
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_FEEDBACK_PARSE_H
#define ROHC_DECOMP_FEEDBACK_PARSE_H

#include <rohc/rohc_buf.h>

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "dllexport.h"

bool ROHC_EXPORT rohc_packet_is_feedback(const uint8_t byte)
	__attribute__((warn_unused_result, pure));

bool ROHC_EXPORT rohc_feedback_get_size(const struct rohc_buf rohc_data,
                                        size_t *const feedback_hdr_len,
                                        size_t *const feedback_data_len)
	__attribute__((warn_unused_result, nonnull(2, 3)));

#endif

