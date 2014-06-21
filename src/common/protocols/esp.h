/*
 * Copyright 2012 Didier Barvaux
 * Copyright 2009,2010 Thales Communications
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
 * @file   esp.h
 * @brief  ESP header description
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * See section 2 of RFC 4303 for details.
 */

#ifndef ROHC_PROTOCOLS_ESP_H
#define ROHC_PROTOCOLS_ESP_H

#include <stdint.h>


/**
 * @brief RTP header
 *
 * See section 2 of RFC 4303 for details.
 */
struct esphdr
{
	uint32_t spi;  /**< ESP Security Parameters Index (SPI) */
	uint32_t sn;   /**< ESP Sequence Number (SN) */
} __attribute__((packed));


#endif
