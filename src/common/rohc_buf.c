/*
 * Copyright 2014 Didier Barvaux
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/**
 * @file   common/rohc_buf.c
 * @brief  Define a network buffer for the ROHC library
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_buf.h"

#include <assert.h>


/**
 * @brief Is the given network buffer malformed?
 *
 * @param buf  The network buffer to check for
 * @return     true if the given network is malformed, false if not
 *
 * @ingroup rohc
 */
bool rohc_buf_is_malformed(const struct rohc_buf buf)
{
	return (buf.data == NULL ||
	        buf.max_len == 0 ||
	        (buf.offset + buf.len) > buf.max_len);
}


/**
 * @brief Is the given network buffer empty?
 *
 * Empty means no data at all.
 *
 * @param buf  The network buffer to check for
 * @return     true if the given network is empty, false if not
 *
 * @ingroup rohc
 */
bool rohc_buf_is_empty(const struct rohc_buf buf)
{
	return (buf.len == 0);
}


/**
 * @brief Shift forward or backward the beginning of the given network buffer
 *
 * If \e offset is positive, shift the beginning of the buffer forward.
 * If \e offset is negative, shift the beginning of the buffer backward.
 * If \e offset is 0, do nothing.
 *
 * Shifting the beginning of the buffer increases (shift forward) or decreases
 * (shift backward) the unused space at the beginning of the buffer. This is
 * useful when parsing a network packet (once bytes are read, shift them
 * forward) for example.
 *
 * The unused space at the beginning of the buffer may also be used to prepend
 * a network header at the very end of the packet handling.
 *
 * @param buf    The network buffer to check for
 * @param offset  The offset to shift the beginning of the buffer of
 * @return     true if the given network is empty, false if not
 *
 * @ingroup rohc
 */
void rohc_buf_shift(struct rohc_buf *const buf, const int offset)
{
	if(offset > 0)
	{
		size_t offset_abs = offset;
		assert((buf->offset + offset_abs) <= buf->max_len);
		assert(buf->len >= offset_abs);
	}
	else
	{
		size_t offset_abs = -offset;
		assert(buf->offset >= offset_abs);
	}

	buf->offset += offset;
	buf->len -= offset;
}


/**
 * @brief How many bytes the given network buffer may contain?
 *
 * @param buf  The network buffer to check
 * @return     The number of bytes one may write to the given network buffer
 *
 * @ingroup rohc
 */
size_t rohc_buf_avail_len(const struct rohc_buf buf)
{
	return (buf.max_len - buf.offset);
}


/**
 * @brief Get the bytes in the given network buffer
 *
 * This function is a shortcut for:
 * \code
	rohc_buf_data_at(buf, 0);
\endcode
 *
 * @param buf  The network buffer to get bytes from
 * @return     The bytes stored in the network buffer
 *
 * @ingroup rohc
 */
uint8_t * rohc_buf_data(const struct rohc_buf buf)
{
	return rohc_buf_data_at(buf, 0);
}


/**
 * @brief Get the bytes at the given offset in the given network buffer
 *
 * @param buf     The network buffer to get bytes from
 * @param offset  The offset to get bytes at
 * @return        The bytes stored in the network buffer at the offset
 *
 * @ingroup rohc
 */
uint8_t * rohc_buf_data_at(const struct rohc_buf buf, const size_t offset)
{
	return (buf.data + buf.offset + offset);
}

