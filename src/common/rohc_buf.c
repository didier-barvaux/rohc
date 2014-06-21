/*
 * Copyright 2014 Didier Barvaux
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
 * @file   common/rohc_buf.c
 * @brief  Define a network buffer for the ROHC library
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_buf.h"

#ifndef __KERNEL__
#  include <string.h>
#endif
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
 * @brief Pull the beginning of the given network buffer
 *
 * Pulling the beginning of the buffer increases the space at the beginning
 * of the buffer. This is useful when parsing a network packet (once bytes
 * are read, pull them) for example.
 *
 * @param buf     The network buffer to check for
 * @param offset  The offset to pull the beginning of the buffer of
 *
 * @ingroup rohc
 */
void rohc_buf_pull(struct rohc_buf *const buf, const size_t offset)
{
	assert((buf->offset + offset) <= buf->max_len);
	assert(buf->len >= offset);
	buf->offset += offset;
	buf->len -= offset;
}


/**
 * @brief Push the beginning of the given network buffer
 *
 * Pushing the beginning of the buffer decreases the space at the beginning
 * of the buffer. This is useful to prepend a network header before the
 * network buffer.
 *
 * @param buf     The network buffer to check for
 * @param offset  The offset to push the beginning of the buffer of
 *
 * @ingroup rohc
 */
void rohc_buf_push(struct rohc_buf *const buf, const size_t offset)
{
	assert(buf->offset >= offset);
	assert((buf->len + offset) <= buf->max_len);
	buf->offset -= offset;
	buf->len += offset;
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


/**
 * @brief Add data at the beginning of the given network buffer
 *
 * @param buf   The network buffer to prepend data to
 * @param data  The data to prepend
 * @param len   The length (in bytes) of the data to prepend
 *
 * @ingroup rohc
 */
void rohc_buf_prepend(struct rohc_buf *const buf,
                      const uint8_t *const data,
                      const size_t len)
{
	rohc_buf_push(buf, len);
	memcpy(rohc_buf_data(*buf), data, len);
}


/**
 * @brief Add data at the end of the given network buffer
 *
 * @param buf   The network buffer to append data to
 * @param data  The data to append
 * @param len   The length (in bytes) of the data to append
 *
 * @ingroup rohc
 */
void rohc_buf_append(struct rohc_buf *const buf,
                     const uint8_t *const data,
                     const size_t len)
{
	assert((buf->len + len) <= rohc_buf_avail_len(*buf));
	memcpy(rohc_buf_data_at(*buf, buf->len), data, len);
	buf->len += len;
}


/**
 * @brief Add a network buffer at the end of the given network buffer
 *
 * @param dst  The network buffer to append data to
 * @param src  The network buffer to append data from
 *
 * @ingroup rohc
 */
void rohc_buf_append_buf(struct rohc_buf *const dst,
                         const struct rohc_buf src)
{
	assert((dst->len + src.len) <= rohc_buf_avail_len(*dst));
	memcpy(rohc_buf_data_at(*dst, dst->len), rohc_buf_data(src), src.len);
	dst->len += src.len;
}


/**
 * @brief Reset the given network buffer
 *
 * @param buf  The network buffer to remove all data from
 *
 * @ingroup rohc
 */
void rohc_buf_reset(struct rohc_buf *const buf)
{
	buf->len = 0;
}

