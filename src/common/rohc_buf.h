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
 * @file   common/rohc_buf.h
 * @brief  Define a network buffer for the ROHC library
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_BUF_H
#define ROHC_BUF_H

#ifdef __cplusplus
extern "C"
{
#endif

/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
	#define ROHC_EXPORT __declspec(dllexport)
#else
	#define ROHC_EXPORT
#endif

#include "rohc_time.h" /* for struct rohc_ts */

#include <stdbool.h>
#include <stdlib.h>


/**
 * @brief A network buffer for the ROHC library
 *
 * May represent one uncompressed packet, one ROHC packet, or a ROHC feedback.
 *
 * The network buffer does not contain the packet data itself. It only has
 * a pointer on it. This is designed this way for performance reasons: no copy
 * required to initialize a network buffer, the struct is small and may be
 * passed as copy to function.
 *
 * The network buffer is able to keep some free space at its beginning. The
 * unused space at the beginning of the buffer may be used to prepend a
 * network header at the very end of the packet handling.
 *
 * The beginning of the network buffer may also be shifted forward with the
 * \ref rohc_buf_pull function or shifted backward with the \ref rohc_buf_push
 * function. This is useful when parsing a network packet (once bytes are
 * read, shift them forward) for example.
 *
 * The network buffer may be initialized manually (see below) or with the
 * helper functions \ref rohc_buf_init_empty or \ref rohc_buf_init_full.
 * \code
   struct rohc_buf packet;
   ...
   packet.time.sec = 0;
   packet.time.nsec = 0;
   packet.max_len = 100;
   packet.data = malloc(packet.max_len);
   packet.offset = 2;
   packet.len = 2;
   packet[packet.offset] = 0x01;
   packet[packet.offset + 1] = 0x02;
   ...
\endcode
 *
 * or as below:
 * \code
   struct rohc_buf packet;
   unsigned char input[100];
   ...
   input[2] = 0x01;
   input[3] = 0x02;
   ...
   packet.time.sec = 0;
   packet.time.nsec = 0;
   packet.max_len = 100;
   packet.data = input;
   packet.offset = 2;
   packet.len = 2;
   ...
\endcode
 *
 * @ingroup rohc
 */
struct rohc_buf
{
	struct rohc_ts time;  /**< The timestamp associated to the data */
	uint8_t *data;        /**< The buffer data */
	size_t max_len;       /**< The maximum length of the buffer */
	size_t offset;        /**< The offset for the beginning of the data */
	size_t len;           /**< The data length (in bytes) */
};


/**
 * @brief Initialize the given network buffer with no data
 *
 * This method is used to initialize an empty network buffer that will be used
 * to create a packet. For example, the ROHC packet for a compression
 * operation, or the uncompressed packet for a decompression operation.
 *
 * @param __data     The packet data to point to
 * @param __max_len  The maxmimum length (in bytes) of the packet data
 *
 * \par Example:
 * \code
	#define PKT_DATA_LEN  145U
	uint8_t pkt_data[PKT_DATA_LEN];
	struct rohc_buf packet = rohc_buf_init_empty(pkt_data, PKT_DATA_LEN);
\endcode
 *
 * @ingroup rohc
 */
#define rohc_buf_init_empty(__data, __max_len) \
	{ \
		.time = { .sec = 0, .nsec = 0, }, \
		.data = (__data), \
		.max_len = (__max_len), \
		.offset = 0, \
		.len = 0, \
	}


/**
 * @brief Initialize the given network buffer with all its data
 *
 * This method is used to initialize a network buffer that will be used for
 * parsing only. For example, the uncompressed packet for a compression
 * operation, or the ROHC packet for a decompression operation.
 *
 * @param __data  The packet data to point to
 * @param __len   The maxmimum length (in bytes) of the packet data
 * @param __time  The timestamp at which the packet was received/handled
 *
 * \par Example:
 * \code
	#define PKT_DATA_LEN  145U
	const uint8_t pkt_data[PKT_DATA_LEN];
	const struct rohc_ts arrival_time = { .sec = 1399745625, .nsec = 42 };
	const struct rohc_buf packet =
		rohc_buf_init_full(pkt_data, PKT_DATA_LEN, arrival_time);
\endcode
 *
 * @ingroup rohc
 */
#define rohc_buf_init_full(__data, __len, __time) \
	{ \
		.time = (__time), \
		.data = (__data), \
		.max_len = (__len), \
		.offset = 0, \
		.len = (__len), \
	}


/**
 * @brief Get the byte at the given offset in the given network buffer
 *
 * @param __buf     The network buffer to get a byte from
 * @param __offset  The offset to get bytes at
 * @return          The byte stored in the network buffer at the offset
 *
 * @ingroup rohc
 */
#define rohc_buf_byte_at(__buf, __offset) \
	((__buf).data)[(__buf).offset + (__offset)]


/**
 * @brief Get the next byte in the given network buffer
 *
 * @param __buf  The network buffer to get the next byte from
 * @return       The next byte stored in the network buffer
 *
 * @ingroup rohc
 */
#define rohc_buf_byte(__buf) \
	rohc_buf_byte_at((__buf), 0)



bool rohc_buf_is_malformed(const struct rohc_buf buf)
	__attribute__((warn_unused_result));

bool rohc_buf_is_empty(const struct rohc_buf buf)
	__attribute__((warn_unused_result));

void rohc_buf_pull(struct rohc_buf *const buf, const size_t offset)
	__attribute__((nonnull(1)));
void rohc_buf_push(struct rohc_buf *const buf, const size_t offset)
	__attribute__((nonnull(1)));

size_t rohc_buf_avail_len(const struct rohc_buf buf)
	__attribute__((warn_unused_result));

uint8_t * rohc_buf_data_at(const struct rohc_buf buf, const size_t offset)
	__attribute__((warn_unused_result));
uint8_t * rohc_buf_data(const struct rohc_buf buf)
	__attribute__((warn_unused_result));

void rohc_buf_prepend(struct rohc_buf *const buf,
                      const uint8_t *const data,
                      const size_t len)
	__attribute__((nonnull(1, 2)));
void rohc_buf_append(struct rohc_buf *const buf,
                     const uint8_t *const data,
                     const size_t len)
	__attribute__((nonnull(1, 2)));
void rohc_buf_append_buf(struct rohc_buf *const dst,
                         const struct rohc_buf src)
	__attribute__((nonnull(1)));

void rohc_buf_reset(struct rohc_buf *const buf)
	__attribute__((nonnull(1)));


#undef ROHC_EXPORT /* do not pollute outside this header */

#ifdef __cplusplus
}
#endif

#endif /* ROHC_BUF_H */

