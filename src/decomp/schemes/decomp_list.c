/*
 * Copyright 2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
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
 * @file   schemes/decomp_list.c
 * @brief  ROHC generic list decompression
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "schemes/decomp_list.h"

#include "rohc_bit_ops.h"

#ifndef __KERNEL__
#  include <string.h>
#endif
#include <assert.h>


/* decode the generic part of the compressed list */

static int rohc_list_decode(struct list_decomp *decomp,
                            const unsigned char *packet,
                            size_t packet_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));


/* decode the 4 types of compressed lists */

static int rohc_list_decode_type_0(struct list_decomp *const decomp,
                                   const unsigned char *const packet,
                                   const size_t packet_len,
                                   const unsigned int gen_id,
                                   const int ps,
                                   const uint8_t m)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_decode_type_1(struct list_decomp *const decomp,
                                   const unsigned char *const packet,
                                   const size_t packet_len,
                                   const unsigned int gen_id,
                                   const int ps,
                                   const int xi_1)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_decode_type_2(struct list_decomp *const decomp,
                                   const unsigned char *const packet,
                                   const size_t packet_len,
                                   const unsigned int gen_id)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int rohc_list_decode_type_3(struct list_decomp *const decomp,
                                   const unsigned char *const packet,
                                   const size_t packet_len,
                                   const unsigned int gen_id,
                                   const int ps,
                                   const int xi_1)
	__attribute__((warn_unused_result, nonnull(1, 2)));


/* miscellaneous util functions */

static bool rohc_list_is_gen_id_known(const struct list_decomp *const decomp,
                                      const unsigned int gen_id)
	__attribute__((warn_unused_result, nonnull(1)));

static int rohc_list_parse_insertion_scheme(struct list_decomp *const decomp,
                                            const uint8_t *packet,
                                            size_t packet_len,
                                            const int ps,
                                            const int xi_1,
                                            const size_t items_nr,
                                            const struct rohc_list *const ref_list,
                                            struct rohc_list *const ins_list)
	__attribute__((warn_unused_result, nonnull(1, 2, 7, 8)));

static int rohc_list_parse_removal_scheme(struct list_decomp *const decomp,
                                          const uint8_t *packet,
                                          size_t packet_len,
                                          const struct rohc_list *const ref_list,
                                          struct rohc_list *const rem_list)
	__attribute__((warn_unused_result, nonnull(1, 2, 4, 5)));

static int rohc_list_decode_mask(struct list_decomp *const decomp,
                                 const char *const descr,
                                 const uint8_t *const packet,
                                 const size_t packet_len,
                                 uint8_t mask[2],
                                 size_t *const mask_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 6)));

static size_t rohc_list_get_xi_nr(const uint8_t ins_mask[2],
                                  const size_t ins_mask_len)
	__attribute__((warn_unused_result));

static size_t rohc_list_get_xi_len(const size_t xi_nr,
                                   const int ps)
	__attribute__((warn_unused_result, const));

static uint8_t rohc_get_bit(const unsigned char byte, const size_t pos)
	__attribute__((warn_unused_result, const));



/**
 * @brief Decompress the compressed list in given packet if present
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The remaining length of the packet to decode (in bytes)
 * @return            The size of the compressed list in packet in case of
 *                    success, -1 in case of failure
 */
int rohc_list_decode_maybe(struct list_decomp *decomp,
                           const unsigned char *packet,
                           size_t packet_len)
{
	size_t read_length = 0;
	int ret;

	assert(decomp != NULL);
	assert(packet != NULL);

	/* check for minimal size (1 byte) */
	if(packet_len < 1)
	{
		rd_list_warn(decomp, "packet too small for compressed list (only %zu "
		             "bytes while at least 1 byte is required)", packet_len);
		goto error;
	}

	if(GET_BIT_0_7(packet) == 0)
	{
		rd_list_debug(decomp, "no bit found for extension list, re-use last one");
		packet++;
		read_length++;
		packet_len--;
	}
	else
	{
		/* some bits were transmitted for the compressed list, decode them */
		ret = rohc_list_decode(decomp, packet, packet_len);
		if(ret < 0)
		{
			rd_list_warn(decomp, "failed to decode the compressed list");
			goto error;
		}
#ifndef __clang_analyzer__ /* silent warning about dead decrement */
		packet += ret;
		packet_len -= ret;
#endif
		read_length += ret;
	}

	return read_length;

error:
	return -1;
}


/**
 * @brief Decompress the compressed list in given packet
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The remaining length of the packet to decode (in bytes)
 * @return            The size of the compressed list in packet in case of
 *                    success, -1 in case of failure
 */
static int rohc_list_decode(struct list_decomp *decomp,
                            const unsigned char *packet,
                            size_t packet_len)
{
	size_t read_length = 0;
	uint8_t et;    /* the type of list encoding */
	bool gp;       /* whether the gen_id field is present or not */
	uint8_t ps;    /* the type of XI field */
	uint8_t m;     /* the CC or Count field (share bits with XI 1) */
	uint8_t xi_1;  /* the XI 1 field (share bits with m) */
	unsigned int gen_id; /* the gen_id if present,
	                        ROHC_LIST_GEN_ID_ANON otherwise */
	int ret;

	/* reset the list of the current packet */
	rohc_list_reset(&decomp->pkt_list);

	/* is there enough data in packet for the ET, PS, m/XI1 and gen_id
	 * fields? */
	if(packet_len < 2)
	{
		rd_list_warn(decomp, "packet too small for compressed list (only %zu "
		             "bytes while at least 2 bytes are required)", packet_len);
		goto error;
	}

	/* parse ET, GP, PS, and m/XI1 fields */
	et = GET_BIT_6_7(packet);
	gp = !!GET_BIT_5(packet);
	ps = GET_REAL(GET_BIT_4(packet));
	m = GET_BIT_0_3(packet);
	xi_1 = m; /* m and XI 1 are the same field */
	packet++;
	read_length++;
	packet_len--;
	rd_list_debug(decomp, "ET = %d, GP = %d, PS = %d, m = XI 1 = %d",
	              et, gp, ps, m);
	assert(m <= ROHC_LIST_ITEMS_MAX);

	/* parse gen_id if present */
	if(gp == 1)
	{
		gen_id = GET_BIT_0_7(packet);
		packet++;
		read_length++;
		packet_len--;
		rd_list_debug(decomp, "gen_id = 0x%02x", gen_id);
	}
	else
	{
		gen_id = ROHC_LIST_GEN_ID_ANON;
		rd_list_debug(decomp, "decode anonymous list");
	}
	decomp->pkt_list.id = gen_id;

	/* decode the compressed list according to its type */
	switch(et)
	{
		case 0:
			ret = rohc_list_decode_type_0(decomp, packet, packet_len,
			                              gen_id, ps, m);
			break;
		case 1:
			ret = rohc_list_decode_type_1(decomp, packet, packet_len,
			                              gen_id, ps, xi_1);
			break;
		case 2:
			ret = rohc_list_decode_type_2(decomp, packet, packet_len, gen_id);
			break;
		case 3:
			ret = rohc_list_decode_type_3(decomp, packet, packet_len,
			                              gen_id, ps, xi_1);
			break;
		default:
			/* should not happen */
			rohc_error(decomp, ROHC_TRACE_DECOMP, decomp->profile_id,
			           "unknown type of compressed list (ET = %u)", et);
			assert(0);
			goto error;
	}
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to decode compressed list type %d", et);
		goto error;
	}
	assert(((size_t) ret) <= packet_len);
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += ret;
	packet_len -= ret;
#endif
	read_length += ret;

	/* RFC3095, section 5.8.2.1 reads:
	 *   When the decompressor receives a compressed list, it retrieves the
	 *   proper ref_list from the sliding window based on the ref_id, and
	 *   decompresses the compressed list obtaining curr_list.
	 *   In U/O-mode, curr_list is inserted into the sliding window
	 *   together with its generation identifier if the compressed list had
	 *   a generation identifier and the sliding window does not contain a
	 *   list with that generation identifier.  All lists with generations
	 *   older than ref_id are removed from the sliding window. */
	if(gen_id == ROHC_LIST_GEN_ID_ANON)
	{
		/* list is not identified by a gen_id, so do not update the sliding
		 * window of lists */
		rd_list_debug(decomp, "anonymous list was received");
	}
	else if(decomp->lists[gen_id].counter > 0)
	{
		/* list is identified by a gen_id, but the sliding window of lists
		 * already contain a list with that generation identifier, so do
		 * not update the sliding window of lists */
		decomp->lists[gen_id].counter++;
		rd_list_debug(decomp, "list with gen_id %u is already present in "
		              "reference lists (received for the #%zu times)",
		              gen_id, decomp->lists[gen_id].counter);
	}
	else
	{
		/* list is identified by a gen_id and the sliding window of lists does
		 * not contain a list with that generation identifier yet, so update
		 * the sliding window of lists */
		rd_list_debug(decomp, "list with gen_id %u is not present yet in "
		              "reference lists, add it", gen_id);
		memcpy(decomp->lists[gen_id].items, decomp->pkt_list.items,
		       ROHC_LIST_ITEMS_MAX * sizeof(struct decomp_list *));
		decomp->lists[gen_id].items_nr = decomp->pkt_list.items_nr;
		decomp->lists[gen_id].counter = 1;
		/* TODO: remove all lists with gen_id < ref_id */
	}

	return read_length;

error:
	return -1;
}


/**
 * @brief Create a list item from a XI item
 *
 * @param decomp            The context for list decompression
 * @param xi_index          The XI index
 * @param xi_index_value    The XI index value
 * @param rohc_packet       The beginning of the XI item in the ROHC header
 * @param rohc_max_len      The remaining length (in bytes) of the ROHC header
 * @param[out] item_length  The length (in bytes) of the created item
 * @return                  true if item was successfully created,
 *                          false if a problem occurred
 */
bool rohc_decomp_list_create_item(struct list_decomp *const decomp,
                                  const unsigned int xi_index,
                                  const unsigned int xi_index_value,
                                  const uint8_t *const rohc_packet,
                                  const size_t rohc_max_len,
                                  size_t *const item_length)
{
	bool is_created;
	int ret;

	assert(decomp != NULL);
	assert(rohc_packet != NULL);

	/* is there enough room in packet for at least one byte of the item? */
	if(rohc_max_len <= 0)
	{
		rd_list_warn(decomp, "packet too small for at least 1 byte of item for "
		             "XI #%u (only %zu bytes available while at least 1 byte "
		             "is required)", xi_index, rohc_max_len);
		goto error;
	}

	/* X bit set in XI, so retrieve the related item in ROHC header */
	ret = decomp->get_item_size(rohc_packet, rohc_max_len);
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to determine the length of list item "
		             "referenced by XI #%d", xi_index);
		goto error;
	}
	*item_length = ret;

	/* is there enough room in packet for the full item? */
	if(rohc_max_len < (*item_length))
	{
		rd_list_warn(decomp, "packet too small for the full item of XI #%u "
		             "(only %zu bytes available while at least %zu bytes are "
		             "required)", xi_index, rohc_max_len, *item_length);
		goto error;
	}

	/* store the item in context on first occurrence and if item changed (may
	 * happen if context is re-used by a new stream with same extension type
	 * at the same location in header but different content) */
	is_created = decomp->create_item(rohc_packet, *item_length, xi_index_value,
	                                 decomp);
	if(!is_created)
	{
		rd_list_warn(decomp, "failed to create new list item");
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Decode an extension list type 0
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The length (in bytes) of the packet to decompress
 * @param gen_id      The id of the current list,
 *                    maybe ROHC_LIST_GEN_ID_ANON if not defined
 * @param ps          The ps field
 * @param m           The m field
 * @return            \li In case of success, the number of bytes read in the given
 *                        packet, ie. the length of the compressed list
 *                    \li -1 in case of failure
 */
static int rohc_list_decode_type_0(struct list_decomp *const decomp,
                                   const unsigned char *packet,
                                   size_t packet_len,
                                   const unsigned int gen_id,
                                   const int ps,
                                   const uint8_t m)
{
	size_t packet_read_len = 0;
	size_t xi_len; /* the length (in bytes) of the XI list */
	unsigned int xi_index; /* the index of the current XI in XI list */
	size_t item_read_len; /* the amount of bytes currently read in the item field */

	assert(decomp != NULL);
	assert(packet != NULL);
	assert(gen_id != ROHC_LIST_GEN_ID_NONE);
	assert(ps == 0 || ps == 1);
	assert(m <= ROHC_LIST_ITEMS_MAX);

	/* determine the length (in bytes) of the XI list */
	if(!ps)
	{
		/* 4-bit XIs */
		if((m % 2) == 0)
		{
			/* even number of XI fields */
			xi_len = m / 2;
		}
		else
		{
			/* odd number of XI fields, there are 4 bits of padding */
			xi_len = (m + 1) / 2;
		}
	}
	else
	{
		/* 8-bit XIs */
		xi_len = m;
	}

	/* is there enough room in packet for all the XI list ? */
	if(packet_len < xi_len)
	{
		rd_list_warn(decomp, "packet too small for m = %d XI items (only %zu "
		             "bytes while at least %zu bytes are required)", m,
		             packet_len, xi_len);
		goto error;
	}

	/* creation of the list from the m XI items */
	item_read_len = 0;
	for(xi_index = 0; xi_index < m; xi_index++)
	{
		unsigned int xi_x_value; /* the value of the X field in one XI field */
		unsigned int xi_index_value; /* the value of the Index field in one XI field */

		/* extract the value of the XI index */
		if(!ps)
		{
			/* 4-bit XI */
			if((xi_index % 2) == 0)
			{
				/* 4-bit XI is stored in MSB */
				xi_x_value = GET_BIT_7(packet + xi_index / 2);
				xi_index_value = GET_BIT_4_6(packet + xi_index / 2);
			}
			else
			{
				/* 4-bit XI is stored in LSB */
				xi_x_value = GET_BIT_3(packet + xi_index / 2);
				xi_index_value = GET_BIT_0_2(packet + xi_index / 2);
			}
			rd_list_debug(decomp, "0x%02x: XI #%u got index %u",
			              packet[xi_index / 2], xi_index, xi_index_value);
		}
		else
		{
			/* 8-bit XI */
			xi_x_value = GET_BIT_7(packet + xi_index);
			xi_index_value = GET_BIT_0_6(packet + xi_index);
			rd_list_debug(decomp, "0x%02x: XI #%u got index %u",
			              packet[xi_index], xi_index, xi_index_value);
		}

		/* is the XI index valid? */
		if(!decomp->check_item(decomp, xi_index_value))
		{
			rd_list_warn(decomp, "XI #%u got invalid index %u", xi_index,
			             xi_index_value);
			goto error;
		}

		/* is there a corresponding item in packet after the XI list? */
		if(xi_x_value)
		{
			const uint8_t *const xi_item = packet + xi_len + item_read_len;
			const size_t xi_item_max_len = packet_len - xi_len - item_read_len;
			size_t item_len;

			rd_list_debug(decomp, "handle XI item #%u", xi_index);

			/* create (or update if it already exists) the corresponding item
			 * with the item transmitted in the ROHC header */
			if(!rohc_decomp_list_create_item(decomp, xi_index, xi_index_value,
			                                 xi_item, xi_item_max_len, &item_len))
			{
				rd_list_warn(decomp, "failed to create XI item #%u from packet",
				             xi_index);
				goto error;
			}

			/* skip the item in ROHC header */
			item_read_len += item_len;
		}
		else
		{
			/* X bit not set in XI, so item is not provided in ROHC header,
			 * it must already be known by decompressor */
			if(!decomp->trans_table[xi_index_value].known)
			{
				rd_list_warn(decomp, "list item with index #%u referenced by XI "
				             "#%d is not known yet", xi_index_value, xi_index);
				goto error;
			}
		}

		/* record the structure of the list of the current packet */
		assert(decomp->pkt_list.items_nr < ROHC_LIST_ITEMS_MAX);
		decomp->pkt_list.items[decomp->pkt_list.items_nr] =
			&decomp->trans_table[xi_index_value];
		decomp->pkt_list.items_nr++;
		rd_list_debug(decomp, "  XI #%u: use item of type 0x%02x (index %u in "
		              "translation table) in list", xi_index,
		              decomp->trans_table[xi_index_value].type, xi_index_value);
	}

	/* ensure that in case of an odd number of 4-bit XIs, the 4 bits of padding
	   are set to 0 */
	if(ps == 0 && (m % 2) != 0)
	{
		const uint8_t xi_padding = GET_BIT_0_3(packet + xi_len - 1);
		if(xi_padding != 0)
		{
			rd_list_warn(decomp, "sender does not conform to ROHC standards: "
			             "when an odd number of 4-bit XIs is used, the last 4 "
			             "bits of the XI list should be set to 0, not 0x%x",
			             xi_padding);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}
	}

	/* skip the XI list and the item list */
	packet_read_len += xi_len + item_read_len;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet_len -= xi_len + item_read_len;
#endif

	return packet_read_len;

error:
	return -1;
}


/**
 * @brief Decode an extension list type 1
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The length (in bytes) of the packet to decompress
 * @param gen_id      The id of the current list,
 *                    maybe ROHC_LIST_GEN_ID_ANON if not defined
 * @param ps          The ps field
 * @param xi_1        The XI 1 field if PS = 1 (4-bit XI)
 * @return            \li In case of success, the number of bytes read in the
 *                        given packet, ie. the length of the compressed list
 *                    \li -1 in case of failure
 */
static int rohc_list_decode_type_1(struct list_decomp *const decomp,
                                   const unsigned char *packet,
                                   size_t packet_len,
                                   const unsigned int gen_id,
                                   const int ps,
                                   const int xi_1)
{
	size_t packet_read_len = 0;
	unsigned int ref_id;
	int ret;

	assert(decomp != NULL);
	assert(packet != NULL);
	assert(gen_id != ROHC_LIST_GEN_ID_NONE);
	assert(ps == 0 || ps == 1);

	/* in case of 8-bit XI, the XI 1 field should be set to 0 */
	if(ps && xi_1 != 0)
	{
		rd_list_warn(decomp, "sender does not conform to ROHC standards: when "
		             "8-bit XIs are used, the 4-bit XI 1 field should be set "
		             "to 0, not 0x%x", xi_1);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}

	/* is there enough data in packet for the ref_id? */
	if(packet_len < 1)
	{
		rd_list_warn(decomp, "packet too small for ref_id and minimal "
		             "insertion bit mask fields (only %zu bytes while at least "
		             "1 byte is required)", packet_len);
		goto error;
	}

	/* parse ref_id */
	ref_id = GET_BIT_0_7(packet);
	packet++;
	packet_len--;
	packet_read_len++;
	rd_list_debug(decomp, "ref_id = 0x%02x", ref_id);
	/* reference list must be known */
	if(!rohc_list_is_gen_id_known(decomp, ref_id))
	{
		rd_list_warn(decomp, "unknown ID 0x%02x given for reference list",
		             ref_id);
		goto error;
	}
	/* reference list must not be empty (RFC 4815, §5.7) */
	if(decomp->lists[ref_id].items_nr == 0)
	{
		rd_list_warn(decomp, "list encoding type 1 must not be used with an "
		             "empty reference list, discard packet");
		goto error;
	}

	/* insertion scheme */
	ret = rohc_list_parse_insertion_scheme(decomp, packet, packet_len, ps, xi_1, 0,
	                                       &(decomp->lists[ref_id]),
	                                       &decomp->pkt_list);
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to decompress list with ID %u based on "
		             "reference list %u: insertion scheme failed", gen_id, ref_id);
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += ret;
	packet_len -= ret;
#endif
	packet_read_len += ret;

	return packet_read_len;

error:
	return -1;
}


/**
 * @brief Decode an extension list type 2
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The length (in bytes) of the packet to decompress
 * @param gen_id      The id of the current list,
 *                    maybe ROHC_LIST_GEN_ID_ANON if not defined
 * @return            \li In case of success, the number of bytes read in the given
 *                        packet, ie. the length of the compressed list
 *                    \li -1 in case of failure
 */
static int rohc_list_decode_type_2(struct list_decomp *const decomp,
                                   const unsigned char *packet,
                                   size_t packet_len,
                                   const unsigned int gen_id)
{
	size_t packet_read_len = 0;
	unsigned int ref_id;
	int ret;

	assert(decomp != NULL);
	assert(packet != NULL);
	assert(gen_id != ROHC_LIST_GEN_ID_NONE);

	/* is there enough data in packet for the ref_id and minimal removal
	   bit mask fields ? */
	if(packet_len < 2)
	{
		rd_list_warn(decomp, "packet too small for ref_id and minimal removal "
		             "bit mask fields (only %zu bytes while at least 2 bytes "
		             "are required)", packet_len);
		goto error;
	}

	/* parse ref_id */
	ref_id = GET_BIT_0_7(packet);
	packet++;
	packet_len--;
	packet_read_len++;
	rd_list_debug(decomp, "ref_id = 0x%02x", ref_id);
	/* reference list must be known */
	if(!rohc_list_is_gen_id_known(decomp, ref_id))
	{
		rd_list_warn(decomp, "unknown ID 0x%02x given for reference list",
		             ref_id);
		goto error;
	}
	/* reference list must not be empty (RFC 4815, §5.7) */
	if(decomp->lists[ref_id].items_nr == 0)
	{
		rd_list_warn(decomp, "list encoding type 2 must not be used with an "
		             "empty reference list, discard packet");
		goto error;
	}

	/* removal scheme */
	ret = rohc_list_parse_removal_scheme(decomp, packet, packet_len,
	                                     &(decomp->lists[ref_id]),
	                                     &(decomp->pkt_list));
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to decompress list with ID %u based on "
		             "reference list %u: removal scheme failed", gen_id, ref_id);
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += ret;
	packet_len -= ret;
#endif
	packet_read_len += ret;

	return packet_read_len;

error:
	return -1;
}


/**
 * @brief Decode an extension list type 3
 *
 * @param decomp      The list decompressor
 * @param packet      The ROHC packet to decompress
 * @param packet_len  The length (in bytes) of the packet to decompress
 * @param gen_id      The id of the current list
 *                    maybe ROHC_LIST_GEN_ID_ANON if not defined
 * @param ps          The ps field
 * @param xi_1        The XI 1 field if PS = 1 (4-bit XI)
 * @return            \li In case of success, the number of bytes read in the given
 *                        packet, ie. the length of the compressed list
 *                    \li -1 in case of failure
 */
static int rohc_list_decode_type_3(struct list_decomp *const decomp,
                                   const unsigned char *packet,
                                   size_t packet_len,
                                   const unsigned int gen_id,
                                   const int ps,
                                   const int xi_1)
{
	size_t packet_read_len = 0;
	struct rohc_list removal_list; /* list after removal scheme but before insertion scheme */
	unsigned int ref_id;
	int ret;

	assert(decomp != NULL);
	assert(packet != NULL);
	assert(gen_id != ROHC_LIST_GEN_ID_NONE);
	assert(ps == 0 || ps == 1);

	/* in case of 8-bit XI, the XI 1 field should be set to 0 */
	if(ps && xi_1 != 0)
	{
		rd_list_warn(decomp, "sender does not conform to ROHC standards: when "
		             "8-bit XIs are used, the 4-bit XI 1 field should be set "
		             "to 0, not 0x%x", xi_1);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
		goto error;
#endif
	}

	/* is there enough data in packet for the ref_id? */
	if(packet_len < 1)
	{
		rd_list_warn(decomp, "packet too small for ref_id and minimal removal "
		             "bit mask fields (only %zu bytes while at least 1 byte "
		             "is required)", packet_len);
		goto error;
	}

	/* parse ref_id */
	ref_id = GET_BIT_0_7(packet);
	packet++;
	packet_len--;
	packet_read_len++;
	rd_list_debug(decomp, "ref_id = 0x%02x", ref_id);
	/* reference list must be known */
	if(!rohc_list_is_gen_id_known(decomp, ref_id))
	{
		rd_list_warn(decomp, "unknown ID 0x%02x given for reference list",
		             ref_id);
		goto error;
	}
	/* reference list must not be empty (RFC 4815, §5.7) */
	if(decomp->lists[ref_id].items_nr == 0)
	{
		rd_list_warn(decomp, "list encoding type 3 must not be used with an "
		             "empty reference list, discard packet");
		goto error;
	}

	/* removal scheme */
	rohc_list_reset(&removal_list);
	ret = rohc_list_parse_removal_scheme(decomp, packet, packet_len,
	                                     &(decomp->lists[ref_id]), &removal_list);
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to decompress list with ID %u based on "
		             "reference list %u: removal scheme failed", gen_id, ref_id);
		goto error;
	}
	packet += ret;
	packet_len -= ret;
	packet_read_len += ret;

	/* insertion scheme */
	ret = rohc_list_parse_insertion_scheme(decomp, packet, packet_len, ps, xi_1,
	                                       removal_list.items_nr, &removal_list,
	                                       &decomp->pkt_list);
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to decompress list with ID %u based on "
		             "reference list %u: insertion scheme failed", gen_id, ref_id);
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += ret;
	packet_len -= ret;
#endif
	packet_read_len += ret;

	return packet_read_len;

error:
	return -1;
}


/**
 * @brief Check if the given gen_id is known, ie. present in list table
 *
 * @param decomp  The list decompressor
 * @param gen_id  The gen_id to check for
 * @return        true if successful, false otherwise
 */
static bool rohc_list_is_gen_id_known(const struct list_decomp *const decomp,
                                      const unsigned int gen_id)
{
	assert(decomp != NULL);
	return (gen_id <= ROHC_LIST_GEN_ID_MAX &&
	        decomp->lists[gen_id].counter > 0);
}


/**
 * @brief Process the insertion scheme of the list compression
 *
 * @param decomp         The list decompressor
 * @param packet         The ROHC packet to decompress
 * @param packet_len     The length (in bytes) of the packet to decompress
 * @param ps             The PS bit
 * @param xi_1           The XI 1 field if PS = 1 (4-bit XI)
 * @param items_nr       The number of items in the initial list
 * @param ref_list       The list to use as reference
 * @param[out] ins_list  The list with new items added
 * @return               \li In case of success, the number of bytes read in the
 *                           given packet, ie. the length of the insertion mask
 *                       \li -1 in case of failure
 */
static int rohc_list_parse_insertion_scheme(struct list_decomp *const decomp,
                                            const uint8_t *packet,
                                            size_t packet_len,
                                            const int ps,
                                            const int xi_1,
                                            const size_t items_nr,
                                            const struct rohc_list *const ref_list,
                                            struct rohc_list *const ins_list)
{
	size_t packet_read_len = 0;
	uint8_t mask[2]; /* removal bit mask on 1-2 bytes */
	size_t mask_len; /* length (in bits) of the removal mask */
	size_t item_read_len; /* the amount of bytes currently read in the item field */
	size_t ref_list_cur_pos; /* current position in reference list */
	size_t xi_index; /* the index of the current XI in XI list */
	size_t xi_len; /* the length (in bytes) of the XI list */
	size_t k; /* the number of ones in insertion mask and the number of elements in XI list */
	size_t i;
	int ret;

	assert(ps == 0 || ps == 1);

	/* parse the insertion bit mask */
	ret = rohc_list_decode_mask(decomp, "insertion", packet, packet_len,
	                            mask, &mask_len);
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to parse the insertion bit mask");
		goto error;
	}
	packet += ret;
	packet_read_len += ret;
	packet_len -= ret;

	/* determine the number of indexes in the XI list */
	k = rohc_list_get_xi_nr(mask, mask_len);

	/* determine the length (in bytes) of the XI list */
	xi_len = rohc_list_get_xi_len(k, ps);
	if(packet_len < xi_len)
	{
		rd_list_warn(decomp, "packet too small for k = %zu XI items (only %zu "
		             "bytes while at least %zu bytes are required)", k,
		             packet_len, xi_len);
		goto error;
	}

	/* will the decompressed list contain too many items? */
	if((items_nr + k) > ROHC_LIST_ITEMS_MAX)
	{
		rd_list_warn(decomp, "failed to decompress list based on reference list "
		             "with %zu existing items and %zu additional new items: too "
		             "many items for list (%u items max)", items_nr, k,
		             ROHC_LIST_ITEMS_MAX);
		goto error;
	}

	/* create current list with reference list and new provided items */
	xi_index = 0;
	item_read_len = 0;
	ref_list_cur_pos = 0;
	for(i = 0; i < mask_len; i++)
	{
		uint8_t new_item_to_insert;

		/* retrieve the corresponding bit in the insertion mask */
		if(i < 7)
		{
			/* bit is located in first byte of insertion mask */
			new_item_to_insert = rohc_get_bit(mask[0], 6 - i);
		}
		else
		{
			/* bit is located in 2nd byte of insertion mask */
			new_item_to_insert = rohc_get_bit(mask[1], 14 - i);
		}

		/* insert item if required */
		if(!new_item_to_insert)
		{
			/* take the next item from reference list (if there no more item in
			   reference list, do nothing) */
			if(ref_list_cur_pos < ref_list->items_nr)
			{
				/* new list, insert the item from reference list */
				rd_list_debug(decomp, "use item from reference list (index %zu) into "
				              "current list (index %zu)", ref_list_cur_pos, i);
				/* use next item from reference list */
				ins_list->items[i] = ref_list->items[ref_list_cur_pos];
				ins_list->items_nr++;
				/* skip item in removal list */
				ref_list_cur_pos++;
			}
		}
		else
		{
			unsigned int xi_x_value; /* the value of the X field in one XI field */
			unsigned int xi_index_value; /* the value of the Index field in one XI field */

			/* new item to insert in list, parse the related XI field */
			if(!ps)
			{
				/* ROHC header contains 4-bit XIs */

				/* which type of XI do we parse ? first one, odd one or even one ? */
				if(xi_index == 0)
				{
					/* first XI is stored in the first byte of the header */
					xi_x_value = GET_BIT_3(&xi_1);
					xi_index_value = GET_BIT_0_2(&xi_1);
				}
				else if((xi_index % 2) != 0)
				{
					/* handle odd XI, ie. XI stored in MSB */
					xi_x_value = GET_BIT_7(packet + (xi_index - 1) / 2);
					xi_index_value = GET_BIT_4_6(packet + (xi_index - 1) / 2);
				}
				else
				{
					/* handle even XI, ie. XI stored in LSB */
					xi_x_value = GET_BIT_3(packet + (xi_index - 1) / 2);
					xi_index_value = GET_BIT_0_2(packet + (xi_index - 1) / 2);
				}
			}
			else
			{
				/* ROHC header contains 8-bit XIs */
				xi_x_value = GET_BIT_7(packet + xi_index);
				xi_index_value = GET_BIT_0_6(packet + xi_index);
			}

			/* is the XI index valid? */
			if(!decomp->check_item(decomp, xi_index_value))
			{
				rd_list_warn(decomp, "XI #%zu got invalid index %u", xi_index,
				             xi_index_value);
				goto error;
			}

			/* parse the corresponding item if present */
			if(xi_x_value)
			{
				const uint8_t *const xi_item = packet + xi_len + item_read_len;
				const size_t xi_item_max_len = packet_len - xi_len - item_read_len;
				size_t item_len;

				rd_list_debug(decomp, "handle XI item #%zu", xi_index);

				/* create (or update if it already exists) the corresponding
				 * item with the item transmitted in the ROHC header */
				if(!rohc_decomp_list_create_item(decomp, xi_index, xi_index_value,
				                                 xi_item, xi_item_max_len,
				                                 &item_len))
				{
					rd_list_warn(decomp, "failed to create XI item #%zu from "
					             "packet", xi_index);
					goto error;
				}

				/* skip the item in ROHC header */
				item_read_len += item_len;
			}
			else
			{
				/* X bit not set in XI, so item is not provided in ROHC header,
				 * it must already be known by decompressor */
				if(!decomp->trans_table[xi_index_value].known)
				{
					rd_list_warn(decomp, "list item with index #%u referenced by "
					             "XI #%zu is not known yet", xi_index_value,
					             xi_index);
					goto error;
				}
			}

			/* use new item from packet */
			rd_list_debug(decomp, "use new item #%zu into current list (index "
			              "%zu)", xi_index, i);
			ins_list->items[i] = &(decomp->trans_table[xi_index_value]);
			ins_list->items_nr++;

			/* skip the XI we have just parsed */
			xi_index++;
		}
	}

	/* ensure that in case of an even number of 4-bit XIs, the 4 bits of
	 * padding are set to 0 */
	if(ps == 0 && (k % 2) == 0)
	{
		const uint8_t xi_padding = GET_BIT_0_3(packet + xi_len - 1);
		if(xi_padding != 0)
		{
			rd_list_warn(decomp, "sender does not conform to ROHC standards: "
			             "when an even number of 4-bit XIs is used, the last 4 "
			             "bits of the XI list should be set to 0, not 0x%x",
			             xi_padding);
#ifdef ROHC_RFC_STRICT_DECOMPRESSOR
			goto error;
#endif
		}
	}

	/* skip the XI list and the item list */
	packet_read_len += xi_len + item_read_len;
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet_len -= xi_len + item_read_len;
#endif

	return packet_read_len;

error:
	return -1;
}


/**
 * @brief Process the removal scheme of the list compression
 *
 * @param decomp            The list decompressor
 * @param packet            The ROHC packet to decompress
 * @param packet_len        The length (in bytes) of the packet to decompress
 * @param ref_list          The list to use as reference
 * @param[in,out] rem_list  in: the initial list,
 *                          out: the list with superfluous items removed
 * @return                  \li In case of success, the number of bytes read in the
 *                              given packet, ie. the length of the removal mask
 *                          \li -1 in case of failure
 */
static int rohc_list_parse_removal_scheme(struct list_decomp *const decomp,
                                          const uint8_t *packet,
                                          size_t packet_len,
                                          const struct rohc_list *const ref_list,
                                          struct rohc_list *const rem_list)
{
	size_t packet_read_len = 0;
	uint8_t mask[2]; /* removal bit mask on 1-2 bytes */
	size_t mask_len; /* length (in bits) of the removal mask */
	size_t i;
	int ret;

	/* parse the removal bit mask */
	ret = rohc_list_decode_mask(decomp, "removal", packet, packet_len,
	                            mask, &mask_len);
	if(ret < 0)
	{
		rd_list_warn(decomp, "failed to parse the removal bit mask");
		goto error;
	}
#ifndef __clang_analyzer__ /* silent warning about dead in/decrement */
	packet += ret;
	packet_len -= ret;
#endif
	packet_read_len += ret;

	/* copy non-removed items from reference list */
	for(i = 0; i < mask_len; i++)
	{
		uint8_t item_to_remove;

		/* retrieve the corresponding bit in the removal mask */
		if(i < 7)
		{
			/* bit is located in first byte of removal mask */
			item_to_remove = rohc_get_bit(mask[0], 6 - i);
		}
		else
		{
			/* bit is located in 2nd byte of insertion mask */
			item_to_remove = rohc_get_bit(mask[1], 14 - i);
		}

		/* remove item if required */
		if(item_to_remove)
		{
			/* skip item only if reference list is large enough */
			if(i < ref_list->items_nr)
			{
				rd_list_debug(decomp, "skip item at index %zu of reference "
				              "list", i);
			}
		}
		else
		{
			rd_list_debug(decomp, "take item at index %zu of reference list "
			              "as item at index %zu of current list", i,
			              rem_list->items_nr);

			/* check that reference list is large enough */
			if(i >= ref_list->items_nr)
			{
				rd_list_warn(decomp, "reference list is too short: item at index "
				             "%zu requested while list contains only %zu items",
				             i, ref_list->items_nr);
				goto error;
			}

			/* take the item of the reference list */
			rem_list->items[rem_list->items_nr] = ref_list->items[i];
			rem_list->items_nr++;
		}
	}

	return packet_read_len;

error:
	return -1;
}


/**
 * @brief Determine the number of bits set to 1 in the insertion/removal bit mask
 *
 * @param decomp          The list decompressor
 * @param descr           The name of bit mask being decoded
 * @param packet          The ROHC packet to decompress
 * @param packet_len      The length (in bytes) of the packet to decompress
 * @param[out] mask       The insertion/removal bit mask on 1-2 bytes
 * @param[out] mask_len   The length of the insertion/removal mask (in bits)
 * @return                \li In case of success, the number of bytes read in the
 *                            given packet, ie. the length of the compressed list
 *                        \li -1 in case of failure
 */
static int rohc_list_decode_mask(struct list_decomp *const decomp,
                                 const char *const descr,
                                 const uint8_t *const packet,
                                 const size_t packet_len,
                                 uint8_t mask[2],
                                 size_t *const mask_len)
{
	size_t parsed_bytes_nr;

	/* is there enough data in packet for minimal insertion bit mask field ? */
	if(packet_len < 1)
	{
		rd_list_warn(decomp, "packet too small for minimal %s bit mask field "
		             "(only %zu bytes while at least 1 byte is required)",
		             descr, packet_len);
		goto error;
	}

	/* determine the number of bits set to 1 in the insertion bit mask */
	mask[0] = packet[0];
	rd_list_debug(decomp, "%s bit mask (first byte) = 0x%02x", descr, mask[0]);
	if(GET_REAL(GET_BIT_7(mask)) == 1)
	{
		/* 15-bit mask */
		if(packet_len < 2)
		{
			rd_list_warn(decomp, "packet too small for a 2-byte %s bit mask "
			             "(only %zu bytes available)", descr, packet_len);
			goto error;
		}
		*mask_len = 15;
		mask[1] = packet[1];
		rd_list_debug(decomp, "%s bit mask (second byte) = 0x%02x", descr, mask[1]);
		parsed_bytes_nr = 2;
	}
	else
	{
		/* 7-bit mask */
		rd_list_debug(decomp, "no second byte of %s bit mask", descr);
		*mask_len = 7;
		parsed_bytes_nr = 1;
	}

	return parsed_bytes_nr;

error:
	return -1;
}


/**
 * @brief Determine the number of indexes in the XI list
 *
 * @param ins_mask      The insertion bit mask
 * @param ins_mask_len  The length of the insertion bit mask (in bits)
 * @return              The number of indexes in the XI list
 */
static size_t rohc_list_get_xi_nr(const uint8_t ins_mask[2],
                                  const size_t ins_mask_len)
{
	size_t xi_nr = 0;
	int j;

	/* determine the number of bits set to 1 in the insertion bit mask */
	for(j = 6; j >= 0; j--)
	{
		if(rohc_get_bit(ins_mask[0], j))
		{
			xi_nr++;
		}
	}
	for(j = ins_mask_len - 8; j >= 0; j--)
	{
		if(rohc_get_bit(ins_mask[0], j))
		{
			xi_nr++;
		}
	}

	return xi_nr;
}


/**
 * @brief Determine the length of the XI list
 *
 * @param xi_nr  The number of indexes in the XI list
 * @param ps     The PS bit
 * @return       The length of the XI list (in bytes)
 */
static size_t rohc_list_get_xi_len(const size_t xi_nr,
                                   const int ps)
{
	size_t xi_len;

	if(ps == 0)
	{
		/* 4-bit XI */
		if((xi_nr - 1) % 2 == 0)
		{
			/* odd number of 4-bit XI fields and first XI field stored in
			   first byte of header, so last byte is full */
			xi_len = (xi_nr - 1) / 2;
		}
		else
		{
			/* even number of 4-bit XI fields and first XI field stored in
			   first byte of header, so last byte is not full */
			xi_len = (xi_nr - 1) / 2 + 1;
		}
	}
	else
	{
		/* 8-bit XI */
		xi_len = xi_nr;
	}

	return xi_len;
}


/**
 * @brief Get the bit in the given byte at the given position
 *
 * @param byte   The byte to analyse
 * @param pos    The position between 0 and 7
 * @return       The requested bit
 */
static uint8_t rohc_get_bit(const unsigned char byte, const size_t pos)
{
	uint8_t bit;

	switch(pos)
	{
		case 0:
			bit = GET_REAL(GET_BIT_0(&byte));
			break;
		case 1:
			bit = GET_REAL(GET_BIT_1(&byte));
			break;
		case 2:
			bit = GET_REAL(GET_BIT_2(&byte));
			break;
		case 3:
			bit = GET_REAL(GET_BIT_3(&byte));
			break;
		case 4:
			bit = GET_REAL(GET_BIT_4(&byte));
			break;
		case 5:
			bit = GET_REAL(GET_BIT_5(&byte));
			break;
		case 6:
			bit = GET_REAL(GET_BIT_6(&byte));
			break;
		case 7:
			bit = GET_REAL(GET_BIT_7(&byte));
			break;
		default:
			/* there is no such bit in a byte */
			assert(0); /* should not happen */
			bit = 0;
			break;
	}

	return bit;
}

