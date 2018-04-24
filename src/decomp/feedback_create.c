/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013 Viveris Technologies
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
 * @file   feedback_create.c
 * @brief  Functions to create ROHC feedback
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "feedback_create.h"
#include "crc.h"
#include "rohc_debug.h"
#include "rohc_bit_ops.h"
#include "sdvl.h"

#ifdef ROHC_FEEDBACK_DEBUG
#  include <stdio.h>
#endif
#include <string.h>
#include <assert.h>


/*
 * Prototypes of private functions.
 */

static bool f_append_cid(struct d_feedback *const feedback,
                         const uint16_t cid,
                         const rohc_cid_type_t cid_type,
                         size_t *const cid_len)
	__attribute__((warn_unused_result, nonnull(1, 4)));


/**
 * @brief Build a FEEDBACK-1 packet.
 *
 * @param sn_bits  The LSB of the Sequence Number (SN) the feedback packet
 *                 is associated with
 * @param feedback The feedback packet to build
 */
void f_feedback1(const uint32_t sn_bits, struct d_feedback *const feedback)
{
	feedback->type = 1; /* set type for add_option */
	feedback->size = 1;
	feedback->data[0] = (sn_bits & 0xff);
}


/**
 * @brief Build a FEEDBACK-2 packet.
 *
 * @param profile_id  The ID of the decompression profile that builds the feedback
 * @param ack_type    The type of acknowledgement:
 *                      \li \ref ROHC_FEEDBACK_ACK,
 *                      \li \ref ROHC_FEEDBACK_NACK,
 *                      \li \ref ROHC_FEEDBACK_STATIC_NACK
 * @param mode        The mode in which ROHC operates:
 *                      \li \ref ROHC_U_MODE,
 *                      \li \ref ROHC_O_MODE,
 *                      \li \ref ROHC_R_MODE
 * @param sn_bits     The LSB of the Sequence Number (SN) the feedback packet
 *                    is associated with
 * @param sn_bits_nr  The number of SN LSB
 * @param feedback    The feedback packet to build
 * @return            true if the packet is successfully built,
 *                    false otherwise
 */
bool f_feedback2(const rohc_profile_t profile_id,
                 const enum rohc_feedback_ack_type ack_type,
                 const rohc_mode_t mode,
                 const uint32_t sn_bits,
                 const size_t sn_bits_nr,
                 struct d_feedback *const feedback)
{
	uint8_t sn_mask_on_first_byte;
	size_t sn_bits_on_first_byte;
	const size_t sn_bits_on_2nd_byte = 8;
	size_t needed_sn_opts_nr;
	size_t sn_bits_to_send;
	size_t sn_bits_shift;
	size_t sn_opt_nr;
	bool is_ok;

	feedback->type = 2; /* set type for add_option */
	feedback->size = 0; /* set size for add_option */

	/* if SN is not valid, it shall be zero */
	if(sn_bits_nr == 0)
	{
		assert(sn_bits == 0);
	}

	if(profile_id == ROHC_PROFILE_UNCOMPRESSED)
	{
		/* FEEDBACK-2 is not supported by the Uncompressed profile */
		assert(0);
		goto error;
	}
	else if(profile_id == ROHC_PROFILE_TCP ||
	        rohc_profile_is_rohcv2(profile_id))
	{
		/* FEEDBACK-2 format for TCP and ROHCv2 profiles */
		feedback->data[feedback->size] = (ack_type & 0x3) << 6;
		sn_bits_on_first_byte = 6;
		sn_mask_on_first_byte = 0x3f;
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: first 2 bits = 0x%02x (ACK type = %d)\n",
		       feedback->data[feedback->size], ack_type);
#endif
	}
	else /* FEEDBACK-2 format for the other profiles */
	{
		feedback->data[feedback->size] = ((ack_type & 0x3) << 6) | ((mode & 0x3) << 4);
		sn_bits_on_first_byte = 4;
		sn_mask_on_first_byte = 0x0f;
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: first 4 bits = 0x%02x (ACK type = %d, mode = %d)\n",
		       feedback->data[feedback->size], ack_type, mode);
#endif
	}

	/* how many SN options are required to store the full SN on the base header
	 * and those SN options? */
	if(rohc_profile_is_rohcv2(profile_id))
	{
		/* ROHCv2 profiles do not have the (M)SN option, use the 6+8=14 bytes
		 * of the base FEEDBACK-2 header */
		needed_sn_opts_nr = 0;
	}
	else
	{
		/* ROHCv1 profiles may use the (M)SN option */
		for(needed_sn_opts_nr = 0; needed_sn_opts_nr <= 3 &&
		    sn_bits_nr > (sn_bits_on_first_byte + sn_bits_on_2nd_byte + needed_sn_opts_nr * 8);
		    needed_sn_opts_nr++)
		{
		}
	}
	assert(needed_sn_opts_nr <= 3); /* should never happen: SN is not larger than 32 bits */
	sn_bits_to_send = sn_bits_on_first_byte + sn_bits_on_2nd_byte + needed_sn_opts_nr * 8;
	assert(sn_bits_to_send >= sn_bits_nr);
#ifdef ROHC_FEEDBACK_DEBUG
	printf("FEEDBACK-2: transmit SN = 0x%08x on %zu bits\n", sn_bits, sn_bits_to_send);
#endif
	sn_bits_shift = sn_bits_to_send;

	/* base header: variable SN bits in first byte */ /* TODO: clear MSB */
	sn_bits_shift -= sn_bits_on_first_byte;
	if(sn_bits_shift < 32)
	{
		feedback->data[feedback->size] |= (sn_bits >> sn_bits_shift) & sn_mask_on_first_byte;
	}
#ifdef ROHC_FEEDBACK_DEBUG
	printf("FEEDBACK-2: %zu bits of SN = 0x%x\n", sn_bits_on_first_byte,
	       feedback->data[feedback->size] & sn_mask_on_first_byte);
#endif
	feedback->size++;

	/* base header: 8 additional SN bits */ /* TOOD: clear MSB */
	sn_bits_shift -= sn_bits_on_2nd_byte;
	feedback->data[feedback->size] = (sn_bits >> sn_bits_shift) & 0xff;
#ifdef ROHC_FEEDBACK_DEBUG
	printf("FEEDBACK-2: %zu bits of SN = 0x%02x\n", sn_bits_on_2nd_byte,
	       feedback->data[feedback->size] & 0xff);
#endif
	feedback->size++;

	/* base header: CRC for TCP and ROHCv2 profiles */
	if(profile_id == ROHC_PROFILE_TCP ||
	   rohc_profile_is_rohcv2(profile_id))
	{
		feedback->data[feedback->size] = 0x00; /* zeroed for computation */
		feedback->size++;
	}

	/* add feedback options */
	if(sn_bits_nr > 0)
	{
		/* add SN option(s) */
		for(sn_opt_nr = 0; sn_opt_nr < needed_sn_opts_nr; sn_opt_nr++)
		{
			uint8_t sn_opt;

			sn_bits_shift -= 8;
			sn_opt = (sn_bits >> sn_bits_shift) & 0xff;

			is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN, &sn_opt,
			                     sizeof(sn_opt));
			if(!is_ok)
			{
#ifdef ROHC_FEEDBACK_DEBUG
				printf("failed to add SN option #%zu to the feedback packet\n",
				       sn_opt_nr + 1);
#endif
				goto error;
			}
#ifdef ROHC_FEEDBACK_DEBUG
			printf("FEEDBACK-2: 8 bits of SN = 0x%02x (SN option #%zu)\n",
			       sn_opt, sn_opt_nr + 1);
#endif
		}
	}
	else
	{
		/* SN-NOT-VALID option */
		is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN_NOT_VALID, NULL, 0);
		if(!is_ok)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add option to the feedback packet\n");
#endif
			goto error;
		}
	}

	return true;

error:
	return false;
}


/**
 * @brief Add an option data to the FEEDBACK-2 packet.
 *
 * @param feedback The feedback packet to which the option must be added
 * @param opt_type The type of option to add
 * @param data     The option data
 * @param data_len The length of option data (in bytes)
 * @return         true if the option is successfully added, false otherwise
 */
bool f_add_option(struct d_feedback *const feedback,
                  const enum rohc_feedback_opt opt_type,
                  const uint8_t *const data,
                  const size_t data_len)
{
	/* options are reserved for FEEDBACK-2 */
	assert(feedback->type == 2);

	/* write option header: type and size */
	feedback->data[feedback->size] = opt_type & 0xf;
	feedback->data[feedback->size] <<= 4;
	if(opt_type == ROHC_FEEDBACK_OPT_CRC || data != NULL)
	{
		assert(data_len == 0 || data_len == 1);
		feedback->data[feedback->size] |= 1;
	}
	feedback->size++;

	if(opt_type == ROHC_FEEDBACK_OPT_CRC)
	{
		/* force 0x00 as data in case of CRC option */
		assert(data == NULL);
		assert(data_len == 0);
		feedback->data[feedback->size] = 0;
		feedback->size++;
	}
	else if(data != NULL)
	{
		/* copy given data if not NULL */
		assert(data_len == 1);
		if((feedback->size + data_len) > FEEDBACK_DATA_MAX_LEN)
		{
			goto error;
		}
		feedback->data[feedback->size] = data[0];
		feedback->size++;
	}
	else
	{
		/* no data given */
		assert(data_len == 0);
	}

	return true;

error:
	return false;
}


/**
 * @brief Append the CID to the feedback packet.
 *
 * @param feedback     The feedback packet to which the CID must be appended
 * @param cid          The Context ID (CID) to append
 * @param cid_type     The type of CID used for the feedback
 * @param[out] cid_len The length of the add-CID or large CID field
 * @return             Whether the CID is successfully appended or not
 */
static bool f_append_cid(struct d_feedback *const feedback,
                         const uint16_t cid,
                         const rohc_cid_type_t cid_type,
                         size_t *const cid_len)
{
	size_t i;

	if(cid_type == ROHC_LARGE_CID)
	{
		/* large CIDs are used */
		assert(cid <= ROHC_LARGE_CID_MAX);

		/* determine the number of bits required for the SDVL-encoded large CID */
		*cid_len = sdvl_get_encoded_len(cid);
		assert((*cid_len) == 1 || (*cid_len) == 2); /* ensured by SDVL algorithm */

		/* check if the feedback packet can contain a SDVL-encoded large CID */
		if((feedback->size + (*cid_len)) > FEEDBACK_DATA_MAX_LEN)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("feedback packet is too small for large CID\n");
#endif
			return false;
		}

#ifdef ROHC_FEEDBACK_DEBUG
		printf("add %zu bytes for large CID to feedback\n", *cid_len);
#endif

		/* move feedback data to make space for the SDVL-encoded large CID */
		assert(feedback->size >= 1);
		for(i = feedback->size; i > 0; i--)
		{
			feedback->data[i - 1 + (*cid_len)] = feedback->data[i - 1];
		}

		/* SDVL-encode the large CID */
		if(!sdvl_encode_full(feedback->data, 4U /* TODO */, cid_len, cid))
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to SDVL-encoded large CID %u, should never "
			       "happen!\n", cid);
#endif
			return false;
		}
		feedback->size += (*cid_len);
	}
	else /* small CID */
	{
		/* small CIDs are used */
		assert(cid <= ROHC_SMALL_CID_MAX);

		/* add 1 byte only if CID is non-zero */
		if(cid != 0)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("add 1 byte for small CID to feedback\n");
#endif

			/* move feedback data to make space for the small CID */
			assert(feedback->size >= 1);
			for(i = feedback->size; i > 0; i--)
			{
				feedback->data[i] = feedback->data[i - 1];
			}

			/* write the small CID to the feedback packet */
			feedback->data[0] = 0xe0;
			feedback->data[0] = (cid & 0xf) | feedback->data[0];
			feedback->size++;
			*cid_len = 1;
		}
#ifdef ROHC_FEEDBACK_DEBUG
		else
		{
			printf("no need to prepend Add-CID byte to feedback\n");
			*cid_len = 0;
		}
#endif
	}

	return true;
}


/**
 * @brief Wrap the feedback packet and add a CRC option if specified.
 *
 * @warning CID may be greater than MAX_CID if the context was not found and
 *          generated a No Context feedback; it must however respect CID type
 *
 * @param feedback          The feedback packet to which the CID must be
 *                          appended
 * @param cid               The Context ID (CID) to append
 * @param cid_type          The type of CID used for the feedback
 * @param protect_with_crc  Whether the CRC option must be added or not
 * @param crc_table         The pre-computed table for fast CRC computation
 * @param final_size        OUT: The final size of the feedback packet
 * @return                  The feedback packet if successful, NULL otherwise
 */
uint8_t * f_wrap_feedback(struct d_feedback *const feedback,
                          const uint16_t cid,
                          const rohc_cid_type_t cid_type,
                          const rohc_feedback_crc_t protect_with_crc,
                          const uint8_t *const crc_table,
                          size_t *const final_size)
{
	uint8_t *feedback_packet;
	size_t feedback_cid_len = 0;
	size_t crc_pos = 0;

	/* append the CID to the feedback packet */
	if(!f_append_cid(feedback, cid, cid_type, &feedback_cid_len))
	{
		goto error;
	}
	assert(feedback_cid_len <= 2);

	/* add the CRC option if specified */
	if(protect_with_crc == ROHC_FEEDBACK_WITH_CRC_OPT)
	{
#ifdef ROHC_FEEDBACK_DEBUG
		printf("add CRC option to feedback\n");
#endif
		if(!f_add_option(feedback, ROHC_FEEDBACK_OPT_CRC, NULL, 0))
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add CRC option to the feedback packet\n");
#endif
			goto error;
		}
		/* CRC goes in the last byte of the feedback (CRC option is the last one) */
		crc_pos = feedback->size - 1;
	}
	else if(protect_with_crc == ROHC_FEEDBACK_WITH_CRC_BASE ||
	        protect_with_crc == ROHC_FEEDBACK_WITH_CRC_BASE_TCP)
	{
		/* CRC goes in the last byte of the base header */
		const size_t feedback_type_len = 1;
		const size_t feedback_base_hdr_len = 2;
		crc_pos = feedback_type_len + feedback_cid_len + feedback_base_hdr_len - 1;
	}
	else if(protect_with_crc != ROHC_FEEDBACK_WITH_NO_CRC)
	{
		assert(0);
		goto error;
	}

	/* allocate memory for the feedback packet */
	feedback_packet = (uint8_t *) malloc(feedback->size);
	if(feedback_packet == NULL)
	{
		goto error;
	}

	/* duplicate the feedback packet */
	memcpy(feedback_packet, feedback->data, feedback->size);

	/* compute the CRC and store it in the feedback packet if specified */
	if(protect_with_crc != ROHC_FEEDBACK_WITH_NO_CRC)
	{
		uint8_t crc = CRC_INIT_8;

		if(protect_with_crc == ROHC_FEEDBACK_WITH_CRC_BASE_TCP)
		{
			uint8_t extra_hdr[2];
			size_t extra_hdr_len;
			if(feedback->size < 8)
			{
				extra_hdr[0] = 0xf0 | (feedback->size & 0x07);
				extra_hdr_len = 1;
			}
			else
			{
				extra_hdr[0] = 0xf0;
				extra_hdr[1] = feedback->size;
				extra_hdr_len = 2;
			}
			crc = crc_calculate(ROHC_CRC_TYPE_8, extra_hdr, extra_hdr_len, crc, crc_table);
#ifdef ROHC_FEEDBACK_DEBUG
			printf("TCP workaround: add %zu-byte extra header to CRC feedback\n",
			       extra_hdr_len);
#endif
		}

		crc = crc_calculate(ROHC_CRC_TYPE_8, feedback_packet, feedback->size,
		                    crc, crc_table);
		feedback_packet[crc_pos] = crc;
#ifdef ROHC_FEEDBACK_DEBUG
		printf("CRC-8 on %d-byte feedback = 0x%02x\n", feedback->size, crc);
#endif
	}

	*final_size = feedback->size;
	feedback->size = 0;

	return feedback_packet;

error:
	feedback->size = 0;
	return NULL;
}

