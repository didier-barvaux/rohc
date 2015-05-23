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
#ifndef __KERNEL__
#	include <string.h>
#endif
#include <assert.h>


/*
 * Prototypes of private functions.
 */

static bool f_append_cid(struct d_feedback *const feedback,
                         const uint16_t cid,
                         const rohc_cid_type_t cid_type)
	__attribute__((warn_unused_result, nonnull(1)));


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
 * @param ack_type    The type of acknowledgement:
 *                      \li \ref ROHC_ACK_TYPE_ACK,
 *                      \li \ref ROHC_ACK_TYPE_NACK,
 *                      \li \ref ROHC_ACK_TYPE_STATIC_NACK
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
bool f_feedback2(const rohc_ack_type_t ack_type,
                 const rohc_mode_t mode,
                 const uint32_t sn_bits,
                 const size_t sn_bits_nr,
                 struct d_feedback *const feedback)
{
	bool is_ok;

	feedback->type = 2; /* set type for add_option */
	feedback->size = 2; /* size of FEEDBACK-2 header */
	feedback->data[0] = ((ack_type & 0x3) << 6) | ((mode & 0x3) << 4);
#ifdef ROHC_FEEDBACK_DEBUG
	printf("FEEDBACK-2: first 4 bits = 0x%02x (ACK type = %d, mode = %d)\n",
	       feedback->data[0], ack_type, mode);
#endif

	if(sn_bits_nr == 0) /* SN is not valid */
	{
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: SN-NOT-VALID\n");
#endif
		feedback->data[1] = 0;

		/* SN option */
		is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN_NOT_VALID, NULL, 0);
		if(!is_ok)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add option to the feedback packet\n");
#endif
			goto error;
		}
	}
	else if(sn_bits_nr <= 12) /* SN may be stored on 12 bits */
	{
		feedback->data[0] |= (sn_bits >> 8) & 0xf;
		feedback->data[1] = sn_bits & 0xff;
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: transmit SN = 0x%08x on 12 bits\n", sn_bits);
		printf("FEEDBACK-2: 4 bits of SN = 0x%x\n", feedback->data[0] & 0xf);
		printf("FEEDBACK-2: 8 bits of SN = 0x%02x\n", feedback->data[1] & 0xff);
#endif
	}
	else if(sn_bits_nr <= (12 + 8)) /* SN may be stored on 20 bits */
	{
		const uint8_t sn_opt = sn_bits & 0xff;

#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: transmit SN = 0x%08x on 20 bits (12 bits in base "
		       "header, 8 bits in SN option)\n", sn_bits);
#endif

		/* base header */
		feedback->data[0] |= (sn_bits >> 16) & 0xf;
		feedback->data[1] = (sn_bits >> 8) & 0xff;
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 4 bits of SN = 0x%x\n", feedback->data[0] & 0xf);
		printf("FEEDBACK-2: 8 bits of SN = 0x%02x\n", feedback->data[1] & 0xff);
#endif

		/* SN option */
		is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN, &sn_opt,
		                     sizeof(sn_opt));
		if(!is_ok)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add option to the feedback packet\n");
#endif
			goto error;
		}
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 8 bits of SN option = 0x%02x\n", sn_opt);
#endif
	}
	else if(sn_bits_nr <= (12 + 8 + 8)) /* SN may be stored on 28 bits */
	{
		const uint8_t sn_opt1 = (sn_bits >> 8) & 0xff;
		const uint8_t sn_opt2 = sn_bits & 0xff;

#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: transmit SN = 0x%08x on 28 bits (12 bits in base "
		       "header, 8 bits in SN option, then 8 bits in SN option)\n", sn_bits);
#endif

		/* base header */
		feedback->data[0] |= (sn_bits >> 24) & 0xf;
		feedback->data[1] = (sn_bits >> 16) & 0xff;
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 4 bits of SN = 0x%x\n", feedback->data[0] & 0xf);
		printf("FEEDBACK-2: 8 bits of SN = 0x%02x\n", feedback->data[1] & 0xff);
#endif

		/* first SN option */
		is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN, &sn_opt1,
		                     sizeof(sn_opt1));
		if(!is_ok)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add option to the feedback packet\n");
#endif
			goto error;
		}
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 8 bits of SN option = 0x%02x\n", sn_opt1);
#endif

		/* second SN option */
		is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN, &sn_opt2,
		                     sizeof(sn_opt2));
		if(!is_ok)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add option to the feedback packet\n");
#endif
			goto error;
		}
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 8 bits of SN option = 0x%02x\n", sn_opt2);
#endif
	}
	else /* SN may be stored on 12 + 8 + 8 + 8 = 36 bits */
	{
		const uint8_t sn_opt1 = (sn_bits >> 16) & 0xff;
		const uint8_t sn_opt2 = (sn_bits >> 8) & 0xff;
		const uint8_t sn_opt3 = sn_bits & 0xff;

#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: transmit SN = 0x%08x on 36 bits (12 bits in base "
		       "header, 8 bits in SN option, 8 bits in SN option, then 8 bits "
		       "in SN option)\n", sn_bits);
#endif

		/* base header */
		feedback->data[0] |= 0;
		feedback->data[1] = (sn_bits >> 24) & 0xff;
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 4 bits of SN = 0x%x\n", feedback->data[0] & 0xf);
		printf("FEEDBACK-2: 8 bits of SN = 0x%02x\n", feedback->data[1] & 0xff);
#endif

		/* first SN option */
		is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN, &sn_opt1,
		                     sizeof(sn_opt1));
		if(!is_ok)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add option to the feedback packet\n");
#endif
			goto error;
		}
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 8 bits of SN option = 0x%02x\n", sn_opt1);
#endif

		/* second SN option */
		is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN, &sn_opt2,
		                     sizeof(sn_opt2));
		if(!is_ok)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add option to the feedback packet\n");
#endif
			goto error;
		}
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 8 bits of SN option = 0x%02x\n", sn_opt2);
#endif

		/* third SN option */
		is_ok = f_add_option(feedback, ROHC_FEEDBACK_OPT_SN, &sn_opt3,
		                     sizeof(sn_opt3));
		if(!is_ok)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add option to the feedback packet\n");
#endif
			goto error;
		}
#ifdef ROHC_FEEDBACK_DEBUG
		printf("FEEDBACK-2: 8 bits of SN option = 0x%02x\n", sn_opt3);
#endif
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
                  const rohc_feedback_opt_t opt_type,
                  const unsigned char *const data,
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
 * @return             Whether the CID is successfully appended or not
 */
static bool f_append_cid(struct d_feedback *const feedback,
                         const uint16_t cid,
                         const rohc_cid_type_t cid_type)
{
	size_t i;

	if(cid_type == ROHC_LARGE_CID)
	{
		size_t largecidsize;

		/* large CIDs are used */
		assert(cid <= ROHC_LARGE_CID_MAX);

		/* determine the number of bits required for the SDVL-encoded large CID */
		largecidsize = sdvl_get_encoded_len(cid);
		assert(largecidsize > 0 && largecidsize <= 5);
		if(largecidsize <= 0 || largecidsize > 4)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to determine the number of bits required to "
			       "SDVL-encode the large CID %u\n", cid);
#endif
			return false;
		}

		/* check if the feedback packet can contain a SDVL-encoded large CID */
		if((feedback->size + largecidsize) > FEEDBACK_DATA_MAX_LEN)
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("feedback packet is too small for large CID\n");
#endif
			return false;
		}

#ifdef ROHC_FEEDBACK_DEBUG
		printf("add %zd bytes for large CID to feedback\n", largecidsize);
#endif

		/* move feedback data to make space for the SDVL-encoded large CID */
		assert(feedback->size >= 1);
		for(i = feedback->size; i > 0; i--)
		{
			feedback->data[i - 1 + largecidsize] = feedback->data[i - 1];
		}

		/* SDVL-encode the large CID */
		if(!sdvl_encode_full(feedback->data, 4U /* TODO */, &largecidsize, cid))
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to SDVL-encoded large CID %u, should never "
			       "happen!\n", cid);
#endif
			return false;
		}
		feedback->size += largecidsize;
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
		}
#ifdef ROHC_FEEDBACK_DEBUG
		else
		{
			printf("no need to prepend Add-CID byte to feedback\n");
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
	uint8_t crc;

	/* append the CID to the feedback packet */
	if(!f_append_cid(feedback, cid, cid_type))
	{
		feedback->size = 0;
		return NULL;
	}

	/* add the CRC option if specified */
	if(protect_with_crc)
	{
#ifdef ROHC_FEEDBACK_DEBUG
		printf("add CRC option to feedback\n");
#endif
		if(!f_add_option(feedback, ROHC_FEEDBACK_OPT_CRC, NULL, 0))
		{
#ifdef ROHC_FEEDBACK_DEBUG
			printf("failed to add CRC option to the feedback packet\n");
#endif
			feedback->size = 0;
			return NULL;
		}
	}

	/* allocate memory for the feedback packet */
	feedback_packet = (uint8_t *) malloc(feedback->size);
	if(feedback_packet == NULL)
	{
		feedback->size = 0;
		return NULL;
	}

	/* duplicate the feedback packet */
	memcpy(feedback_packet, feedback->data, feedback->size);

	/* compute the CRC and store it in the feedback packet if specified */
	if(protect_with_crc)
	{
		crc = crc_calculate(ROHC_CRC_TYPE_8, feedback_packet, feedback->size,
		                    CRC_INIT_8, crc_table);
		feedback_packet[feedback->size - 1] = crc & 0xff;
	}

	*final_size = feedback->size;
	feedback->size = 0;

	return feedback_packet;
}

