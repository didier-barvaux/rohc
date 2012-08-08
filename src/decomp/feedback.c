/*
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file feedback.c
 * @brief ROHC feedback routines.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "rohc.h"
#include "feedback.h"
#include "rohc_traces.h"
#include "rohc_debug.h"

#include <assert.h>


/*
 * Prototypes of private functions.
 */

int f_append_cid(struct d_feedback *feedback, int cid, int largecidUsed);


/**
 * @brief Build a FEEDBACK-1 packet.
 *
 * @param sn       The Sequence Number (SN) the feedback packet is
 *                 associated with
 * @param feedback The feedback packet to build
 * @return         Whether the build is successful or not
 */
int f_feedback1(int sn, struct d_feedback *feedback)
{
	feedback->type = 1; /* set type for add_option */
	feedback->size = 1;
	feedback->data[0] = (sn & 0xff);

	return 1;
}


/**
 * @brief Build a FEEDBACK-2 packet.
 *
 * @param acktype  The type of acknowledgement: ACK, NACK or S-NACK
 * @param mode     The mode in which ROHC operates: U_MODE, O_MODE or R_MODE
 * @param sn       The Sequence Number (SN) the feedback packet is
 *                 associated with
 * @param feedback The feedback packet to build
 * @return         ROHC_OK if the packet is successfully built,
 *                 ROHC_ERROR otherwise
 */
int f_feedback2(int acktype, int mode, uint32_t sn, struct d_feedback *feedback)
{
	uint32_t sn_nbo;

	/* handle 16-bit and 32-bit SN */
	if((sn & 0xffff) == sn)
	{
		sn_nbo = htons((uint16_t) sn);
	}
	else
	{
		sn_nbo = htonl(sn);
	}

	feedback->type = 2; /* set type for add_option */
	feedback->size = 2; /* size of FEEDBACK-2 header */
	feedback->data[0] = ((acktype & 0x3) << 6) | ((mode & 0x3) << 4);

	if(sn < (1 << 12)) /* SN may be stored on 12 bits */
	{
		rohc_debugf(3, "FEEDBACK-2: transmit SN = 0x%x on 12 bits\n", sn);
		feedback->data[0] |= (sn_nbo >> 8) & 0xf;
		feedback->data[1] = sn_nbo & 0xff;
	}
	else if(sn < (1 << 20)) /* SN may be stored on 20 bits */
	{
		const uint8_t sn_last_bits = sn_nbo & 0xff;
		int ret;

		rohc_debugf(3, "FEEDBACK-2: transmit SN = 0x%04x on 20 bits (12 bits "
		            "in base header, 8 bits in SN option)\n", sn);
		feedback->data[0] |= (sn_nbo >> 16) & 0xf;
		rohc_debugf(3, "FEEDBACK-2: 4 bits of SN = 0x%x\n", feedback->data[0] & 0xf);
		feedback->data[1] = (sn_nbo >> 8) & 0xff;
		rohc_debugf(3, "FEEDBACK-2: 8 bits of SN = 0x%02x\n", feedback->data[1] & 0xff);
		ret = f_add_option(feedback, OPT_TYPE_SN, &sn_last_bits,
		                   sizeof(sn_last_bits));
		if(ret != ROHC_OK)
		{
			rohc_debugf(0, "failed to add option to the feedback packet\n");
			goto error;
		}
		rohc_debugf(3, "FEEDBACK-2: 8 bits of SN = 0x%02x\n", sn_last_bits);
	}
	else /* SN cannot be stored on 20 bits */
	{
		/* should not happen */
		rohc_debugf(3, "FEEDBACK-2: SN 0x%04x cannot be stored on 20 bits\n", sn);
		assert(0);
		goto error;
	}

	return ROHC_OK;

error:
	return ROHC_ERROR;
}


/**
 * @brief Add an option data to the FEEDBACK-2 packet.
 *
 * @param feedback The feedback packet to which the option must be added
 * @param opt_type The type of option to add
 * @param data     The option data
 * @param data_len The length of option data (in bytes)
 * @return         ROHC_OK if the option is successfully added,
 *                 ROHC_ERROR otherwise
 */
int f_add_option(struct d_feedback *feedback,
                 const uint8_t opt_type,
                 const unsigned char *data,
                 const size_t data_len)
{
	/* options are reserved for FEEDBACK-2 */
	assert(feedback->type == 2);

	/* write option header: type and size */
	feedback->data[feedback->size] = opt_type & 0xf;
	feedback->data[feedback->size] <<= 4;
	if(opt_type == OPT_TYPE_CRC || data != NULL)
	{
		assert(data_len == 0 || data_len == 1);
		feedback->data[feedback->size] |= 1;
	}
	feedback->size++;

	if(opt_type == OPT_TYPE_CRC)
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
			return ROHC_ERROR;
		}
		feedback->data[feedback->size] = data[0];
		feedback->size++;
	}
	else
	{
		/* no data given */
		assert(data_len == 0);
	}

	return ROHC_OK;
}


/**
 * @brief Append the CID to the feedback packet.
 *
 * @param feedback     The feedback packet to which the CID must be appended
 * @param cid          The Context ID (CID) to append
 * @param largecidUsed Whether large CIDs are used or not
 * @return             Whether the CID is successfully appended or not
 */
int f_append_cid(struct d_feedback *feedback, int cid, int largecidUsed)
{
	size_t i;

	if(largecidUsed)
	{
		unsigned char *acid;
		size_t largecidsize;

		/* large CIDs are used */

		/* determine the number of bits required for the SDVL-encoded large CID */
		largecidsize = c_bytesSdvl(cid, 0 /* length detection */);
		assert(largecidsize > 0 && largecidsize <= 5);
		if(largecidsize <= 0 || largecidsize > 4)
		{
			rohc_debugf(0, "failed to determine the number of bits required to "
			            "SDVL-encode the large CID %d\n", cid);
			return 0;
		}

		/* check if the feedback packet can contain a SDVL-encoded large CID */
		if(feedback->size + largecidsize > 30)
		{
			rohc_debugf(0, "feedback packet is too small for large CID\n");
			return 0;
		}

		rohc_debugf(2, "add %zd bytes for large CID to feedback\n", largecidsize);

		/* move feedback data to make space for the SDVL-encoded large CID */
		assert(feedback->size >= 1);
		for(i = feedback->size; i > 0; i--)
		{
			feedback->data[i - 1 + largecidsize] = feedback->data[i - 1];
		}

		/* allocate memory for the large CID */
		acid = (unsigned char *) malloc(largecidsize);
		if(acid == NULL)
		{
			feedback->size = 0;
			return 0;
		}

		/* SDVL-encode the large CID */
		if(!c_encodeSdvl(acid, cid, 0 /* length detection */))
		{
			rohc_debugf(0, "failed to SDVL-encoded large CID %d: this should never "
			            "happen!\n", cid);
			zfree(acid);
			return 0;
		}

		/* copy the large CID to the feedback packet */
		memcpy(feedback->data, acid, largecidsize);
		feedback->size += largecidsize;

		/* free the large CID */
		zfree(acid);
	}
	else if(cid > 0 && cid < 16)
	{
		rohc_debugf(2, "add 1 byte for small CID to feedback\n");

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

	return 1;
}


/**
 * @brief Wrap the feedback packet and add a CRC option if specified.
 *
 * @param feedback     The feedback packet to which the CID must be appended
 * @param cid          The Context ID (CID) to append
 * @param largecidUsed Whether large CIDs are used or not
 * @param with_crc     Whether the CRC option must be added or not
 * @param crc_table    The pre-computed table for fast CRC computation
 * @param final_size   OUT: The final size of the feedback packet
 * @return             The feedback packet if successful, NULL otherwise
 */
unsigned char * f_wrap_feedback(struct d_feedback *feedback,
                                int cid, int largecidUsed,
                                int with_crc,
                                unsigned char *crc_table,
                                int *final_size)
{
	unsigned char *feedback_packet;
	unsigned int crc;
	int ret;

	/* append the CID to the feedback packet */
	if(!f_append_cid(feedback, cid, largecidUsed))
	{
		feedback->size = 0;
		return NULL;
	}

	/* add the CRC option if specified */
	if(with_crc)
	{
		rohc_debugf(2, "add CRC option to feedback\n");
		ret = f_add_option(feedback, OPT_TYPE_CRC, NULL, 0);
		if(ret != ROHC_OK)
		{
			rohc_debugf(0, "failed to add CRC option to the feedback packet\n");
			feedback->size = 0;
			return NULL;
		}
	}

	/* allocate memory for the feedback packet */
	feedback_packet = (unsigned char *) malloc(feedback->size);
	if(feedback_packet == NULL)
	{
		feedback->size = 0;
		return NULL;
	}

	/* duplicate the feedback packet */
	memcpy(feedback_packet, feedback->data, feedback->size);

	/* compute the CRC and store it in the feedback packet if specified */
	if(with_crc)
	{
		crc = crc_calculate(ROHC_CRC_TYPE_8, feedback_packet, feedback->size,
		                    CRC_INIT_8, crc_table);
		feedback_packet[feedback->size - 1] = (unsigned char) (crc & 0xff);
	}

	*final_size = feedback->size;
	feedback->size = 0;

	return feedback_packet;
}

