/**
 * @file feedback.c
 * @brief ROHC feedback routines.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#include "feedback.h"


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
 */
void f_feedback2(int acktype, int mode, int sn, struct d_feedback *feedback)
{
	unsigned char tkn = sn & 0xff;

	feedback->type = 2; /* set type for add_option */
	feedback->size = 2; /* size of FEEDBACK-2 header */
	feedback->data[0] = ((acktype & 0x3) << 6) | ((mode & 0x3) << 4);

	if(sn < 255) /* 12-bit SN */
	{
		feedback->data[0] |= (sn & 0xf00) >> 8;
		feedback->data[1] = sn & 0xff;
	}
	else /* 20-bit SN */
	{
		feedback->data[0] |= (sn & 0xf0000) >> 16;
		feedback->data[1] = sn & 0xff00 >> 8;
		if(!f_add_option(feedback, OPT_TYPE_SN, &tkn))
			rohc_debugf(0, "failed to add option to the feedback packet\n");
	}
}


/**
 * @brief Add an option data to the FEEDBACK-2 packet.
 *
 * @param feedback The feedback packet to which the option must be added
 * @param opt_type The type of option to add
 * @param data     The option data
 * @return         Whether the option is successfully added or not
 */
int f_add_option(struct d_feedback *feedback,
                  int opt_type, unsigned char *data)
{
	int result = 0;

	if(feedback->type == 2)
	{
		feedback->data[feedback->size] = opt_type & 0xf;
		feedback->data[feedback->size] <<= 4;
		if(data != NULL)
			feedback->data[feedback->size] |= 1;
		feedback->size++;

		if(opt_type == OPT_TYPE_CRC || data)
		{
			if(opt_type == OPT_TYPE_CRC)
				feedback->data[feedback->size] = 0;
			else
				feedback->data[feedback->size] = data[0];
			feedback->size++;
		}

		result = 1;
	}

	return result;
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
	unsigned char *acid;
	int largecidsize, i;

	if(largecidUsed)
	{
		/* large CIDs are used */
		largecidsize = c_bytesSdvl(cid);

		/* check if the feedback packet can contain a large CID */
		if(feedback->size + largecidsize > 30)
		{
			rohc_debugf(0, "feedback packet is too small for large CID\n");
			return 0;
		}

		/* move feedback data to make space for the large CID */
		for(i = feedback->size - 1; i >= 0; i--)
			feedback->data[i + largecidsize] = feedback->data[i];

		/* allocate memory for the large CID */
		acid = (unsigned char *) malloc(largecidsize);
		if(acid == NULL)
		{
			feedback->size = 0;
			return 0;
		}

		if(!c_encodeSdvl(acid, cid))
		{
			rohc_debugf(0, "this should never happen!\n");
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
		/* move feedback data to make space for the small CID */
		for(i = feedback->size - 1; i >= 0; i--)
			feedback->data[i + 1] = feedback->data[i];

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
 * @param final_size   OUT: The final size of the feedback packet
 * @return             The feedback packet if successful, NULL otherwise
 */
unsigned char * f_wrap_feedback(struct d_feedback *feedback,
                                int cid, int largecidUsed,
                                int with_crc,
                                int *final_size)
{
	unsigned char *feedback_packet;
	unsigned int crc;

	/* append the CID to the feedback packet */
	if(!f_append_cid(feedback, cid, largecidUsed))
		return NULL;

	/* add the CRC option if specified */
	if(with_crc)
	{
		if(!f_add_option(feedback, OPT_TYPE_CRC, (unsigned char *) 1))
			rohc_debugf(0, "failed to add option to the feedback packet\n");
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
		crc = crc_calculate(CRC_TYPE_8, feedback_packet, feedback->size);
		feedback_packet[feedback->size - 1] = (unsigned char) (crc & 0xff);
	}

	*final_size = feedback->size;
	feedback->size = 0;
	
	return feedback_packet;
}

