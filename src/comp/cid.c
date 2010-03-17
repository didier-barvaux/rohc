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
 * @file cid.c
 * @brief Context ID (CID) routines.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "cid.h"
#include "rohc_traces.h"


/**
 * @brief Set an add-CID value.
 *
 * Add-CID is needed when using small CIDs.
 *
 * @param cid The small CID to set
 * @return    The add-CID byte
 */
unsigned char c_add_cid(int cid)
{
	unsigned char ret_value = 0xe0;
	ret_value |= (cid & 0x0f);
	return ret_value;
}


/**
 * @brief Build the CID part of the ROHC packets.
 *
 * @param context        The compression context
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param first_position OUT: The position of the first byte to be completed
 *                       by other functions
 * @return               The position in the rohc-packet-under-build buffer
 */
int code_cid_values(struct c_context *context,
                    unsigned char *dest,
                    int dest_size,
                    int *first_position)
{
	int counter = 0;

	/* small CID */
	if(context->compressor->medium.cid_type == SMALL_CID)
	{
		if(context->cid > 0)
		{
			dest[counter] = c_add_cid(context->cid);
			rohc_debugf(3, "add-CID = 0x%02x\n", dest[counter]);

			*first_position = 1;
			counter = 2;
		}
		else
		{
			rohc_debugf(3, "CID = 0 => no add-CID\n");
			*first_position = 0;
			counter = 1;
		}
	}
	else /* large CID */
	{
		int len, i;

		*first_position = 0;
		counter++;
	
		c_encodeSdvl(&dest[counter], context->cid, -1);
		len = c_bytesSdvl(context->cid, -1);
		
		rohc_debugf(3, "SDVL-encoded large CID = ");
		for(i = 0; i < len; i++)
			rohc_debugf_(3, "0x%02x ", dest[counter + i]);
		rohc_debugf_(3, "\n");
		
		counter += len;
	}

	return counter;
}

