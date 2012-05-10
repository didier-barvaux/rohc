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

#include "rohc_traces.h"
#include "cid.h"
#include "sdvl.h"

#include <stdint.h>
#include <assert.h>


/*
 * Prototypes of private functions
 */

static unsigned char c_add_cid(const int cid);


/*
 * Definitions of functions that may used by other ROHC modules
 */

/**
 * @brief Build the CID part of the ROHC packets.
 *
 * @param cid_type       The type of CID in use for the compression context:
 *                       ROHC_SMALL_CID or ROHC_LARGE_CID
 * @param cid            The value of the CID for the compression context
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param first_position OUT: The position of the first byte to be completed
 *                       by other functions
 * @return               The position in the rohc-packet-under-build buffer
 */
int code_cid_values(const rohc_cid_type_t cid_type,
                    const int cid,
                    unsigned char *const dest,
                    const int dest_size,
                    int *const first_position)
{
	int counter = 0;

	/* small CID */
	if(cid_type == ROHC_SMALL_CID)
	{
		if(cid > 0)
		{
			dest[counter] = c_add_cid(cid);
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
		size_t len;
		int ret;
		size_t i;

		*first_position = 0;
		counter++;

		/* determine the size of the SDVL-encoded large CID */
		len = c_bytesSdvl(cid, 0 /* length detection */);
		assert(len > 0 && len <= 5);
		if(len <= 0 || len > 4)
		{
			rohc_debugf(0, "failed to determine the number of bits required to "
			            "SDVL-encode the large CID %d\n", cid);
			/* TODO: should handle the error */
		}

		/* SDVL-encode the large CID */
		ret = c_encodeSdvl(&dest[counter], cid, 0 /* length detection */);
		if(ret != 1)
		{
			rohc_debugf(0, "failed to SDVL-encode the large CID %d\n", cid);
			/* TODO: should handle the error */
		}

		/* print the SDVL-encoded large CID */
		rohc_debugf(3, "SDVL-encoded large CID = ");
		for(i = 0; i < len; i++)
		{
			rohc_debugf_(3, "0x%02x ", dest[counter + i]);
		}
		rohc_debugf_(3, "\n");

		counter += len;
	}

	return counter;
}


/*
 * Definitions of private functions
 */


/**
 * @brief Set an add-CID value.
 *
 * Add-CID is needed when using small CIDs.
 *
 * @param cid The small CID to set
 * @return    The add-CID byte
 */
static unsigned char c_add_cid(const int cid)
{
	const uint8_t add_cid_type = 0xe0;

	return (add_cid_type | (cid & 0x0f));
}

