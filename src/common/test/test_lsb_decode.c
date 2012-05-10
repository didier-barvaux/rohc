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
 * @file    test_lsb_decode.c
 * @brief   Test Least Significant Bits (LSB) encoding/decoding at wraparound
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "wlsb.h"
#include "lsb.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>


/**
 * @brief Test LSB encoding/decoding at wraparound
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	struct c_wlsb *wlsb; /* the W-LSB encoding context */
	struct d_lsb_decode lsb; /* the LSB decoding context */

	const short p = 3; /* the shift parameter to run test with */

	uint16_t value16; /* the value to encode */
	uint16_t value16_encoded; /* the encoded value to decode */
	uint16_t value16_decoded; /* the decoded value */

	bool be_verbose; /* whether to run in verbose mode or not */
	int is_failure = 1; /* test fails by default */

	uint32_t i;
	int ret;

	/* do we run in verbose mode ? */
	if(argc == 1)
	{
		/* no argument, run in silent mode */
		be_verbose = false;
	}
	else if(argc == 2 && strcmp(argv[1], "verbose") == 0)
	{
		/* run in verbose mode */
		be_verbose = true;
	}
	else
	{
		/* invalid usage */
		printf("test the Least Significant Bits (LSB) encoding/decoding at wraparound\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* start encoding with value 0 */
	value16 = 0;

	/* create the W-LSB encoding context */
	wlsb = c_create_wlsb(16, C_WINDOW_WIDTH, p);
	if(wlsb == NULL)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding\n");
		goto error;
	}

	/* init the LSB decoding context */
	d_lsb_init(&lsb, value16, p);

	/* initialize the W-LSB encoding context */
	for(i = 1; i < 3; i++)
	{
		/* update encoding context */
		c_add_wlsb(wlsb, value16, value16);

		/* transmit all bits without encoding */
		value16_encoded = value16;
		value16_decoded = value16_encoded;

		/* update decoding context */
		d_lsb_update(&lsb, value16_decoded);

		/* next value to encode/decode */
		value16 = i % 0xffff;
	}

	/* encode then decode 16-bit values from ranges [3, 0xffff] and [0, 1] */
	for(i = 3; i <= 0x10001; i++)
	{
		size_t required_bits;
		uint16_t required_bits_mask;

		/* encode */
		if(be_verbose)
		{
			printf("encode value 0x%04x ...\n", value16);
		}
		ret = c_get_k_wlsb(wlsb, value16, &required_bits);
		if(ret != 1)
		{
			fprintf(stderr, "failed to determine how many bits are required "
			        "to be sent\n");
			goto destroy_wlsb;
		}
		assert(required_bits <= 16);
		if(required_bits == 16)
		{
			required_bits_mask = 0xffff;
		}
		else
		{
			required_bits_mask = (1 << required_bits) - 1;
		}
		value16_encoded = value16 & required_bits_mask;
		if(be_verbose)
		{
			printf("encoded on %zd bits: 0x%04x\n", required_bits, value16_encoded);
		}

		/* update encoding context */
		c_add_wlsb(wlsb, value16, value16);

		/* decode */
		if(be_verbose)
		{
			printf("decode %zd-bit value 0x%04x ...\n", required_bits, value16_encoded);
		}
		ret = d_lsb_decode16(&lsb, value16_encoded, required_bits,
		                     &value16_decoded);
		if(ret != 1)
		{
			fprintf(stderr, "failed to decode 16-bit value\n");
			goto destroy_wlsb;
		}
		if(be_verbose)
		{
			printf("decoded: 0x%04x\n", value16_decoded);
		}

		/* update decoding context */
		d_lsb_update(&lsb, value16_decoded);

		/* check test result */
		if(value16 != value16_decoded)
		{
			fprintf(stderr, "original and decoded values do not match\n");
			goto destroy_wlsb;
		}

		/* next value to encode/decode */
		value16 = i & 0xffff;
	}

	/* test succeeds */
	is_failure = 0;

destroy_wlsb:
	c_destroy_wlsb(wlsb);
error:
	return is_failure;
}

