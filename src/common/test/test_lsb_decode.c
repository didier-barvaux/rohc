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


/** Print trace on stdout only in verbose mode */
#define trace(is_verbose, format, ...) \
	do { \
		if(is_verbose) { \
			printf(format, ##__VA_ARGS__); \
		} \
	} while(0)


static bool run_test16_with_shift_param(bool be_verbose, const short p);
static bool run_test32_with_shift_param(bool be_verbose, const short p);


/**
 * @brief Test LSB encoding/decoding at wraparound
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	/* the shift parameters to run test with */
	const size_t p_nums = 4;
	const short p_params[] = { -1, 0, 2, 3 };
	size_t p_index;

	bool verbose; /* whether to run in verbose mode or not */
	bool extraverbose; /* whether to run in extra verbose mode or not */
	int is_failure = 1; /* test fails by default */

	/* do we run in verbose mode ? */
	if(argc == 1)
	{
		/* no argument, run in silent mode */
		verbose = false;
		extraverbose = false;
	}
	else if((argc == 2 || argc == 3) && strcmp(argv[1], "verbose") == 0)
	{
		/* run in verbose mode */
		verbose = true;

		if(argc == 3 && strcmp(argv[2], "verbose") == 0)
		{
			/* run in extra verbose mode */
			extraverbose = true;
		}
		else
		{
			extraverbose = false;
		}
	}
	else
	{
		/* invalid usage */
		printf("test the Least Significant Bits (LSB) encoding/decoding at wraparound\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* run the test with different shift values */
	for(p_index = 0; p_index < p_nums; p_index++)
	{
		/* 16-bit field */
		trace(verbose, "run test with 16-bit field and shift parameter %d\n",
		      p_params[p_index]);
		if(!run_test16_with_shift_param(extraverbose, p_params[p_index]))
		{
			fprintf(stderr, "test with 16-bit field and shift parameter %d "
			        "failed\n", p_params[p_index]);
			goto error;
		}
		trace(extraverbose, "\n");

		/* 32-bit field */
		trace(verbose, "run test with 32-bit field and shift parameter %d\n",
		      p_params[p_index]);
		if(!run_test32_with_shift_param(extraverbose, p_params[p_index]))
		{
			fprintf(stderr, "test with 32-bit field and shift parameter %d "
			        "failed\n", p_params[p_index]);
			goto error;
		}
		trace(extraverbose, "\n");
	}

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Run the test with the given shift parameter
 *
 * @param be_verbose  Whether to print traces or not
 * @param p           The shift parameter to run test with
 * @return            true if test succeeds, false otherwise
 */
bool run_test16_with_shift_param(bool be_verbose, const short p)
{
	struct c_wlsb *wlsb; /* the W-LSB encoding context */
	struct d_lsb_decode lsb; /* the LSB decoding context */

	uint16_t value16; /* the value to encode */
	uint16_t value16_encoded; /* the encoded value to decode */
	uint16_t value16_decoded; /* the decoded value */

	int is_success = false; /* test fails by default */

	uint32_t i;
	int ret;

	/* create the W-LSB encoding context */
	wlsb = c_create_wlsb(16, C_WINDOW_WIDTH, p);
	if(wlsb == NULL)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding\n");
		goto error;
	}

	/* init the LSB decoding context with value 0 */
	value16 = 0;
	trace(be_verbose, "\tinitialize with 16 bits of value 0x%04x ...\n", value16);
	d_lsb_init(&lsb, value16, p);

	/* initialize the W-LSB encoding context */
	for(i = 1; i < 3; i++)
	{
		/* value to encode/decode */
		value16 = i % 0xffff;

		trace(be_verbose, "\tinitialize with 16 bits of value 0x%04x ...\n", value16);

		/* update encoding context */
		c_add_wlsb(wlsb, value16, value16);

		/* transmit all bits without encoding */
		value16_encoded = value16;
		value16_decoded = value16_encoded;

		/* update decoding context */
		d_lsb_update(&lsb, value16_decoded);
	}

	/* encode then decode 16-bit values from ranges [3, 0xffff] and [0, 100] */
	for(i = 3; i <= (((uint32_t) 0xffff) + 1 + 100); i++)
	{
		size_t required_bits;
		uint16_t required_bits_mask;

		/* value to encode/decode */
		value16 = i % (((uint32_t) 0xffff) + 1);

		/* encode */
		trace(be_verbose, "\tencode value 0x%04x ...\n", value16);
		ret = wlsb_get_k_16bits(wlsb, value16, &required_bits);
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
		trace(be_verbose, "\t\tencoded on %zd bits: 0x%04x\n", required_bits,
		      value16_encoded);

		/* update encoding context */
		c_add_wlsb(wlsb, value16, value16);

		/* decode */
		trace(be_verbose, "\t\tdecode %zd-bit value 0x%04x ...\n", required_bits,
		      value16_encoded);
		ret = d_lsb_decode16(&lsb, value16_encoded, required_bits,
		                     &value16_decoded);
		if(ret != 1)
		{
			fprintf(stderr, "failed to decode %zd-bit value\n", required_bits);
			goto destroy_wlsb;
		}
		trace(be_verbose, "\t\tdecoded: 0x%04x\n", value16_decoded);

		/* update decoding context */
		d_lsb_update(&lsb, value16_decoded);

		/* check test result */
		if(value16 != value16_decoded)
		{
			fprintf(stderr, "original and decoded values do not match while "
			        "testing value 0x%04x with shift parameter %d\n", value16, p);
			goto destroy_wlsb;
		}
	}

	/* test succeeds */
	trace(be_verbose, "\ttest with shift parameter %d is successful\n", p);
	is_success = true;

destroy_wlsb:
	c_destroy_wlsb(wlsb);
error:
	return is_success;
}


/**
 * @brief Run the test with the given shift parameter
 *
 * @param be_verbose  Whether to print traces or not
 * @param p           The shift parameter to run test with
 * @return            true if test succeeds, false otherwise
 */
bool run_test32_with_shift_param(bool be_verbose, const short p)
{
	struct c_wlsb *wlsb; /* the W-LSB encoding context */
	struct d_lsb_decode lsb; /* the LSB decoding context */

	uint32_t value32; /* the value to encode */
	uint32_t value32_encoded; /* the encoded value to decode */
	uint32_t value32_decoded; /* the decoded value */

	int is_success = false; /* test fails by default */

	uint64_t i;
	int ret;

	/* create the W-LSB encoding context */
	wlsb = c_create_wlsb(16, C_WINDOW_WIDTH, p);
	if(wlsb == NULL)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding\n");
		goto error;
	}

	/* init the LSB decoding context with value 0 */
	value32 = 0;
	trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n", value32);
	d_lsb_init(&lsb, value32, p);

	/* initialize the W-LSB encoding context */
	for(i = 1; i < 3; i++)
	{
		/* value to encode/decode */
		value32 = i % 0xffffffff;

		trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n", value32);

		/* update encoding context */
		c_add_wlsb(wlsb, value32, value32);

		/* transmit all bits without encoding */
		value32_encoded = value32;
		value32_decoded = value32_encoded;

		/* update decoding context */
		d_lsb_update(&lsb, value32_decoded);
	}

	/* encode then decode 32-bit values from ranges [3, 100] */
	for(i = 3; i <= 100; i++)
	{
		size_t required_bits;
		uint32_t required_bits_mask;

		/* value to encode/decode */
		value32 = i % (((uint64_t) 0xffffffff) + 1);

		/* encode */
		trace(be_verbose, "\tencode value 0x%08x ...\n", value32);
		ret = wlsb_get_k_32bits(wlsb, value32, &required_bits);
		if(ret != 1)
		{
			fprintf(stderr, "failed to determine how many bits are required "
			        "to be sent\n");
			goto destroy_wlsb;
		}
		assert(required_bits <= 32);
		if(required_bits == 32)
		{
			required_bits_mask = 0xffffffff;
		}
		else
		{
			required_bits_mask = (1 << required_bits) - 1;
		}
		value32_encoded = value32 & required_bits_mask;
		trace(be_verbose, "\t\tencoded on %zd bits: 0x%08x\n", required_bits,
		      value32_encoded);

		/* update encoding context */
		c_add_wlsb(wlsb, value32, value32);

		/* decode */
		trace(be_verbose, "\t\tdecode %zd-bit value 0x%08x ...\n", required_bits,
		      value32_encoded);
		ret = d_lsb_decode32(&lsb, value32_encoded, required_bits,
		                     &value32_decoded);
		if(ret != 1)
		{
			fprintf(stderr, "failed to decode %zd-bit value\n", required_bits);
			goto destroy_wlsb;
		}
		trace(be_verbose, "\t\tdecoded: 0x%08x\n", value32_decoded);

		/* update decoding context */
		d_lsb_update(&lsb, value32_decoded);

		/* check test result */
		if(value32 != value32_decoded)
		{
			fprintf(stderr, "original and decoded values do not match while "
			        "testing value 0x%08x with shift parameter %d\n", value32, p);
			goto destroy_wlsb;
		}
	}

	/* destroy the W-LSB encoding context */
	c_destroy_wlsb(wlsb);

	/* create the W-LSB encoding context again */
	wlsb = c_create_wlsb(16, C_WINDOW_WIDTH, p);
	if(wlsb == NULL)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding\n");
		goto error;
	}

	/* init the LSB decoding context with value 0xffffffff - 100 - 3 */
	value32 = 0xffffffff - 100 - 3;
	trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n", value32);
	d_lsb_init(&lsb, value32, p);

	/* initialize the W-LSB encoding context */
	for(i = (0xffffffff - 100 - 3); i < (0xffffffff - 100); i++)
	{
		/* value to encode/decode */
		value32 = i % 0xffffffff;

		trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n", value32);

		/* update encoding context */
		c_add_wlsb(wlsb, value32, value32);

		/* transmit all bits without encoding */
		value32_encoded = value32;
		value32_decoded = value32_encoded;

		/* update decoding context */
		d_lsb_update(&lsb, value32_decoded);
	}

	/* encode then decode 32-bit values from ranges
	 * [0xffffffff-100, 0xffffffff] and [0, 100] */
	for(i = (0xffffffff - 100); i <= (((uint64_t) 0xffffffff) + 1 + 100); i++)
	{
		size_t required_bits;
		uint32_t required_bits_mask;

		/* value to encode/decode */
		value32 = i % (((uint64_t) 0xffffffff) + 1);

		/* encode */
		trace(be_verbose, "\tencode value 0x%08x ...\n", value32);
		ret = wlsb_get_k_32bits(wlsb, value32, &required_bits);
		if(ret != 1)
		{
			fprintf(stderr, "failed to determine how many bits are required "
			        "to be sent\n");
			goto destroy_wlsb;
		}
		assert(required_bits <= 32);
		if(required_bits == 32)
		{
			required_bits_mask = 0xffffffff;
		}
		else
		{
			required_bits_mask = (1 << required_bits) - 1;
		}
		value32_encoded = value32 & required_bits_mask;
		trace(be_verbose, "\t\tencoded on %zd bits: 0x%08x\n", required_bits,
		      value32_encoded);

		/* update encoding context */
		c_add_wlsb(wlsb, value32, value32);

		/* decode */
		trace(be_verbose, "\t\tdecode %zd-bit value 0x%08x ...\n", required_bits,
		      value32_encoded);
		ret = d_lsb_decode32(&lsb, value32_encoded, required_bits,
		                     &value32_decoded);
		if(ret != 1)
		{
			fprintf(stderr, "failed to decode %zd-bit value\n", required_bits);
			goto destroy_wlsb;
		}
		trace(be_verbose, "\t\tdecoded: 0x%08x\n", value32_decoded);

		/* update decoding context */
		d_lsb_update(&lsb, value32_decoded);

		/* check test result */
		if(value32 != value32_decoded)
		{
			fprintf(stderr, "original and decoded values do not match while "
			        "testing value 0x%08x with shift parameter %d\n", value32, p);
			goto destroy_wlsb;
		}
	}

	/* test succeeds */
	trace(be_verbose, "\ttest with shift parameter %d is successful\n", p);
	is_success = true;

destroy_wlsb:
	c_destroy_wlsb(wlsb);
error:
	return is_success;
}

