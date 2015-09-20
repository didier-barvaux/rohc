/*
 * Copyright 2012,2013 Didier Barvaux
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
 * @file    test_lsb_decode_packet_loss.c
 * @brief   Test the robustness of LSB encoding/decoding against packet loss
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "schemes/comp_wlsb.h"
#include "schemes/decomp_wlsb.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>


/** The width of the W-LSB sliding window */
#define ROHC_WLSB_WINDOW_WIDTH  4U


/** Print trace on stdout only in verbose mode */
#define trace(is_verbose, format, ...) \
	do { \
		if(is_verbose) { \
			printf(format, ##__VA_ARGS__); \
		} \
	} while(0)


static bool run_test8_with_shift_param(bool be_verbose,
                                       const short p,
                                       const size_t win_size,
                                       const size_t loss_nr);
static bool run_test16_with_shift_param(bool be_verbose,
                                        const short p,
                                        const size_t win_size,
                                        const size_t loss_nr);
static bool run_test32_with_shift_param(bool be_verbose,
                                        const short p,
                                        const size_t win_size,
                                        const size_t loss_nr);


/**
 * @brief Test the robustness of LSB encoding/decoding against packet loss
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	/* the shift parameters to run test with */
	const size_t p_nums = 4;
	const short p_params[] = {
		ROHC_LSB_SHIFT_IP_ID,
		ROHC_LSB_SHIFT_RTP_TS,
		ROHC_LSB_SHIFT_RTP_SN,
		ROHC_LSB_SHIFT_SN
	};
	size_t p_index;

	bool verbose; /* whether to run in verbose mode or not */
	bool extraverbose; /* whether to run in extra verbose mode or not */
	int is_failure = 1; /* test fails by default */

	const size_t win_size = ROHC_WLSB_WINDOW_WIDTH;
	assert(win_size > 0);
	const size_t loss_nr = win_size - 1;

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
		printf("test the robustness of LSB encoding/decoding against packet loss\n");
		printf("usage: %s [verbose [verbose]]\n", argv[0]);
		goto error;
	}

	/* run the test with different shift values */
	for(p_index = 0; p_index < p_nums; p_index++)
	{
		/* 8-bit field */
		trace(verbose, "run test with 8-bit field, shift parameter %d, window "
		      "width %zu, and %zu lost values\n", p_params[p_index], win_size,
		      loss_nr);
		if(!run_test8_with_shift_param(extraverbose, p_params[p_index],
		                               win_size, loss_nr))
		{
			fprintf(stderr, "test with 8-bit field and shift parameter %d "
			        "failed\n", p_params[p_index]);
			goto error;
		}
		trace(extraverbose, "\n");

		/* 16-bit field */
		trace(verbose, "run test with 16-bit field, shift parameter %d, windows "
		      "width %zu, and %zu lost values\n", p_params[p_index], win_size,
		      loss_nr);
		if(!run_test16_with_shift_param(extraverbose, p_params[p_index],
		                                win_size, loss_nr))
		{
			fprintf(stderr, "test with 16-bit field and shift parameter %d "
			        "failed\n", p_params[p_index]);
			goto error;
		}
		trace(extraverbose, "\n");

		/* 32-bit field */
		trace(verbose, "run test with 32-bit field, shift parameter %d, windows "
		      "width %zu, and %zu lost values\n", p_params[p_index], win_size,
		      loss_nr);
		if(!run_test32_with_shift_param(extraverbose, p_params[p_index],
		                                win_size, loss_nr))
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
 * @param win_size    The width of the W-LSB window
 * @param loss_nr     The number of values to lose
 * @return            true if test succeeds, false otherwise
 */
static bool run_test8_with_shift_param(bool be_verbose,
                                       const short p,
                                       const size_t win_size,
                                       const size_t loss_nr)
{
	struct c_wlsb *wlsb; /* the W-LSB encoding context */
	struct rohc_lsb_decode *lsb; /* the LSB decoding context */

	uint8_t value8; /* the value to encode */
	uint8_t value8_encoded; /* the encoded value to decode */
	uint8_t value8_decoded; /* the decoded value */

	int is_success = false; /* test fails by default */

	uint32_t i;

	assert(win_size > 0);

	/* create the W-LSB encoding context */
	wlsb = c_create_wlsb(8, win_size, p);
	if(wlsb == NULL)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding context\n");
		goto error;
	}

	/* init the LSB decoding context with value 0 */
	value8 = 0;
	trace(be_verbose, "\tinitialize with 8 bits of value 0x%02x ...\n", value8);
	lsb = rohc_lsb_new(8);
	if(lsb == NULL)
	{
		fprintf(stderr, "no memory to allocate LSB decoding context\n");
		goto destroy_wlsb;
	}
	rohc_lsb_set_ref(lsb, value8, false);

	/* initialize the W-LSB encoding context */
	for(i = 1; i < 3; i++)
	{
		/* value to encode/decode */
		value8 = i % 0xffff;

		trace(be_verbose, "\tinitialize with 8 bits of value 0x%02x ...\n", value8);

		/* update encoding context */
		c_add_wlsb(wlsb, value8, value8);

		/* transmit all bits without encoding */
		value8_encoded = value8;
		value8_decoded = value8_encoded;

		/* update decoding context */
		rohc_lsb_set_ref(lsb, value8_decoded, false);
	}

	/* 1/ encode then decode 8-bit values from range [3, win_size]
	 * 2/ encode then drop 8-bit values from range
	 *    [win_size + 1, win_size + loss_nr]
	 * 3/ encode then decode 8-bit values from range
	 *    [win_size + loss_nr + 1, win_size + loss_nr + 10]
	 */
	for(i = 3; i <= ((uint32_t) (win_size + loss_nr + 10)); i++)
	{
		size_t required_bits;
		uint8_t required_bits_mask;
		bool lsb_decode_ok;

		/* value to encode/decode */
		value8 = i % (((uint32_t) 0xff) + 1);

		/* encode */
		trace(be_verbose, "\tencode value 0x%02x ...\n", value8);
		required_bits = wlsb_get_k_8bits(wlsb, value8);
		assert(required_bits <= 8);
		if(required_bits == 8)
		{
			required_bits_mask = 0xff;
		}
		else
		{
			required_bits_mask = (1 << required_bits) - 1;
		}
		value8_encoded = value8 & required_bits_mask;
		trace(be_verbose, "\t\tencoded on %zu bits: 0x%02x\n", required_bits,
		      value8_encoded);

		/* update encoding context */
		c_add_wlsb(wlsb, value8, value8);

		/* do we lose that value? */
		if(i >= (win_size + 1) && i <= (win_size + loss_nr))
		{
			/* value is lost, so do not decode it */
			trace(be_verbose, "\t\tlose %zu-bit value 0x%02x\n", required_bits,
			      value8_encoded);
		}
		else
		{
			uint32_t decoded32;

			/* value is not lost, so decode it */
			trace(be_verbose, "\t\tdecode %zu-bit value 0x%02x ...\n", required_bits,
			      value8_encoded);
			lsb_decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, value8_encoded,
			                                required_bits, p, &decoded32);
			if(!lsb_decode_ok)
			{
				fprintf(stderr, "failed to decode %zu-bit value\n", required_bits);
				goto destroy_lsb;
			}
			assert(decoded32 <= 0xff);
			value8_decoded = decoded32;
			trace(be_verbose, "\t\tdecoded: 0x%02x\n", value8_decoded);

			/* update decoding context */
			rohc_lsb_set_ref(lsb, value8_decoded, false);

			/* check test result */
			if(value8 != value8_decoded)
			{
				fprintf(stderr, "original and decoded values do not match while "
				        "testing value 0x%02x with shift parameter %d\n", value8, p);
				goto destroy_lsb;
			}
		}
	}

	/* test succeeds */
	trace(be_verbose, "\ttest with shift parameter %d is successful\n", p);
	is_success = true;

destroy_lsb:
	rohc_lsb_free(lsb);
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
 * @param win_size    The width of the W-LSB window
 * @param loss_nr     The number of values to lose
 * @return            true if test succeeds, false otherwise
 */
static bool run_test16_with_shift_param(bool be_verbose,
                                        const short p,
                                        const size_t win_size,
                                        const size_t loss_nr)
{
	struct c_wlsb *wlsb; /* the W-LSB encoding context */
	struct rohc_lsb_decode *lsb; /* the LSB decoding context */

	uint16_t value16; /* the value to encode */
	uint16_t value16_encoded; /* the encoded value to decode */
	uint16_t value16_decoded; /* the decoded value */

	int is_success = false; /* test fails by default */

	uint32_t i;

	assert(win_size > 0);

	/* create the W-LSB encoding context */
	wlsb = c_create_wlsb(16, win_size, p);
	if(wlsb == NULL)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding context\n");
		goto error;
	}

	/* init the LSB decoding context with value 0 */
	value16 = 0;
	trace(be_verbose, "\tinitialize with 16 bits of value 0x%04x ...\n", value16);
	lsb = rohc_lsb_new(16);
	if(lsb == NULL)
	{
		fprintf(stderr, "no memory to allocate LSB decoding context\n");
		goto destroy_wlsb;
	}
	rohc_lsb_set_ref(lsb, value16, false);

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
		rohc_lsb_set_ref(lsb, value16_decoded, false);
	}

	/* 1/ encode then decode 16-bit values from range [3, win_size]
	 * 2/ encode then drop 16-bit values from range
	 *    [win_size + 1, win_size + loss_nr]
	 * 3/ encode then decode 16-bit values from range
	 *    [win_size + loss_nr + 1, win_size + loss_nr + 10]
	 */
	for(i = 3; i <= ((uint32_t) (win_size + loss_nr + 10)); i++)
	{
		size_t required_bits;
		uint16_t required_bits_mask;
		bool lsb_decode_ok;

		/* value to encode/decode */
		value16 = i % (((uint32_t) 0xffff) + 1);

		/* encode */
		trace(be_verbose, "\tencode value 0x%04x ...\n", value16);
		required_bits = wlsb_get_k_16bits(wlsb, value16);
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
		trace(be_verbose, "\t\tencoded on %zu bits: 0x%04x\n", required_bits,
		      value16_encoded);

		/* update encoding context */
		c_add_wlsb(wlsb, value16, value16);

		/* do we lose that value? */
		if(i >= (win_size + 1) && i <= (win_size + loss_nr))
		{
			/* value is lost, so do not decode it */
			trace(be_verbose, "\t\tlose %zu-bit value 0x%04x\n", required_bits,
			      value16_encoded);
		}
		else
		{
			uint32_t decoded32;

			/* value is not lost, so decode it */
			trace(be_verbose, "\t\tdecode %zu-bit value 0x%04x ...\n", required_bits,
			      value16_encoded);
			lsb_decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, value16_encoded,
			                                required_bits, p, &decoded32);
			if(!lsb_decode_ok)
			{
				fprintf(stderr, "failed to decode %zu-bit value\n", required_bits);
				goto destroy_lsb;
			}
			assert(decoded32 <= 0xffff);
			value16_decoded = decoded32;
			trace(be_verbose, "\t\tdecoded: 0x%04x\n", value16_decoded);

			/* update decoding context */
			rohc_lsb_set_ref(lsb, value16_decoded, false);

			/* check test result */
			if(value16 != value16_decoded)
			{
				fprintf(stderr, "original and decoded values do not match while "
				        "testing value 0x%04x with shift parameter %d\n", value16, p);
				goto destroy_lsb;
			}
		}
	}

	/* test succeeds */
	trace(be_verbose, "\ttest with shift parameter %d is successful\n", p);
	is_success = true;

destroy_lsb:
	rohc_lsb_free(lsb);
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
 * @param win_size    The width of the W-LSB window
 * @param loss_nr     The number of values to lose
 * @return            true if test succeeds, false otherwise
 */
static bool run_test32_with_shift_param(bool be_verbose,
                                        const short p,
                                        const size_t win_size,
                                        const size_t loss_nr)
{
	struct c_wlsb *wlsb; /* the W-LSB encoding context */
	struct rohc_lsb_decode *lsb; /* the LSB decoding context */

	uint32_t value32; /* the value to encode */
	uint32_t value32_encoded; /* the encoded value to decode */
	uint32_t value32_decoded; /* the decoded value */

	int is_success = false; /* test fails by default */

	uint64_t i;

	assert(win_size > 0);

	/* create the W-LSB encoding context */
	wlsb = c_create_wlsb(32, ROHC_WLSB_WINDOW_WIDTH, p);
	if(wlsb == NULL)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding context\n");
		goto error;
	}

	/* init the LSB decoding context with value 0 */
	value32 = 0;
	trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n", value32);
	lsb = rohc_lsb_new(32);
	if(lsb == NULL)
	{
		fprintf(stderr, "no memory to allocate LSB decoding context\n");
		goto destroy_wlsb;
	}
	rohc_lsb_set_ref(lsb, value32, false);

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
		rohc_lsb_set_ref(lsb, value32_decoded, false);
	}

	/* 1/ encode then decode 16-bit values from range [3, win_size]
	 * 2/ encode then drop 16-bit values from range
	 *    [win_size + 1, win_size + loss_nr]
	 * 3/ encode then decode 16-bit values from range
	 *    [win_size + loss_nr + 1, win_size + loss_nr + 10]
	 */
	for(i = 3; i <= ((uint32_t) (win_size + loss_nr + 10)); i++)
	{
		size_t required_bits;
		uint32_t required_bits_mask;
		bool lsb_decode_ok;

		/* value to encode/decode */
		value32 = i % (((uint64_t) 0xffffffff) + 1);

		/* encode */
		trace(be_verbose, "\tencode value 0x%08x ...\n", value32);
		required_bits = wlsb_get_k_32bits(wlsb, value32);
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
		trace(be_verbose, "\t\tencoded on %zu bits: 0x%08x\n", required_bits,
		      value32_encoded);

		/* update encoding context */
		c_add_wlsb(wlsb, value32, value32);

		/* do we lose that value? */
		if(i >= (win_size + 1) && i <= (win_size + loss_nr))
		{
			/* value is lost, so do not decode it */
			trace(be_verbose, "\t\tlose %zu-bit value 0x%04x\n", required_bits,
			      value32_encoded);
		}
		else
		{
			/* decode */
			trace(be_verbose, "\t\tdecode %zu-bit value 0x%08x ...\n", required_bits,
			      value32_encoded);
			lsb_decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, value32_encoded,
			                                required_bits, p, &value32_decoded);
			if(!lsb_decode_ok)
			{
				fprintf(stderr, "failed to decode %zu-bit value\n", required_bits);
				goto destroy_lsb;
			}
			trace(be_verbose, "\t\tdecoded: 0x%08x\n", value32_decoded);

			/* update decoding context */
			rohc_lsb_set_ref(lsb, value32_decoded, false);

			/* check test result */
			if(value32 != value32_decoded)
			{
				fprintf(stderr, "original and decoded values do not match while "
				        "testing value 0x%08x with shift parameter %d\n", value32, p);
				goto destroy_lsb;
			}
		}
	}

	/* test succeeds */
	trace(be_verbose, "\ttest with shift parameter %d is successful\n", p);
	is_success = true;

destroy_lsb:
	rohc_lsb_free(lsb);
destroy_wlsb:
	c_destroy_wlsb(wlsb);
error:
	return is_success;
}

