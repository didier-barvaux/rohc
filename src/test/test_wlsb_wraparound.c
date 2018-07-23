/*
 * Copyright 2012,2013,2014 Didier Barvaux
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
 * @file    test_lsb_decode_wraparound.c
 * @brief   Test Least Significant Bits (LSB) encoding/decoding at wraparound
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


static bool run_test8_with_shift_param(bool be_verbose, const short p);
static bool run_test16_with_shift_param(bool be_verbose, const short p);
static bool run_test32_with_shift_param(bool be_verbose, const short p);

static void init_wlsb_8(struct c_wlsb *const wlsb,
                        struct rohc_lsb_decode *const lsb,
                        const uint8_t value8)
	__attribute__((nonnull(1, 2)));
static bool test_wlsb_8(struct c_wlsb *const wlsb,
                        struct rohc_lsb_decode *const lsb,
                        const uint8_t value8,
                        const short p,
                        const bool be_verbose)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void init_wlsb_16(struct c_wlsb *const wlsb,
                         struct rohc_lsb_decode *const lsb,
                         const uint16_t value16)
	__attribute__((nonnull(1, 2)));
static bool test_wlsb_16(struct c_wlsb *const wlsb,
                         struct rohc_lsb_decode *const lsb,
                         const uint16_t value16,
                         const short p,
                         const bool be_verbose)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static void init_wlsb_32(struct c_wlsb *const wlsb,
                         struct rohc_lsb_decode *const lsb,
                         const uint32_t value32)
	__attribute__((nonnull(1, 2)));
static bool test_wlsb_32(struct c_wlsb *const wlsb,
                         struct rohc_lsb_decode *const lsb,
                         const uint32_t value32,
                         const short p,
                         const bool be_verbose)
	__attribute__((warn_unused_result, nonnull(1, 2)));


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
		printf("usage: %s [verbose [verbose]]\n", argv[0]);
		goto error;
	}

	/* run the test with different shift values */
	for(p_index = 0; p_index < p_nums; p_index++)
	{
		/* 8-bit field */
		trace(verbose, "run test with 8-bit field and shift parameter %d\n",
		      p_params[p_index]);
		if(!run_test8_with_shift_param(extraverbose, p_params[p_index]))
		{
			fprintf(stderr, "test with 8-bit field and shift parameter %d "
			        "failed\n", p_params[p_index]);
			goto error;
		}
		trace(extraverbose, "\n");

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
bool run_test8_with_shift_param(bool be_verbose, const short p)
{
	struct c_wlsb wlsb; /* the W-LSB encoding context */
	struct rohc_lsb_decode lsb; /* the LSB decoding context */

	uint8_t value8; /* the value to encode */

	int is_success = false; /* test fails by default */

	uint32_t i;
	bool is_ok;

	/* create the W-LSB encoding context */
	is_ok = wlsb_new(&wlsb, ROHC_WLSB_WINDOW_WIDTH);
	if(!is_ok)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding context\n");
		goto error;
	}

	/* init the LSB decoding context with value 0 */
	value8 = 0;
	trace(be_verbose, "\tinitialize with 8 bits of value 0x%02x ...\n", value8);
	rohc_lsb_init(&lsb, 8);
	rohc_lsb_set_ref(&lsb, value8, false);

	/* initialize the W-LSB encoding context */
	for(i = 1; i < 3; i++)
	{
		value8 = i % 0xffff;
		trace(be_verbose, "\tinitialize with 8 bits of value 0x%02x ...\n", value8);
		init_wlsb_8(&wlsb, &lsb, value8);
	}

	/* encode then decode 8-bit values from ranges [3, 0xff] and [0, 100] */
	for(i = 3; i <= (((uint32_t) 0xff) + 1 + 100); i++)
	{
		/* encode/decode value */
		value8 = i % (((uint32_t) 0xff) + 1);
		if(!test_wlsb_8(&wlsb, &lsb, value8, p, be_verbose))
		{
			goto destroy_wlsb;
		}
	}

	/* test succeeds */
	trace(be_verbose, "\ttest with shift parameter %d is successful\n", p);
	is_success = true;

destroy_wlsb:
	wlsb_free(&wlsb);
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
bool run_test16_with_shift_param(bool be_verbose, const short p)
{
	struct c_wlsb wlsb; /* the W-LSB encoding context */
	struct rohc_lsb_decode lsb; /* the LSB decoding context */

	uint16_t value16; /* the value to encode */

	int is_success = false; /* test fails by default */

	uint32_t i;
	bool is_ok;

	/* create the W-LSB encoding context */
	is_ok = wlsb_new(&wlsb, ROHC_WLSB_WINDOW_WIDTH);
	if(!is_ok)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding context\n");
		goto error;
	}

	/* init the LSB decoding context with value 0 */
	value16 = 0;
	trace(be_verbose, "\tinitialize with 16 bits of value 0x%04x ...\n", value16);
	rohc_lsb_init(&lsb, 16);
	rohc_lsb_set_ref(&lsb, value16, false);

	/* initialize the W-LSB encoding context */
	for(i = 1; i < 3; i++)
	{
		value16 = i % 0xffff;
		trace(be_verbose, "\tinitialize with 16 bits of value 0x%04x ...\n",
		      value16);
		init_wlsb_16(&wlsb, &lsb, value16);
	}

	/* encode then decode 16-bit values from ranges [3, 0xffff] and [0, 100] */
	for(i = 3; i <= (((uint32_t) 0xffff) + 1 + 100); i++)
	{
		/* encode/decode value */
		value16 = i % (((uint32_t) 0xffff) + 1);
		if(!test_wlsb_16(&wlsb, &lsb, value16, p, be_verbose))
		{
			goto destroy_wlsb;
		}
	}

	/* test succeeds */
	trace(be_verbose, "\ttest with shift parameter %d is successful\n", p);
	is_success = true;

destroy_wlsb:
	wlsb_free(&wlsb);
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
	struct c_wlsb wlsb; /* the W-LSB encoding context */
	struct rohc_lsb_decode lsb; /* the LSB decoding context */

	uint32_t value32; /* the value to encode */

	int is_success = false; /* test fails by default */

	uint64_t i;
	bool is_ok;

	/* create the W-LSB encoding context */
	is_ok = wlsb_new(&wlsb, ROHC_WLSB_WINDOW_WIDTH);
	if(!is_ok)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding context\n");
		goto error;
	}

	/* init the LSB decoding context with value 0 */
	value32 = 0;
	trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n", value32);
	rohc_lsb_init(&lsb, 32);
	rohc_lsb_set_ref(&lsb, value32, false);

	/* initialize the W-LSB encoding context */
	for(i = 1; i < 3; i++)
	{
		value32 = i % 0xffffffff;
		trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n",
		      value32);
		init_wlsb_32(&wlsb, &lsb, value32);
	}

	/* encode then decode 32-bit values from ranges [3, 100] */
	for(i = 3; i <= 100; i++)
	{
		/* encode/decode value */
		value32 = i % (((uint64_t) 0xffffffff) + 1);
		if(!test_wlsb_32(&wlsb, &lsb, value32, p, be_verbose))
		{
			goto destroy_wlsb;
		}
	}

	/* destroy the W-LSB encoding context */
	wlsb_free(&wlsb);

	/* create the W-LSB encoding context again */
	is_ok = wlsb_new(&wlsb, ROHC_WLSB_WINDOW_WIDTH);
	if(!is_ok)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding\n");
		goto error;
	}

	/* init the LSB decoding context with value 0xffffffff - 100 - 3 */
	value32 = 0xffffffff - 100 - 3;
	trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n", value32);
	rohc_lsb_init(&lsb, 32);
	rohc_lsb_set_ref(&lsb, value32, false);

	/* initialize the W-LSB encoding context */
	for(i = (0xffffffff - 100 - 3); i < (0xffffffff - 100); i++)
	{
		value32 = i % 0xffffffff;
		trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n",
		      value32);
		init_wlsb_32(&wlsb, &lsb, value32);
	}

	/* encode then decode 32-bit values from ranges
	 * [0xffffffff-100, 0xffffffff] and [0, 100] */
	for(i = (0xffffffff - 100); i <= (((uint64_t) 0xffffffff) + 1 + 100); i++)
	{
		/* encode/decode value */
		value32 = i % (((uint64_t) 0xffffffff) + 1);
		if(!test_wlsb_32(&wlsb, &lsb, value32, p, be_verbose))
		{
			goto destroy_wlsb;
		}
	}

	/* destroy the W-LSB encoding context */
	wlsb_free(&wlsb);

	/* create the W-LSB encoding context again */
	is_ok = wlsb_new(&wlsb, 64U);
	if(!is_ok)
	{
		fprintf(stderr, "no memory to allocate W-LSB encoding\n");
		goto error;
	}

	/* init the LSB decoding context with value 0xffffffff - 4500 - 1700 */
	value32 = 0xffffffff - 4500 - 1700;
	trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n",
	      value32);
	rohc_lsb_init(&lsb, 32);
	rohc_lsb_set_ref(&lsb, value32, false);

	/* initialize the W-LSB encoding context */
	for(i = (0xffffffff - 4500 - 1700); i < (0xffffffff - 1700); i += 1500)
	{
		value32 = i % 0xffffffff;
		trace(be_verbose, "\tinitialize with 32 bits of value 0x%08x ...\n",
		      value32);
		init_wlsb_32(&wlsb, &lsb, value32);
	}

	/* encode several values (+1500, last value is duplicated) */
	if(!test_wlsb_32(&wlsb, &lsb, 0xffffffff - 1700, p, be_verbose))
	{
		goto destroy_wlsb;
	}
	if(!test_wlsb_32(&wlsb, &lsb, 0xffffffff - 200, p, be_verbose))
	{
		goto destroy_wlsb;
	}
	if(!test_wlsb_32(&wlsb, &lsb, 1300, p, be_verbose))
	{
		goto destroy_wlsb;
	}
	if(!test_wlsb_32(&wlsb, &lsb, 2800, p, be_verbose))
	{
		goto destroy_wlsb;
	}
	if(!test_wlsb_32(&wlsb, &lsb, 2800, p, be_verbose))
	{
		goto destroy_wlsb;
	}

	/* test succeeds */
	trace(be_verbose, "\ttest with shift parameter %d is successful\n", p);
	is_success = true;

destroy_wlsb:
	wlsb_free(&wlsb);
error:
	return is_success;
}


/**
 * @brief Initialize W-LSB encoding with the given value
 *
 * @param wlsb    The W-LSB encoding context
 * @param lsb     The LSB decoding context
 * @param value8  The value to encode/decode
 */
static void init_wlsb_8(struct c_wlsb *const wlsb,
                        struct rohc_lsb_decode *const lsb,
                        const uint8_t value8)
{
	/* transmit all bits without W-LSB encoding, so update encoding and
	 * decoding contexts */
	c_add_wlsb(wlsb, value8, value8);
	rohc_lsb_set_ref(lsb, value8, false);
}


/**
 * @brief Encode/decode the given value with W-LSB
 *
 * @param wlsb        The W-LSB encoding context
 * @param lsb         The LSB decoding context
 * @param value8      The value to encode/decode
 * @param p           The shift parameter to run test with
 * @param be_verbose  Whether to print traces or not
 * @return            true if test succeeds, false otherwise
 */
static bool test_wlsb_8(struct c_wlsb *const wlsb,
                        struct rohc_lsb_decode *const lsb,
                        const uint8_t value8,
                        const short p,
                        const bool be_verbose)
{
	uint8_t value8_encoded;
	uint8_t value8_decoded;
	size_t required_bits;
	uint8_t required_bits_mask;
	uint32_t decoded32;
	bool lsb_decode_ok;

	/* encode */
	trace(be_verbose, "\tencode value 0x%02x ...\n", value8);
	for(required_bits = 0;
	    required_bits <= 8 && !wlsb_is_kp_possible_8bits(wlsb, value8, required_bits, p);
	    required_bits++)
	{
	}
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

	/* decode */
	trace(be_verbose, "\t\tdecode %zu-bit value 0x%02x ...\n", required_bits,
	      value8_encoded);
	lsb_decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, value8_encoded,
	                                required_bits, p, &decoded32);
	if(!lsb_decode_ok)
	{
		fprintf(stderr, "failed to decode %zu-bit value\n", required_bits);
		goto error;
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
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Initialize W-LSB encoding with the given value
 *
 * @param wlsb        The W-LSB encoding context
 * @param lsb         The LSB decoding context
 * @param value16     The value to encode/decode
 */
static void init_wlsb_16(struct c_wlsb *const wlsb,
                         struct rohc_lsb_decode *const lsb,
                         const uint16_t value16)
{
	/* transmit all bits without W-LSB encoding, so update encoding and
	 * decoding contexts */
	c_add_wlsb(wlsb, value16, value16);
	rohc_lsb_set_ref(lsb, value16, false);
}


/**
 * @brief Encode/decode the given value with W-LSB
 *
 * @param wlsb        The W-LSB encoding context
 * @param lsb         The LSB decoding context
 * @param value16     The value to encode/decode
 * @param p           The shift parameter to run test with
 * @param be_verbose  Whether to print traces or not
 * @return            true if test succeeds, false otherwise
 */
static bool test_wlsb_16(struct c_wlsb *const wlsb,
                         struct rohc_lsb_decode *const lsb,
                         const uint16_t value16,
                         const short p,
                         const bool be_verbose)
{
	uint16_t value16_encoded;
	uint16_t value16_decoded;
	size_t required_bits;
	uint16_t required_bits_mask;
	uint32_t decoded32;
	bool lsb_decode_ok;

	/* encode */
	trace(be_verbose, "\tencode value 0x%04x ...\n", value16);
	for(required_bits = 0;
	    required_bits <= 16 && !wlsb_is_kp_possible_16bits(wlsb, value16, required_bits, p);
	    required_bits++)
	{
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
	trace(be_verbose, "\t\tencoded on %zu bits: 0x%04x\n", required_bits,
	      value16_encoded);

	/* update encoding context */
	c_add_wlsb(wlsb, value16, value16);

	/* decode */
	trace(be_verbose, "\t\tdecode %zu-bit value 0x%04x ...\n", required_bits,
	      value16_encoded);
	lsb_decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, value16_encoded,
	                                required_bits, p, &decoded32);
	if(!lsb_decode_ok)
	{
		fprintf(stderr, "failed to decode %zu-bit value\n", required_bits);
		goto error;
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
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Initialize W-LSB encoding with the given value
 *
 * @param wlsb        The W-LSB encoding context
 * @param lsb         The LSB decoding context
 * @param value32     The value to encode/decode
 */
static void init_wlsb_32(struct c_wlsb *const wlsb,
                         struct rohc_lsb_decode *const lsb,
                         const uint32_t value32)
{
	/* transmit all bits without W-LSB encoding, so update encoding and
	 * decoding contexts */
	c_add_wlsb(wlsb, value32, value32);
	rohc_lsb_set_ref(lsb, value32, false);
}


/**
 * @brief Encode/decode the given value with W-LSB
 *
 * @param wlsb        The W-LSB encoding context
 * @param lsb         The LSB decoding context
 * @param value32     The value to encode/decode
 * @param p           The shift parameter to run test with
 * @param be_verbose  Whether to print traces or not
 * @return            true if test succeeds, false otherwise
 */
static bool test_wlsb_32(struct c_wlsb *const wlsb,
                         struct rohc_lsb_decode *const lsb,
                         const uint32_t value32,
                         const short p,
                         const bool be_verbose)
{
	uint32_t value32_encoded;
	uint32_t value32_decoded;
	size_t required_bits;
	uint32_t required_bits_mask;
	bool lsb_decode_ok;

	/* encode */
	trace(be_verbose, "\tencode value 0x%08x ...\n", value32);
	for(required_bits = 0;
	    required_bits <= 32 && !wlsb_is_kp_possible_32bits(wlsb, value32, required_bits, p);
	    required_bits++)
	{
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
	trace(be_verbose, "\t\tencoded on %zu bits: 0x%08x\n", required_bits,
	      value32_encoded);

	/* update encoding context */
	c_add_wlsb(wlsb, value32, value32);

	/* decode */
	trace(be_verbose, "\t\tdecode %zu-bit value 0x%08x ...\n", required_bits,
	      value32_encoded);
	lsb_decode_ok = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, value32_encoded,
	                                required_bits, p, &value32_decoded);
	if(!lsb_decode_ok)
	{
		fprintf(stderr, "failed to decode %zu-bit value\n", required_bits);
		goto error;
	}
	trace(be_verbose, "\t\tdecoded: 0x%08x\n", value32_decoded);

	/* update decoding context */
	rohc_lsb_set_ref(lsb, value32_decoded, false);

	/* check test result */
	if(value32 != value32_decoded)
	{
		fprintf(stderr, "original and decoded values do not match while "
		        "testing value 0x%08x with shift parameter %d\n", value32, p);
		goto error;
	}

	return true;

error:
	return false;
}

