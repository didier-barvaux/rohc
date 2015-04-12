/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2012,2013,2014 Viveris Technologies
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
 * @file    test_rtp_ts_wraparound.c
 * @brief   Test RTP TS encoding/decoding at wraparound
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "schemes/comp_scaled_rtp_ts.h"
#include "schemes/decomp_scaled_rtp_ts.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>


/** The width of the W-LSB sliding window */
#define ROHC_WLSB_WINDOW_WIDTH  4U

/** The number of TS_STRIDE transmissions */
#define ROHC_INIT_TS_STRIDE_MIN  3U


/** Print trace on stdout only in verbose mode */
#define trace(is_verbose, format, ...) \
	do { \
		if(is_verbose) { \
			fprintf(stderr, format, ##__VA_ARGS__); \
		} \
	} while(0)


static bool run_test(bool be_verbose, const unsigned int incr);


/**
 * @brief Test RTP TS encoding/decoding at wraparound
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	bool verbose; /* whether to run in verbose mode or not */
	int is_failure = 1; /* test fails by default */

	/* do we run in verbose mode ? */
	if(argc == 1)
	{
		/* no argument, run in silent mode */
		verbose = false;
	}
	else if(argc == 2 && strcmp(argv[1], "verbose") == 0)
	{
		/* run in verbose mode */
		verbose = true;
	}
	else
	{
		/* invalid usage */
		printf("test the RTP TS encoding/decoding at wraparound\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* run the test with irregular increment */
	trace(verbose, "test TS wraparound with irregular increment\n");
	if(!run_test(verbose, 0))
	{
		fprintf(stderr, "failed to handle RTP TS wraparound with irregular "
		        "increment\n");
		goto error;
	}

	/* run the test with power-of-two increment */
	trace(verbose, "test TS wraparound with power-of-two increment\n");
	if(!run_test(verbose, 256))
	{
		fprintf(stderr, "failed to handle RTP TS wraparound with power-of-two "
		        "increment\n");
		goto error;
	}

	/* run the test with non-power-of-two increment */
	trace(verbose, "test TS wraparound with non-power-of-two increment\n");
	if(!run_test(verbose, 257))
	{
		fprintf(stderr, "failed to handle RTP TS wraparound with "
		        "non-power-of-two increment\n");
		goto error;
	}

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}


/**
 * @brief Run the test
 *
 * @param be_verbose  Whether to print traces or not
 * @param incr        Increment between TS values
 * @return            true if test succeeds, false otherwise
 */
bool run_test(bool be_verbose, const unsigned int incr)
{
	struct ts_sc_comp ts_sc_comp;      /* the RTP TS encoding context */
	struct ts_sc_decomp *ts_sc_decomp; /* the RTP TS decoding context */

	uint32_t value; /* the value to encode */
	uint32_t value_encoded; /* the encoded value to decode */
	uint32_t value_decoded; /* the decoded value */

	unsigned int real_incr;

	int is_success = false; /* test fails by default */
	int ret;

	uint64_t i;

	/* create the RTP TS encoding context */
	ret = c_create_sc(&ts_sc_comp, ROHC_WLSB_WINDOW_WIDTH, NULL, NULL);
	if(ret != 1)
	{
		fprintf(stderr, "failed to initialize the RTP TS encoding context\n");
		goto error;
	}

	/* create the RTP TS decoding context */
	ts_sc_decomp = d_create_sc(NULL, NULL);
	if(ts_sc_decomp == NULL)
	{
		fprintf(stderr, "failed to initialize the RTP TS decoding context\n");
		goto destroy_ts_sc_comp;
	}

	/* compute the initial value to encode */
	if(incr == 0)
	{
		real_incr = (20 + 10) / 2;
	}
	else
	{
		real_incr = incr;
	}
	value = (0xffffffff - 50 * real_incr);
	if(value > 0xffffffff)
	{
		value = 0;
	}

	/* encode then decode values from ranges [0xffffffff - 50 * incr, 0xffffffff]
	 * and [0, 49 * incr] */
	for(i = 1; i < 100; i++)
	{
		size_t required_bits_less_equal_than_2;
		size_t required_bits_more_than_2;
		uint32_t required_bits_mask;
		uint32_t ts_stride;

		/* value to encode/decode */
		if(incr == 0)
		{
			if((i % 2) == 0)
				real_incr = 20;
			else
				real_incr = 10;
		}
		else
		{
			real_incr = incr;
		}
		value += real_incr;
		if(value > 0xffffffff)
		{
			value = 0;
		}
		trace(be_verbose, "\t#%" PRIu64 ": encode value 0x%08x (+%u) ...\n",
		      i, value, real_incr);

		/* update encoding context */
		c_add_ts(&ts_sc_comp, value, i);

		/* transmit the required bits wrt to encoding state */
		switch(ts_sc_comp.state)
		{
			case INIT_TS:
				/* transmit all bits without encoding */
				trace(be_verbose, "\t\ttransmit all bits without encoding\n");
				value_encoded = value;
				required_bits_less_equal_than_2 = 32;
				required_bits_more_than_2 = 32;
				/* change for INIT_STRIDE state */
				ts_sc_comp.state = INIT_STRIDE;
				/* simulate transmission */
				/* decode received unscaled TS */
				if(!ts_decode_unscaled_bits(ts_sc_decomp, value_encoded,
				                            required_bits_more_than_2,
				                            &value_decoded, false))
				{
					trace(be_verbose, "failed to decode received absolute unscaled TS\n");
					goto destroy_ts_sc_decomp;
				}
				break;

			case INIT_STRIDE:
				/* transmit all bits along with TS_STRIDE */
				trace(be_verbose, "\t\ttransmit all bits without encoding "
				      "and TS_STRIDE\n");
				value_encoded = value;
				ts_stride = get_ts_stride(&ts_sc_comp);
				required_bits_less_equal_than_2 = 32;
				required_bits_more_than_2 = 32;
				/* change for INIT_STRIDE state? */
				ts_sc_comp.nr_init_stride_packets++;
				if(ts_sc_comp.nr_init_stride_packets >= ROHC_INIT_TS_STRIDE_MIN)
				{
					ts_sc_comp.state = SEND_SCALED;
				}
				/* simulate transmission */
				/* decode received unscaled TS */
				if(!ts_decode_unscaled_bits(ts_sc_decomp, value_encoded,
				                            required_bits_more_than_2,
				                            &value_decoded, false))
				{
					trace(be_verbose, "failed to decode received unscaled TS\n");
					goto destroy_ts_sc_decomp;
				}
				d_record_ts_stride(ts_sc_decomp, ts_stride);
				break;

			case SEND_SCALED:
				/* transmit TS_SCALED */
				trace(be_verbose, "\t\ttransmit some bits of TS_SCALED\n");
				/* get TS_SCALED */
				value_encoded = get_ts_scaled(&ts_sc_comp);
				/* determine how many bits of TS_SCALED we need to send */
				if(!nb_bits_scaled(&ts_sc_comp, &required_bits_less_equal_than_2,
				                   &required_bits_more_than_2))
				{
					size_t nr_bits;
					uint32_t mask;

					/* this is the first TS scaled to be sent, we cannot code it
					 * with W-LSB and we must find its size (in bits) */
					for(nr_bits = 1, mask = 1;
					    nr_bits <= 32 && (value_encoded & mask) != value_encoded;
					    nr_bits++, mask |= (1 << (nr_bits - 1)))
					{
					}
					assert((value_encoded & mask) == value_encoded);
					required_bits_less_equal_than_2 = nr_bits;
					required_bits_more_than_2 = nr_bits;
				}
				assert(required_bits_less_equal_than_2 <= 32);
				assert(required_bits_more_than_2 <= 32);
				/* truncate the encoded TS_SCALED to the number of bits we send */
				if(required_bits_more_than_2 == 32)
				{
					required_bits_mask = 0xffffffff;
				}
				else if(required_bits_less_equal_than_2 <= 2)
				{
					required_bits_mask = (1 << required_bits_less_equal_than_2) - 1;
				}
				else if(required_bits_more_than_2 > 2)
				{
					required_bits_mask = (1 << required_bits_more_than_2) - 1;
				}
				else
				{
					assert(0);
				}
				value_encoded = value_encoded & required_bits_mask;
				/* save the new TS_SCALED value */
				add_scaled(&ts_sc_comp, i);
				/* simulate transmission */
				/* decode TS */
				if(required_bits_less_equal_than_2 > 0 || required_bits_more_than_2 > 0)
				{
					const size_t required_bits =
						(required_bits_less_equal_than_2 <= 2 ?
						 required_bits_less_equal_than_2 : required_bits_more_than_2);

					/* decode the received TS_SCALED value */
					if(!ts_decode_scaled_bits(ts_sc_decomp, value_encoded,
					                          required_bits, &value_decoded))
					{
						trace(be_verbose, "failed to decode received TS_SCALED\n");
						goto destroy_ts_sc_decomp;
					}
				}
				else
				{
					/* deduct TS from SN */
					value_decoded = ts_deduce_from_sn(ts_sc_decomp, i);
				}
				break;
			default:
				trace(be_verbose, "unknown RTP TS encoding state, "
				      "should not happen\n");
				assert(0);
				goto destroy_ts_sc_decomp;
		}
		trace(be_verbose, "\t\tencoded on %zu/2 or %zu/32 bits: 0x%04x\n",
		      required_bits_less_equal_than_2, required_bits_more_than_2,
		      value_encoded);

		/* check test result */
		if(value != value_decoded)
		{
			fprintf(stderr, "original and decoded values do not match while "
			        "testing value 0x%08x\n", value);
			goto destroy_ts_sc_decomp;
		}

		/* update decoding context */
		ts_update_context(ts_sc_decomp, value_decoded, i);
	}

	/* test succeeds */
	trace(be_verbose, "\ttest is successful\n");
	is_success = true;

destroy_ts_sc_decomp:
	rohc_ts_scaled_free(ts_sc_decomp);
destroy_ts_sc_comp:
	c_destroy_sc(&ts_sc_comp);
error:
	return is_success;
}

