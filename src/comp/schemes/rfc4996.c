/*
 * Copyright 2012,2013,2014,2015 Didier Barvaux
 * Copyright 2012 WBX
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
 * @file   src/comp/schemes/rfc4996.c
 * @brief  Library of encoding methods from RFC4997 and RFC4996
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rfc4996.h"
#include "rohc_comp_internals.h"
#include "rohc_utils.h"
#include "protocols/tcp.h"
#include "protocols/rfc6846.h"

#include <string.h>
#ifdef __KERNEL__
#  include <bitops.h> /* for __builtin_popcount() in Linux kernel */
#endif
#include <assert.h>


/**
 * @brief Compress the 8 bits given, depending of the context value.
 *
 * See RFC4996 page 46
 *
 * @param packet_value     The packet value
 * @param is_static        Whether the value is static or not
 * @param[out] rohc_data   The compressed value
 * @param rohc_max_len     The max remaining length in the ROHC buffer
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_static_or_irreg8(const uint8_t packet_value,
                       const bool is_static,
                       uint8_t *const rohc_data,
                       const size_t rohc_max_len,
                       int *const indicator)
{
	size_t length;

	if(is_static)
	{
		*indicator = 0;
		length = 0;
	}
	else
	{
		if(rohc_max_len < 1)
		{
			goto error;
		}
		rohc_data[0] = packet_value;
		*indicator = 1;
		length = 1;
	}

	return length;

error:
	return -1;
}


/**
 * @brief Compress the 16 bits given, depending of the context value.
 *
 * @param packet_value     The packet value
 * @param is_static        Whether the value is static or not
 * @param[out] rohc_data   The compressed value
 * @param rohc_max_len     The max remaining length in the ROHC buffer
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_static_or_irreg16(const uint16_t packet_value,
                        const bool is_static,
                        uint8_t *const rohc_data,
                        const size_t rohc_max_len,
                        int *const indicator)
{
	size_t field_len;

	if(is_static)
	{
		field_len = 0;
		*indicator = 0;
	}
	else
	{
		field_len = sizeof(uint16_t);

		if(rohc_max_len < field_len)
		{
			goto error;
		}

		memcpy(rohc_data, &packet_value, sizeof(uint16_t));
		*indicator = 1;
	}

	return field_len;

error:
	return -1;
}


/**
 * @brief Compress the 32 bits given, depending of the context value.
 *
 * @param packet_value     The packet value
 * @param is_static        Whether the value is static or not
 * @param[out] rohc_data   The compressed value
 * @param rohc_max_len     The max remaining length in the ROHC buffer
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_static_or_irreg32(const uint32_t packet_value,
                        const bool is_static,
                        uint8_t *const rohc_data,
                        const size_t rohc_max_len,
                        int *const indicator)
{
	size_t field_len;

	if(is_static)
	{
		field_len = 0;
		*indicator = 0;
	}
	else
	{
		field_len = sizeof(uint32_t);

		if(rohc_max_len < field_len)
		{
			goto error;
		}

		memcpy(rohc_data, &packet_value, sizeof(uint32_t));
		*indicator = 1;
	}

	return field_len;

error:
	return -1;
}


/**
 * @brief Compress the 16 bits value, regarding if null or not
 *
 * @param packet_value     The packet value
 * @param[out] rohc_data   The compressed value
 * @param rohc_max_len     The max remaining length in the ROHC buffer
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_zero_or_irreg16(const uint16_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator)
{
	size_t field_len;

	if(packet_value != 0)
	{
		field_len = sizeof(uint16_t);

		if(rohc_max_len < field_len)
		{
			goto error;
		}

		memcpy(rohc_data, &packet_value, sizeof(uint16_t));
		*indicator = 0;
	}
	else
	{
		field_len = 0;
		*indicator = 1;
	}

	return field_len;

error:
	return -1;
}


/**
 * @brief Compress the 32 bits value, regarding if null or not
 *
 * @param packet_value     The packet value
 * @param[out] rohc_data   The compressed value
 * @param rohc_max_len     The max remaining length in the ROHC buffer
 * @param[out] indicator   The indicator: 1 if present, 0 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_zero_or_irreg32(const uint32_t packet_value,
                      uint8_t *const rohc_data,
                      const size_t rohc_max_len,
                      int *const indicator)
{
	size_t field_len;

	if(packet_value != 0)
	{
		field_len = sizeof(uint32_t);

		if(rohc_max_len < field_len)
		{
			goto error;
		}

		memcpy(rohc_data, &packet_value, field_len);
		*indicator = 0;
	}
	else
	{
		field_len = 0;
		*indicator = 1;
	}

	return field_len;

error:
	return -1;
}


/**
 * @brief Compress the given 32-bit value
 *
 * See variable_length_32_enc in RFC4996 page 46.
 *
 * @param old_value       The previous 32-bit value
 * @param new_value       The 32-bit value to compress
 * @param wlsb            The W-LSB encoding context
 * @param[out] rohc_data  The compressed value
 * @param rohc_max_len    The max remaining length in the ROHC buffer
 * @param[out] indicator  The indicator for the compressed value
 * @return                The number of ROHC bytes written in case of success,
 *                        -1 in case of error
 */
int variable_length_32_enc(const uint32_t old_value,
                           const uint32_t new_value,
                           const struct c_wlsb *const wlsb,
                           uint8_t *const rohc_data,
                           const size_t rohc_max_len,
                           int *const indicator)
{
	size_t encoded_len;

	if(new_value == old_value)
	{
		/* 0-byte value */
		encoded_len = 0;
		*indicator = 0;
	}
	else if(wlsb_is_kp_possible_32bits(wlsb, new_value, 8, 63))
	{
		/* 1-byte value */
		encoded_len = 1;
		if(rohc_max_len < encoded_len)
		{
			goto error;
		}
		*indicator = 1;
		rohc_data[0] = new_value & 0xff;
	}
	else if(wlsb_is_kp_possible_32bits(wlsb, new_value, 16, 16383))
	{
		/* 2-byte value */
		encoded_len = 2;
		if(rohc_max_len < encoded_len)
		{
			goto error;
		}
		*indicator = 2;
		rohc_data[0] = (new_value >> 8) & 0xff;
		rohc_data[1] = new_value & 0xff;
	}
	else
	{
		/* 4-byte value */
		encoded_len = 4;
		if(rohc_max_len < encoded_len)
		{
			goto error;
		}
		*indicator = 3;
		rohc_data[0] = (new_value >> 24) & 0xff;
		rohc_data[1] = (new_value >> 16) & 0xff;
		rohc_data[2] = (new_value >> 8) & 0xff;
		rohc_data[3] = new_value & 0xff;
	}

	assert(encoded_len <= sizeof(uint32_t));
	assert((*indicator) >= 0 && (*indicator) <= 3);

	return encoded_len;

error:
	return -1;
}


/**
 * @brief Calculate the scaled and residue values from unscaled value and scaling factor
 *
 * See RFC4996 page 49
 *
 * @param scaled_value     TODO
 * @param residue_field    TODO
 * @param scaling_factor   TODO
 * @param unscaled_value   TODO
 */
void c_field_scaling(uint32_t *const scaled_value,
                     uint32_t *const residue_field,
                     const uint32_t scaling_factor,
                     const uint32_t unscaled_value)
{
	if(scaling_factor == 0)
	{
		*residue_field = unscaled_value;
		*scaled_value = 0;
	}
	else
	{
		*residue_field = unscaled_value % scaling_factor;
		*scaled_value = unscaled_value / scaling_factor;
		assert(unscaled_value ==
		       (((*scaled_value) * scaling_factor) + (*residue_field)));
	}
}


/**
 * @brief Is is possible to use the rsf_index_enc encoding?
 *
 * See RFC4996 page 71
 *
 * @param rsf_flags  The RSF flags
 * @return           true if the rsf_index_enc may be used, false if it cannot
 */
bool rsf_index_enc_possible(const uint8_t rsf_flags)
{
	/* the rsf_index_enc encoding is possible only if at most one of the RST,
	 * SYN or FIN flag is set */
	return (__builtin_popcount(rsf_flags) <= 1);
}


/**
 * @brief Calculate the rsf_index from the rsf flags
 *
 * See RFC4996 page 71
 *
 * @param rsf_flags  The RSF flags
 * @return           The rsf index
 */
unsigned int rsf_index_enc(const uint8_t rsf_flags)
{
	switch(rsf_flags)
	{
		case RSF_NONE:
			return 0;
		case RSF_RST_ONLY:
			return 1;
		case RSF_SYN_ONLY:
			return 2;
		case RSF_FIN_ONLY:
			return 3;
		default:
			assert(0);
			return 0;
	}
}


/**
 * @brief Compress or not the IP-ID
 *
 * See RFC4996 page 76
 *
 * @param behavior         The IP-ID behavior
 * @param ip_id_nbo        The IP-ID value to compress (in NBO)
 * @param ip_id_offset     The IP-ID offset value to compress (in HBO)
 * @param wlsb             The W-LSB encoding context
 * @param p                The W-LSB shift parameter p
 * @param[out] rohc_data   The compressed value
 * @param rohc_max_len     The max remaining length in the ROHC buffer
 * @param[out] indicator   The indicator: 0 if short, 1 if long
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int c_optional_ip_id_lsb(const int behavior,
                         const uint16_t ip_id_nbo,
                         const uint16_t ip_id_offset,
                         const struct c_wlsb *const wlsb,
                         const rohc_lsb_shift_t p,
                         uint8_t *const rohc_data,
                         const size_t rohc_max_len,
                         int *const indicator)
{
	size_t length = 0;

	switch(behavior)
	{
		case ROHC_IP_ID_BEHAVIOR_SEQ_SWAP:
		case ROHC_IP_ID_BEHAVIOR_SEQ:
			if(wlsb_is_kp_possible_16bits(wlsb, ip_id_offset, 8, p))
			{
				if(rohc_max_len < 1)
				{
					goto error;
				}
				rohc_data[0] = ip_id_offset & 0xff;
				*indicator = 0;
				length++;
			}
			else
			{
				if(rohc_max_len < sizeof(uint16_t))
				{
					goto error;
				}
				memcpy(rohc_data, &ip_id_nbo, sizeof(uint16_t));
				length += sizeof(uint16_t);
				*indicator = 1;
			}
			break;
		case ROHC_IP_ID_BEHAVIOR_RAND:
		case ROHC_IP_ID_BEHAVIOR_ZERO:
			*indicator = 0;
			break;
		default:
			assert(0); /* should never happen */
			*indicator = 0;
			break;
	}

	return length;

error:
	return -1;
}


/**
 * @brief Encode the DSCP field
 *
 * See RFC4996 page 75
 *
 * @param context_value    The DSCP value in the compression context
 * @param packet_value     The DSCP value in the packet to compress
 * @param[out] rohc_data   The compressed value
 * @param rohc_max_len     The max remaining length in the ROHC buffer
 * @param[out] indicator   The indicator: 1 if present, 1 if not
 * @return                 The number of ROHC bytes written,
 *                         -1 if a problem occurs
 */
int dscp_encode(const uint8_t context_value,
                const uint8_t packet_value,
                uint8_t *const rohc_data,
                const size_t rohc_max_len,
                int *const indicator)
{
	size_t len;

	if(packet_value == context_value)
	{
		*indicator = 0;
		len = 0;
	}
	else
	{
		/* 6 bits + 2 bits padding */
		if(rohc_max_len < 1)
		{
			goto error;
		}
		rohc_data[0] = ((packet_value & 0x3F) << 2);
		*indicator = 1;
		len = 1;
	}

	return len;

error:
	return -1;
}


/**
 * @brief Whether the ACK number may be transmitted scaled or not
 *
 * The ACK number may be transmitted scaled if:
 *  \li the \e ack_stride scaling factor is non-zero,
 *  \li both the \e ack_stride scaling factor and the scaling residue didn't
 *      change in the last few packets
 *
 * @param ack_stride  The \e ack_stride scaling factor
 * @param nr_trans    The number of transmissions since last change
 * @return            true if the ACK number may be transmitted scaled,
 *                    false if the ACK number shall be transmitted unscaled
 */
bool tcp_is_ack_scaled_possible(const uint16_t ack_stride,
                                const size_t nr_trans)
{
	return (ack_stride != 0 && nr_trans >= ROHC_OA_REPEAT_MIN);
}


/**
 * @brief Whether the \e ack_stride scaling factor shall be transmitted or not
 *
 * @param ack_stride  The \e ack_stride scaling factor
 * @param nr_trans    The number of transmissions since last change
 * @return            true if the ACK number may be transmitted scaled,
 *                    false if the ACK number shall be transmitted unscaled
 */
bool tcp_is_ack_stride_static(const uint16_t ack_stride,
                              const size_t nr_trans)
{
	return (ack_stride == 0 || nr_trans >= ROHC_OA_REPEAT_MIN);
}

