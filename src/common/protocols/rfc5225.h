/*
 * Copyright 2018 Viveris Technologies
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
 * @file   rfc5225.h
 * @brief  ROHC packets for the ROHCv2 profiles defined in RFC5225
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_PROTOCOLS_RFC5225_H
#define ROHC_PROTOCOLS_RFC5225_H

#include <stdint.h>

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif


#define ROHC_PACKET_TYPE_IR         0xFD
#define ROHC_PACKET_TYPE_CO_REPAIR  0xFB



/************************************************************************
 * Compressed IPv4 header                                               *
 ************************************************************************/

/**
 * @brief The IPv4 static part
 *
 * See RFC5225 page 61
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t version_flag:1;
	uint8_t innermost_ip:1;
	uint8_t reserved:6;
#else
	uint8_t reserved:6;
	uint8_t innermost_ip:1;
	uint8_t version_flag:1;
#endif
	uint8_t protocol;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__((packed)) ipv4_static_t;


/**
 * @brief The IPv4 dynamic part for the innermost IP header of the IP-only profile,
 *        IP-ID not present
 *
 * See RFC5225 page 61-62
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:3;
	uint8_t reorder_ratio:2;
	uint8_t df:1;
	uint8_t ip_id_behavior_innermost:2;
#else
	uint8_t ip_id_behavior_innermost:2;
	uint8_t df:1;
	uint8_t reorder_ratio:2;
	uint8_t reserved:3;
#endif
	uint8_t tos_tc;
	uint8_t ttl_hopl;
	uint16_t msn;
} __attribute__((packed)) ipv4_endpoint_innermost_dynamic_noipid_t;


/**
 * @brief The IPv4 dynamic part for the innermost IP header of the IP-only profile,
 *        IP-ID present
 *
 * See RFC5225 page 61-62
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:3;
	uint8_t reorder_ratio:2;
	uint8_t df:1;
	uint8_t ip_id_behavior_innermost:2;
#else
	uint8_t ip_id_behavior_innermost:2;
	uint8_t df:1;
	uint8_t reorder_ratio:2;
	uint8_t reserved:3;
#endif
	uint8_t tos_tc;
	uint8_t ttl_hopl;
	uint16_t ip_id_innermost;
	uint16_t msn;
} __attribute__((packed)) ipv4_endpoint_innermost_dynamic_ipid_t;


/**
 * @brief The IPv4 dynamic part for any outer IP header, IP-ID not present
 *
 * See RFC5225 page 62
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:5;
	uint8_t df:1;
	uint8_t ip_id_behavior_outer:2;
#else
	uint8_t ip_id_behavior_outer:2;
	uint8_t df:1;
	uint8_t reserved:5;
#endif
	uint8_t tos_tc;
	uint8_t ttl_hopl;
} __attribute__((packed)) ipv4_outer_dynamic_noipid_t;


/**
 * @brief The IPv4 dynamic part for any outer IP header, IP-ID present
 *
 * See RFC5225 page 62
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:5;
	uint8_t df:1;
	uint8_t ip_id_behavior_outer:2;
#else
	uint8_t ip_id_behavior_outer:2;
	uint8_t df:1;
	uint8_t reserved:5;
#endif
	uint8_t tos_tc;
	uint8_t ttl_hopl;
	uint16_t ip_id_outer;
} __attribute__((packed)) ipv4_outer_dynamic_ipid_t;


/************************************************************************
 * Compressed IPv6 base header and its extension headers                *
 ************************************************************************/

/**
 * @brief The IPv6 static part, null flow_label encoded with 1 bit
 *
 * See RFC5225 page 58-59
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t version_flag:1;
	uint8_t innermost_ip:1;
	uint8_t reserved1:1;
	uint8_t flow_label_enc_discriminator:1;
	uint8_t reserved2:4;
#else
	uint8_t reserved2:4;
	uint8_t flow_label_enc_discriminator:1;
	uint8_t reserved1:1;
	uint8_t innermost_ip:1;
	uint8_t version_flag:1;
#endif
	uint8_t next_header;
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
} __attribute__((packed)) ipv6_static_nofl_t;


/**
 * @brief The IPv6 static part, flow_label encoded with 1+20 bit
 *
 * See RFC5225 page 58-59
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t version_flag:1;
	uint8_t innermost_ip:1;
	uint8_t reserved:1;
	uint8_t flow_label_enc_discriminator:1;
	uint8_t flow_label_msb:4;
#else
	uint8_t flow_label_msb:4;
	uint8_t flow_label_enc_discriminator:1;
	uint8_t reserved:1;
	uint8_t innermost_ip:1;
	uint8_t version_flag:1;
#endif
	uint16_t flow_label_lsb;
	uint8_t next_header;
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
} __attribute__((packed)) ipv6_static_fl_t;


/**
 * @brief The IPv6 dynamic part for the innermost IP header of the IP-only profile
 *
 * See RFC5225 page 59
 */
typedef struct
{
	uint8_t tos_tc;
	uint8_t ttl_hopl;
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:6;
	uint8_t reorder_ratio:2;
#else
	uint8_t reorder_ratio:2;
	uint8_t reserved:6;
#endif
	uint16_t msn;
} __attribute__((packed)) ipv6_endpoint_dynamic_t;


/**
 * @brief The IPv6 dynamic part for any outer IP header of the IP-only profile
 *        and all IP headers of the other ROHCv2 profiles
 *
 * See RFC5225 page 59
 */
typedef struct
{
	uint8_t tos_tc;
	uint8_t ttl_hopl;
} __attribute__((packed)) ipv6_regular_dynamic_t;


/**
 * @brief The CRC part of the co_repair packet format
 *
 * See RFC5225 §6.8.2.2 page 44
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t r1:1;          /**< Reserved field, must be 0 */
	uint8_t header_crc:7;  /**< CRC-7 over uncompressed headers */
	uint8_t r2:5;          /**< Reserved field, must be 0 */
	uint8_t ctrl_crc:3;    /**< CRC-3 over control fields */
#else
	uint8_t header_crc:7;
	uint8_t r1:1;
	uint8_t ctrl_crc:3;
	uint8_t r2:5;
#endif
} __attribute__((packed)) co_repair_crc_t;


/**
 * @brief The pt_0_crc3 packet format
 *
 * See RFC5225 page 91
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:1;  /**< '0'                              [ 1 ] */
	uint8_t msn:4;            /**< msn_lsb(4)                       [ 4 ] */
	uint8_t header_crc:3;     /**< crc3(THIS.UVALUE, THIS.ULENGTH)  [ 3 ] */
#else
	uint8_t header_crc:3;
	uint8_t msn:4;
	uint8_t discriminator:1;
#endif
} __attribute__((packed)) pt_0_crc3_t;


/**
 * @brief The pt_0_crc7 packet format
 *
 * See RFC5225 page 91
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:3;  /**< '100'                            [ 3 ] */
	uint8_t msn_1:5;          /**< 5 MSB of msn_lsb(6)              [ 5 ] */
	uint8_t msn_2:1;          /**< last LSB of msn_lsb(6)           [ 6 ] */
	uint8_t header_crc:7;     /**< crc7(THIS.UVALUE, THIS.ULENGTH)  [ 7 ] */
#else
	uint8_t msn_1:5;
	uint8_t discriminator:3;
	uint8_t header_crc:7;
	uint8_t msn_2:1;
#endif
} __attribute__((packed)) pt_0_crc7_t;


/**
 * @brief The pt_1_seq_id packet format
 *
 * See RFC5225 page 91
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:3;/**< '101'                                 [ 3 ] */
	uint8_t header_crc:3;   /**< crc3(THIS.UVALUE, THIS.ULENGTH)       [ 3 ] */
	uint8_t msn_1:2;        /**< 2 MSB of msn_lsb(6)                   [ 2 ] */
	uint8_t msn_2:4;        /**< 4 LSB of msn_lsb(6)                   [ 4 ] */
	uint8_t ip_id:4;        /**< ip_id_lsb(ip_id_behavior.UVALUE, 4)   [ 4 ] */
#else
	uint8_t msn_1:2;
	uint8_t header_crc:3;
	uint8_t discriminator:3;
	uint8_t ip_id:4;
	uint8_t msn_2:4;
#endif
} __attribute__((packed)) pt_1_seq_id_t;


/**
 * @brief The pt_2_seq_id packet format
 *
 * See RFC5225 page 91
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint32_t discriminator:3;/**< '110'                                          [ 3 ] */
	uint32_t ip_id_1:5;      /**< 5 MSB of ip_id_lsb(ip_id_behavior.UVALUE, 6)   [ 5 ] */
	uint32_t ip_id_2:1;      /**< 1 LSB of ip_id_lsb(ip_id_behavior.UVALUE, 6)   [ 1 ] */
	uint32_t header_crc:7;   /**< crc7(THIS.UVALUE, THIS.ULENGTH)                [ 7 ] */
	uint32_t msn:8;          /**< msn_lsb(8)                                     [ 8 ] */
#else
	uint8_t ip_id_1:5;
	uint8_t discriminator:3;
	uint8_t header_crc:7;
	uint8_t ip_id_2:1;
	uint8_t msn:8; 
#endif
} __attribute__((packed)) pt_2_seq_id_t;


/**
 * @brief The fixed part of the co_common packet format
 *
 * See RFC5225 page 90/91
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:8;  /**< '11111010'                       [ 8 ] */
	uint8_t ip_id_ind:1;      /**< irregular(1)                     [ 1 ] */
	uint8_t header_crc:7;     /**< crc7(THIS.UVALUE, THIS.ULENGTH)  [ 7 ] */
	uint8_t flags_ind:1;      /**< irregular(1)                     [ 1 ] */
	uint8_t ttl_hopl_ind:1;   /**< irregular(1)                     [ 1 ] */
	uint8_t tos_tc_ind:1;     /**< irregular(1)                     [ 1 ] */
	uint8_t reorder_ratio:2;  /**< irregular(2)                     [ 2 ] */
	uint8_t control_crc3:3;   /**< control_crc3_encoding            [ 3 ] */
#else
	uint8_t discriminator:8;  /**< '11111010'                       [ 8 ] */
	uint8_t header_crc:7;     /**< crc7(THIS.UVALUE, THIS.ULENGTH)  [ 7 ] */
	uint8_t ip_id_ind:1;      /**< irregular(1)                     [ 1 ] */
	uint8_t control_crc3:3;   /**< 4 LSB of msn_lsb(6)              [ 3 ] */
	uint8_t reorder_ratio:2;  /**< irregular(2)                     [ 2 ] */
	uint8_t tos_tc_ind:1;     /**< irregular(1)                     [ 1 ] */
	uint8_t ttl_hopl_ind:1;   /**< irregular(1)                     [ 1 ] */
	uint8_t flags_ind:1;      /**< irregular(1)                     [ 1 ] */
#endif
} __attribute__((packed)) co_common_base_t;


/**
 * @brief The profile_2_3_4_flags_enc packet part
 *
 * See RFC5225 page 76
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t ip_outer_indicator:1; /**< irregular(1)              [ 1 ] */
	uint8_t df:1;                 /**< dont_fragment(ip_version) [ 1 ] */
	uint8_t ip_id_behavior:2;     /**< irregular(2)              [ 2 ] */
	uint8_t reserved:4;           /**< compressed_value(4, 0)    [ 4 ] */
#else
	uint8_t reserved:4;
	uint8_t ip_id_behavior:2;
	uint8_t df:1;
	uint8_t ip_outer_indicator:1;
#endif
} __attribute__((packed)) profile_2_3_4_flags_t;


#endif /* ROHC_PROTOCOLS_RFC5225_H */

