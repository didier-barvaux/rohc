/*
 * Copyright 2012,2013,2014 Didier Barvaux
 * Copyright 2013,2018 Viveris Technologies
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
 * @file   rfc6846.h
 * @brief  ROHC packets for the ROHCv1 IP/TCP profile defined in RFC6846
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_PROTOCOLS_RFC6846_H
#define ROHC_PROTOCOLS_RFC6846_H

#include <stdint.h>

#ifdef __KERNEL__
#  include <endian.h>
#else
#  include "config.h" /* for WORDS_BIGENDIAN */
#endif


/* See RFC6846 §7.1 and §7.2 */
#define ROHC_PACKET_TYPE_IR      0xFD
#define ROHC_PACKET_TYPE_IR_CR   0xfc
#define ROHC_PACKET_TYPE_IR_DYN  0xF8


/**
 * @brief The different chains used by the TCP profile
 */
typedef enum
{
	ROHC_TCP_CHAIN_STATIC    = 0,  /**< The TCP static chain */
	ROHC_TCP_CHAIN_DYNAMIC   = 1,  /**< The TCP dynamic chain */
	ROHC_TCP_CHAIN_REPLICATE = 2,  /**< The TCP replicate chain */
	ROHC_TCP_CHAIN_IRREGULAR = 3,  /**< The TCP irregular chain */
	ROHC_TCP_CHAIN_CO        = 4,  /**< Not a chain, but in CO packet */

} rohc_tcp_chain_t;


/************************************************************************
 * Compressed TCP options                                             *
 ************************************************************************/

/**
 * @brief The largest index that may be used to identify one TCP option
 *
 * The ROHC standard defines that one TCP option is identified by an index. It
 * also defines that index is in range [0 ; 15].
 */
#define MAX_TCP_OPTION_INDEX 15U


/**
 * @brief The maximum of TCP options supported by the TCP profile
 *
 * One TCP header may contain up to 40 bytes of options, so it may contain
 * up 40 1-byte options, so the ROHC (de)compressors should expect such TCP
 * packets. However the m field in the compressed list of TCP options (see
 * RFC 6846, section 6.3.3 for more details) cannot be larger than 15, so
 * restrict the number of TCP options that value. One TCP packet with more
 * than 15 TCP options will be compressed with the IP-only profile.
 *
 * @see ROHC_TCP_OPTS_MAX_PROTO
 */
#define ROHC_TCP_OPTS_MAX  15U


#define TCP_INDEX_NOP          0U
#define TCP_INDEX_EOL          1U
#define TCP_INDEX_MSS          2U
#define TCP_INDEX_WS           3U
#define TCP_INDEX_TS           4U
#define TCP_INDEX_SACK_PERM    5U
#define TCP_INDEX_SACK         6U
#define TCP_INDEX_GENERIC7     7U
#define TCP_INDEX_GENERIC8     8U
#define TCP_INDEX_GENERIC9     9U
#define TCP_INDEX_GENERIC10   10U
#define TCP_INDEX_GENERIC11   11U
#define TCP_INDEX_GENERIC12   12U
#define TCP_INDEX_GENERIC13   13U
#define TCP_INDEX_GENERIC14   14U
#define TCP_INDEX_GENERIC15   15U



/************************************************************************
 * Compressed IPv4 header                                               *
 ************************************************************************/

/**
 * @brief The IPv4 static part
 *
 * See RFC4996 page 62
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t version_flag:1;
	uint8_t reserved:7;
#else
	uint8_t reserved:7;
	uint8_t version_flag:1;
#endif
	uint8_t protocol;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__((packed)) ipv4_static_t;


/** The different IP-ID behaviors */
typedef enum
{
	IP_ID_BEHAVIOR_SEQ       = 0, /**< IP-ID increases */
	IP_ID_BEHAVIOR_SEQ_SWAP  = 1, /**< IP-ID increases in little endian */
	IP_ID_BEHAVIOR_RAND      = 2, /**< IP-ID is random */
	IP_ID_BEHAVIOR_ZERO      = 3, /**< IP-ID is constant zero */
} tcp_ip_id_behavior_t;


/**
 * @brief The IPv4 dynamic part without IP-ID field
 *
 * See RFC4996 page 62
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:5;
	uint8_t df:1;
	uint8_t ip_id_behavior:2;
	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;
#else
	uint8_t ip_id_behavior:2;
	uint8_t df:1;
	uint8_t reserved:5;
	uint8_t ip_ecn_flags:2;
	uint8_t dscp:6;
#endif
	uint8_t ttl_hopl;
} __attribute__((packed)) ipv4_dynamic1_t;


/**
 * @brief The IPv4 dynamic part with IP-ID field
 *
 * See RFC4996 page 62
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:5;
	uint8_t df:1;
	uint8_t ip_id_behavior:2;
	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;
#else
	uint8_t ip_id_behavior:2;
	uint8_t df:1;
	uint8_t reserved:5;
	uint8_t ip_ecn_flags:2;
	uint8_t dscp:6;
#endif
	uint8_t ttl_hopl;
	uint16_t ip_id;
} __attribute__((packed)) ipv4_dynamic2_t;


/**
 * @brief The IPv4 replicate part
 *
 * See RFC6846 page 64
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:4;        /* reserved                 =:= '0000'       [ 4 ]; */
	uint8_t ip_id_behavior:2;  /* ip_id_behavior_innermost =:= irregular(2) [ 2 ]; */
	uint8_t ttl_flag:1;        /* ttl_flag                 =:= irregular(1) [ 1 ]; */
	uint8_t df:1;              /* df                       =:= irregular(1) [ 1 ]; */
	uint8_t dscp:6;            /* dscp                     =:= irregular(6) [ 6 ]; */
	uint8_t ip_ecn_flags:2;    /* ip_ecn_flags             =:= irregular(2) [ 2 ]; */
#else
	uint8_t df:1;
	uint8_t ttl_flag:1;
	uint8_t ip_id_behavior:2;
	uint8_t reserved:4;
	uint8_t ip_ecn_flags:2;
	uint8_t dscp:6;
#endif
	/* ip_id    =:= ip_id_enc_dyn(ip_id_behavior_innermost.UVALUE) [ 0, 16 ]; */
	/* ttl_hopl =:= static_or_irreg(ttl_flag.UVALUE, 8)            [ 0, 8 ]; */
} __attribute__((packed)) ipv4_replicate_t;



/************************************************************************
 * Compressed IPv6 base header and its extension headers                *
 ************************************************************************/

/** The static part of IPv6 option header */
typedef struct
{
	uint8_t next_header;
	uint8_t length;
} __attribute__((packed)) ip_opt_static_t;


/** The static part of IPv6 Destination option header */
typedef struct
{
	uint8_t next_header;
	uint8_t length;
} __attribute__((packed)) ip_dest_opt_static_t;


/** The static part of IPv6 Hop-by-Hop option header */
typedef struct
{
	uint8_t next_header;
	uint8_t length;
} __attribute__((packed)) ip_hop_opt_static_t;


/** The static part of IPv6 Routing option header */
typedef struct
{
	uint8_t next_header;
	uint8_t length;
	uint8_t value[1];
} __attribute__((packed)) ip_rout_opt_static_t;


/**
 * @brief The IPv6 static part, null flow_label encoded with 1 bit
 *
 * See RFC4996 page 58
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t version_flag:1;
	uint8_t reserved1:2;
	uint8_t flow_label_enc_discriminator:1;
	uint8_t reserved2:4;
#else
	uint8_t reserved2:4;
	uint8_t flow_label_enc_discriminator:1;
	uint8_t reserved1:2;
	uint8_t version_flag:1;
#endif
	uint8_t next_header;
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
} __attribute__((packed)) ipv6_static1_t;


/**
 * @brief The IPv6 static part, flow_label encoded with 1+20 bits
 *
 * See RFC4996 page 59
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t version_flag:1;
	uint8_t reserved:2;
	uint8_t flow_label_enc_discriminator:1;
	uint8_t flow_label1:4;
#else
	uint8_t flow_label1:4;
	uint8_t flow_label_enc_discriminator:1;
	uint8_t reserved:2;
	uint8_t version_flag:1;
#endif
	uint16_t flow_label2;
	uint8_t next_header;
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
} __attribute__((packed)) ipv6_static2_t;


/**
 * @brief The IPv6 dynamic part
 *
 * See RFC4996 page 59
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t dscp:6;
	uint8_t ip_ecn_flags:2;
#else
	uint8_t ip_ecn_flags:2;
	uint8_t dscp:6;
#endif
	uint8_t ttl_hopl;
} __attribute__((packed)) ipv6_dynamic_t;


/**
 * @brief The IPv6 replicate part with short Flow Label
 *
 * See RFC6846 page 60
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t dscp:6;          /* dscp         =:= irregular(6) [ 6 ]; */
	uint8_t ip_ecn_flags:2;  /* ip_ecn_flags =:= irregular(2) [ 2 ]; */
	uint8_t reserved1:3;     /* reserved     =:= '000'        [ 3 ]; */
	uint8_t fl_enc_flag:1;   /* flow_label   =:= fl_enc       [ 1 ]; */
	uint8_t reserved2:4;     /* reserved     =:= '0000'       [ 4 ]; */
#else
	uint8_t ip_ecn_flags:2;
	uint8_t dscp:6;
	uint8_t reserved2:4;
	uint8_t fl_enc_flag:1;
	uint8_t reserved1:3;
#endif
} __attribute__((packed)) ipv6_replicate1_t;


/**
 * @brief The IPv6 replicate part with long Flow Label
 *
 * See RFC6846 page 60
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t dscp:6;          /* dscp         =:= irregular(6) [ 6 ]; */
	uint8_t ip_ecn_flags:2;  /* ip_ecn_flags =:= irregular(2) [ 2 ]; */
	uint8_t reserved:3;      /* reserved     =:= '000'        [ 3 ]; */
	uint8_t fl_enc_flag:1;   /* flow_label   =:= fl_enc       [ 21 ]; */
	uint8_t flow_label1:4;
#else
	uint8_t ip_ecn_flags:2;
	uint8_t dscp:6;
	uint8_t flow_label1:4;
	uint8_t fl_enc_flag:1;
	uint8_t reserved:3;
#endif
	uint16_t flow_label2;
} __attribute__((packed)) ipv6_replicate2_t;



/************************************************************************
 * Compressed TCP header and its options                                *
 ************************************************************************/

/**
 * @brief The TCP static part
 *
 * See RFC4996 page 73/74
 */
typedef struct
{
	uint16_t src_port;          /**< irregular(16)                          [ 16 ] */
	uint16_t dst_port;          /**< irregular(16)                          [ 16 ] */
} __attribute__((packed)) tcp_static_t;


/**
 * @brief The TCP dynamic part
 *
 * See RFC4996 page 73/74
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t ecn_used:1;         /**< one_bit_choice                         [ 1 ] */
	uint8_t ack_stride_flag:1;  /**< irregular(1)                           [ 1 ] */
	uint8_t ack_zero:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t urp_zero:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t tcp_res_flags:4;    /**< irregular(4)                           [ 4 ] */

	uint8_t tcp_ecn_flags:2;    /**< irregular(2)                           [ 2 ] */
	uint8_t urg_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t ack_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t rsf_flags:3;        /**< irregular(3)                           [ 3 ] */
#else
	uint8_t tcp_res_flags:4;
	uint8_t urp_zero:1;
	uint8_t ack_zero:1;
	uint8_t ack_stride_flag:1;
	uint8_t ecn_used:1;

	uint8_t rsf_flags:3;
	uint8_t psh_flag:1;
	uint8_t ack_flag:1;
	uint8_t urg_flag:1;
	uint8_t tcp_ecn_flags:2;
#endif
	uint16_t msn;               /**< irregular(16)                          [ 16 ] */
	uint32_t seq_num;           /**< irregular(32)                          [ 32 ] */

	/* variable fields:
	 *   zero_or_irreg(ack_zero.CVALUE, 32)                                 [ 0, 32 ]
	 *   irregular(16)                                                      [ 16 ]
	 *   irregular(16)                                                      [ 16 ]
	 *   zero_or_irreg(urp_zero.CVALUE, 16)                                 [ 0, 16 ]
	 *   static_or_irreg(ack_stride_flag.CVALUE, 16)                        [ 0, 16 ]
	 *   list_tcp_options                                                   [ VARIABLE ]
	 */

} __attribute__((packed)) tcp_dynamic_t;


/**
 * @brief The different presence flags for port_replicate() encoding scheme
 */
enum
{
	ROHC_TCP_PORT_STATIC    = 0, /**< port is static, so it is not transmitted */
	ROHC_TCP_PORT_LSB8      = 1, /**< port is not static and it is compressible */
	ROHC_TCP_PORT_IRREGULAR = 2, /**< port is not static and it is not compressible */
	ROHC_TCP_PORT_RESERVED  = 3, /**< reserved value */
};


/**
 * @brief The TCP replicate part
 *
 * See RFC6846 pages 75-76
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t reserved:1;           /**< reserved '0'                      [ 1 ] */
	uint8_t window_presence:1;    /**< irregular(1)                      [ 1 ] */
	uint8_t list_present:1;       /**< irregular(1)                      [ 1 ] */
	uint8_t src_port_presence:2;  /**< irregular(2)                      [ 2 ] */
	uint8_t dst_port_presence:2;  /**< irregular(2)                      [ 2 ] */
	uint8_t ack_stride_flag:1;    /**< irregular(1)                      [ 1 ] */

	uint8_t ack_presence:1;       /**< irregular(1)                      [ 1 ] */
	uint8_t urp_presence:1;       /**< irregular(1)                      [ 1 ] */
	uint8_t urg_flag:1;           /**< irregular(1)                      [ 1 ] */
	uint8_t ack_flag:1;           /**< irregular(1)                      [ 1 ] */
	uint8_t psh_flag:1;           /**< irregular(1)                      [ 1 ] */
	uint8_t rsf_flags:2;          /**< rsf_index_enc                     [ 2 ] */
	uint8_t ecn_used:1;           /**< one_bit_choice                    [ 1 ] */
#else
	uint8_t ack_stride_flag:1;
	uint8_t dst_port_presence:2;
	uint8_t src_port_presence:2;
	uint8_t list_present:1;
	uint8_t window_presence:1;
	uint8_t reserved:1;

	uint8_t ecn_used:1;
	uint8_t rsf_flags:2;
	uint8_t psh_flag:1;
	uint8_t ack_flag:1;
	uint8_t urg_flag:1;
	uint8_t urp_presence:1;
	uint8_t ack_presence:1;
#endif
	uint16_t msn;               /**< irregular(16)                          [ 16 ] */
	uint32_t seq_num;           /**< irregular(32)                          [ 32 ] */

	/* variable fields:
	 *   src_port      =:= port_replicate(src_port_presence)            [ 0, 8, 16 ]
	 *   dst_port      =:= port_replicate(dst_port_presence)            [ 0, 8, 16 ]
	 *   window        =:= static_or_irreg(window_presence, 16)         [ 0, 16 ]
	 *   urg_point     =:= static_or_irreg(urp_presence, 16)            [ 0, 16 ]
	 *   ack_number    =:= static_or_irreg(ack_presence, 32)            [ 0, 32 ]
	 *   ecn_padding   =:= optional_2bit_padding(ecn_used.CVALUE)       [ 0, 2 ]
	 *   tcp_res_flags =:= static_or_irreg(ecn_used.CVALUE, 4)          [ 0, 4 ]
	 *   tcp_ecn_flags =:= static_or_irreg(ecn_used.CVALUE, 2)          [ 0, 2 ]
	 *   checksum      =:= irregular(16)                                [ 16 ]
	 *   ack_stride    =:= static_or_irreg(ack_stride_flag.CVALUE, 16)  [ 0, 16 ]
	 *   options       =:= tcp_list_presence_enc(list_present.CVALUE)   [ VARIABLE ]
	 */

} __attribute__((packed)) tcp_replicate_t;


/**
 * @brief The Common compressed packet format
 *
 * See RFC4996 page 80/81
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1

	uint8_t discriminator:7;         /**< '1111101'                         [ 7 ] */
	uint8_t ttl_hopl_outer_flag:1;   /**< compressed_value(1,
												           ttl_irregular_chain_flag)   [ 1 ] */

	uint8_t ack_flag:1;              /**< irregular(1)                      [ 1 ] */
	uint8_t psh_flag:1;              /**< irregular(1)                      [ 1 ] */
	uint8_t rsf_flags:2;             /**< rsf_index_enc                     [ 2 ] */
	uint8_t msn:4;                   /**< lsb(4, 4)                         [ 4 ] */

	uint8_t seq_indicator:2;         /**< irregular(2)                      [ 2 ] */
	uint8_t ack_indicator:2;         /**< irregular(2)                      [ 2 ] */
	uint8_t ack_stride_indicator:1;  /**< irregular(1)                      [ 1 ] */
	uint8_t window_indicator:1;      /**< irregular(1)                      [ 1 ] */
	uint8_t ip_id_indicator:1;       /**< irregular(1)                      [ 1 ] */
	uint8_t urg_ptr_present:1;       /**< irregular(1)                      [ 1 ] */

	uint8_t reserved:1;              /**< compressed_value(1, 0)            [ 1 ] */
	uint8_t ecn_used:1;              /**< one_bit_choice                    [ 1 ] */
	uint8_t dscp_present:1;          /**< irregular(1)                      [ 1 ] */
	uint8_t ttl_hopl_present:1;      /**< irregular(1)                      [ 1 ] */
	uint8_t list_present:1;          /**< irregular(1)                      [ 1 ] */
	uint8_t ip_id_behavior:2;        /**< ip_id_behavior_choice(true)       [ 2 ] */
	uint8_t urg_flag:1;              /**< irregular(1)                      [ 1 ] */

	uint8_t df:1;                    /**< dont_fragment(version.UVALUE)     [ 1 ] */
	uint8_t header_crc:7;            /**< crc7(THIS.UVALUE,THIS.ULENGTH)    [ 7 ] */

#else

	uint8_t ttl_hopl_outer_flag:1;
	uint8_t discriminator:7;

	uint8_t msn:4;
	uint8_t rsf_flags:2;
	uint8_t psh_flag:1;
	uint8_t ack_flag:1;

	uint8_t urg_ptr_present:1;
	uint8_t ip_id_indicator:1;
	uint8_t window_indicator:1;
	uint8_t ack_stride_indicator:1;
	uint8_t ack_indicator:2;
	uint8_t seq_indicator:2;

	uint8_t urg_flag:1;
	uint8_t ip_id_behavior:2;
	uint8_t list_present:1;
	uint8_t ttl_hopl_present:1;
	uint8_t dscp_present:1;
	uint8_t ecn_used:1;
	uint8_t reserved:1;

	uint8_t header_crc:7;
	uint8_t df:1;

#endif

	/* variable fields:
	 *   variable_length_32_enc(seq_indicator.CVALUE)                       [ 0, 8, 16, 32 ]
	 *   variable_length_32_enc(ack_indicator.CVALUE)                       [ 0, 8, 16, 32 ]
	 *   static_or_irreg(ack_stride_indicator.CVALUE, 16)                   [ 0, 16 ]
	 *   static_or_irreg(window_indicator.CVALUE, 16)                       [ 0, 16 ]
	 *   optional_ip_id_lsb(ip_id_behavior.UVALUE,ip_id_indicator.CVALUE)   [ 0, 8, 16 ]
	 *   static_or_irreg(urg_ptr_present.CVALUE, 16)                        [ 0, 16 ]
	 *   dscp_enc-dscp_present.CVALUE)                                      [ 0, 8 ]
	 *   static_or_irreg(ttl_hopl_present.CVALUE, 8)                        [ 0, 8 ]
	 *   tcp_list_presence_enc(list_present.CVALUE)                         [ VARIABLE ]
	 *   irregular chain                                                    [ VARIABLE ]
	 */

} __attribute__((packed)) co_common_t;


/**
 * @brief The rnd_1 compressed packet format
 *
 * Send LSBs of sequence number
 * See RFC4996 page 81
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:6;    /**< '101110'                               [  6 ] */
	uint8_t seq_num1:2;         /**< lsb(18, 65535)                         [ 18 ] */
	uint16_t seq_num2;          /**< sequel of \e seq_num1                  [  - ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t seq_num1:2;
	uint8_t discriminator:6;
	uint16_t seq_num2;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_1_t;


/**
 * @brief The rnd_2 compressed packet format
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 81
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1100'                                 [ 4 ] */
	uint8_t seq_num_scaled:4;   /**< lsb(4, 7)                              [ 4 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t seq_num_scaled:4;
	uint8_t discriminator:4;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_2_t;


/**
 * @brief The rnd_3 compressed packet format
 *
 * Send acknowledgment number LSBs
 * See RFC4996 page 81
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:1;    /**< '0'                                    [  1 ] */
	uint8_t ack_num1:7;         /**< lsb(15, 8191)                          [ 15 ] */
	uint8_t ack_num2;           /**< sequel of \e ack_num1                  [  - ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t ack_num1:7;
	uint8_t discriminator:1;
	uint8_t ack_num2:8;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_3_t;


/**
 * @brief The rnd_4 compressed packet format
 *
 * Send acknowlegment number scaled
 * See RFC4996 page 81
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1101'                                 [ 4 ] */
	uint8_t ack_num_scaled:4;   /**< lsb(4, 3)                              [ 4 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t ack_num_scaled:4;
	uint8_t discriminator:4;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_4_t;


/**
 * @brief The rnd_5 compressed packet format
 *
 * Send ACK and sequence number
 * See RFC4996 page 82
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:3;    /**< '100'                                  [  3 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint32_t header_crc:3;      /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
	uint32_t seq_num1:5;        /**< lsb(14, 8191)                          [ 14 ] */
	uint32_t seq_num2:8;        /**< sequel of \e seq_num1                  [  - ] */
	uint32_t seq_num3:1;        /**< sequel of \e seq_num1 and \e seq_num2  [  - ] */
	uint32_t ack_num1:7;        /**< lsb(15, 8191)                          [ 15 ] */
	uint32_t ack_num2:8;        /**< sequel of \e ack_num1                  [  - ] */
#else
	uint8_t msn:4;
	uint8_t psh_flag:1;
	uint8_t discriminator:3;
	uint8_t seq_num1:5;
	uint8_t header_crc:3;
	uint8_t seq_num2;
	uint8_t ack_num1:7;
	uint8_t seq_num3:1;
	uint8_t ack_num2;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_5_t;


/**
 * @brief The rnd_6 compressed packet format
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 82
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1010'                                 [ 4 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
#else
	uint8_t psh_flag:1;
	uint8_t header_crc:3;
	uint8_t discriminator:4;
#endif
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t seq_num_scaled:4;   /**< lsb(4, 7)                              [ 4 ] */
#else
	uint8_t seq_num_scaled:4;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_6_t;


/**
 * @brief The rnd_7 compressed packet format
 *
 * Send ACK and window
 * See RFC4996 page 82
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:6;    /**< '101111'                               [ 6 ] */
	uint8_t ack_num1:2;         /**< lsb(18, 65535)                         [ 18 ] */
	uint16_t ack_num2;          /**< sequel of \e ack_num1                  [ - ]*/
#else
	uint8_t ack_num1:2;
	uint8_t discriminator:6;
	uint16_t ack_num2;
#endif
	uint16_t window;            /**< irregular(16)                          [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_7_t;


/**
 * @brief The rnd_8 compressed packet format
 *
 * Can send LSBs of TTL, RSF flags, change ECN behavior and options list
 * See RFC4996 page 82
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:5;    /**< '10110'                                [ 5 ] */
	uint8_t rsf_flags:2;        /**< rsf_index_enc                          [ 2 ] */
	uint8_t list_present:1;     /**< irregular(1)                           [ 1 ] */
	uint16_t header_crc:7;      /**< crc7(THIS.UVALUE, THIS.ULENGTH)        [ 7 ] */
	uint16_t msn1:1;            /**< lsb(4, 4)                              [ 4 ] */
	uint16_t msn2:3;            /**< sequel of \e msn1                      [ - ] */
	uint16_t psh_flag:1;        /**< irregular(1)                           [ 1 ] */
	uint16_t ttl_hopl:3;        /**< lsb(3, 3)                              [ 3 ] */
	uint16_t ecn_used:1;        /**< one_bit_choice                         [ 1 ] */
#else
	uint8_t list_present:1;
	uint8_t rsf_flags:2;
	uint8_t discriminator:5;
	uint8_t msn1:1;
	uint8_t header_crc:7;
	uint8_t ecn_used:1;
	uint8_t ttl_hopl:3;
	uint8_t psh_flag:1;
	uint8_t msn2:3;
#endif
	uint16_t seq_num;           /**< lsb(16, 65535)                         [ 16 ] */
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
	uint8_t options[0];         /**< tcp_list_presence_enc(list_present.CVALUE)
	                                                                        [ VARIABLE ] */
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) rnd_8_t;


/**
 * @brief The seq_1 compressed packet format
 *
 * Send LSBs of sequence number
 * See RFC4996 page 83
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1010'                                 [ 4 ] */
	uint8_t ip_id:4;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 4, 3) [ 4 ] */
#else
	uint8_t ip_id:4;
	uint8_t discriminator:4;
#endif
	uint16_t seq_num;           /**< lsb(16, 32767)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_1_t;


/**
 * @brief The seq_2 compressed packet format
 *
 * Send scaled sequence number LSBs
 * See RFC4996 page 83
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint16_t discriminator:5;   /**< '11010'                                [ 5 ] */
	uint16_t ip_id1:3;          /**< ip_id_lsb(ip_id_behavior.UVALUE, 7, 3) [ 7 ] */
	uint16_t ip_id2:4;          /**< sequel of ip_id1                       [ - ] */
	uint16_t seq_num_scaled:4;  /**< lsb(4, 7)                              [ 4 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t ip_id1:3;
	uint8_t discriminator:5;
	uint8_t seq_num_scaled:4;
	uint8_t ip_id2:4;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_2_t;


/**
 * @brief The seq_3 compressed packet format
 *
 * Send acknowledgment number LSBs
 * See RFC4996 page 83
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1001'                                 [  4 ] */
	uint8_t ip_id:4;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 4, 3) [  4 ] */
#else
	uint8_t ip_id:4;
	uint8_t discriminator:4;
#endif
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_3_t;


/**
 * @brief The seq_4 compressed packet format
 *
 * Send scaled acknowledgment number scaled
 * See RFC4996 page 84
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:1;    /**< '0'                                    [ 1 ] */
	uint8_t ack_num_scaled:4;   /**< lsb(4, 3)                              [ 4 ] */
	uint8_t ip_id:3;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 3, 1) [ 3 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t ip_id:3;
	uint8_t ack_num_scaled:4;
	uint8_t discriminator:1;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_4_t;


/**
 * @brief The seq_5 compressed packet format
 *
 * Send ACK and sequence number
 * See RFC4996 page 84
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1000'                                 [  4 ] */
	uint8_t ip_id:4;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 4, 3) [  4 ] */
#else
	uint8_t ip_id:4;
	uint8_t discriminator:4;
#endif
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
	uint16_t seq_num;           /**< lsb(16, 32767)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_5_t;


/**
 * @brief The seq_6 compressed packet format
 *
 * Send both ACK and scaled sequence number LSBs
 * See RFC4996 page 84
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint16_t discriminator:5;   /**< '11011'                                [  5 ] */
	uint16_t seq_num_scaled1:3; /**< lsb(4, 7)                              [  4 ] */
	uint16_t seq_num_scaled2:1; /**< sequel of \e seq_num_scaled1           [  4 ] */
	uint16_t ip_id:7;           /**< ip_id_lsb(ip_id_behavior.UVALUE, 7, 3) [  7 ] */
#else
	uint8_t seq_num_scaled1:3;
	uint8_t discriminator:5;
	uint8_t ip_id:7;
	uint8_t seq_num_scaled2:1;
#endif
	uint16_t ack_num;           /**< lsb(16, 16383)                         [ 16 ] */
#if WORDS_BIGENDIAN == 1
	uint8_t msn:4;              /**< lsb(4, 4)                              [ 4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [ 1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [ 3 ] */
#else
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_6_t;


/**
 * @brief The seq_7 compressed packet format
 *
 * Send ACK and window
 * See RFC4996 page 85
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1100'                                 [  4 ] */
	uint8_t window1:4;          /**< lsb(15, 16383)                         [ 15 ] */
	uint8_t window2;            /**< sequel of \e window1                   [  - ] */
	uint8_t window3:3;          /**< sequel of \e window1 and \e window2    [  - ] */
	uint8_t ip_id:5;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 5, 3) [  5 ] */
	uint16_t ack_num;           /**< lsb(16, 32767)                         [ 16 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:3;       /**< crc3(THIS.UVALUE, THIS.ULENGTH)        [  3 ] */
#else
	uint8_t window1:4;
	uint8_t discriminator:4;
	uint8_t window2;
	uint8_t ip_id:5;
	uint8_t window3:3;
	uint16_t ack_num;
	uint8_t header_crc:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
#endif
	/* irregular chain                                                      [ VARIABLE ] */
} __attribute__((packed)) seq_7_t;


/**
 * @brief The seq_8 compressed packet format
 *
 * Can send LSBs of TTL, RSF flags, change ECN behavior, and options list
 * See RFC4996 page 85
 */
typedef struct
{
#if WORDS_BIGENDIAN == 1
	uint8_t discriminator:4;    /**< '1011'                                 [  4 ] */
	uint8_t ip_id:4;            /**< ip_id_lsb(ip_id_behavior.UVALUE, 4, 3) [  4 ] */
	uint8_t list_present:1;     /**< irregular(1)                           [  1 ] */
	uint8_t header_crc:7;       /**< crc7(THIS.UVALUE, THIS.ULENGTH)        [  7 ] */
	uint8_t msn:4;              /**< lsb(4, 4)                              [  4 ] */
	uint8_t psh_flag:1;         /**< irregular(1)                           [  1 ] */
	uint8_t ttl_hopl:3;         /**< lsb(3, 3)                              [  3 ] */
	uint8_t ecn_used:1;         /**< one_bit_choice                         [  1 ] */
	uint8_t ack_num1:7;         /**< lsb(15, 8191)                          [ 15 ] */
	uint8_t ack_num2;           /**< sequel of \e ack_num1                  [  - ] */
	uint8_t rsf_flags:2;        /**< rsf_index_enc                          [  2 ] */
	uint8_t seq_num1:6;         /**< lsb(14, 8191)                          [ 14 ] */
	uint8_t seq_num2;           /**< sequel of \e seq_num1                  [  - ] */
#else
	uint8_t ip_id:4;
	uint8_t discriminator:4;
	uint8_t header_crc:7;
	uint8_t list_present:1;
	uint8_t ttl_hopl:3;
	uint8_t psh_flag:1;
	uint8_t msn:4;
	uint8_t ack_num1:7;
	uint8_t ecn_used:1;
	uint8_t ack_num2;
	uint8_t seq_num1:6;
	uint8_t rsf_flags:2;
	uint8_t seq_num2:8;
#endif
	uint8_t options[0];       /**< tcp_list_presence_enc(list_present.CVALUE)
	                                                                      [ VARIABLE ] */
	/* irregular chain                                                    [ VARIABLE ] */
} __attribute__((packed)) seq_8_t;



/************************************************************************
 * Helper functions                                                     *
 ************************************************************************/

static inline char * tcp_ip_id_behavior_get_descr(const tcp_ip_id_behavior_t ip_id_behavior)
	__attribute__((warn_unused_result, const));


/**
 * @brief Get a string that describes the given IP-ID behavior
 *
 * @param behavior  The type of the option to get a description for
 * @return          The description of the option
 */
static inline char * tcp_ip_id_behavior_get_descr(const tcp_ip_id_behavior_t behavior)
{
	switch(behavior)
	{
		case IP_ID_BEHAVIOR_SEQ:
			return "sequential";
		case IP_ID_BEHAVIOR_SEQ_SWAP:
			return "sequential swapped";
		case IP_ID_BEHAVIOR_RAND:
			return "random";
		case IP_ID_BEHAVIOR_ZERO:
			return "constant zero";
		default:
			return "unknown IP-ID behavior";
	}
}

#endif /* ROHC_PROTOCOLS_RFC6846_H */

