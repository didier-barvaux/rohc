--
-- Copyright 2016 Didier Barvaux
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
--
-- @file   rohc_rfc3095.lua
-- @brief  Wireshark dissector helpers for the RFC3095 profiles of the ROHC protocol
-- @author Didier Barvaux <didier@barvaux.org>
--

-- static chain
local f_chain_static = ProtoField.bytes("rohc_lua.pkt.chain.static", "Static chain")
---- IPv4 part
local f_chain_static_ipv4 = ProtoField.bytes("rohc_lua.pkt.chain.static.ipv4", "IPv4 static chain")
local f_chain_static_ipv4_version  = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv4.version",
                                                      "Version", base.DEC, nil, 0xf0)
local f_chain_static_ipv4_padding  = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv4.padding",
                                                      "Padding", base.HEX, nil, 0x0f)
local f_chain_static_ipv4_protocol = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv4.protocol",
                                                      "Protocol", base.DEC)
local f_chain_static_ipv4_srcaddr  = ProtoField.ipv4("rohc_lua.pkt.chain.static.ipv4.saddr",
                                                     "Source address")
local f_chain_static_ipv4_dstaddr  = ProtoField.ipv4("rohc_lua.pkt.chain.static.ipv4.daddr",
                                                     "Destination address")
---- IPv6 part
local f_chain_static_ipv6 = ProtoField.bytes("rohc_lua.pkt.chain.static.ipv6", "IPv6 static chain")
local f_chain_static_ipv6_version   = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv6.version",
                                                       "Version", base.DEC, nil, 0xf0)
local f_chain_static_ipv6_flowlabel = ProtoField.bytes("rohc_lua.pkt.chain.static.ipv6.flow_label",
                                                       "Flow Label")
local f_chain_static_ipv6_next_hdr  = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv6.next_header",
                                                       "Next header", base.DEC)
local f_chain_static_ipv6_srcaddr  = ProtoField.ipv6("rohc_lua.pkt.chain.static.ipv6.saddr",
                                                     "Source address")
local f_chain_static_ipv6_dstaddr  = ProtoField.ipv6("rohc_lua.pkt.chain.static.ipv6.daddr",
                                                     "Destination address")
-- UDP part
local f_chain_static_udp = ProtoField.bytes("rohc_lua.pkt.chain.static.udp", "UDP static chain")
local f_chain_static_udp_srcport = ProtoField.uint16("rohc_lua.pkt.chain.static.udp.sport",
                                                     "Source port")
local f_chain_static_udp_dstport = ProtoField.uint16("rohc_lua.pkt.chain.static.udp.dport",
                                                     "Destination port")

-- dynamic chain
local f_chain_dyn = ProtoField.bytes("rohc_lua.pkt.chain.dynamic", "Dynamic chain")
---- IPv4 part
local f_chain_dyn_ipv4 = ProtoField.bytes("rohc_lua.pkt.chain.dynamic.ipv4", "IPv4 dynamic chain")
local f_chain_dyn_ipv4_tos     = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.tos",
                                                  "Type Of Service (TOS)", base.HEX)
local f_chain_dyn_ipv4_ttl     = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.ttl",
                                                  "Time To Live (TTL)", base.DEC)
local f_chain_dyn_ipv4_id      = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.ipv4.id",
                                                   "Identifier (IP-ID)", base.DEC)
local f_chain_dyn_ipv4_df      = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.df",
                                                  "Don't Fragment (DF)", base.DEC, nil, 0x80)
local f_chain_dyn_ipv4_rnd     = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.rnd",
                                                  "Random (RND)", base.DEC, nil, 0x40)
local f_chain_dyn_ipv4_nbo     = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.nbo",
                                                  "Network Byte Order (NBO)", base.DEC, nil, 0x20)
local f_chain_dyn_ipv4_padding = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.padding",
                                                  "Padding", base.HEX, nil, 0x0f)
---- IPv6 part
local f_chain_dyn_ipv6 = ProtoField.bytes("rohc_lua.pkt.chain.dynamic.ipv6", "IPv6 dynamic chain")
local f_chain_dyn_ipv6_tc = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv6.tc",
                                             "Traffic Class (TC)", base.HEX)
local f_chain_dyn_ipv6_hl = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv6.hl",
                                             "Hop Limit (HL)", base.DEC)
-- UDP part
local f_chain_dyn_udp = ProtoField.bytes("rohc_lua.pkt.chain.dynamic.udp", "UDP dynamic chain")
local f_chain_dyn_udp_check = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.udp.checksum",
                                                "Checksum", base.HEX)
-- additional SN for non-RTP profiles
local f_chain_dyn_sn = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.sn",
                                         "Sequence Number (SN)", base.DEC)

-- List encoding
local f_list = ProtoField.bytes("rohc_lua.pkt.list", "Compressed list")
---- generic fields
local f_list_et     = ProtoField.uint8("rohc_lua.pkt.list.et", "Encoding Type (ET)",
                                       base.DEC, nil, 0xc0)
local f_list_gp     = ProtoField.uint8("rohc_lua.pkt.list.gp", "gen_id present (GP)",
                                       base.DEC, nil, 0x20)
local f_list_ps     = ProtoField.uint8("rohc_lua.pkt.list.ps", "Size of XI fields",
                                       base.DEC, nil, 0x10)
local f_list_xi1    = ProtoField.uint8("rohc_lua.pkt.list.xi1", "XI 1",
                                       base.HEX, nil, 0x0f)
local f_list_gen_id = ProtoField.uint8("rohc_lua.pkt.list.gen_id", "gen_id", base.DEC)
local f_list_ref_id = ProtoField.uint8("rohc_lua.pkt.list.ref_id", "ref_id", base.DEC)
---- insertion/removal bitmasks
local f_list_bitmask_ins  = ProtoField.bytes("rohc_lua.pkt.list.bitmask.insertion",
                                             "Insertion bitmask")
local f_list_bitmask_rem  = ProtoField.bytes("rohc_lua.pkt.list.bitmask.removal",
                                             "Removal bitmask")
local f_list_bitmask_type = ProtoField.uint8("rohc_lua.pkt.list.bitmask.type",
                                             "Bitmask type", base.DEC, nil, 0x80)
local f_list_bitmask_7b   = ProtoField.uint8("rohc_lua.pkt.list.bitmask.mask.7b",
                                             "Bitmask (7 bits)", base.HEX, nil, 0x7f)
local f_list_bitmask_15b  = ProtoField.uint16("rohc_lua.pkt.list.bitmask.mask.15b",
                                              "Bitmask (15 bits)", base.HEX, nil, 0x7fff)
---- XI and item lists
local f_list_xi      = ProtoField.bytes("rohc_lua.pkt.list.xi", "XI fields")
local f_list_xi_4bo  = ProtoField.uint8("rohc_lua.pkt.list.xi_4b_odd", "XI (PS = 0)",
                                               base.HEX, nil, 0xf0)
local f_list_xi_4be  = ProtoField.uint8("rohc_lua.pkt.list.xi_4b_even", "XI (PS = 0)",
                                               base.HEX, nil, 0x0f)
local f_list_xi_4bp  = ProtoField.uint8("rohc_lua.pkt.list.xi_4b_padding", "XI padding",
                                               base.HEX, nil, 0x0f)
local f_list_xi_8b   = ProtoField.uint8("rohc_lua.pkt.list.xi0", "XI (PS = 1)", base.HEX)
local f_list_items   = ProtoField.bytes("rohc_lua.pkt.list.items", "List items")
local f_list_item    = ProtoField.bytes("rohc_lua.pkt.list.items.item", "List item")
---- list encoding type 0
local f_list_type_0_m      = ProtoField.uint8("rohc_lua.pkt.list.m", "Number of XI fields",
                                              base.DEC, nil, 0x0f)
---- list encoding type 2
local f_list_type_2_res    = ProtoField.uint8("rohc_lua.pkt.list.res", "Reserved",
                                              base.DEC, nil, 0x10)
local f_list_type_2_count  = ProtoField.uint8("rohc_lua.pkt.list.count",
                                              "Number of elements in reference list",
                                              base.DEC, nil, 0x0f)

-- IPv6 options
local ipv6_opt_types = {
	[0]   = "Hop-by-Hop option",
	[43]  = "IPv6 Routing header",
	[44]  = "IPv6 Fragment header",
	[60]  = "IPv6 destination option",
	[135] = "Mobility header",
}
local f_ipv6_opt_type = ProtoField.uint8("rohc_lua.pkt.list.items.item.ipv6_opt.type",
                                         "IPv6 option type", base.DEC, ipv6_opt_types)
local f_ipv6_opt_len = ProtoField.uint8("rohc_lua.pkt.list.items.item.ipv6_opt.len",
                                         "IPv6 option data length", base.DEC)
local f_ipv6_opt_data = ProtoField.bytes("rohc_lua.pkt.list.items.item.ipv6_opt.data",
                                         "IPv6 option data")

-- UO-0 packet
local f_pkt_uo0      = ProtoField.bytes("rohc_lua.pkt.uo0", "UO-0")
local f_pkt_uo0_type = ProtoField.uint8("rohc_lua.pkt.uo0.type", "UO-0 type octet",
                                        base.HEX, nil, 0x80)
local f_pkt_uo0_sn   = ProtoField.uint8("rohc_lua.pkt.uo0.sn", "SN", base.DEC, nil, 0x78)
local f_pkt_uo0_crc3 = ProtoField.uint8("rohc_lua.pkt.uo0.crc3", "CRC", base.HEX, nil, 0x07)

-- UO-1 packet
local f_pkt_uo1       = ProtoField.bytes("rohc_lua.pkt.uo1", "UO-1")
local f_pkt_uo1_type  = ProtoField.uint8("rohc_lua.pkt.uo1.type", "UO-1 type octet",
                                         base.HEX, nil, 0xc0)
local f_pkt_uo1_ip_id = ProtoField.uint8("rohc_lua.pkt.uo1.ip_id", "IP-ID", base.DEC, nil, 0x3f)
local f_pkt_uo1_sn    = ProtoField.uint8("rohc_lua.pkt.uo1.sn", "SN", base.DEC, nil, 0xf8)
local f_pkt_uo1_crc3  = ProtoField.uint8("rohc_lua.pkt.uo1.crc3", "CRC", base.HEX, nil, 0x07)

-- UOR-2 packet
local f_pkt_uor2      = ProtoField.bytes("rohc_lua.pkt.uor2", "UOR-2")
local f_pkt_uor2_type = ProtoField.uint8("rohc_lua.pkt.uor2.type", "UOR-2 type octet",
                                         base.HEX, nil, 0xe0)
local f_pkt_uor2_sn   = ProtoField.uint8("rohc_lua.pkt.uor2.sn", "SN", base.DEC, nil, 0x1f)
local f_pkt_uor2_x    = ProtoField.uint8("rohc_lua.pkt.uor2.x", "X", base.DEC, nil, 0x80)
local f_pkt_uor2_crc7 = ProtoField.uint8("rohc_lua.pkt.uor2.crc7", "CRC", base.HEX, nil, 0x7f)

-- UOR extension 0
local f_pkt_uor_ext0       = ProtoField.bytes("rohc_lua.pkt.ext0", "Extension 0")
local f_pkt_uor_ext0_type  = ProtoField.uint8("rohc_lua.pkt.ext0.type",
                                              "Extension 0 type octet", base.HEX, nil, 0xc0)
local f_pkt_uor_ext0_sn    = ProtoField.uint8("rohc_lua.pkt.ext0.sn", "SN",
                                              base.DEC, nil, 0x38)
local f_pkt_uor_ext0_ip_id = ProtoField.uint8("rohc_lua.pkt.ext0.ip_id", "IP-ID",
                                              base.DEC, nil, 0x07)

-- UOR extension 1
local f_pkt_uor_ext1       = ProtoField.bytes("rohc_lua.pkt.ext1", "Extension 1")
local f_pkt_uor_ext1_type  = ProtoField.uint8("rohc_lua.pkt.ext1.type",
                                              "Extension 1 type octet", base.HEX, nil, 0xc0)
local f_pkt_uor_ext1_sn    = ProtoField.uint8("rohc_lua.pkt.ext1.sn", "SN",
                                              base.DEC, nil, 0x38)
local f_pkt_uor_ext1_ip_id = ProtoField.uint16("rohc_lua.pkt.ext1.ip_id", "IP-ID",
                                               base.DEC, nil, 0x07ff)

-- UOR extension 2
local f_pkt_uor_ext2         = ProtoField.bytes("rohc_lua.pkt.ext2", "Extension 2")
local f_pkt_uor_ext2_type    = ProtoField.uint8("rohc_lua.pkt.ext2.type",
                                                "Extension 2 type octet", base.HEX, nil, 0xc0)
local f_pkt_uor_ext2_sn      = ProtoField.uint8("rohc_lua.pkt.ext1.sn", "SN",
                                                base.DEC, nil, 0x38)
local f_pkt_uor_ext2_ip_id_2 = ProtoField.uint16("rohc_lua.pkt.ext2.ip_id2",
                                                 "outer IP-ID", base.DEC, nil, 0x07ff)
local f_pkt_uor_ext2_ip_id   = ProtoField.uint8("rohc_lua.pkt.ext2.ip_id",
                                                "inner IP-ID", base.DEC)

-- UOR extension 3
local f_pkt_uor_ext3       = ProtoField.bytes("rohc_lua.pkt.ext3", "Extension 3")
local f_pkt_uor_ext3_type  = ProtoField.uint8("rohc_lua.pkt.ext3.type",
                                              "Extension 3 type octet", base.HEX, nil, 0xc0)
local f_pkt_uor_ext3_flags = ProtoField.bytes("rohc_lua.pkt.ext3.flags", "Extension 3 flags")
local f_pkt_uor_ext3_S     = ProtoField.uint8("rohc_lua.pkt.ext3.S", "S", base.DEC, nil, 0x20)
local f_pkt_uor_ext3_mode  = ProtoField.uint8("rohc_lua.pkt.ext3.mode", "Mode", base.DEC, nil, 0x18)
local f_pkt_uor_ext3_I     = ProtoField.uint8("rohc_lua.pkt.ext3.I", "I", base.DEC, nil, 0x04)
local f_pkt_uor_ext3_ip    = ProtoField.uint8("rohc_lua.pkt.ext3.ip", "ip", base.DEC, nil, 0x02)
local f_pkt_uor_ext3_ip2   = ProtoField.uint8("rohc_lua.pkt.ext3.ip2", "ip2", base.DEC, nil, 0x01)
-- inner IP header flags
local f_pkt_uor_ext3_inner_flags =
	ProtoField.bytes("rohc_lua.pkt.ext3.inner_flags", "Inner IP header flags")
local f_pkt_uor_ext3_tos = ProtoField.uint8("rohc_lua.pkt.ext3.tos", "tos", base.DEC, nil, 0x80)
local f_pkt_uor_ext3_ttl = ProtoField.uint8("rohc_lua.pkt.ext3.ttl", "ttl", base.DEC, nil, 0x40)
local f_pkt_uor_ext3_df  = ProtoField.uint8("rohc_lua.pkt.ext3.df", "df", base.DEC, nil, 0x20)
local f_pkt_uor_ext3_pr  = ProtoField.uint8("rohc_lua.pkt.ext3.pr", "pr", base.DEC, nil, 0x10)
local f_pkt_uor_ext3_ipx = ProtoField.uint8("rohc_lua.pkt.ext3.ipx", "ipx", base.DEC, nil, 0x08)
local f_pkt_uor_ext3_nbo = ProtoField.uint8("rohc_lua.pkt.ext3.nbo", "nbo", base.DEC, nil, 0x04)
local f_pkt_uor_ext3_rnd = ProtoField.uint8("rohc_lua.pkt.ext3.rnd", "rnd", base.DEC, nil, 0x02)
local f_pkt_uor_ext3_reserved = ProtoField.uint8("rohc_lua.pkt.ext3.reserved", "reserved", base.HEX, nil, 0x01)
-- outer IP header flags
local f_pkt_uor_ext3_outer_flags =
	ProtoField.bytes("rohc_lua.pkt.ext3.outer_flags", "Outer IP header flags")
local f_pkt_uor_ext3_tos2 = ProtoField.uint8("rohc_lua.pkt.ext3.tos2", "tos2", base.DEC, nil, 0x80)
local f_pkt_uor_ext3_ttl2 = ProtoField.uint8("rohc_lua.pkt.ext3.ttl2", "ttl2", base.DEC, nil, 0x40)
local f_pkt_uor_ext3_df2  = ProtoField.uint8("rohc_lua.pkt.ext3.df2", "df2", base.DEC, nil, 0x20)
local f_pkt_uor_ext3_pr2  = ProtoField.uint8("rohc_lua.pkt.ext3.pr2", "pr2", base.DEC, nil, 0x10)
local f_pkt_uor_ext3_ipx2 = ProtoField.uint8("rohc_lua.pkt.ext3.ipx2", "ipx2", base.DEC, nil, 0x08)
local f_pkt_uor_ext3_nbo2 = ProtoField.uint8("rohc_lua.pkt.ext3.nbo2", "nbo2", base.DEC, nil, 0x04)
local f_pkt_uor_ext3_rnd2 = ProtoField.uint8("rohc_lua.pkt.ext3.rnd2", "rnd2", base.DEC, nil, 0x02)
local f_pkt_uor_ext3_I2   = ProtoField.uint8("rohc_lua.pkt.ext3.I2", "I2", base.DEC, nil, 0x01)
-- SN
local f_pkt_uor_ext3_sn   = ProtoField.uint8("rohc_lua.pkt.ext3.sn", "SN", base.DEC)
-- inner IP header fields
local f_pkt_uor_ext3_inner_fields =
	ProtoField.bytes("rohc_lua.pkt.ext3.inner_fields", "Inner IP header fields")
local f_pkt_uor_ext3_inner_tos   = ProtoField.uint8("rohc_lua.pkt.ext3.tos", "Inner TOS", base.HEX)
local f_pkt_uor_ext3_inner_ttl   = ProtoField.uint8("rohc_lua.pkt.ext3.ttl", "Inner TTL", base.DEC)
local f_pkt_uor_ext3_inner_proto = ProtoField.uint8("rohc_lua.pkt.ext3.proto", "Inner protocol", base.DEC)
-- inner IP-ID
local f_pkt_uor_ext3_inner_ip_id = ProtoField.uint8("rohc_lua.pkt.ext3.ip_id", "Inner IP-ID", base.DEC)
-- outer IP header fields
local f_pkt_uor_ext3_outer_fields =
	ProtoField.bytes("rohc_lua.pkt.ext3.outer_fields", "Outer IP header fields")
local f_pkt_uor_ext3_outer_tos   = ProtoField.uint8("rohc_lua.pkt.ext3.tos2", "Outer TOS", base.HEX)
local f_pkt_uor_ext3_outer_ttl   = ProtoField.uint8("rohc_lua.pkt.ext3.ttl2", "Outer TTL", base.DEC)
local f_pkt_uor_ext3_outer_proto = ProtoField.uint8("rohc_lua.pkt.ext3.proto2", "Outer protocol", base.DEC)
local f_pkt_uor_ext3_outer_ip_id = ProtoField.uint8("rohc_lua.pkt.ext3.ip_id2", "Outer IP-ID", base.DEC)

-- UO remainder
local f_pkt_uor_rnd_outer_ip_id = ProtoField.uint16("rohc_lua.pkt.uor.rnd_outer_ip_id",
                                                    "Random IP-ID of outer IPv4 header",
                                                    base.HEX)
local f_pkt_uor_rnd_inner_ip_id = ProtoField.uint16("rohc_lua.pkt.uor.rnd_inner_ip_id",
                                                    "Random IP-ID of inner IPv4 header",
                                                    base.HEX)
local f_pkt_uor_udp_check       = ProtoField.uint16("rohc_lua.pkt.uor.udp_checksum",
                                                    "UDP checksum", base.HEX)

rohc_protocol_rfc3095_fields = {
	f_chain_static,
	f_chain_static_ipv4, f_chain_static_ipv4_version, f_chain_static_ipv4_padding,
	f_chain_static_ipv4_protocol, f_chain_static_ipv4_srcaddr, f_chain_static_ipv4_dstaddr,
	f_chain_static_ipv6, f_chain_static_ipv6_version, f_chain_static_ipv6_flowlabel,
	f_chain_static_ipv6_next_hdr, f_chain_static_ipv6_srcaddr, f_chain_static_ipv6_dstaddr,
	f_chain_static_udp, f_chain_static_udp_srcport, f_chain_static_udp_dstport,
	f_chain_dyn,
	f_chain_dyn_ipv4, f_chain_dyn_ipv4_tos, f_chain_dyn_ipv4_ttl, f_chain_dyn_ipv4_id,
	f_chain_dyn_ipv4_df, f_chain_dyn_ipv4_rnd, f_chain_dyn_ipv4_nbo, f_chain_dyn_ipv4_padding,
	f_chain_dyn_ipv6, f_chain_dyn_ipv6_tc, f_chain_dyn_ipv6_hl,
	f_chain_dyn_udp, f_chain_dyn_udp_check,
	f_chain_dyn_sn,
	f_list, f_list_et, f_list_gp, f_list_ps, f_list_xi1, f_list_gen_id, f_list_ref_id,
	f_list_bitmask_ins, f_list_bitmask_rem, f_list_bitmask_type,
	f_list_bitmask_7b, f_list_bitmask_15b,
	f_list_xi, f_list_xi_4be, f_list_xi_4bo, f_list_xi_4bp, f_list_xi_8b,
	f_list_items, f_list_item,
	f_ipv6_opt_type, f_ipv6_opt_len, f_ipv6_opt_data,
	f_list_type_0_m,
	f_list_type_2_res, f_list_type_2_count,
	f_pkt_uo0, f_pkt_uo0_type, f_pkt_uo0_sn, f_pkt_uo0_crc3,
	f_pkt_uo1, f_pkt_uo1_type, f_pkt_uo1_ip_id, f_pkt_uo1_sn, f_pkt_uo1_crc3,
	f_pkt_uor2, f_pkt_uor2_type, f_pkt_uor2_sn, f_pkt_uor2_x, f_pkt_uor2_crc7,
	f_pkt_uor_ext0, f_pkt_uor_ext0_type, f_pkt_uor_ext0_sn, f_pkt_uor_ext0_ip_id,
	f_pkt_uor_ext1, f_pkt_uor_ext1_type, f_pkt_uor_ext1_sn, f_pkt_uor_ext1_ip_id,
	f_pkt_uor_ext2, f_pkt_uor_ext2_type, f_pkt_uor_ext2_sn, f_pkt_uor_ext2_ip_id_2,
	f_pkt_uor_ext2_ip_id,
	f_pkt_uor_ext3, f_pkt_uor_ext3_type,
	f_pkt_uor_ext3_flags, f_pkt_uor_ext3_S, f_pkt_uor_ext3_mode,
	f_pkt_uor_ext3_I, f_pkt_uor_ext3_ip, f_pkt_uor_ext3_ip2,
	f_pkt_uor_ext3_inner_flags,
	f_pkt_uor_ext3_tos, f_pkt_uor_ext3_ttl, f_pkt_uor_ext3_df, f_pkt_uor_ext3_pr,
	f_pkt_uor_ext3_ipx, f_pkt_uor_ext3_nbo, f_pkt_uor_ext3_rnd, f_pkt_uor_ext3_reserved,
	f_pkt_uor_ext3_outer_flags,
	f_pkt_uor_ext3_tos2, f_pkt_uor_ext3_ttl2, f_pkt_uor_ext3_df2, f_pkt_uor_ext3_pr2,
	f_pkt_uor_ext3_ipx2, f_pkt_uor_ext3_nbo2, f_pkt_uor_ext3_rnd2, f_pkt_uor_ext3_I2,
	f_pkt_uor_ext3_sn,
	f_pkt_uor_ext3_inner_fields, f_pkt_uor_ext3_inner_tos, f_pkt_uor_ext3_inner_ttl,
	f_pkt_uor_ext3_inner_proto, f_pkt_uor_ext3_inner_ip_id,
	f_pkt_uor_ext3_outer_fields, f_pkt_uor_ext3_outer_tos, f_pkt_uor_ext3_outer_ttl,
	f_pkt_uor_ext3_outer_proto, f_pkt_uor_ext3_outer_ip_id,
	f_pkt_uor_rnd_outer_ip_id, f_pkt_uor_rnd_inner_ip_id, f_pkt_uor_udp_check,
}

-- dissect static chain, IP part
local function dissect_static_chain_ip(static_chain, pktinfo, tree)
	local offset = 0

	local ip_version = static_chain:range(offset, 1):bitfield(0, 4)
	if ip_version == 4 then
		local ipv4_tree = tree:add(f_chain_static_ipv4, static_chain)
		ipv4_tree:add(f_chain_static_ipv4_version, static_chain:range(offset, 1))
		ipv4_tree:add(f_chain_static_ipv4_padding, static_chain:range(offset, 1))
		offset = offset + 1
		local protocol = static_chain:range(offset, 1):uint()
		pktinfo.private["rohc_embedded_protocol"] = protocol
		ipv4_tree:add(f_chain_static_ipv4_protocol, static_chain:range(offset, 1))
		offset = offset + 1
		pktinfo.net_src = static_chain:range(offset, 4):ipv4()
		ipv4_tree:add(f_chain_static_ipv4_srcaddr, static_chain:range(offset, 4))
		offset = offset + 4
		pktinfo.net_dst = static_chain:range(offset, 4):ipv4()
		ipv4_tree:add(f_chain_static_ipv4_dstaddr, static_chain:range(offset, 4))
		offset = offset + 4
		ipv4_tree:set_len(offset)
	elseif ip_version == 6 then
		local ipv6_tree = tree:add(f_chain_static_ipv6, static_chain)
		ipv6_tree:add(f_chain_static_ipv6_version, static_chain:range(offset, 1))
		ipv6_tree:add(f_chain_static_ipv6_flowlabel, static_chain:range(offset, 3))
		offset = offset + 3
		local next_header = static_chain:range(offset, 1):uint()
		pktinfo.private["rohc_embedded_protocol"] = next_header
		ipv6_tree:add(f_chain_static_ipv6_next_hdr, static_chain:range(offset, 1))
		offset = offset + 1
		--pktinfo.net_src = static_chain:range(offset, 16):ipv6()
		ipv6_tree:add(f_chain_static_ipv6_srcaddr, static_chain:range(offset, 16))
		offset = offset + 16
		--pktinfo.net_dst = static_chain:range(offset, 16):ipv6()
		ipv6_tree:add(f_chain_static_ipv6_dstaddr, static_chain:range(offset, 16))
		offset = offset + 16
		ipv6_tree:set_len(offset)
	else
		error("static chain: IP part: unsupported IP version "..ip_version)
		return nil
	end

	return offset, ip_version
end

-- dissect static chain, UDP part
local function dissect_static_chain_udp(static_chain, pktinfo, tree)
	local offset = 0

	local udp_tree = tree:add(f_chain_static_udp, static_chain)

	-- UDP source port
	local sport = static_chain:range(offset, 2):uint()
	udp_tree:add(f_chain_static_udp_srcport, sport)
	pktinfo.private["rohc_embedded_udp_sport"] = sport
	offset = offset + 2

	-- UDP destination port
	local dport = static_chain:range(offset, 2):uint()
	udp_tree:add(f_chain_static_udp_dstport, dport)
	pktinfo.private["rohc_embedded_udp_dport"] = dport
	offset = offset + 2

	udp_tree:set_len(offset)
	return offset
end

-- dissect static chain
local function dissect_static_chain(static_chain, pktinfo, rohc_tree, profile_id)
	local chain_static_tree = rohc_tree:add(f_chain_static, static_chain)
	local remain_data = static_chain
	local offset = 0
	local protocol

	-- dissect IP part
	if profile_id == 0x0001 or profile_id == 0x0002 or profile_id == 0x0003 or
	   profile_id == 0x0004 or profile_id == 0x0006 or profile_id == 0x0008 or
	   profile_id == 0x0007 then
		-- dissect outer IP header
		local ip_part_len, ip_version =
			dissect_static_chain_ip(remain_data, pktinfo, chain_static_tree)
		offset = offset + ip_part_len
		remain_data = remain_data:range(ip_part_len, remain_data:len() - ip_part_len)
		pktinfo.private["rohc_ip_hdr_1_version"] = ip_version
		-- dissect inner IP header (if any)
		if pktinfo.private["rohc_embedded_protocol"] == "4" or
		   pktinfo.private["rohc_embedded_protocol"] == "41" then
			pktinfo.private["rohc_ip_hdrs_nr"] = 2
			ip_part_len, ip_version =
				dissect_static_chain_ip(remain_data, pktinfo, chain_static_tree)
			offset = offset + ip_part_len
			remain_data = remain_data:range(ip_part_len, remain_data:len() - ip_part_len)
			pktinfo.private["rohc_ip_hdr_2_version"] = ip_version
		else
			pktinfo.private["rohc_ip_hdrs_nr"] = 1
		end
	end

	if profile_id == 0x0001 or profile_id == 0x0002 then
		-- dissect UDP part
		local udp_part_len = dissect_static_chain_udp(remain_data, pktinfo, chain_static_tree)
		offset = offset + udp_part_len
		remain_data = remain_data:range(udp_part_len, remain_data:len() - udp_part_len)
	elseif profile_id == 0x0003 then
		-- dissect ESP part
	elseif profile_id == 0x0006 then
		-- dissect TCP part
	elseif profile_id == 0x0007 or profile_id == 0x0008 then
		-- dissect UDP-Lite part
	end

	if profile_id == 0x0001 or profile_id == 0x0007 then
		-- dissect RTP part
	end

	chain_static_tree:set_len(offset)
	return offset
end

local function dissect_dynamic_chain_ip_exts(list, pktinfo, tree)
	local list_tree = tree:add(f_list, list)
	local offset = 0
	local remaining_xis_nr
	local items_nr

	-- List Encoding Type
	local et = list:range(offset, 1):bitfield(0, 2)
	list_tree:add(f_list_et, list:range(offset, 1))

	-- gp: is gen_id present?
	local gp = list:range(0, 1):bitfield(2, 1)
	list_tree:add(f_list_gp, list:range(offset, 1))

	local ps
	if et == 0 then
		-- list flags and number of elements
		ps = list:range(0, 1):bitfield(3, 1)
		list_tree:add(f_list_ps, list:range(offset, 1))
		local m = list:range(0, 1):bitfield(4, 4)
		list_tree:add(f_list_type_0_m, list:range(offset, 1))
		offset = offset + 1
		remaining_xis_nr = m
		items_nr = 0
	elseif et == 1 then
		-- list flags and number of elements
		ps = list:range(0, 1):bitfield(3, 1)
		list_tree:add(f_list_ps, list:range(offset, 1))
		list_tree:add(f_list_xi1, list:range(offset, 1))
		items_nr = list:range(offset, 1):bitfield(4, 1)
		offset = offset + 1
	elseif et == 2 then
		-- list flags and number of elements
		list_tree:add(f_list_type_2_res, list:range(offset, 1))
		list_tree:add(f_list_type_2_count, list:range(offset, 1))
		offset = offset + 1
		remaining_xis_nr = 0
		items_nr = 0
	else -- et == 3
		-- list flags and number of elements
		ps = list:range(0, 1):bitfield(3, 1)
		list_tree:add(f_list_ps, list:range(offset, 1))
		list_tree:add(f_list_xi1, list:range(offset, 1))
		items_nr = list:range(offset, 1):bitfield(4, 1)
		offset = offset + 1
	end

	-- gen_id
	if gp == 1 then
		list_tree:add(f_list_gen_id, list:range(offset, 1))
		offset = offset + 1
	end

	-- Encoding Type 1, 2 or 3: ref_id
	if et == 1 or et == 2 or et == 3 then
		list_tree:add(f_list_ref_id, list:range(offset, 1))
		offset = offset + 1
	end

	-- Encoding Type 2 or 3: removal bitmask
	if et == 2 or et == 3 then
		local bitmask_rem_tree =
			list_tree:add(f_list_bitmask_rem, list:range(offset, list:len() - offset))
		local bitmask_type = list:range(offset, 1):bitfield(0, 1)
		bitmask_rem_tree:add(f_list_bitmask_type, list:range(offset, 1))
		if bitmask_type == 0 then
			bitmask_rem_tree:add(f_list_bitmask_7b, list:range(offset, 1))
			offset = offset + 1
			bitmask_rem_tree:set_len(1)
		else
			bitmask_rem_tree:add(f_list_bitmask_8b, list:range(offset, 2))
			offset = offset + 2
			bitmask_rem_tree:set_len(2)
		end
	end

	-- Encoding Type 1 or 3: insertion bitmask
	if et == 1 or et == 3 then
		local bitmask_ins_tree =
			list_tree:add(f_list_bitmask_ins, list:range(offset, list:len() - offset))
		local bitmask_type = list:range(offset, 1):bitfield(0, 1)
		bitmask_ins_tree:add(f_list_bitmask_type, list:range(offset, 1))
		local ins_bitmask_len
		if bitmask_type == 0 then
			ins_bitmask_len = 7
			bitmask_ins_tree:add(f_list_bitmask_7b, list:range(offset, 1))
		else
			ins_bitmask_len = 15
			bitmask_ins = list:range(offset, 2):bitfield(1, 15)
			bitmask_ins_tree:add(f_list_bitmask_8b, list:range(offset, 2))
		end
		local insertions_nr = 0
		for i = 1, 7 do
			insertions_nr = insertions_nr + list:range(offset, 1):bitfield(i, 1)
		end
		remaining_xis_nr = insertions_nr - 1
		offset = offset + (ins_bitmask_len + 1) / 8
		bitmask_ins_tree:set_len((ins_bitmask_len + 1) / 8)
	end

	-- XI fields
	if remaining_xis_nr > 0 then
		local xi_len
		if ps == 0 then
			xi_len = (remaining_xis_nr + 1) / 2
		else
			xi_len = remaining_xis_nr
		end
		local xi_tree = list_tree:add(f_list_xi, list:range(offset, xi_len))
		for i = 1, remaining_xis_nr do
			if ps == 0 then
				-- 4-bit XI fields
				if (i % 2) ~= 0 then
					xi_tree:add(f_list_xi_4bo, list:range(offset, 1)) -- odd
					items_nr = items_nr + list:range(offset, 1):bitfield(0, 1)
				else
					xi_tree:add(f_list_xi_4be, list:range(offset, 1)) -- even
					items_nr = items_nr + list:range(offset, 1):bitfield(4, 1)
					offset = offset + 1
				end
			else
				-- 8-bit XI fields
				xi_tree:add(f_list_xi_8b, list:range(offset, 1))
				items_nr = items_nr + list:range(offset, 1):bitfield(0, 1)
				offset = offset + 1
			end
		end
		-- 4-bit padding in case of odd number of XI fields
		if ps == 0 and (remaining_xis_nr % 2) ~= 0 then
			xi_tree:add(f_list_xi_4bp, list:range(offset, 1))
			offset = offset + 1
		end
	end

	-- items
	if items_nr > 0 then
		local items_tree = list_tree:add(f_list_items, list:range(offset, list:len() - offset))
		local items_len = 0
		for i = 1, items_nr do
			local ipv6_opt_len = (list:range(offset + 1, 1):uint() + 1) * 8
			local item_tree = items_tree:add(f_list_item, list:range(offset, ipv6_opt_len))
			item_tree:add(f_ipv6_opt_type, list:range(offset, 1))
			offset = offset + 1
			item_tree:add(f_ipv6_opt_len, list:range(offset, 1))
			offset = offset + 1
			item_tree:add(f_ipv6_opt_data, list:range(offset, ipv6_opt_len - 2))
			offset = offset + ipv6_opt_len - 2
			items_len = items_len + ipv6_opt_len
		end
		items_tree:set_len(items_len)
	end

	list_tree:set_len(offset)
	return offset
end

-- dissect dynamic chain, IP part
local function dissect_dynamic_chain_ip(dyn_chain, pktinfo, tree, ip_version)
	local offset = 0
	local rnd = 0

	if ip_version == 4 then
		local ipv4_tree = tree:add(f_chain_dyn_ipv4, dyn_chain)
		ipv4_tree:add(f_chain_dyn_ipv4_tos, dyn_chain:range(offset, 1))
		offset = offset + 1
		ipv4_tree:add(f_chain_dyn_ipv4_ttl, dyn_chain:range(offset, 1))
		offset = offset + 1
		ipv4_tree:add(f_chain_dyn_ipv4_id, dyn_chain:range(offset, 2))
		offset = offset + 2
		ipv4_tree:add(f_chain_dyn_ipv4_df,      dyn_chain:range(offset, 1))
		rnd = dyn_chain:range(offset, 1):bitfield(1, 1)
		ipv4_tree:add(f_chain_dyn_ipv4_rnd,     dyn_chain:range(offset, 1))
		ipv4_tree:add(f_chain_dyn_ipv4_nbo,     dyn_chain:range(offset, 1))
		ipv4_tree:add(f_chain_dyn_ipv4_padding, dyn_chain:range(offset, 1))
		offset = offset + 1
		-- handle generic extension header list
		local list = dyn_chain:range(offset, dyn_chain:len() - offset)
		local ip_exts_len = dissect_dynamic_chain_ip_exts(list, pktinfo, ipv4_tree)
		offset = offset + ip_exts_len
		ipv4_tree:set_len(offset)
	elseif ip_version == 6 then
		local ipv6_tree = tree:add(f_chain_dyn_ipv6, dyn_chain)
		-- Traffic Class
		ipv6_tree:add(f_chain_dyn_ipv6_tc, dyn_chain:range(offset, 1))
		offset = offset + 1
		-- Hop Limit
		ipv6_tree:add(f_chain_dyn_ipv6_hl, dyn_chain:range(offset, 1))
		offset = offset + 1
		-- Generic extension header list
		local list = dyn_chain:range(offset, dyn_chain:len() - offset)
		local ip_exts_len = dissect_dynamic_chain_ip_exts(list, pktinfo, ipv6_tree)
		offset = offset + ip_exts_len
		ipv6_tree:set_len(offset)
	else
		error("static chain: IP part: unsupported IP version "..ip_version)
		return nil
	end

	return offset
end

-- dissect dynamic chain, UDP part
local function dissect_dynamic_chain_udp(dyn_chain, pktinfo, tree, profile_id)
	local offset = 0

	local udp_tree = tree:add(f_chain_dyn_udp, dyn_chain)
	-- UDP checksum
	local udp_check = dyn_chain:range(offset, 2):uint()
	udp_tree:add(f_chain_dyn_udp_check, dyn_chain:range(offset, 2))
	offset = offset + 2

	udp_tree:set_len(offset)
	return offset, udp_check
end

-- dissect dynamic chain
local function dissect_dynamic_chain(dyn_chain, pktinfo, rohc_tree, profile_id)
	local chain_dyn_tree = rohc_tree:add(f_chain_dyn, dyn_chain)
	local remain_data = dyn_chain
	local offset = 0

	-- dissect IP part
	if profile_id == 0x0001 or profile_id == 0x0002 or profile_id == 0x0003 or
	   profile_id == 0x0004 or profile_id == 0x0006 or profile_id == 0x0008 or
	   profile_id == 0x0007 then
		-- dissect outer IP header
		local ip_version = tonumber(pktinfo.private["rohc_ip_hdr_1_version"])
		local ip_part_len, rnd =
			dissect_dynamic_chain_ip(remain_data, pktinfo, chain_dyn_tree, ip_version)
		offset = offset + ip_part_len
		remain_data = remain_data:range(ip_part_len, remain_data:len() - ip_part_len)
		pktinfo.private["rnd_outer_ip_id"] = rnd
		-- dissect inner IP header (if any)
		if pktinfo.private["rohc_ip_hdrs_nr"] == "2" then
			ip_version = tonumber(pktinfo.private["rohc_ip_hdr_2_version"])
			ip_part_len, rnd =
				dissect_dynamic_chain_ip(remain_data, pktinfo, chain_dyn_tree, ip_version)
			offset = offset + ip_part_len
			remain_data = remain_data:range(ip_part_len, remain_data:len() - ip_part_len)
			pktinfo.private["rnd_inner_ip_id"] = rnd
		end
	end

	if profile_id == 0x0001 or profile_id == 0x0002 then
		-- dissect UDP part
		local udp_part_len, udp_check =
			dissect_dynamic_chain_udp(remain_data, pktinfo, chain_dyn_tree, profile_id)
		offset = offset + udp_part_len
		remain_data = remain_data:range(udp_part_len, remain_data:len() - udp_part_len)
		pktinfo.private["udp_check"] = udp_check
	elseif profile_id == 0x0003 then
		-- dissect ESP part
	elseif profile_id == 0x0006 then
		-- dissect TCP part
	elseif profile_id == 0x0007 or profile_id == 0x0008 then
		-- dissect UDP-Lite part
	end

	if profile_id == 0x0001 or profile_id == 0x0007 then
		-- dissect RTP part
		error("unsupported ROHC packet: RTP profile is not supported yet")
	elseif profile_id == 0x0002 or profile_id == 0x0004 then
		-- SN for non-RTP profiles
		chain_dyn_tree:add(f_chain_dyn_sn, remain_data:range(0, 2))
		offset = offset + 2
		remain_data = remain_data:range(2, remain_data:len() - 2)
	end

	chain_dyn_tree:set_len(offset)
	return offset
end

-- dissect profile-specific part of IR packet
function rohc_rfc3095_dissect_pkt_ir(ir_pkt, pktinfo, ir_tree, profile_id)
	local offset = 0
	-- static chain
	local static_chain = ir_pkt:range(offset, ir_pkt:len() - offset)
	local static_chain_len = dissect_static_chain(static_chain, pktinfo, ir_tree, profile_id)
	offset = offset + static_chain_len
	-- dynamic chain
	local dyn_chain = ir_pkt:range(offset, ir_pkt:len() - offset)
	local dyn_chain_len = dissect_dynamic_chain(dyn_chain, pktinfo, ir_tree, profile_id)
	offset = offset + dyn_chain_len
	return offset, protocol
end

-- dissect IR-DYN packet
-- dissect profile-specific part of IR-DYN packet
function rohc_rfc3095_dissect_pkt_irdyn(irdyn_pkt, pktinfo, irdyn_tree, profile_id)
	local offset = 0
	-- dynamic chain
	local dyn_chain = irdyn_pkt:range(offset, irdyn_pkt:len() - offset)
	local dyn_chain_len = dissect_dynamic_chain(dyn_chain, pktinfo, irdyn_tree, profile_id)
	offset = offset + dyn_chain_len
	return offset
end

-- dissect UOR extension 0
local function dissect_pkt_uor_ext0(uor_pkt, pktinfo, rohc_tree)
	local offset = 0
	local ext_tree = rohc_tree:add(f_pkt_uor_ext0, uor_pkt)
	ext_tree:add(f_pkt_uor_ext0_type,  uor_pkt:range(offset, 1))
	ext_tree:add(f_pkt_uor_ext0_sn,    uor_pkt:range(offset, 1))
	ext_tree:add(f_pkt_uor_ext0_ip_id, uor_pkt:range(offset, 1))
	offset = offset + 1
	ext_tree:set_len(offset)
	return offset
end

-- dissect UOR extension 1
local function dissect_pkt_uor_ext1(uor_pkt, pktinfo, rohc_tree)
	local offset = 0
	local ext_tree = rohc_tree:add(f_pkt_uor_ext1, uor_pkt)
	ext_tree:add(f_pkt_uor_ext1_type,  uor_pkt:range(offset, 1))
	ext_tree:add(f_pkt_uor_ext1_sn,    uor_pkt:range(offset, 1))
	ext_tree:add(f_pkt_uor_ext1_ip_id, uor_pkt:range(offset, 2))
	offset = offset + 2
	ext_tree:set_len(offset)
	return offset
end

-- dissect UOR extension 2
local function dissect_pkt_uor_ext2(uor_pkt, pktinfo, rohc_tree)
	local offset = 0
	local ext_tree = rohc_tree:add(f_pkt_uor_ext2, uor_pkt)
	ext_tree:add(f_pkt_uor_ext2_type,    uor_pkt:range(offset, 1))
	ext_tree:add(f_pkt_uor_ext2_sn,      uor_pkt:range(offset, 1))
	ext_tree:add(f_pkt_uor_ext2_ip_id_2, uor_pkt:range(offset, 2))
	offset = offset + 2
	ext_tree:add(f_pkt_uor_ext2_ip_id, uor_pkt:range(offset, 1))
	offset = offset + 1
	ext_tree:set_len(offset)
	return offset
end

-- dissect UOR extension 3
local function dissect_pkt_uor_ext3(uor_pkt, pktinfo, rohc_tree)
	local offset = 0
	local ext_tree = rohc_tree:add(f_pkt_uor_ext3, uor_pkt)
	-- extension 3 flags
	local ext_flags_tree = ext_tree:add(f_pkt_uor_ext3_flags, uor_pkt:range(offset, 1))
	ext_flags_tree:add(f_pkt_uor_ext3_type, uor_pkt:range(offset, 1))
	local ext3_S = uor_pkt:range(offset, 1):bitfield(2, 1)
	ext_flags_tree:add(f_pkt_uor_ext3_S,    uor_pkt:range(offset, 1))
	ext_flags_tree:add(f_pkt_uor_ext3_mode, uor_pkt:range(offset, 1))
	local ext3_I = uor_pkt:range(offset, 1):bitfield(5, 1)
	ext_flags_tree:add(f_pkt_uor_ext3_I,    uor_pkt:range(offset, 1))
	local ext3_ip = uor_pkt:range(offset, 1):bitfield(6, 1)
	ext_flags_tree:add(f_pkt_uor_ext3_ip,   uor_pkt:range(offset, 1))
	local ext3_ip2 = uor_pkt:range(offset, 1):bitfield(7, 1)
	ext_flags_tree:add(f_pkt_uor_ext3_ip2,  uor_pkt:range(offset, 1))
	offset = offset + 1
	-- inner IP header flags
	local ext3_ip_tos = 0
	local ext3_ip_ttl = 0
	local ext3_ip_pr = 0
	local ext3_ip_ipx = 0
	if ext3_ip == 1 then
		local ext_inner_flags_tree =
			ext_tree:add(f_pkt_uor_ext3_inner_flags, uor_pkt:range(offset, 1))
		ext3_ip_tos = uor_pkt:range(offset, 1):bitfield(0, 1)
		ext_inner_flags_tree:add(f_pkt_uor_ext3_tos,      uor_pkt:range(offset, 1))
		ext3_ip_ttl = uor_pkt:range(offset, 1):bitfield(1, 1)
		ext_inner_flags_tree:add(f_pkt_uor_ext3_ttl,      uor_pkt:range(offset, 1))
		ext_inner_flags_tree:add(f_pkt_uor_ext3_df,       uor_pkt:range(offset, 1))
		ext3_ip_pr = uor_pkt:range(offset, 1):bitfield(3, 1)
		ext_inner_flags_tree:add(f_pkt_uor_ext3_pr,       uor_pkt:range(offset, 1))
		ext3_ip_ipx = uor_pkt:range(offset, 1):bitfield(4, 1)
		ext_inner_flags_tree:add(f_pkt_uor_ext3_ipx,      uor_pkt:range(offset, 1))
		ext_inner_flags_tree:add(f_pkt_uor_ext3_nbo,      uor_pkt:range(offset, 1))
		ext_inner_flags_tree:add(f_pkt_uor_ext3_rnd,      uor_pkt:range(offset, 1))
		ext_inner_flags_tree:add(f_pkt_uor_ext3_reserved, uor_pkt:range(offset, 1))
		offset = offset + 1
	end
	-- outer IP header flags
	local ext3_ip2_tos = 0
	local ext3_ip2_ttl = 0
	local ext3_ip2_pr = 0
	local ext3_ip2_ipx = 0
	local ext3_ip2_I = 0
	if ext3_ip2 == 1 then
		local ext_outer_flags_tree =
			ext_tree:add(f_pkt_uor_ext3_outer_flags, uor_pkt:range(offset, 1))
		ext3_ip2_tos = uor_pkt:range(offset, 1):bitfield(0, 1)
		ext_outer_flags_tree:add(f_pkt_uor_ext3_tos2, uor_pkt:range(offset, 1))
		ext3_ip2_ttl = uor_pkt:range(offset, 1):bitfield(1, 1)
		ext_outer_flags_tree:add(f_pkt_uor_ext3_ttl2, uor_pkt:range(offset, 1))
		ext_outer_flags_tree:add(f_pkt_uor_ext3_df2,  uor_pkt:range(offset, 1))
		ext3_ip2_pr = uor_pkt:range(offset, 1):bitfield(3, 1)
		ext_outer_flags_tree:add(f_pkt_uor_ext3_pr2,  uor_pkt:range(offset, 1))
		ext3_ip2_ipx = uor_pkt:range(offset, 1):bitfield(4, 1)
		ext_outer_flags_tree:add(f_pkt_uor_ext3_ipx2, uor_pkt:range(offset, 1))
		ext_outer_flags_tree:add(f_pkt_uor_ext3_nbo2, uor_pkt:range(offset, 1))
		ext_outer_flags_tree:add(f_pkt_uor_ext3_rnd2, uor_pkt:range(offset, 1))
		ext3_ip2_I = uor_pkt:range(offset, 1):bitfield(7, 1)
		ext_outer_flags_tree:add(f_pkt_uor_ext3_I2,   uor_pkt:range(offset, 1))
		offset = offset + 1
	end
	-- SN field
	if ext3_S == 1 then
		ext_tree:add(f_pkt_uor_ext3_sn, uor_pkt:range(offset, 1))
		offset = offset + 1
	end
	-- TODO: TS field
	-- inner IP header fields
	local ext_inner_fields_nr = ext3_ip_tos + ext3_ip_ttl + ext3_ip_pr + ext3_ip_ipx
	if ext_inner_fields_nr > 0 then
		local ext_inner_fields_tree =
			ext_tree:add(f_pkt_uor_ext3_inner_fields, uor_pkt:range(offset, ext_inner_fields_nr))
		if ext3_ip_tos == 1 then
			ext_inner_fields_tree:add(f_pkt_uor_ext3_inner_tos, uor_pkt:range(offset, 1))
			offset = offset + 1
		end
		if ext3_ip_ttl == 1 then
			ext_inner_fields_tree:add(f_pkt_uor_ext3_inner_ttl, uor_pkt:range(offset, 1))
			offset = offset + 1
		end
		if ext3_ip_pr == 1 then
			ext_inner_fields_tree:add(f_pkt_uor_ext3_inner_proto, uor_pkt:range(offset, 1))
			offset = offset + 1
		end
		if ext3_ip_ipx == 1 then
			error("UOR extension 3: unsupported IPX flag is set for inner IP")
			return nil
		end
	end
	-- inner IP-ID
	if ext3_I == 1 then
		ext_tree:add(f_pkt_uor_ext3_inner_ip_id, uor_pkt:range(offset, 2))
		offset = offset + 2
	end
	-- outer IP header fields
	local ext_outer_fields_nr =
		ext3_ip2_tos + ext3_ip2_ttl + ext3_ip2_pr + ext3_ip2_ipx + ext3_ip2_I
	if ext_outer_fields_nr > 0 then
		local ext_outer_fields_tree =
			ext_tree:add(f_pkt_uor_ext3_outer_fields, uor_pkt:range(offset, ext_outer_fields_nr))
		if ext3_ip2_tos == 1 then
			ext_outer_fields_tree:add(f_pkt_uor_ext3_outer_tos, uor_pkt:range(offset, 1))
			offset = offset + 1
		end
		if ext3_ip2_ttl == 1 then
			ext_outer_fields_tree:add(f_pkt_uor_ext3_outer_ttl, uor_pkt:range(offset, 1))
			offset = offset + 1
		end
		if ext3_ip2_pr == 1 then
			ext_outer_fields_tree:add(f_pkt_uor_ext3_outer_proto, uor_pkt:range(offset, 1))
			offset = offset + 1
		end
		if ext3_ip2_ipx == 1 then
			error("UOR extension 3: unsupported IPX flag is set for outer IP")
			return nil
		end
		if ext3_I2 == 1 then
			ext_outer_fields_tree:add(f_pkt_uor_ext3_outer_ip_id, uor_pkt:range(offset, 2))
			offset = offset + 2
		end
	end
	-- TODO: RTP header flags and fields

	ext_tree:set_len(offset)
	return offset
end

-- dissect UOR extensions
local function dissect_pkt_uor_ext(uor_pkt, pktinfo, rohc_tree)
	local ext_type = uor_pkt:range(0, 1):bitfield(0, 2)
	local offset
	if ext_type == 0 then
		offset = dissect_pkt_uor_ext0(uor_pkt, pktinfo, rohc_tree)
	elseif ext_type == 1 then
		offset = dissect_pkt_uor_ext1(uor_pkt, pktinfo, rohc_tree)
	elseif ext_type == 2 then
		offset = dissect_pkt_uor_ext2(uor_pkt, pktinfo, rohc_tree)
	else
		offset = dissect_pkt_uor_ext3(uor_pkt, pktinfo, rohc_tree)
	end
	return offset
end

-- dissect UOR remainder
local function dissect_uor_remainder(uor_bytes, pktinfo, uor_tree, profile_id)
	local offset = 0
	-- outer IP-ID if random
	if pktinfo.private["rnd_outer_ip_id"] == "1" then
		uor_tree:add(f_pkt_uor_rnd_outer_ip_id, uor_bytes:range(offset, 2))
		offset = offset + 2
	end
	-- inner IP-ID if random
	if pktinfo.private["rnd_inner_ip_id"] == "1" then
		uor_tree:add(f_pkt_uor_rnd_inner_ip_id, uor_bytes:range(offset, 2))
		offset = offset + 2
	end
	-- UDP and RTP profiles: UDP checksum if not zero
	if profile_id == 0x0001 or profile_id == 0x0002 then
		if pktinfo.private["udp_check"] ~= "0" then
			uor_tree:add(f_pkt_uor_udp_check, uor_bytes:range(offset, 2))
			offset = offset + 2
		end
	end
	return offset
end

-- dissect UO-0 packet
local function dissect_pkt_uo0(uo0_pkt, pktinfo, rohc_tree)
	local offset = 0
	local uo0_tree = rohc_tree:add(f_pkt_uo0, uo0_pkt)
	uo0_tree:add(f_pkt_uo0_type, uo0_pkt:range(offset, 1))
	uo0_tree:add(f_pkt_uo0_sn,   uo0_pkt:range(offset, 1))
	uo0_tree:add(f_pkt_uo0_crc3, uo0_pkt:range(offset, 1))
	offset = offset + 1
	-- UO remainder
	local uor_bytes = uo0_pkt:range(offset, uo0_pkt:len() - offset)
	local remainder_len = dissect_uor_remainder(uor_bytes, pktinfo, uo0_tree)
	offset = offset + remainder_len
	uo0_tree:set_len(offset)
	return offset
end

-- dissect UO-1 packet
local function dissect_pkt_uo1(uo1_pkt, pktinfo, rohc_tree)
	local offset = 0
	local uo1_tree = rohc_tree:add(f_pkt_uo1, uo1_pkt)
	uo1_tree:add(f_pkt_uo1_type,  uo1_pkt:range(offset, 1))
	uo1_tree:add(f_pkt_uo1_ip_id, uo1_pkt:range(offset, 1))
	offset = offset + 1
	uo1_tree:add(f_pkt_uo1_sn,    uo1_pkt:range(offset, 1))
	uo1_tree:add(f_pkt_uo1_crc3,  uo1_pkt:range(offset, 1))
	offset = offset + 1
	-- UO remainder
	local uor_bytes = uo1_pkt:range(offset, uo1_pkt:len() - offset)
	local remainder_len = dissect_uor_remainder(uor_bytes, pktinfo, uo1_tree)
	offset = offset + remainder_len
	uo1_tree:set_len(offset)
	return offset
end

-- dissect UOR-2 packet
local function dissect_pkt_uor2(uor2_pkt, pktinfo, rohc_tree)
	local offset = 0
	local uor2_tree = rohc_tree:add(f_pkt_uor2, uor2_pkt)
	uor2_tree:add(f_pkt_uor2_type,  uor2_pkt:range(offset, 1))
	uor2_tree:add(f_pkt_uor2_sn,    uor2_pkt:range(offset, 1))
	offset = offset + 1
	local ext = uor2_pkt:range(offset, 1):bitfield(0, 1)
	uor2_tree:add(f_pkt_uor2_x,     uor2_pkt:range(offset, 1))
	uor2_tree:add(f_pkt_uor2_crc7,  uor2_pkt:range(offset, 1))
	offset = offset + 1
	-- extensions
	if ext == 1 then
		local ext_bytes = uor2_pkt:range(offset, uor2_pkt:len() - offset)
		local ext_len = dissect_pkt_uor_ext(ext_bytes, pktinfo, uor2_tree)
		offset = offset + ext_len
	end
	-- UO remainder
	local uor_bytes = uor2_pkt:range(offset, uor2_pkt:len() - offset)
	local remainder_len = dissect_uor_remainder(uor_bytes, pktinfo, uor2_tree)
	offset = offset + remainder_len
	uor2_tree:set_len(offset)
	return offset
end

-- dissect UOR packets
function rohc_rfc3095_dissect_pkt_uor(uor_pkt, pktinfo, rohc_tree)
	local hdr_len

	if uor_pkt:range(offset, 1):bitfield(0, 1) == 0x0 then
		-- UO-0
		pktinfo.private["rohc_packet_type"] = "UO-0"
		hdr_len = dissect_pkt_uo0(uor_pkt, pktinfo, rohc_tree)
	elseif uor_pkt:range(offset, 1):bitfield(0, 2) == 0x2 then
		-- UO-1
		pktinfo.private["rohc_packet_type"] = "UO-1"
		hdr_len = dissect_pkt_uo1(uor_pkt, pktinfo, rohc_tree)
	elseif uor_pkt:range(offset, 1):bitfield(0, 3) == 0x6 then
		-- UOR-2
		pktinfo.private["rohc_packet_type"] = "UOR-2"
		hdr_len = dissect_pkt_uor2(uor_pkt, pktinfo, rohc_tree)
	else
		error("unsupported ROHC packet")
		return nil
	end

	return hdr_len
end

