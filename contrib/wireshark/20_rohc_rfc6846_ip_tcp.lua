--
-- Copyright 2018 Didier Barvaux
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
-- @file   rohc_rfc6846_ip_tcp.lua
-- @brief  Wireshark dissector for the RFC6846 IP/TCP profile of the ROHC protocol
-- @author Didier Barvaux <didier@barvaux.org>
--

local rohc_rfc6846_ip_tcp_profile_id = 0x0006

-- register the RFC 6846 IP/TCP profile of the ROHC protocol
local rohc_rfc6846_ip_tcp =
	Proto("rohc_rfc6846_ip_tcp", "ROHCv1 IP/TCP profile (RFC 6846)")

local rohc_protocol_info = {
	version    = "1.0",
	author     = "Didier Barvaux",
	repository = "https://rohc-lib.org/"
}
set_plugin_info(rohc_protocol_info)

function rohc_rfc6846_ip_tcp.dissector(tvbuf, pktinfo, root)
	local protocol
	local offset = 0

	-- packet type?
	local hdr_len
	if pktinfo.private["rohc_packet_type"] == "IR" then
		-- IR packet
		hdr_len = rohc_rfc6846_dissect_pkt_ir(tvbuf, pktinfo, root)
	elseif pktinfo.private["rohc_packet_type"] == "IR-DYN" then
		-- IR-DYN packet
		hdr_len = rohc_rfc6846_dissect_pkt_irdyn(tvbuf, pktinfo, root)
	else
		co_pkt = tvbuf:range(offset, tvbuf:len() - offset)
		hdr_len = rohc_rfc6846_dissect_pkt_co(co_pkt, pktinfo, root)
	end
	offset = offset + hdr_len

	return offset
end


-- list of TCP options
local f_list_tcp_opts = ProtoField.bytes("rohc_lua.pkt.chain.dynamic.tcp.opt",
                                         "TCP options list")
local f_list_tcp_opts_reserved
                           = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.reserved",
                                              "Reserved", base.HEX, nil, 0xe0)
local f_list_tcp_opts_ps   = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.ps",
                                                   "PS", base.DEC, nil, 0x10)
local f_list_tcp_opts_m    = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.m",
                                              "m", base.DEC, nil, 0x0f)
local f_list_tcp_opts_xi0_odd_x
                           = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.xi.x",
                                              "XI X", base.DEC, nil, 0x80)
local f_list_tcp_opts_xi0_odd_idx
                           = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.xi.index",
                                              "XI index", base.DEC, nil, 0x70)
local f_list_tcp_opts_xi0_even_x
                           = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.xi.x",
                                              "XI X", base.DEC, nil, 0x08)
local f_list_tcp_opts_xi0_even_idx
                           = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.xi.index",
                                              "XI index", base.DEC, nil, 0x07)
local f_list_tcp_opts_xi0_padding
                           = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.xi.padding",
                                              "XI Padding", base.DEC, nil, 0x0f)

-- static chain
local f_chain_static = ProtoField.bytes("rohc_lua.pkt.chain.static", "Static chain")
---- IP part
local f_chain_static_version_flag  = ProtoField.uint8("rohc_lua.pkt.chain.static.ip.version_flag",
                                                      "version_flag", base.DEC, nil, 0x80)
---- IPv4 part
local f_chain_static_ipv4 = ProtoField.bytes("rohc_lua.pkt.chain.static.ipv4", "IPv4 static chain")
local f_chain_static_ipv4_reserved = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv4.reserved",
                                                      "reserved", base.HEX, nil, 0x7f)
local f_chain_static_ipv4_protocol = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv4.protocol",
                                                      "Protocol", base.DEC)
local f_chain_static_ipv4_srcaddr  = ProtoField.ipv4("rohc_lua.pkt.chain.static.ipv4.saddr",
                                                     "Source address")
local f_chain_static_ipv4_dstaddr  = ProtoField.ipv4("rohc_lua.pkt.chain.static.ipv4.daddr",
                                                     "Destination address")
---- IPv6 part
local f_chain_static_ipv6 = ProtoField.bytes("rohc_lua.pkt.chain.static.ipv6", "IPv6 static chain")
local f_chain_static_ipv6_reserved  = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv6.reserved",
                                                       "reserved", base.HEX, nil, 0x60)
local f_chain_static_ipv6_flowlabel = ProtoField.uint32("rohc_lua.pkt.chain.static.ipv6.flow_label",
                                                        "Flow Label", base.HEX, nil, 0x1FFFFF)
local f_chain_static_ipv6_next_hdr  = ProtoField.uint8("rohc_lua.pkt.chain.static.ipv6.next_header",
                                                       "Next header", base.DEC)
local f_chain_static_ipv6_srcaddr   = ProtoField.ipv6("rohc_lua.pkt.chain.static.ipv6.saddr",
                                                      "Source address")
local f_chain_static_ipv6_dstaddr   = ProtoField.ipv6("rohc_lua.pkt.chain.static.ipv6.daddr",
                                                      "Destination address")
-- TCP part
local f_chain_static_tcp = ProtoField.bytes("rohc_lua.pkt.chain.static.tcp", "TCP static chain")
local f_chain_static_tcp_srcport = ProtoField.uint16("rohc_lua.pkt.chain.static.tcp.sport",
                                                     "Source port")
local f_chain_static_tcp_dstport = ProtoField.uint16("rohc_lua.pkt.chain.static.tcp.dport",
                                                     "Destination port")

-- dynamic chain
local f_chain_dyn = ProtoField.bytes("rohc_lua.pkt.chain.dynamic", "Dynamic chain")
---- IPv4 part
local f_chain_dyn_ipv4 = ProtoField.bytes("rohc_lua.pkt.chain.dynamic.ipv4", "IPv4 dynamic chain")
local f_chain_dyn_ipv4_reserved  = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.reserved",
                                                    "reserved", base.HEX, nil, 0xf8)
local f_chain_dyn_ipv4_df        = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.df",
                                                    "Don't Fragment (DF)", base.DEC, nil, 0x04)
local f_chain_dyn_ipv4_ip_id_behavior
                                 = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.ip_id_behavior",
                                                    "IP-ID behavior", base.DEC, nil, 0x03)
local f_chain_dyn_ipv4_dscp      = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.dscp",
                                                    "DSCP", base.HEX, nil, 0xfc)
local f_chain_dyn_ipv4_ecn_flags = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.ecn_flags",
                                                    "ECN flags", base.HEX, nil, 0x03)
local f_chain_dyn_ipv4_ttl       = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.ipv4.ttl",
                                                    "Time To Live (TTL)", base.DEC)
local f_chain_dyn_ipv4_id        = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.ipv4.id",
                                                     "Identifier (IP-ID)", base.DEC)
---- IPv6 part
-- TODO
-- TCP part
local f_chain_dyn_tcp = ProtoField.bytes("rohc_lua.pkt.chain.dynamic.tcp", "TCP dynamic chain")
local f_chain_dyn_tcp_ecn_used  = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.ecn_used",
                                                   "ECN used", base.HEX, nil, 0x80)
local f_chain_dyn_tcp_ack_stride_flag
                                = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.ack_stride_flag",
                                                   "ACK stride flag", base.HEX, nil, 0x40)
local f_chain_dyn_tcp_ack_zero  = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.ack_zero",
                                                   "ACK zero", base.HEX, nil, 0x20)
local f_chain_dyn_tcp_urp_zero  = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.urp_zero",
                                                   "URP zero", base.HEX, nil, 0x10)
local f_chain_dyn_tcp_res_flags = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.res_flags",
                                                   "RES flags", base.HEX, nil, 0x0F)
local f_chain_dyn_tcp_ecn_flags = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.ecn_flags",
                                                   "ECN flags", base.HEX, nil, 0xc0)
local f_chain_dyn_tcp_urg_flag  = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.urg_flag",
                                                   "URG flag", base.HEX, nil, 0x20)
local f_chain_dyn_tcp_ack_flag  = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.ack_flag",
                                                   "ACK flag", base.HEX, nil, 0x10)
local f_chain_dyn_tcp_psh_flag  = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.psh_flag",
                                                   "PSH flag", base.HEX, nil, 0x08)
local f_chain_dyn_tcp_rsf_flags = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.rsf_flags",
                                                   "RSF flags", base.HEX, nil, 0x07)
local f_chain_dyn_tcp_msn       = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.tcp.msn",
                                                    "Master Sequence Number (MSN)", base.DEC)
local f_chain_dyn_tcp_seqnum    = ProtoField.uint32("rohc_lua.pkt.chain.dynamic.tcp.seqnum",
                                                    "TCP Sequence number", base.DEC)
local f_chain_dyn_tcp_acknum    = ProtoField.uint32("rohc_lua.pkt.chain.dynamic.tcp.acknum",
                                                    "TCP ACK number", base.DEC)
local f_chain_dyn_tcp_window    = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.tcp.window",
                                                    "TCP window", base.DEC)
local f_chain_dyn_tcp_checksum  = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.tcp.checksum",
                                                    "TCP checksum", base.HEX)
local f_chain_dyn_tcp_urg_ptr   = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.tcp.urg_ptr",
                                                    "TCP URG pointer", base.DEC)
local f_chain_dyn_tcp_ack_stride
                                = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.tcp.ack_stride",
                                                    "TCP ACK stride", base.DEC)
-- TCP options
local f_chain_dyn_tcp_opts_mss  = ProtoField.uint16("rohc_lua.pkt.chain.dynamic.tcp.opts.mss",
                                                    "MSS", base.DEC)
local f_chain_dyn_tcp_opts_ws   = ProtoField.uint8("rohc_lua.pkt.chain.dynamic.tcp.opts.ws",
                                                   "WS", base.DEC)

-- irregular chain
local f_chain_irreg = ProtoField.bytes("rohc_lua.pkt.chain.irregular", "Irregular chain")
---- IPv4 part
local f_chain_irreg_ipv4 = ProtoField.bytes("rohc_lua.pkt.chain.irregular.ipv4", "IPv4 irregular chain")
local f_chain_irreg_ipv4_ip_id
                         = ProtoField.uint16("rohc_lua.pkt.chain.irregular.ipv4.ip_id",
                                             "IP-ID", base.DEC)
local f_chain_irreg_ipv4_dscp
                         = ProtoField.uint8("rohc_lua.pkt.chain.irregular.ipv4.dscp",
                                             "DSCP", base.HEX, nil, 0xfc)
local f_chain_irreg_ipv4_ip_ecn_flags
                         = ProtoField.uint8("rohc_lua.pkt.chain.irregular.ipv4.ip_ecn_flags",
                                             "IP ECN flags", base.HEX, nil, 0x03)
local f_chain_irreg_ipv4_ttl_hopl
                         = ProtoField.uint8("rohc_lua.pkt.chain.irregular.ipv4.ttl_hopl",
                                             "TTL/HL", base.DEC)
---- IPv6 part
local f_chain_irreg_ipv6 = ProtoField.bytes("rohc_lua.pkt.chain.irregular.ipv6", "IPv6 irregular chain")
---- TCP part
local f_chain_irreg_tcp = ProtoField.bytes("rohc_lua.pkt.chain.irregular.tcp", "TCP irregular chain")
local f_chain_irreg_tcp_ip_ecn_flags
                        = ProtoField.uint8("rohc_lua.pkt.chain.irregular.tcp.ip_ecn_flags",
                                           "IP ECN flags", base.HEX, nil, 0xc0)
local f_chain_irreg_tcp_res_flags
                        = ProtoField.uint8("rohc_lua.pkt.chain.irregular.tcp.res_flags",
                                           "RES flags", base.HEX, nil, 0x3c)
local f_chain_irreg_tcp_ecn_flags
                        = ProtoField.uint8("rohc_lua.pkt.chain.irregular.tcp.ecn_flags",
                                           "TCP ECN flags", base.HEX, nil, 0x03)
local f_chain_irreg_tcp_checksum
                        = ProtoField.uint16("rohc_lua.pkt.chain.irregular.tcp.checksum",
                                            "TCP checksum", base.HEX)

-- co_common
local f_co_common           = ProtoField.bytes("rohc_lua.pkt.co_common",
                                               "TCP co_common")
local f_co_common_discriminator
                            = ProtoField.uint8("rohc_lua.pkt.co_common.discriminator",
                                               "discriminator", base.HEX, nil, 0xfe)
local f_co_common_ttl_hopl_outer_flag
                            = ProtoField.uint8("rohc_lua.pkt.co_common.ttl_hopl_outer_flag",
                                               "ttl_hopl_outer_flag", base.HEX, nil, 0x01)
local f_co_common_ack_flag  = ProtoField.uint8("rohc_lua.pkt.co_common.ack_flag",
                                               "ACK flag", base.DEC, nil, 0x80)
local f_co_common_psh_flag  = ProtoField.uint8("rohc_lua.pkt.co_common.psh_flag",
                                               "PSH flag", base.DEC, nil, 0x40)
local f_co_common_rsf_flags = ProtoField.uint8("rohc_lua.pkt.co_common.rsf_flags",
                                               "RSF flags", base.HEX, nil, 0x30)
local f_co_common_msn       = ProtoField.uint8("rohc_lua.pkt.co_common.msn",
                                               "MSN", base.DEC, nil, 0x0f)
local f_co_common_seq_indicator
                            = ProtoField.uint8("rohc_lua.pkt.co_common.seq_indicator",
                                               "Sequence indicator", base.DEC, nil, 0xc0)
local f_co_common_ack_indicator
                            = ProtoField.uint8("rohc_lua.pkt.co_common.ack_indicator",
                                               "ACK indicator", base.DEC, nil, 0x30)
local f_co_common_ack_stride_indicator
                            = ProtoField.uint8("rohc_lua.pkt.co_common.ack_stride_indicator",
                                               "ACK stride indicator", base.DEC, nil, 0x08)
local f_co_common_window_indicator
                            = ProtoField.uint8("rohc_lua.pkt.co_common.window_indicator",
                                               "Window indicator", base.DEC, nil, 0x04)
local f_co_common_ip_id_indicator
                            = ProtoField.uint8("rohc_lua.pkt.co_common.ip_id_indicator",
                                               "IP-ID indicator", base.DEC, nil, 0x02)
local f_co_common_urg_ptr_present
                            = ProtoField.uint8("rohc_lua.pkt.co_common.urg_ptr_present",
                                               "URG pointer present", base.DEC, nil, 0x01)
local f_co_common_reserved  = ProtoField.uint8("rohc_lua.pkt.co_common.reserved",
                                               "reserved", base.HEX, nil, 0x80)
local f_co_common_ecn_used  = ProtoField.uint8("rohc_lua.pkt.co_common.ecn_used",
                                               "ECN used", base.DEC, nil, 0x40)
local f_co_common_dscp_present
                            = ProtoField.uint8("rohc_lua.pkt.co_common.dscp_present",
                                               "DSCP present", base.DEC, nil, 0x20)
local f_co_common_ttl_hopl_present
                            = ProtoField.uint8("rohc_lua.pkt.co_common.ttl_hopl_present",
                                               "TTL/HL present", base.DEC, nil, 0x10)
local f_co_common_list_present
                            = ProtoField.uint8("rohc_lua.pkt.co_common.list_present",
                                               "list present", base.DEC, nil, 0x08)
local f_co_common_ip_id_behavior_innermost
                            = ProtoField.uint8("rohc_lua.pkt.co_common.ip_id_behavior_innermost",
                                               "innermost IP-ID behavior", base.DEC, nil, 0x06)
local f_co_common_urg_flag  = ProtoField.uint8("rohc_lua.pkt.co_common.urg_flag",
                                               "URG flag", base.DEC, nil, 0x01)
local f_co_common_df        = ProtoField.uint8("rohc_lua.pkt.co_common.df",
                                               "DF", base.DEC, nil, 0x80)
local f_co_common_crc       = ProtoField.uint8("rohc_lua.pkt.co_common.header_crc",
                                               "header CRC", base.HEX, nil, 0x7f)
local f_co_common_seqnum    = ProtoField.bytes("rohc_lua.pkt.co_common.seqnum",
                                               "Sequence number")
local f_co_common_acknum    = ProtoField.bytes("rohc_lua.pkt.co_common.acknum",
                                               "ACK number")
local f_co_common_ack_stride
                            = ProtoField.uint16("rohc_lua.pkt.co_common.ack_stride",
                                                "ACK stride", base.DEC)
local f_co_common_window    = ProtoField.uint16("rohc_lua.pkt.co_common.window",
                                                "window", base.DEC)
local f_co_common_ip_id8    = ProtoField.uint8("rohc_lua.pkt.co_common.ip_id",
                                               "innermost IP-ID (LSB)", base.HEX)
local f_co_common_ip_id16   = ProtoField.uint16("rohc_lua.pkt.co_common.ip_id",
                                                "innermost IP-ID", base.DEC)
local f_co_common_urg_ptr   = ProtoField.uint16("rohc_lua.pkt.co_common.urg_ptr",
                                                "URG pointer", base.DEC)
local f_co_common_dscp      = ProtoField.uint8("rohc_lua.pkt.co_common.dscp",
                                                "DSCP", base.HEX, nil, 0xfc)
local f_co_common_padding   = ProtoField.uint8("rohc_lua.pkt.co_common.dscp_padding",
                                                "DSCP padding", base.HEX, nil, 0x03)
local f_co_common_ttl_hopl  = ProtoField.uint8("rohc_lua.pkt.co_common.ttl_hopl",
                                                "TTL/HL", base.DEC)


rohc_rfc6846_ip_tcp.fields = {
	f_chain_static, f_chain_static_version_flag,
	f_chain_static_ipv4, f_chain_static_ipv4_reserved,
	f_chain_static_ipv4_protocol, f_chain_static_ipv4_srcaddr, f_chain_static_ipv4_dstaddr,
	f_chain_static_ipv6, f_chain_static_ipv6_flowlabel,
	f_chain_static_ipv6_next_hdr, f_chain_static_ipv6_srcaddr, f_chain_static_ipv6_dstaddr,
	f_chain_static_tcp, f_chain_static_tcp_srcport, f_chain_static_tcp_dstport,
	f_chain_dyn,
	f_chain_dyn_ipv4, f_chain_dyn_ipv4_reserved, f_chain_dyn_ipv4_df,
	f_chain_dyn_ipv4_ip_id_behavior, f_chain_dyn_ipv4_dscp, f_chain_dyn_ipv4_ecn_flags,
	f_chain_dyn_ipv4_ttl, f_chain_dyn_ipv4_id,
	f_chain_dyn_tcp, f_chain_dyn_tcp_ecn_used, f_chain_dyn_tcp_ack_stride_flag,
	f_chain_dyn_tcp_ack_zero, f_chain_dyn_tcp_urp_zero, f_chain_dyn_tcp_res_flags,
	f_chain_dyn_tcp_ecn_flags, f_chain_dyn_tcp_urg_flag, f_chain_dyn_tcp_ack_flag,
	f_chain_dyn_tcp_psh_flag, f_chain_dyn_tcp_rsf_flags, f_chain_dyn_tcp_msn,
	f_chain_dyn_tcp_seqnum, f_chain_dyn_tcp_acknum, f_chain_dyn_tcp_window,
	f_chain_dyn_tcp_checksum, f_chain_dyn_tcp_urg_ptr, f_chain_dyn_tcp_ack_stride,
	f_chain_dyn_tcp_opts_mss, f_chain_dyn_tcp_opts_ws,
	f_chain_irreg,
	f_chain_irreg_ipv4, f_chain_irreg_ipv4_ip_id, f_chain_irreg_ipv4_dscp,
	f_chain_irreg_ipv4_ip_ecn_flags, f_chain_irreg_ipv4_ttl_hopl,
	f_chain_irreg_ipv6,
	f_chain_irreg_tcp, f_chain_irreg_tcp_ip_ecn_flags, f_chain_irreg_tcp_res_flags,
	f_chain_irreg_tcp_ecn_flags, f_chain_irreg_tcp_checksum,
	f_list_tcp_opts, f_list_tcp_opts_reserved, f_list_tcp_opts_ps,
	f_list_tcp_opts_m, f_list_tcp_opts_xi0_odd_x, f_list_tcp_opts_xi0_odd_idx,
	f_list_tcp_opts_xi0_even_x, f_list_tcp_opts_xi0_even_idx,
	f_list_tcp_opts_xi0_padding,
	f_co_common, f_co_common_discriminator, f_co_common_ttl_hopl_outer_flag,
	f_co_common_ack_flag, f_co_common_psh_flag, f_co_common_rsf_flags, f_co_common_msn,
	f_co_common_seq_indicator, f_co_common_ack_indicator, f_co_common_ack_stride_indicator,
	f_co_common_window_indicator, f_co_common_ip_id_indicator, f_co_common_urg_ptr_present,
	f_co_common_reserved, f_co_common_ecn_used, f_co_common_dscp_present,
	f_co_common_ttl_hopl_present, f_co_common_list_present,
	f_co_common_ip_id_behavior_innermost, f_co_common_urg_flag, f_co_common_df,
	f_co_common_crc, f_co_common_seqnum, f_co_common_acknum, f_co_common_ack_stride,
	f_co_common_window, f_co_common_ip_id8, f_co_common_ip_id16, f_co_common_urg_ptr,
	f_co_common_dscp, f_co_common_padding, f_co_common_ttl_hopl,
}


-- dissect list of TCP options
local function dissect_list_tcp_opts(tcp_opts, pktinfo, tree)
	local tcp_opts_len = 0

	local tcp_opts_tree = tree:add(f_list_tcp_opts, tcp_opts)
	local ps = tcp_opts:range(tcp_opts_len, 1):bitfield(3, 1)
	local m = tcp_opts:range(tcp_opts_len, 1):bitfield(4, 4)
	tcp_opts_tree:add(f_list_tcp_opts_reserved, tcp_opts:range(tcp_opts_len, 1))
	tcp_opts_tree:add(f_list_tcp_opts_ps,       tcp_opts:range(tcp_opts_len, 1))
	tcp_opts_tree:add(f_list_tcp_opts_m,        tcp_opts:range(tcp_opts_len, 1))
	tcp_opts_len = tcp_opts_len + 1

	-- XI items
	local pos2index = {}
	local opts_nr = 0
	local items_nr = 0
	if ps == 0 then
		for xi_pos=1,m,2 do
			local xi_x   = tcp_opts:range(tcp_opts_len, 1):bitfield(0, 1)
			local xi_idx = tcp_opts:range(tcp_opts_len, 1):bitfield(1, 3)
			tcp_opts_tree:add(f_list_tcp_opts_xi0_odd_x,       tcp_opts:range(tcp_opts_len, 1))
			tcp_opts_tree:add(f_list_tcp_opts_xi0_odd_idx,     tcp_opts:range(tcp_opts_len, 1))
			pktinfo.private["rohc_tcp_opts_" .. opts_nr .. "_idx"] = xi_idx
			pktinfo.private["rohc_tcp_opts_" .. opts_nr .. "_x"] = xi_x
			opts_nr = opts_nr + 1
			if xi_x == 1 then
				pos2index[items_nr] = xi_idx
				items_nr = items_nr + 1
			end
			if xi_pos < m or (m % 2) == 0 then
				local xi_x   = tcp_opts:range(tcp_opts_len, 1):bitfield(4, 1)
				local xi_idx = tcp_opts:range(tcp_opts_len, 1):bitfield(5, 3)
				tcp_opts_tree:add(f_list_tcp_opts_xi0_even_x,   tcp_opts:range(tcp_opts_len, 1))
				tcp_opts_tree:add(f_list_tcp_opts_xi0_even_idx, tcp_opts:range(tcp_opts_len, 1))
				pktinfo.private["rohc_tcp_opts_" .. opts_nr .. "_idx"] = xi_idx
				pktinfo.private["rohc_tcp_opts_" .. opts_nr .. "_x"] = xi_x
				opts_nr = opts_nr + 1
				if xi_x == 1 then
					pos2index[items_nr] = xi_idx
					items_nr = items_nr + 1
				end
			else
				tcp_opts_tree:add(f_list_tcp_opts_xi0_padding,  tcp_opts:range(tcp_opts_len, 1))
			end
			tcp_opts_len = tcp_opts_len + 1
		end
	else
		-- TODO PS=1
		error("list with PS=1 not implemented yet")
	end
	pktinfo.private["rohc_tcp_opts_irreg_items_nr"] = m - items_nr
print("m = "..m)
print("items_nr = "..items_nr)

	-- list items
	for item_pos=1,items_nr do
	local opt_idx = pos2index[item_pos-1]
		if opt_idx == 0 then
			-- NOP: empty list item
		elseif opt_idx == 1 then
			-- EOL: TODO
			error("eol_dynamic() not implemented yet")
		elseif opt_idx == 2 then
			-- MSS
			tcp_opts_tree:add(f_chain_dyn_tcp_opts_mss, tcp_opts:range(tcp_opts_len, 2))
			tcp_opts_len = tcp_opts_len + 2
		elseif opt_idx == 3 then
			-- WS
			tcp_opts_tree:add(f_chain_dyn_tcp_opts_ws, tcp_opts:range(tcp_opts_len, 1))
			tcp_opts_len = tcp_opts_len + 1
		elseif opt_idx == 4 then
			-- TS: TODO
			error("ts_dynamic() not implemented yet")
		elseif opt_idx == 5 then
			-- SACK Permitted: empty list item
		elseif opt_idx == 6 then
			-- SACK: TODO
			error("sack_dynamic() not implemented yet")
		else
			-- generic: TODO
			error("generic_dynamic() not implemented yet")
		end
	end

	tcp_opts_tree:set_len(tcp_opts_len)

	return tcp_opts_len, m
end


-- dissect static chain, IP part
local function dissect_static_chain_ip(static_chain, pktinfo, tree)
	local offset = 0
	local ip_version

	local version_flag = static_chain:range(offset, 1):bitfield(0, 1)
	if version_flag == 0 then
		ip_version = 4
		local ipv4_tree = tree:add(f_chain_static_ipv4, static_chain)
		ipv4_tree:add(f_chain_static_version_flag, static_chain:range(offset, 1))
		ipv4_tree:add(f_chain_static_ipv4_reserved, static_chain:range(offset, 1))
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
	else
		ip_version = 6
		local ipv6_tree = tree:add(f_chain_static_ipv6, static_chain)
		ipv6_tree:add(f_chain_static_ipv6_version, static_chain:range(offset, 1))
		ipv6_tree:add(f_chain_static_ipv6_reserved, static_chain:range(offset, 1))
		local fl_enc_discriminator = static_chain:range(offset, 1):bitfield(4, 1)
		if fl_enc_discriminator == 0 then
			ipv6_tree:add(f_chain_static_ipv6_fl_enc_reserved, static_chain:range(offset, 1))
			offset = offset + 1
		else
			ipv6_tree:add(f_chain_static_ipv6_flowlabel, static_chain:range(offset, 3))
			offset = offset + 3
		end
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
	end

	return offset, ip_version
end

-- dissect static chain, TCP part
local function dissect_static_chain_tcp(static_chain, pktinfo, tree)
	local offset = 0

	local tcp_tree = tree:add(f_chain_static_tcp, static_chain)

	-- TCP source port
	local sport = static_chain:range(offset, 2):uint()
	tcp_tree:add(f_chain_static_tcp_srcport, sport)
	pktinfo.private["rohc_embedded_tcp_sport"] = sport
	offset = offset + 2

	-- TCP destination port
	local dport = static_chain:range(offset, 2):uint()
	tcp_tree:add(f_chain_static_tcp_dstport, dport)
	pktinfo.private["rohc_embedded_tcp_dport"] = dport
	offset = offset + 2

	tcp_tree:set_len(offset)
	return offset
end

-- dissect static chain
local function dissect_static_chain(static_chain, pktinfo, rohc_tree)
	local chain_static_tree = rohc_tree:add(f_chain_static, static_chain)
	local remain_data = static_chain
	local offset = 0
	local protocol
	local ip_hdrs_nr = 0

	-- dissect IP part
	pktinfo.private["rohc_embedded_protocol"] = "4"
	pktinfo.private["rohc_ip_hdrs_nr"] = 0
	while pktinfo.private["rohc_embedded_protocol"] == "4" or
		   pktinfo.private["rohc_embedded_protocol"] == "41" do
		local ip_part_len, ip_version =
			dissect_static_chain_ip(remain_data, pktinfo, chain_static_tree)
		offset = offset + ip_part_len
		remain_data = remain_data:range(ip_part_len, remain_data:len() - ip_part_len)
		pktinfo.private["rohc_ip_hdr_" .. (ip_hdrs_nr+1) .. "_version"] = ip_version
		ip_hdrs_nr = ip_hdrs_nr + 1
	end
	pktinfo.private["rohc_ip_hdrs_nr"] = ip_hdrs_nr

	-- dissect TCP part
	local tcp_part_len = dissect_static_chain_tcp(remain_data, pktinfo, chain_static_tree)
	offset = offset + tcp_part_len

	chain_static_tree:set_len(offset)
	return offset
end


-- dissect dynamic chain, IP part
local function dissect_dynamic_chain_ip(dyn_chain, pktinfo, tree, ip_version, is_innermost)
	local offset = 0
	local ip_id_behavior

	if ip_version == 4 then
		local ipv4_tree = tree:add(f_chain_dyn_ipv4, dyn_chain)
		ipv4_tree:add(f_chain_dyn_ipv4_reserved,       dyn_chain:range(offset, 1))
		ipv4_tree:add(f_chain_dyn_ipv4_df,             dyn_chain:range(offset, 1))
		ip_id_behavior = dyn_chain:range(offset, 1):bitfield(7, 1)
		ipv4_tree:add(f_chain_dyn_ipv4_ip_id_behavior, dyn_chain:range(offset, 1))
		offset = offset + 1
		ipv4_tree:add(f_chain_dyn_ipv4_dscp,           dyn_chain:range(offset, 1))
		ipv4_tree:add(f_chain_dyn_ipv4_ecn_flags,      dyn_chain:range(offset, 1))
		offset = offset + 1
		ipv4_tree:add(f_chain_dyn_ipv4_ttl,            dyn_chain:range(offset, 1))
		offset = offset + 1
		if ip_id_behavior ~= 3 then
			ipv4_tree:add(f_chain_dyn_ipv4_id, dyn_chain:range(offset, 2))
			offset = offset + 2
		end
		ipv4_tree:set_len(offset)
	elseif ip_version == 6 then
		-- TODO
		error("ipv6_dynamic() not implemented yet")
		ip_id_behavior = 2
	else
		error("dynamic chain: IP part: unsupported IP version "..ip_version)
		return nil
	end

	return offset, ip_id_behavior
end

-- dissect dynamic chain, TCP part
local function dissect_dynamic_chain_tcp(dyn_chain, pktinfo, tree)
	local offset = 0

	local tcp_tree = tree:add(f_chain_dyn_tcp, dyn_chain)
	local ecn_used = dyn_chain:range(offset, 1):bitfield(0, 1)
	pktinfo.private["ecn_used"] = ecn_used
	local ack_stride_flag = dyn_chain:range(offset, 1):bitfield(1, 1)
	local ack_zero = dyn_chain:range(offset, 1):bitfield(2, 1)
	local urp_zero = dyn_chain:range(offset, 1):bitfield(3, 1)
	tcp_tree:add(f_chain_dyn_tcp_ecn_used,         dyn_chain:range(offset, 1))
	tcp_tree:add(f_chain_dyn_tcp_ack_stride_flag,  dyn_chain:range(offset, 1))
	tcp_tree:add(f_chain_dyn_tcp_ack_zero,         dyn_chain:range(offset, 1))
	tcp_tree:add(f_chain_dyn_tcp_urp_zero,         dyn_chain:range(offset, 1))
	tcp_tree:add(f_chain_dyn_tcp_res_flags,        dyn_chain:range(offset, 1))
	offset = offset + 1
	tcp_tree:add(f_chain_dyn_tcp_ecn_flags,        dyn_chain:range(offset, 1))
	tcp_tree:add(f_chain_dyn_tcp_urg_flag,         dyn_chain:range(offset, 1))
	tcp_tree:add(f_chain_dyn_tcp_ack_flag,         dyn_chain:range(offset, 1))
	tcp_tree:add(f_chain_dyn_tcp_psh_flag,         dyn_chain:range(offset, 1))
	tcp_tree:add(f_chain_dyn_tcp_rsf_flags,        dyn_chain:range(offset, 1))
	offset = offset + 1
	tcp_tree:add(f_chain_dyn_tcp_msn,              dyn_chain:range(offset, 2))
	offset = offset + 2
	tcp_tree:add(f_chain_dyn_tcp_seqnum,           dyn_chain:range(offset, 4))
	offset = offset + 4
	if ack_zero == 0 then
		tcp_tree:add(f_chain_dyn_tcp_acknum,        dyn_chain:range(offset, 4))
		offset = offset + 4
	end
	tcp_tree:add(f_chain_dyn_tcp_window,           dyn_chain:range(offset, 2))
	offset = offset + 2
	tcp_tree:add(f_chain_dyn_tcp_checksum,         dyn_chain:range(offset, 2))
	offset = offset + 2
	if urp_zero == 0 then
		tcp_tree:add(f_chain_dyn_tcp_urg_ptr,       dyn_chain:range(offset, 2))
		offset = offset + 2
	end
	if ack_stride_flag == 1 then
		tcp_tree:add(f_chain_dyn_tcp_ack_stride,    dyn_chain:range(offset, 2))
		offset = offset + 2
	end

	-- TCP options
	local tcp_opts_len, tcp_opts_nr =
		dissect_list_tcp_opts(dyn_chain:range(offset, dyn_chain:len() - offset),
		                      pktinfo, tcp_tree)
	offset = offset + tcp_opts_len
	pktinfo.private["rohc_tcp_opts_nr"] = tcp_opts_nr

	tcp_tree:set_len(offset)
	return offset
end

-- dissect dynamic chain
local function dissect_dynamic_chain(dyn_chain, pktinfo, rohc_tree)
	local ip_hdrs_nr = tonumber(pktinfo.private["rohc_ip_hdrs_nr"])
	local chain_dyn_tree = rohc_tree:add(f_chain_dyn, dyn_chain)
	local remain_data = dyn_chain
	local offset = 0

	-- dissect IP part
	for ip_hdr_pos=1,ip_hdrs_nr do
		-- dissect IP header
		local ip_version = tonumber(pktinfo.private["rohc_ip_hdr_" .. ip_hdr_pos .. "_version"])
		local is_innermost = (ip_hdr_pos == ip_hdrs_nr)
		local ip_part_len, ip_id_behavior =
			dissect_dynamic_chain_ip(remain_data, pktinfo, chain_dyn_tree, ip_version, is_innermost)
		offset = offset + ip_part_len
		remain_data = remain_data:range(ip_part_len, remain_data:len() - ip_part_len)
		pktinfo.private["rohc_ip_hdr_" .. ip_hdr_pos .. "_ip_id_behavior"] = ip_id_behavior
	end

	-- dissect TCP part
	local tcp_part_len =
		dissect_dynamic_chain_tcp(remain_data, pktinfo, chain_dyn_tree)
	offset = offset + tcp_part_len

	chain_dyn_tree:set_len(offset)
	return offset
end


-- dissect irregular chain, IP part
local function dissect_irreg_chain_ip(irreg_chain, pktinfo, tree,
                                      ip_version, is_innermost, ip_id_behavior,
                                      ttl_irregular_chain_flag)
	local offset = 0

	if ip_version == 4 then
		local ipv4_tree = tree:add(f_chain_irreg_ipv4, irreg_chain)

		-- random IP-ID
		if ip_id_behavior == 2 then
			ipv4_tree:add(f_chain_irreg_ipv4_ip_id,           irreg_chain:range(offset, 2))
			offset = offset + 2
		end

		if is_innermost then
		else
			local ecn_used = tonumber(pktinfo.private["ecn_used"])
			if ecn_used == 1 then
				ipv4_tree:add(f_chain_irreg_ipv4_dscp,         irreg_chain:range(offset, 1))
				ipv4_tree:add(f_chain_irreg_ipv4_ip_ecn_flags, irreg_chain:range(offset, 1))
				offset = offset + 1
			end
			if ttl_irregular_chain_flag == 1 then
				ipv4_tree:add(f_chain_irreg_ipv4_ttl_hopl,     irreg_chain:range(offset, 1))
				offset = offset + 1
			end
		end
		ipv4_tree:set_len(offset)

	elseif ip_version == 6 then
		-- TODO
		error("ipv6_irregular() not implemented yet")
	else
		error("irregular chain: IP part: unsupported IP version "..ip_version)
		return nil
	end

	return offset
end

-- dissect irregular chain, TCP options part
local function dissect_irreg_chain_tcp_opts(irreg_chain, offset, pktinfo, tree)
	local opts_nr = tonumber(pktinfo.private["rohc_tcp_opts_nr"])
	local tcp_opts_len = 0

	local tcp_opts_tree
	if offset == irreg_chain:len() then
		tcp_opts_tree = tree
	else
		local tcp_opts = irreg_chain:range(offset, irreg_chain:len() - offset)
		tcp_opts_tree = tree:add(f_list_tcp_opts, tcp_opts)
	end

	for opt_pos=1,opts_nr do
		local opt_idx = tonumber(pktinfo.private["rohc_tcp_opts_" .. (opt_pos-1) .. "_idx"])
		local opt_x = tonumber(pktinfo.private["rohc_tcp_opts_" .. (opt_pos-1) .. "_x"])
		if opt_x == 0 then
			if opt_idx == 0 then
				-- NOP: empty list item
			elseif opt_idx == 1 then
				-- EOL: TODO
				error("eol_irregular() not implemented yet")
			elseif opt_idx == 2 then
				-- MSS: empty list item
			elseif opt_idx == 3 then
				-- WS: empty list item
			elseif opt_idx == 4 then
				-- TS: TODO
				error("ts_irregular() not implemented yet")
			elseif opt_idx == 5 then
				-- SACK Permitted: empty list item
			elseif opt_idx == 6 then
				-- SACK: TODO
				error("sack_irregular() not implemented yet")
			else
				-- generic: TODO
				error("generic_irregular() not implemented yet")
			end
		end
	end

	tcp_opts_tree:set_len(tcp_opts_len)

	return tcp_opts_len
end

-- dissect irregular chain, TCP part
local function dissect_irreg_chain_tcp(irreg_chain, pktinfo, tree)
	local ecn_used = tonumber(pktinfo.private["ecn_used"])
	local offset = 0

	local tcp_tree = tree:add(f_chain_irreg_tcp, irreg_chain)
	if ecn_used == 1 then
		tcp_tree:add(f_chain_irreg_tcp_ip_ecn_flags,  irreg_chain:range(offset, 1))
		tcp_tree:add(f_chain_irreg_tcp_res_flags,     irreg_chain:range(offset, 1))
		tcp_tree:add(f_chain_irreg_tcp_ecn_flags,     irreg_chain:range(offset, 1))
		offset = offset + 1
	end
	tcp_tree:add(f_chain_irreg_tcp_checksum,         irreg_chain:range(offset, 2))
	offset = offset + 2

	-- TCP options
	local tcp_opts_len =
		dissect_irreg_chain_tcp_opts(irreg_chain, offset, pktinfo, tcp_tree)
	offset = offset + tcp_opts_len

	tcp_tree:set_len(offset)
	return offset
end

-- dissect irregular chain
local function dissect_irreg_chain(irreg_chain, pktinfo, rohc_tree, ttl_irregular_chain_flag)
	local ip_hdrs_nr = tonumber(pktinfo.private["rohc_ip_hdrs_nr"])
	local chain_irreg_tree = rohc_tree:add(f_chain_irreg, irreg_chain)
	local remain_data = irreg_chain
	local offset = 0

	-- dissect IP part
	for ip_hdr_pos=1,ip_hdrs_nr do
		-- dissect IP header
		local ip_version = tonumber(pktinfo.private["rohc_ip_hdr_" .. ip_hdr_pos .. "_version"])
		local is_innermost = (ip_hdr_pos == ip_hdrs_nr)
		local ip_id_behavior =
			tonumber(pktinfo.private["rohc_ip_hdr_" .. ip_hdr_pos .. "_ip_id_behavior"])
		local ip_part_len =
			dissect_irreg_chain_ip(remain_data, pktinfo, chain_irreg_tree,
			                       ip_version, is_innermost, ip_id_behavior,
			                       ttl_irregular_chain_flag)
		offset = offset + ip_part_len
		remain_data = remain_data:range(ip_part_len, remain_data:len() - ip_part_len)
	end

	-- dissect TCP part
	local tcp_part_len =
		dissect_irreg_chain_tcp(remain_data, pktinfo, chain_irreg_tree)
	offset = offset + tcp_part_len

	chain_irreg_tree:set_len(offset)
	return offset
end

-- dissect profile-specific part of IR packet
function rohc_rfc6846_dissect_pkt_ir(ir_pkt, pktinfo, ir_tree)
	local offset = 0
	-- static chain
	local static_chain = ir_pkt:range(offset, ir_pkt:len() - offset)
	local static_chain_len = dissect_static_chain(static_chain, pktinfo, ir_tree)
	offset = offset + static_chain_len
	-- dynamic chain
	local dyn_chain = ir_pkt:range(offset, ir_pkt:len() - offset)
	local dyn_chain_len = dissect_dynamic_chain(dyn_chain, pktinfo, ir_tree)
	offset = offset + dyn_chain_len
	return offset, protocol
end

-- dissect IR-DYN packet
-- dissect profile-specific part of IR-DYN packet
function rohc_rfc6846_dissect_pkt_irdyn(irdyn_pkt, pktinfo, irdyn_tree)
	local offset = 0
	-- dynamic chain
	local dyn_chain = irdyn_pkt:range(offset, irdyn_pkt:len() - offset)
	local dyn_chain_len = dissect_dynamic_chain(dyn_chain, pktinfo, irdyn_tree)
	offset = offset + dyn_chain_len
	return offset
end

-- dissect CO packets
function rohc_rfc6846_dissect_pkt_co(co_pkt, pktinfo, co_tree)
	local offset = 0
	local ttl_irregular_chain_flag = 0

	if co_pkt:range(offset, 1):bitfield(0, 7) == 0x7d then
		-- co_common
		pktinfo.private["rohc_packet_type"] = "co_common"
		local co_common_tree = co_tree:add(f_co_common, co_pkt)
		ttl_irregular_chain_flag = co_pkt:range(offset, 1):bitfield(7, 1)
		co_common_tree:add(f_co_common_discriminator,        co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_ttl_hopl_outer_flag,  co_pkt:range(offset, 1))
		offset = offset + 1
		co_common_tree:add(f_co_common_ack_flag,             co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_psh_flag,             co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_rsf_flags,            co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_msn,                  co_pkt:range(offset, 1))
		offset = offset + 1
		local seq_indicator = co_pkt:range(offset, 1):bitfield(0, 2)
		local ack_indicator = co_pkt:range(offset, 1):bitfield(2, 2)
		local ack_stride_indicator = co_pkt:range(offset, 1):bitfield(4, 1)
		local window_indicator = co_pkt:range(offset, 1):bitfield(5, 1)
		local ip_id_indicator = co_pkt:range(offset, 1):bitfield(6, 1)
		local urg_ptr_present = co_pkt:range(offset, 1):bitfield(7, 1)
		co_common_tree:add(f_co_common_seq_indicator,        co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_ack_indicator,        co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_ack_stride_indicator, co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_window_indicator,     co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_ip_id_indicator,      co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_urg_ptr_present,      co_pkt:range(offset, 1))
		offset = offset + 1
		local ecn_used = co_pkt:range(offset, 1):bitfield(1, 1)
		pktinfo.private["ecn_used"] = ecn_used
		local dscp_present = co_pkt:range(offset, 1):bitfield(2, 1)
		local ttl_hopl_present = co_pkt:range(offset, 1):bitfield(3, 1)
		local list_present = co_pkt:range(offset, 1):bitfield(4, 1)
		local ip_id_behavior_innermost = co_pkt:range(offset, 1):bitfield(5, 2)
		co_common_tree:add(f_co_common_reserved,             co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_ecn_used,             co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_dscp_present,         co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_ttl_hopl_present,     co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_list_present,         co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_ip_id_behavior_innermost, co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_urg_flag,             co_pkt:range(offset, 1))
		offset = offset + 1
		co_common_tree:add(f_co_common_df,                   co_pkt:range(offset, 1))
		co_common_tree:add(f_co_common_crc,                  co_pkt:range(offset, 1))
		offset = offset + 1
		if seq_indicator == 1 then
			co_common_tree:add(f_co_common_seqnum,            co_pkt:range(offset, 1))
			offset = offset + 1
		elseif seq_indicator == 2 then
			co_common_tree:add(f_co_common_seqnum,            co_pkt:range(offset, 2))
			offset = offset + 2
		elseif seq_indicator == 3 then
			co_common_tree:add(f_co_common_seqnum,            co_pkt:range(offset, 4))
			offset = offset + 4
		end
		if ack_indicator == 1 then
			co_common_tree:add(f_co_common_acknum,            co_pkt:range(offset, 1))
			offset = offset + 1
		elseif ack_indicator == 2 then
			co_common_tree:add(f_co_common_acknum,            co_pkt:range(offset, 2))
			offset = offset + 2
		elseif ack_indicator == 3 then
			co_common_tree:add(f_co_common_acknum,            co_pkt:range(offset, 4))
			offset = offset + 4
		end
		if ack_stride_indicator == 1 then
			co_common_tree:add(f_co_common_ack_stride,        co_pkt:range(offset, 2))
			offset = offset + 2
		end
		if window_indicator == 1 then
			co_common_tree:add(f_co_common_window,            co_pkt:range(offset, 2))
			offset = offset + 2
		end
		if ip_id_behavior_innermost == 0 or ip_id_behavior_innermost == 1 then
			if ip_id_indicator == 0 then
				co_common_tree:add(f_co_common_ip_id8,         co_pkt:range(offset, 1))
				offset = offset + 1
			else
				co_common_tree:add(f_co_common_ip_id16,        co_pkt:range(offset, 2))
				offset = offset + 2
			end
		end
		if urg_ptr_present == 1 then
			co_common_tree:add(f_co_common_urg_ptr,           co_pkt:range(offset, 2))
			offset = offset + 2
		end
		if dscp_present == 1 then
			co_common_tree:add(f_co_common_dscp,              co_pkt:range(offset, 1))
			co_common_tree:add(f_co_common_padding,           co_pkt:range(offset, 1))
			offset = offset + 1
		end
		if ttl_hopl_present == 1 then
			co_common_tree:add(f_co_common_ttl_hopl,          co_pkt:range(offset, 1))
			offset = offset + 1
		end
		-- TCP options
		if list_present == 1 then
			local tcp_opts_len, tcp_opts_nr =
				dissect_list_tcp_opts(co_pkt:range(offset, co_pkt:len() - offset),
				                      pktinfo, co_common_tree)
			offset = offset + tcp_opts_len
			pktinfo.private["rohc_tcp_opts_nr"] = tcp_opts_nr
		end

		co_common_tree:set_len(offset)
	else
		-- other CO packets: TODO
		error("CO packet not implemented yet")
	end

	-- irregular chain
	local irreg_chain = co_pkt:range(offset, co_pkt:len() - offset)
	local irreg_chain_len =
		dissect_irreg_chain(irreg_chain, pktinfo, co_tree, ttl_irregular_chain_flag)
	offset = offset + irreg_chain_len

	return offset
end


-- tell the ROHC protocol that this dissector is able to parse the IP/TCP profile
local rohc_profiles = DissectorTable.get("rohc.profiles")
rohc_profiles:add(rohc_rfc6846_ip_tcp_profile_id, rohc_rfc6846_ip_tcp)

