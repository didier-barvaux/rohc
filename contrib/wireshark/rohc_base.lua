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
-- @file   rohc_base.lua
-- @brief  Wireshark dissector for the ROHC protocol
-- @author Didier Barvaux <didier@barvaux.org>
--

-- register the ROHC protocol
local rohc_protocol = Proto("rohc_lua", "RObust Header Compression (ROHC) -- LUA")

-- ROHC profiles
local profile_ids = {
	[0x0000] = "ROHCv1 Uncompressed profile (RFC 3095)",
	[0x0001] = "ROHCv1 IP/UDP/RTP profile (RFC 3095)",
	[0x0002] = "ROHCv1 IP/UDP profile (RFC 3095)",
	[0x0003] = "ROHCv1 IP/ESP profile (RFC 3095)",
	[0x0004] = "ROHCv1 IP-only profile (RFC 3843)",
	[0x0005] = "ROHCv1 IP/UDP/RTP Link-Layer Assisted Profile (LLA) profile (RFC 4362)",
	[0x0006] = "ROHCv1 IP/TCP profile (RFC 6846)",
	[0x0007] = "ROHCv1 IP/UDP-Lite/RTP profile (RFC 4019)",
	[0x0008] = "ROHCv1 IP/UDP-Lite profile (RFC 4019)"
}

-- padding octets
local f_padding = ProtoField.bytes("rohc_lua.padding", "Padding")

-- Add-CID
local f_add_cid      = ProtoField.bytes("rohc_lua.add_cid", "Add-CID")
local f_add_cid_type = ProtoField.new("Add-CID type", "rohc_lua.add_cid.type",
                                      ftypes.UINT8, nil, base.HEX, 0xf0)
local f_add_cid_value = ProtoField.new("Add-CID value", "rohc_lua.add_cid.cid",
                                       ftypes.UINT8, nil, base.DEC, 0x0f)

-- feedback octets
local f_feedback      = ProtoField.bytes("rohc_lua.feedback", "Feedback")
local f_feedback_type = ProtoField.uint8("rohc_lua.feedback.type", "Feedback type",
                                         base.HEX, nil, 0xf8)
local f_feedback_code = ProtoField.uint8("rohc_lua.feedback.code", "Feedback code",
                                         base.DEC, nil, 0x07)
local f_feedback_size = ProtoField.uint8("rohc_lua.feedback.size", "Feedback size", base.DEC)
local f_feedback1     = ProtoField.bytes("rohc_lua.feedback.feedback1", "FEEDBACK-1")
local f_feedback2     = ProtoField.bytes("rohc_lua.feedback.feedback2", "FEEDBACK-2")

-- segment octets
local f_segment   = ProtoField.bytes("rohc_lua.segment", "Segment")

-- common fields for IR and IR-DYN packets
local f_pkt_profile = ProtoField.uint8("rohc_lua.pkt.profile", "Profile",
                                       base.HEX, profile_ids)
local f_pkt_crc8    = ProtoField.uint8("rohc_lua.pkt.crc8", "CRC-8", base.HEX)
-- IR packet
local f_pkt_ir      = ProtoField.bytes("rohc_lua.pkt.ir", "IR")
local f_pkt_ir_type = ProtoField.uint8("rohc_lua.pkt.ir.type", "IR type octet",
                                       base.HEX, nil, 0xfe)
local f_pkt_ir_x    = ProtoField.uint8("rohc_lua.pkt.ir.x", "Profile specific information",
                                       base.DEC, nil, 0x01)
-- IR-DYN packet
local f_pkt_irdyn      = ProtoField.bytes("rohc_lua.pkt.irdyn", "IR-DYN")
local f_pkt_irdyn_type = ProtoField.uint8("rohc_lua.pkt.irdyn.type", "IR-DYN type octet", base.HEX)

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

-- payload
local f_payload         = ProtoField.bytes("rohc_lua.payload", "ROHC payload")
local f_payload_trailer = ProtoField.bytes("rohc_lua.payload.trailer",
                                           "Remaining bytes after ROHC payload")


rohc_protocol.fields = {
	f_padding,
	f_add_cid, f_add_cid_type, f_add_cid_value,
	f_feedback, f_feedback_type, f_feedback_code, f_feedback_size, f_feedback1, f_feedback2,
	f_segment,
	f_pkt_profile, f_pkt_crc8,
	f_pkt_ir, f_pkt_ir_type, f_pkt_ir_x,
	f_pkt_irdyn, f_pkt_irdyn_type, f_pkt_irdyn_x,
	f_chain_static,
	f_chain_static_ipv4, f_chain_static_ipv4_version, f_chain_static_ipv4_padding,
	f_chain_static_ipv4_protocol, f_chain_static_ipv4_srcaddr, f_chain_static_ipv4_dstaddr,
	f_chain_dyn,
	f_chain_dyn_ipv4, f_chain_dyn_ipv4_tos, f_chain_dyn_ipv4_ttl, f_chain_dyn_ipv4_id,
	f_chain_dyn_ipv4_df, f_chain_dyn_ipv4_rnd, f_chain_dyn_ipv4_nbo, f_chain_dyn_ipv4_padding,
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
	f_payload, f_payload_trailer
}

local ef_cid = ProtoExpert.new("rohc_lua.cid", "CID",
                               expert.group.PROTOCOL, expert.severity.NOTE)
rohc_protocol.experts = { ef_cid }


-- list of ROHC contexts, indexed per CID
local rohc_contexts = { }


-- dissect Add-CID octet
local function dissect_add_cid_if_any(bytes, pktinfo, tree)
	local add_cid_found = (bytes:range(offset, 1):bitfield(0, 4) == 0x0e)
	local add_cid_value = 0
	local add_cid_count = 0
	local offset = 0

	if add_cid_found then
		local add_cid_tree = tree:add(f_add_cid, bytes:range(offset, 1))
		add_cid_tree:add(f_add_cid_type, bytes:range(offset, 1))
		add_cid_tree:add(f_add_cid_value, bytes:range(offset, 1))
		add_cid_value = bytes:range(offset, 1):bitfield(4, 4)
		add_cid_count = add_cid_count + 1
		offset = offset + 1
	end

	return offset, add_cid_value, add_cid_count
end

-- dissect ROHC feedback
local function dissect_feedback(feedback_bytes, pktinfo, rohc_tree)
	local feedback_size

	local feedback_code = feedback_bytes:range(0, 1):bitfield(5, 3)
	if feedback_code == 0 then
		feedback_size = 2 + feedback_bytes:range(1, 1)
	else
		feedback_size = 1 + feedback_code
	end

	local offset = 0
	local feedback_tree = rohc_tree:add(f_feedback, feedback_bytes:range(offset, feedback_size))
	feedback_tree:add(f_feedback_type, feedback_bytes:range(offset, 1))
	feedback_tree:add(f_feedback_code, feedback_bytes:range(offset, 1))
	offset = offset + 1
	if feedback_code == 0 then
		feedback_tree:add(f_feedback_size, feedback_bytes:range(offset, 1))
		offset = offset + 1
	end

	-- remaining feedback data
	local feedback_type = 0
	if true then -- TODO: handle large CIDs
		-- small CIDs
		if (feedback_size - offset) == 1 then
			-- FEEDBACK-1
			feedback_type = 1
		elseif feedback_bytes:range(offset, 1):bitfield(0, 2) == 3 then
			-- parse Add-CID if any
			local add_cid_len, add_cid_value, add_cid_count =
				dissect_add_cid_if_any(feedback_bytes:range(offset, 1), pktinfo, feedback_tree)
			offset = offset + add_cid_len
			if (feedback_size - offset) == 2 then
				-- FEEDBACK-1
				feedback_type = 1
			else
				-- FEEDBACK-2
				feedback_type = 2
			end
		else
			-- FEEDBACK-2
			feedback_type = 2
		end
	else
		-- large CIDs
		error("unsupported ROHC packet: large CIDs not supported yet")
		return -1
	end

	if feedback_type == 1 then
		feedback_tree:add(f_feedback1, feedback_bytes:range(offset, feedback_size - offset))
		offset = feedback_size
	elseif feedback_type == 2 then
		feedback_tree:add(f_feedback2, feedback_bytes:range(offset, feedback_size - offset))
		offset = feedback_size
	else
		error("unsupported ROHC packet: unknown feedback type")
	end

	return offset
end

-- dissect static chain
local function dissect_static_chain(static_chain, pktinfo, rohc_tree, profile_id)
	local offset = 0
	local protocol

	local chain_static_tree = rohc_tree:add(f_chain_static, static_chain)

	if profile_id == 0x0001 or profile_id == 0x0002 or profile_id == 0x0003 or
	   profile_id == 0x0004 or profile_id == 0x0006 or profile_id == 0x0008 or
	   profile_id == 0x0007 then
		-- dissect IP part
		-- TODO: handle IPv6
		local ipv4_tree = chain_static_tree:add(f_chain_static_ipv4, static_chain)
		ipv4_tree:add(f_chain_static_ipv4_version, static_chain:range(offset, 1))
		ipv4_tree:add(f_chain_static_ipv4_padding, static_chain:range(offset, 1))
		offset = offset + 1
		protocol = static_chain:range(offset, 1):uint()
		ipv4_tree:add(f_chain_static_ipv4_protocol, static_chain:range(offset, 1))
		offset = offset + 1
		pktinfo.cols.src:set(static_chain:range(offset + 0, 1):uint().."."..
		                     static_chain:range(offset + 1, 1):uint().."."..
		                     static_chain:range(offset + 2, 1):uint().."."..
		                     static_chain:range(offset + 3, 1):uint())
		ipv4_tree:add(f_chain_static_ipv4_srcaddr, static_chain:range(offset, 4))
		offset = offset + 4
		ipv4_tree:add(f_chain_static_ipv4_dstaddr, static_chain:range(offset, 4))
		offset = offset + 4
	end

	if profile_id == 0x0001 or profile_id == 0x0002 then
		-- dissect UDP part
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

	return offset, protocol
end

-- dissect dynamic chain
local function dissect_dynamic_chain(dyn_chain, pktinfo, rohc_tree, profile_id)
	local offset = 0

	local chain_dyn_tree = rohc_tree:add(f_chain_dyn, dyn_chain)

	if profile_id == 0x0001 or profile_id == 0x0002 or profile_id == 0x0003 or
	   profile_id == 0x0004 or profile_id == 0x0006 or profile_id == 0x0008 or
	   profile_id == 0x0007 then
		-- dissect IP part
		-- TODO: handle IPv6
		local ipv4_tree = chain_dyn_tree:add(f_chain_dyn_ipv4, dyn_chain)
		ipv4_tree:add(f_chain_dyn_ipv4_tos, dyn_chain:range(offset, 1))
		offset = offset + 1
		ipv4_tree:add(f_chain_dyn_ipv4_ttl, dyn_chain:range(offset, 1))
		offset = offset + 1
		ipv4_tree:add(f_chain_dyn_ipv4_id, dyn_chain:range(offset, 2))
		offset = offset + 2
		ipv4_tree:add(f_chain_dyn_ipv4_df,      dyn_chain:range(offset, 1))
		ipv4_tree:add(f_chain_dyn_ipv4_rnd,     dyn_chain:range(offset, 1))
		ipv4_tree:add(f_chain_dyn_ipv4_nbo,     dyn_chain:range(offset, 1))
		ipv4_tree:add(f_chain_dyn_ipv4_padding, dyn_chain:range(offset, 1))
		offset = offset + 1
		-- TODO: handle generic extension header list
	end

	if profile_id == 0x0001 or profile_id == 0x0002 then
		-- dissect UDP part
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

	return offset
end

-- dissect IR packet
local function dissect_pkt_ir(ir_pkt, pktinfo, ir_tree)
	local offset = 0
	-- packet type and profile-specific bit
	ir_tree:add(f_pkt_ir_type, ir_pkt:range(offset, 1))
	ir_tree:add(f_pkt_ir_x,    ir_pkt:range(offset, 1))
	offset = offset + 1
	-- profile ID
	local profile_id = ir_pkt:range(offset, 1):uint()
	pktinfo.cols.info:append(" profile="..profile_ids[profile_id])
	ir_tree:add(f_pkt_profile, ir_pkt:range(offset, 1))
	offset = offset + 1
	-- CRC
	ir_tree:add(f_pkt_crc8, ir_pkt:range(offset, 1))
	offset = offset + 1
	-- static chain
	local static_chain = ir_pkt:range(offset, ir_pkt:len() - offset)
	local static_chain_len, protocol =
		dissect_static_chain(static_chain, pktinfo, ir_tree, profile_id)
	offset = offset + static_chain_len
	-- dynamic chain
	local dyn_chain = ir_pkt:range(offset, ir_pkt:len() - offset)
	local dyn_chain_len = dissect_dynamic_chain(dyn_chain, pktinfo, ir_tree, profile_id)
	offset = offset + dyn_chain_len
	return offset, profile_id, protocol
end

-- dissect IR-DYN packet
local function dissect_pkt_irdyn(irdyn_pkt, pktinfo, irdyn_tree)
	local offset = 0
	-- packet type
	irdyn_tree:add(f_pkt_irdyn_type, irdyn_pkt:range(offset, 1))
	offset = offset + 1
	-- profile ID
	local profile_id = irdyn_pkt:range(offset, 1):uint()
	pktinfo.cols.info:append(" profile="..profile_ids[profile_id])
	irdyn_tree:add(f_pkt_profile, irdyn_pkt:range(offset, 1))
	offset = offset + 1
	-- CRC
	irdyn_tree:add(f_pkt_crc8, irdyn_pkt:range(offset, 1))
	offset = offset + 1
	-- dynamic chain
	local dyn_chain = irdyn_pkt:range(offset, irdyn_pkt:len() - offset)
	local dyn_chain_len = dissect_dynamic_chain(dyn_chain, pktinfo, irdyn_tree, profile_id)
	offset = offset + dyn_chain_len
	return offset, profile_id
end

-- dissect UOR extension 0
local function dissect_pkt_uor_ext0(uor_pkt, pktinfo, rohc_tree)
	local offset = 0
	local ext_tree = rohc_tree:add(f_pkt_uor_ext0, uor_pkt)
	ext_tree:add(f_pkt_uor_ext0_type,  uor_pkt:range(offset, 1))
	ext_tree:add(f_pkt_uor_ext0_sn,    uor_pkt:range(offset, 1))
	ext_tree:add(f_pkt_uor_ext0_ip_id, uor_pkt:range(offset, 1))
	offset = offset + 1
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
			return -1
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
			return -1
		end
		if ext3_I2 == 1 then
			ext_outer_fields_tree:add(f_pkt_uor_ext3_outer_ip_id, uor_pkt:range(offset, 2))
			offset = offset + 2
		end
	end
	-- TODO: RTP header flags and fields

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

-- dissect UO-0 packet
local function dissect_pkt_uo0(uo0_pkt, pktinfo, rohc_tree)
	local offset = 0
	local uo0_tree = rohc_tree:add(f_pkt_uo0, uo0_pkt)
	uo0_tree:add(f_pkt_uo0_type, uo0_pkt:range(offset, 1))
	uo0_tree:add(f_pkt_uo0_sn,   uo0_pkt:range(offset, 1))
	uo0_tree:add(f_pkt_uo0_crc3, uo0_pkt:range(offset, 1))
	offset = offset + 1
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
		local ext_len = dissect_pkt_uor_ext(ext_bytes, pktinfo, rohc_tree)
		offset = offset + ext_len
	end
	return offset
end

function rohc_protocol.dissector(tvbuf, pktinfo, root)
	-- general packet format (RFC 3095, §5.2):
	--     --- --- --- --- --- --- --- ---
	--    :           Padding             :  variable length
	--     --- --- --- --- --- --- --- ---
	--    :           Feedback            :  0 or more feedback elements
	--     --- --- --- --- --- --- --- ---
	--    :            Header             :  variable, with CID information
	--     --- --- --- --- --- --- --- ---
	--    :           Payload             :
	--     --- --- --- --- --- --- --- ---

	-- RFC 3095, §5.2.6 "ROHC initial decompressor processing"
	-- 1110:     Padding or Add-CID octet
	-- 11110:    Feedback
	-- 11111000: IR-DYN packet
	-- 1111110:  IR packet
	-- 1111111:  Segment

	pktinfo.cols.protocol:set("ROHC")
	pktinfo.cols.info:set("ROHC")
	local pktlen = tvbuf:reported_length_remaining()
	local tree = root:add(rohc_protocol, tvbuf:range(offset, pktlen))
	local offset = 0

	-- how many padding octets?
	local padding_bytes_nr = 0
	while tvbuf:range(offset, 1) == 0xe0 do
		print("padding octet detected")
		padding_bytes_nr = padding_bytes_nr + 1
	end
	print(padding_bytes_nr, " padding octets detected")
	if padding_bytes_nr > 0 then
		local padding_bytes = tvbuf:range(offset, padding_bytes_nr)
		tree:add(f_padding, padding_bytes)
		offset = offset + padding_bytes_nr
	end

	-- parse Add-CID and feedback blocks
	local add_cid_value = 0
	local add_cid_found
	local add_cid_count = 0
	local feedback_found
	repeat
		add_cid_found = (tvbuf:range(offset, 1):bitfield(0, 4) == 0x0e)
		feedback_found = (tvbuf:range(offset, 1):bitfield(0, 5) == 0x1e)

		-- Add-CID ?
		local add_cid_len, add_cid_value, add_cid_count =
			dissect_add_cid_if_any(tvbuf:range(offset, 1), pktinfo, tree)
		offset = offset + add_cid_len

		-- feedback?
		if feedback_found then
			print("feedback octet detected")
			if add_cid_found then
				error("malformed ROHC packet: feedback octet found after Add-CID octet")
				return
			end
			-- parse feedback
			local feedback_bytes = tvbuf:range(offset, tvbuf:len() - offset)
			local feedback_len = dissect_feedback(feedback_bytes, pktinfo, tree)
			if feedback_len < 0 then
				return
			end
			offset = offset + feedback_len
		end
	until not add_cid_found and not feedback_found

	-- segment?
	if tvbuf:range(offset, 1):bitfield(0, 7) == 0x7f then
		print("segment octet detected")
		-- TODO: parse segment
		local segment_tree = tree:add(f_segment, tvbuf:range(offset, 1))
		offset = offset + 1
		error("unsupported ROHC packet: segment is not supported yet")
		return
	end

	-- determine CID for small CIDs
	-- TODO: handle large CIDs
	local cid
	if add_cid_count > 1 then
		error("malformed ROHC packet: "..add_cid_count.." Add-CID octets found")
		return
	elseif add_cid_count == 1 then
		cid = add_cid_value
	else
		cid = 0
	end
	tree:add_proto_expert_info(ef_cid, "CID = "..cid)
	pktinfo.cols.info:append(" CID="..cid)

	-- packet type?
	print("packet type = 0x"..tvbuf:range(offset, 1))
	local profile_id
	local protocol
	local hdr_len
	if tvbuf:range(offset, 1):bitfield(0, 7) == 0x7e then
		-- IR packet
		local ir_pkt = tvbuf:range(offset, tvbuf:len() - offset)
		local ir_tree = tree:add(f_pkt_ir, ir_pkt)
		hdr_len, profile_id, protocol = dissect_pkt_ir(ir_pkt, pktinfo, ir_tree)
	elseif tvbuf:range(offset, 1):uint() == 0xf8 then
		-- IR-DYN packet
		local irdyn_pkt = tvbuf:range(offset, tvbuf:len() - offset)
		local irdyn_tree = tree:add(f_pkt_irdyn, irdyn_pkt)
		hdr_len, profile_id = dissect_pkt_irdyn(irdyn_pkt, pktinfo, irdyn_tree)
		protocol = rohc_contexts[cid]["protocol"]
	else
		profile_id = rohc_contexts[cid]["profile"]
		protocol = rohc_contexts[cid]["protocol"]
		print("CID "..cid.." uses profile ID 0x"..profile_id.." and protocol "..protocol)

		if tvbuf:range(offset, 1):bitfield(0, 1) == 0x0 then
			-- UO-0
			hdr_len = dissect_pkt_uo0(tvbuf:range(offset, tvbuf:len() - offset), pktinfo, tree)
		elseif tvbuf:range(offset, 1):bitfield(0, 2) == 0x2 then
			-- UO-1
			hdr_len = dissect_pkt_uo1(tvbuf:range(offset, tvbuf:len() - offset), pktinfo, tree)
		elseif tvbuf:range(offset, 1):bitfield(0, 3) == 0x6 then
			-- UOR-2
			hdr_len = dissect_pkt_uor2(tvbuf:range(offset, tvbuf:len() - offset), pktinfo, tree)
		else
			error("unsupported ROHC packet")
			return
		end
	end
	offset = offset + hdr_len

	-- ROHC payload
	local payload_bytes = tvbuf:range(offset, tvbuf:len() - offset)
	print("profile ID = "..profile_id)
	print("protocol = "..protocol)
	if profile_id == 0x0004 then
		-- TODO: handle IPv6
		local ip_tables = DissectorTable.get("ip.proto")
		local ipv4_payload_len =
			ip_tables:try(protocol, payload_bytes:tvb(), pktinfo, root)
		offset = offset + ipv4_payload_len
	else
		-- TODO: handle RTP, UDP, ESP, TCP
		local payload_tree = root:add(f_payload, payload_bytes)
		offset = offset + payload_bytes
	end
	if offset ~= tvbuf:len() then
		root:add(f_payload_trailer, tvbuf:range(offset, tvbuf:len() - offset))
	end

	-- remember the context information
	rohc_contexts[cid] = { ["profile"] = profile_id, ["protocol"] = protocol }
end

local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0x22f1, rohc_protocol)

