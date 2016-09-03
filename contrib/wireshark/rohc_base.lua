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

local rohc_protocol_info = {
	version    = "1.0",
	author     = "Didier Barvaux",
	repository = "https://rohc-lib.org/"
}
set_plugin_info(rohc_protocol_info)

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
local rohc_profiles = DissectorTable.new("rohc.profiles", "ROHC profiles",
                                         ftypes.UINT16, base.HEX)

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
	-- remaining bytes are specific to the ROHC profile
	pktinfo.private["rohc_packet_type"] = 1
	pktinfo.private["rohc_profile_id"] = profile_id
	local ir_remain_bytes = ir_pkt:range(offset, ir_pkt:len() - offset)
	local profiles = DissectorTable.get("rohc.profiles")
	local profile_part_len = profiles:try(profile_id, ir_remain_bytes:tvb(), pktinfo, ir_tree)
	offset = offset + profile_part_len
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
	-- remaining bytes are specific to the ROHC profile
	pktinfo.private["rohc_packet_type"] = 2
	pktinfo.private["rohc_profile_id"] = profile_id
	local irdyn_remain_bytes = irdyn_pkt:range(offset, irdyn_pkt:len() - offset)
	local profiles = DissectorTable.get("rohc.profiles")
	local profile_part_len =
		profiles:try(profile_id, irdyn_remain_bytes:tvb(), pktinfo, irdyn_tree)
	offset = offset + profile_part_len
	return offset, profile_id
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
		hdr_len, profile_id = dissect_pkt_ir(ir_pkt, pktinfo, ir_tree)
		protocol = tonumber(pktinfo.private["rohc_embedded_protocol"])
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

		-- remaining bytes are specific to the ROHC profile
		local rohc_remain_bytes = tvbuf:range(offset, tvbuf:len() - offset)
		local profiles = DissectorTable.get("rohc.profiles")
		hdr_len = profiles:try(profile_id, rohc_remain_bytes:tvb(), pktinfo, tree)
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

