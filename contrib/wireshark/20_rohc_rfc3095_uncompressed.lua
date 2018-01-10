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
-- @file   rohc_rfc3095_ip_udp.lua
-- @brief  Wireshark dissector for the RFC3095 IP/UDP profile of the ROHC protocol
-- @author Didier Barvaux <didier@barvaux.org>
--

local rohc_rfc3095_uncompressed_profile_id = 0x0000

-- register the RFC 3095 Uncompressed profile of the ROHC protocol
local rohc_rfc3095_uncompressed =
	Proto("rohc_rfc3095_uncompressed", "ROHCv1 Uncompressed profile (RFC 3095)")

local rohc_protocol_info = {
	version    = "1.0",
	author     = "Didier Barvaux",
	repository = "https://rohc-lib.org/"
}
set_plugin_info(rohc_protocol_info)

-- get Ethertype from IP version
local function get_ethertype_from_ip_version(bytes)
	local ip_version = bytes:range(offset, 1):bitfield(0, 4)
	local ethertype
	if ip_version == 4 then
		ethertype = 0x0800
	elseif ip_version == 6 then
		ethertype = 0x86dd
	else
		ethertype = nil
	end
	return ethertype
end

-- dissect Normal packet
local function uncompressed_dissect_pkt_normal(normal_pkt, pktinfo, tree)
	local normal_tree = rohc_tree:add(f_pkt_normal, normal_pkt)
	local offset = 0

	return offset
end

function rohc_rfc3095_uncompressed.dissector(tvbuf, pktinfo, root)
	local protocol
	local offset = 0

	-- packet type?
	local hdr_len
	if pktinfo.private["rohc_packet_type"] == "IR" then
		-- IR packet
		-- no additional fields, except the original uncompressed packet
		hdr_len = 0
		-- determine the embedded protocol
		pktinfo.private["rohc_embedded_protocol"] = get_ethertype_from_ip_version(tvbuf)
	else
		-- Normal packet
		pktinfo.private["rohc_packet_type"] = "Normal"
		-- no additional fields, except the original uncompressed packet
		-- TODO: large CID
		hdr_len = 0
		-- determine the embedded protocol
		pktinfo.private["rohc_embedded_protocol"] = get_ethertype_from_ip_version(tvbuf)
	end
	offset = offset + hdr_len

	return offset + 1
end

-- tell the ROHC protocol that this dissector is able to parse the Uncompressed profile
local rohc_profiles = DissectorTable.get("rohc.profiles")
rohc_profiles:add(rohc_rfc3095_uncompressed_profile_id, rohc_rfc3095_uncompressed)

