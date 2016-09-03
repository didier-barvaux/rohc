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
-- @file   rohc_rfc3843_iponly.lua
-- @brief  Wireshark dissector for the RFC3843 IP-only profile of the ROHC protocol
-- @author Didier Barvaux <didier@barvaux.org>
--

-- RFC3843 IP-only profile depends on RFC3095 profiles
require("rohc_rfc3095.lua")

local rohc_rfc3843_ip_only_profile_id = 0x0004

-- register the RFC 3843 IP-only profile of the ROHC protocol
local rohc_rfc3843_ip_only =
	Proto("rohc_rfc3843_iponly", "ROHCv1 IP-only profile (RFC 3843)")

local rohc_protocol_info = {
	version    = "1.0",
	author     = "Didier Barvaux",
	repository = "https://rohc-lib.org/"
}
set_plugin_info(rohc_protocol_info)

rohc_rfc3843_ip_only.fields = rohc_protocol_rfc3095_fields

function rohc_rfc3843_ip_only.dissector(tvbuf, pktinfo, root)
	local protocol
	local offset = 0

	-- packet type?
	local hdr_len
	if pktinfo.private["rohc_packet_type"] == "1" then
		-- IR packet
		hdr_len = rohc_rfc3095_dissect_pkt_ir(tvbuf, pktinfo, root,
		                                      rohc_rfc3843_ip_only_profile_id)
	elseif pktinfo.private["rohc_packet_type"] == "2" then
		-- IR-DYN packet
		hdr_len = rohc_rfc3095_dissect_pkt_irdyn(tvbuf, pktinfo, root,
		                                         rohc_rfc3843_ip_only_profile_id)
	else
		uor_pkt = tvbuf:range(offset, tvbuf:len() - offset)
		hdr_len = rohc_rfc3095_dissect_pkt_uor(uor_pkt, pktinfo, root)
	end
	offset = offset + hdr_len

	return offset, protocol
end

-- tell the ROHC protocol that this dissector is able to parse the IP-only profile
local rohc_profiles = DissectorTable.get("rohc.profiles")
rohc_profiles:add(rohc_rfc3843_ip_only_profile_id, rohc_rfc3843_ip_only)

