--
-- Copyright 2018 Viveris Technologies
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
-- @file   gtp_rohc.lua
-- @brief  Wireshark dissector for the ROHC protocol with GTP tunnels
-- @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
--

do
	-- register the GTP/ROHC protocol
	local gtp_rohc_proto = Proto("GTP_ROHC", "GTP with ROHC T-PDU")

	-- declare some Fields to be read
	local gtp_tpdu_data_f = Field.new("gtp.tpdu_data")

	local original_gtp_dissector

	-- retrieve the ROHC dissector
	local ethertype_table = DissectorTable.get("ethertype")
	local rohc_proto = ethertype_table:get_dissector(0x22f1)

	function gtp_rohc_proto.dissector(buffer, pinfo, tree)
		original_gtp_dissector:call(buffer, pinfo, tree)
		local gtp_tpdu_data = gtp_tpdu_data_f()
		if gtp_tpdu_data ~= nil then
			local gtp_hdr_len = 8
			local gtp_tpdu_data_len = buffer:len() - gtp_hdr_len
			local gtp_tpdu_data = buffer:range(gtp_hdr_len, gtp_tpdu_data_len)
			rohc_proto:call(gtp_tpdu_data:tvb(), pinfo, tree)
		end
	end

	-- save the original dissector so we can still get to it
	-- then replace it by ours
	local udp_dissector_table = DissectorTable.get("udp.port")
	original_gtp_dissector = udp_dissector_table:get_dissector(2152)
	udp_dissector_table:add(2152, gtp_rohc_proto) 
end
