#! /usr/bin/env python2
#
# Copyright 2018 Viveris Technologies
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#
# file:        generate_reference_stream_rtp.py
# description: Generate one RTP stream that might be taken as reference for tests
# author:      Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#

from scapy.all import *
import sys

if len(sys.argv) != 2:
    print 'usage: generate_reference_stream_rtp.py <pkts_nr>'
    sys.exit(1)

pkts_nr = int(sys.argv[1])
pcap_file_name = "reference_stream_rtp_%ipkts.pcap" % (pkts_nr)

print "generate one RTP stream with %i packets in file '%s'" % (pkts_nr, pcap_file_name)

pcap_writer = PcapWriter(pcap_file_name)

payload = ""
payload_len = 20
for num in range(0, payload_len):
    payload = payload + "A"

last_percent_printed = 0

ip_id = 0
sn = 0
ts = 0
for num in range(0, pkts_nr):
    percent = int(num * 100 / pkts_nr)
    if percent != last_percent_printed and (percent % 10) == 0:
        print "%i / %i packets generated" % (num, pkts_nr)
        last_percent_printed = percent

    packet = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/Dot1Q(vlan=1)/IP(src='192.168.0.1', dst='192.168.0.2', id=ip_id)/UDP(sport=1234, dport=1234, chksum=0)/RTP(sequence=sn, timestamp=ts)/payload[:payload_len]
    pcap_writer.write(packet)
    del packet

    sn = (sn + 1) % 0xffff
    ts = (ts + 240) % 0xffffffff
    ip_id = (ip_id + 1) % 0xffff

