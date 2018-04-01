#! /usr/bin/env python2
#
# Copyright 2017 Viveris Technologies
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
# file:        generate_reference_stream_tcp.py
# description: Generate one TCP stream that might be taken as reference for tests
# author:      Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#

from scapy.all import *
import sys

if len(sys.argv) != 2:
    print 'usage: generate_reference_stream_tcp.py <pkts_nr>'
    sys.exit(1)

pkts_nr = int(sys.argv[1])
pcap_file_name = "reference_stream_tcp_%ipkts.pcap" % (pkts_nr)

print "generate one TCP stream with %i packets in file '%s'" % (pkts_nr, pcap_file_name)

packets = []

payload = ""
payload_len = 418 - 14 - 4 - 20 - 20 - 12
for num in range(0, payload_len):
    payload = payload + "A"

last_percent_printed = 0

ip_id = 0
syn_sent = False
seq_num = 0
ack_num = 0
ts = 0
for num in range(0, pkts_nr):
    percent = int(num * 100 / pkts_nr)
    if percent != last_percent_printed and (percent % 10) == 0:
        print "%i / %i packets generated" % (num, pkts_nr)
        last_percent_printed = percent

    options = []
    if syn_sent is True:
        tcp_flags = "A"
        options.append(('NOP', None))
        options.append(('NOP', None))
        options.append(('Timestamp', (ts, ts)))
        cur_payload_len = payload_len
    else:
        tcp_flags = "S"
        options.append(('MSS', 1460))
        options.append(('SAckOK', ''))
        options.append(('Timestamp', (ts, ts)))
        options.append(('NOP', None))
        options.append(('WScale', 7))
        cur_payload_len = 0
    packets.append(Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/Dot1Q(vlan=1)/IP(src='192.168.0.1', dst='192.168.0.2', id=ip_id)/TCP(sport=4242, dport=4243, flags=tcp_flags, seq=seq_num, ack=ack_num, options=options)/payload[:cur_payload_len])
    if syn_sent is True:
        seq_num = (seq_num + cur_payload_len) % 0xffffffff
    else:
        seq_num = (seq_num + 1) % 0xffffffff
        syn_sent = True
    ts = (ts + 1) % 0xffffffff
    ip_id = (ip_id + 1) % 0xffff

wrpcap(pcap_file_name, packets)

