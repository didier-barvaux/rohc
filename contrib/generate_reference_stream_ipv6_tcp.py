#! /usr/bin/env python2
#
# Copyright 2017,2018 Viveris Technologies
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
# description: Generate TCP stream(s) that might be taken as reference for tests
# author:      Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#

from scapy.all import *
import sys

if len(sys.argv) != 4:
    print 'usage: generate_reference_stream_tcp.py <pkts_nr> <streams_nr> <pkt_len>'
    sys.exit(1)

pkts_nr = int(sys.argv[1])
streams_nr = int(sys.argv[2])
pkt_len = int(sys.argv[3])
pcap_file_name = "reference_stream_ipv6_tcp_%ipkts_%istreams_%iBpkt.pcap" \
        % (pkts_nr, streams_nr, pkt_len)

print "generate %i TCP stream(s) with %i %i-byte packets in file '%s'" \
        % (streams_nr, pkts_nr, pkt_len, pcap_file_name)

pcap_writer = PcapWriter(pcap_file_name)

payload = ""
payload_len = pkt_len - 14 - 4 - 40 - 20
for num in range(0, payload_len):
    payload = payload + "A"

last_percent_printed = 0

streams = []
for num in range(0, streams_nr):
    streams.append({})
    streams[num]['ip_id'] = 0
    streams[num]['syn_sent'] = False
    streams[num]['seq_num'] = 0
    streams[num]['ack_num'] = 0
    streams[num]['ts'] = 0

stream_num = 0
for num in range(0, pkts_nr):
    percent = int(num * 100 / pkts_nr)
    if percent != last_percent_printed and (percent % 10) == 0:
        print "%i / %i packets generated" % (num, pkts_nr)
        last_percent_printed = percent

    options = []
    if streams[stream_num]['syn_sent'] is True:
        tcp_flags = "A"
#        options.append(('NOP', None))
#        options.append(('NOP', None))
#        options.append(('Timestamp', (ts, ts)))
        cur_payload_len = payload_len
    else:
        tcp_flags = "S"
        options.append(('MSS', 1460))
        options.append(('SAckOK', ''))
        options.append(('Timestamp', (streams[stream_num]['ts'], streams[stream_num]['ts'])))
        options.append(('NOP', None))
        options.append(('WScale', 7))
        cur_payload_len = 0

    packet = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/Dot1Q(vlan=1)/IPv6(src='fe80::1:1', dst='fe80::0:%i' % ((stream_num / 100) % 254))/TCP(sport=4242, dport=4243+stream_num, flags=tcp_flags, seq=streams[stream_num]['seq_num'], ack=streams[stream_num]['ack_num'], options=options)/payload[:cur_payload_len]
    pcap_writer.write(packet)
    del packet

    if streams[stream_num]['syn_sent'] is True:
        streams[stream_num]['seq_num'] = (streams[stream_num]['seq_num'] + cur_payload_len) % 0xffffffff
    else:
        streams[stream_num]['seq_num'] = (streams[stream_num]['seq_num'] + 1) % 0xffffffff
        streams[stream_num]['syn_sent'] = True
    #streams[stream_num]['ts'] = (streams[stream_num]['ts'] + 1) % 0xffffffff
    #streams[stream_num]['ip_id'] = (streams[stream_num]['ip_id'] + 1) % 0xffff

    stream_num = (stream_num + 1) % streams_nr

