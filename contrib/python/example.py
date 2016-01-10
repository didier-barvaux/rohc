#!/usr/bin/env python
#
# Copyright 2015,2016 Didier Barvaux
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

"""
Example that shows how to compress, then decompress a sequence of packets
"""

from __future__ import print_function

import sys
import struct

from rohc import *
from RohcCompressor import *
from RohcDecompressor import *

RTP_PAYLOAD = 'hello, Python world!'

def print_usage():
    print("usage: example.py packets_number [verbose [verbose]]")

verbose_level = 0
verbose_rohc = False
if len(sys.argv) != 2 and len(sys.argv) != 3 and len(sys.argv) != 4:
    print_usage()
    sys.exit(1)
packets_nr = int(sys.argv[1])
if len(sys.argv) >= 3:
    if sys.argv[2] != 'verbose':
        print_usage()
        sys.exit(1)
    if len(sys.argv) < 4:
        verbose_level = 1
    else:
        if sys.argv[3] != 'verbose':
            print_usage()
            sys.exit(1)
        verbose_level = 2
        verbose_rohc = True

# create a stream of IPv4/UDP/RTP packets
print("create a stream of RTP packets")
uncomp_pkts = []
ip_hdr_fmt = '!BBHHHBB2s4s4s'
ip_hdr_len = struct.calcsize(ip_hdr_fmt) # bytes
udp_hdr_fmt = '!HHH2s'
udp_hdr_len = struct.calcsize(udp_hdr_fmt) # bytes
rtp_hdr_fmt = '!BBHII'
rtp_hdr_len = struct.calcsize(rtp_hdr_fmt) # bytes
udp_pkt_len = udp_hdr_len + rtp_hdr_len + len(RTP_PAYLOAD)
ip_pkt_len = ip_hdr_len + udp_pkt_len
ip_version = 4
ip_ihl = ip_hdr_len // 4
ip_tos = 0
ip_id = 0
ip_frag_off = 0
ip_ttl = 64
ip_proto = 17 # UDP
ip_chksum = b'\x7c\xaf' # hardcoded IP checksum to avoid computation
ip_saddr = struct.pack('!BBBB', 127, 0, 0, 1)
ip_daddr = ip_saddr
udp_sport = 1235
udp_dport = 1234
udp_chksum = b'\x00\x00' # disable UDP checksum for better compression
rtp_version = 2
rtp_padding_bit = 0
rtp_ext_bit = 0
rtp_cc = 0
rtp_marker = 0
rtp_pt = 0
rtp_ssrc = 0
for i in range(0, packets_nr):
    rtp_seq = i
    rtp_ts = i * 300
    ip_packet = pack(ip_hdr_fmt + udp_hdr_fmt[1:] + rtp_hdr_fmt[1:], \
                     (ip_version << 4) | ip_ihl, ip_tos, ip_pkt_len, ip_id, \
                     ip_frag_off, ip_ttl, ip_proto, ip_chksum, ip_saddr, ip_daddr, \
                     udp_sport, udp_dport, udp_pkt_len, udp_chksum, \
                     (rtp_version << 6) | (rtp_padding_bit << 5) | (rtp_ext_bit << 4) | rtp_cc, \
                     (rtp_marker << 7) | rtp_pt, rtp_seq, rtp_ts, rtp_ssrc)
    ip_packet += bytes(RTP_PAYLOAD, encoding='utf-8')
    uncomp_pkts.append(ip_packet)
print("%i %i-byte RTP packets created with %i-byte payload" \
      % (len(uncomp_pkts), len(uncomp_pkts[0]), len(RTP_PAYLOAD)))

# create one ROHC compressor
print("create ROHC compressor")
comp = RohcCompressor(cid_type=ROHC_LARGE_CID, profiles=[ROHC_PROFILE_RTP], \
        verbose=verbose_rohc)
if comp is None:
    print("failed to create the ROHC compressor")
    sys.exit(1)

# create one ROHC decompressor
print("create ROHC decompressor")
decomp = RohcDecompressor(cid_type=ROHC_LARGE_CID, profiles=[ROHC_PROFILE_RTP], \
        verbose=verbose_rohc)
if decomp is None:
    print("failed to create the ROHC decompressor")
    sys.exit(1)

# compress/decompress the packets, one by one
pkts_nr = 0
uncomp_len = 0
comp_len = 0
for uncomp_pkt in uncomp_pkts:
    pkts_nr += 1
    uncomp_len += len(uncomp_pkt)

    if verbose_level == 0:
        print('.', flush=True, end='')

    # compression
    if verbose_level >= 1:
        print("compress   packet #%i: %i bytes -> " % (pkts_nr, len(uncomp_pkt)), end='')
    (status, comp_pkt) = comp.compress(uncomp_pkt)
    if status != ROHC_STATUS_OK:
        print("failed to compress packet: %s (%i)" % (rohc_strerror(status), status))
        sys.exit(1)
    if verbose_level >= 1:
        print(len(comp_pkt), "bytes")
    comp_len += len(comp_pkt)

    # decompression
    if verbose_level >= 1:
        print("decompress packet #%i: %i bytes -> " \
              % (pkts_nr, len(comp_pkt)), end='')
    (status, decomp_pkt, _, _) = decomp.decompress(comp_pkt)
    if status != ROHC_STATUS_OK:
        print("failed to decompress packet: %s (%i)" \
              % (rohc_strerror(status), status))
        sys.exit(1)
    if verbose_level >= 1:
        print(len(decomp_pkt), "bytes")

    # compare the decompressed packet with the original one
    if decomp_pkt != uncomp_pkt:
        print("decompressed packet does not match original packet")
        sys.exit(1)

if verbose_level == 0:
    print()
print("all %i packets were successfully compressed" % pkts_nr)

gain = uncomp_len - comp_len
gain_percent = 100 - comp_len * 100 / uncomp_len
if gain == 0:
    print("no byte saved by compression")
elif gain > 0:
    print("%i bytes (%i%%) saved by compression" % (gain, gain_percent))
else:
    print("%i bytes (%i%%) lost by compression" % (abs(gain), abs(gain_percent)))

