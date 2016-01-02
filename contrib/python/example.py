#!/usr/bin/env python
#
# Copyright 2015 Didier Barvaux
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

import sys
from scapy.all import *
from rohc import *
from RohcCompressor import *
from RohcDecompressor import *

RTP_PAYLOAD = 'hello, Python world!'

verbose_level = 0
verbose_rohc = False
if len(sys.argv) != 2 and len(sys.argv) != 3 and len(sys.argv) != 4:
    print "usage: example.py packets_number [verbose [verbose]]"
    sys.exit(1)
packets_nr = int(sys.argv[1])
if len(sys.argv) >= 3:
    if sys.argv[2] != 'verbose':
        print "usage: example.py packets_number [verbose [verbose]]"
        sys.exit(1)
    if len(sys.argv) < 4:
        verbose_level = 1
    else:
        if sys.argv[3] != 'verbose':
            print "usage: example.py packets_number [verbose [verbose]]"
            sys.exit(1)
        verbose_level = 2
        verbose_rohc = True

# create a stream of IPv4/UDP/RTP packets
print "create a stream of RTP packets"
uncomp_pkts = []
for i in range(0, packets_nr):
    uncomp_pkts.append(IP(id=0)/UDP(dport=1234,chksum=0)/RTP(sequence=i,timestamp=i*300)/RTP_PAYLOAD)
print "%i %i-byte RTP packets created with %i-byte payload" % \
      (len(uncomp_pkts), len(uncomp_pkts[0]), len(RTP_PAYLOAD))

# create one ROHC compressor
print "create ROHC compressor"
comp = RohcCompressor(cid_type=ROHC_LARGE_CID, profiles=[ROHC_PROFILE_RTP], \
        verbose=verbose_rohc)
if comp is None:
    print "failed to create the ROHC compressor"
    sys.exit(1)

# create one ROHC decompressor
print "create ROHC decompressor"
decomp = RohcDecompressor(cid_type=ROHC_LARGE_CID, profiles=[ROHC_PROFILE_RTP], \
        verbose=verbose_rohc)
if decomp is None:
    print "failed to create the ROHC decompressor"
    sys.exit(1)

# compress/decompress the packets, one by one
pkts_nr = 0
uncomp_len = 0
comp_len = 0
for uncomp_pkt in uncomp_pkts:
    pkts_nr += 1
    uncomp_len += len(str(uncomp_pkt))

    if verbose_level == 0:
        sys.stdout.write('.')
        sys.stdout.flush()

    # compression
    if verbose_level >= 1:
        print "compress   packet #%i: %i bytes ->" % (pkts_nr, len(str(uncomp_pkt))),
    (status, comp_pkt) = comp.compress(str(uncomp_pkt))
    if status != ROHC_STATUS_OK:
        print "failed to compress packet: %s (%i)" % \
              (rohc_strerror(status), status)
        sys.exit(1)
    if verbose_level >= 1:
        print "%i bytes" % len(comp_pkt)
    comp_len += len(comp_pkt)

    # decompression
    if verbose_level >= 1:
        print "decompress packet #%i: %i bytes ->" % (pkts_nr, len(comp_pkt)),
    (status, decomp_pkt, _, _) = decomp.decompress(comp_pkt)
    if status != ROHC_STATUS_OK:
        print "failed to decompress packet: %s (%i)" % \
              (rohc_strerror(status), status)
        sys.exit(1)
    if verbose_level >= 1:
        print "%i bytes" % len(decomp_pkt)

    # compare the decompressed packet with the original one
    if decomp_pkt != str(uncomp_pkt):
        print "decompressed packet does not match original packet"
        sys.exit(1)

if verbose_level == 0:
    print
print "all %i packets were successfully compressed" % pkts_nr

gain = uncomp_len - comp_len
gain_percent = 100 - comp_len * 100 / uncomp_len
if gain > 0:
    print "%i bytes (%i%%) saved by compression" % (gain, gain_percent)
else:
    print "%i bytes (%i%%) lost by compression" % (abs(gain), abs(gain_percent))

