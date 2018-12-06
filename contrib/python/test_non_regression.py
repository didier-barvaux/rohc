#!/usr/bin/env python
#
# Copyright 2015,2016,2018 Didier Barvaux
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

"""
Introduction
------------

The program takes a flow of IP packets as input (in the PCAP format) and
tests the ROHC compression/decompression library with them. The program
also tests the feedback mechanism.

Details
-------

The program defines two compressor/decompressor pairs and sends the flow
of IP packet through Compressor 1 and Decompressor 1 (flow A) and through
Compressor 2 and Decompressor 2 (flow B). See the figure below.

The feedback for flow A is sent by Decompressor 1 to Compressor 1 via
Compressor 2 and Decompressor 2. The feedback for flow  B is sent by
Decompressor 2 to Compressor 2 via Compressor 1 and Decompressor 1.

         +-- IP packets                             IP packets <--+
         |   flow A (input)                    flow A (output)    |
         |                                                        |
         |    +----------------+    ROHC    +----------------+    |
         +--> |                |            |                | ---+
              |  Compressor 1  | ---------> | Decompressor 1 |
         +--> |                |            |                | ---+
         |    +----------------+            +----------------+    |
feedback |                                                        | feedback
flow B   |                                                        | flow A
         |    +----------------+     ROHC   +----------------+    |
         +--- |                |            |                | <--+
              | Decompressor 2 | <--------- |  Compressor 2  |
         +--- |                |            |                | <--+
         |    +----------------+            +----------------+    |
         |                                                        |
         +--> IP packets                             IP packets --+
              flow B (output)                    flow B (input)

Checks
------

The program checks for the status of the compression and decompression
processes. The program also compares input IP packets from flow A (resp.
flow B) with output IP packets from flow A (resp. flow B).

The program optionally compares the ROHC packets generated with the ones
given as input to the program.

Output
------

The program outputs the compression/decompression/comparison status of every
packets of flow A and flow B on stdout. It also outputs the log of the
different processes (startup, compression, decompression, comparison and
shutdown).
"""

from __future__ import print_function
from __future__ import division
from __future__ import unicode_literals
from __future__ import absolute_import
from builtins import range
from builtins import int
from future import standard_library
standard_library.install_aliases()

import sys
import pcap

from rohc import *
from RohcCompressor import *
from RohcDecompressor import *

ETHER_HDR_LEN       = 14 # bytes
ETHER_FRAME_MIN_LEN = 60 # bytes

ALL_PROFILES_V1 = [ROHC_PROFILE_UNCOMPRESSED, \
                   ROHC_PROFILE_RTP, \
                   ROHC_PROFILE_UDP, \
                   ROHC_PROFILE_ESP, \
                   ROHC_PROFILE_IP, \
                   ROHC_PROFILE_TCP, \
                   ROHC_PROFILE_UDPLITE, \
                  ]

ALL_PROFILES_V2 = [ROHC_PROFILE_UNCOMPRESSED, \
                   ROHCv2_PROFILE_IP, \
                   ROHCv2_PROFILE_IP_UDP, \
                   ROHCv2_PROFILE_IP_UDP_RTP, \
                   ROHCv2_PROFILE_IP_ESP, \
                   ROHC_PROFILE_TCP, \
                  ]


def usage():
    print("ROHC non-regression tool: test the Python binding of the ROHC")
    print("                          library with a flow of network packets")
    print
    print("usage: test_non_regression.py [OPTIONS] CID_TYPE FLOW")
    print
    print("with:")
    print("  CID_TYPE    The type of CID to use among 'smallcid' and 'largecid'")
    print("  FLOW        The flow of Ethernet frames to compress (PCAP format)")
    print
    print("options:")
    print("  -v                         Print version information and exit")
    print("  -h                         Print this usage and exit")
    print("  -c FILE                    Compare the generated ROHC packets with the")
    print("                             ROHC packets stored in FILE (PCAP format)")
    print("  --max-contexts NUM         The maximum number of ROHC contexts to")
    print("                             simultaneously use during the test")
    print("  --optimistic-approach NUM  The nr of repetitions for Optimistic Approach")
    print("  --rohc-version NUM         The ROHC version to use: 1 for ROHCv1")
    print("                             and 2 for ROHCv2")
    print("  --verbose                  Run the test in verbose mode")
    print("  --quiet                    Run the test in silent mode")


def parse_opts(opts):
    print_version = False
    cid_type = None
    cid_max = None
    oa_repetitions = None
    proto_version = 1
    verbose = False
    profiles = None
    pcap_in = None
    pcap_cmp = None

    max_opts = len(opts)
    opt_idx = 0
    while opt_idx < max_opts:
        if opts[opt_idx] == "-v":
            return (True, True, None, None, None, None, None, None, None)
        elif opts[opt_idx] == "-h":
            return (False, False, None, None, None, None, None, None, None)
        elif opts[opt_idx] == "-c":
            opt_idx += 1
            if opt_idx >= max_opts:
                print("option -c expects one value")
                return (False, False, None, None, None, None, None, None, None)
            pcap_cmp = opts[opt_idx]
        elif opts[opt_idx] ==  "--max-contexts":
            opt_idx += 1
            if opt_idx >= max_opts:
                print("option --max-contexts expects one value")
                return (False, False, None, None, None, None, None, None, None)
            cid_max = int(opts[opt_idx]) - 1
        elif opts[opt_idx] ==  "--optimistic-approach":
            opt_idx += 1
            if opt_idx >= max_opts:
                print("option --optimistic-approach expects one value")
                return (False, False, None, None, None, None, None, None, None)
            oa_repetitions = int(opts[opt_idx])
        elif opts[opt_idx] ==  "--rohc-version":
            opt_idx += 1
            if opt_idx >= max_opts:
                print("option --rohc-version expects one value")
                return (False, False, None, None, None, None, None, None, None)
            proto_version = int(opts[opt_idx])
        elif opts[opt_idx] ==  "--verbose":
            verbose = True
        elif opts[opt_idx] ==  "--quiet":
            verbose = False
        elif cid_type is None:
            if opts[opt_idx] == 'smallcid':
                cid_type = ROHC_SMALL_CID
            elif opts[opt_idx] == 'largecid':
                cid_type = ROHC_LARGE_CID
            else:
                print("unexpected CID type '%s'" % opts[opt_idx])
                return (False, False, None, None, None, None, None, None, None)
        elif pcap_in is None:
            pcap_in = opts[opt_idx]
        else:
            print("unexpected option '%s'" % opts[opt_idx])
            return (False, False, None, None, None, None, None, None, None)
        opt_idx += 1

    if proto_version == 1:
        profiles = ALL_PROFILES_V1
    elif proto_version == 2:
        profiles = ALL_PROFILES_V2
    else:
        print("unexpected ROHC version", proto_version, \
              ": only versions 1 or 2 are supported")
        return (False, False, None, None, None, None, None, None, None)

    if cid_type == ROHC_SMALL_CID:
        if cid_max is None:
            cid_max = ROHC_SMALL_CID_MAX
        elif cid_max > ROHC_SMALL_CID_MAX:
            print("unexpected CID_MAX", cid_max, "for small CIDs")
            return (False, False, None, None, None, None, None, None, None)
    else:
        if cid_max is None:
            cid_max = ROHC_LARGE_CID_MAX
        elif cid_max > ROHC_LARGE_CID_MAX:
            print("unexpected CID_MAX", cid_max, "for large CIDs")
            return (False, False, None, None, None, None, None, None, None)

    if cid_type is None:
        print("no CID type specified")
        return (False, False, None, None, None, None, None, None, None)

    if pcap_in is None:
        print("no input file specified")
        return (False, False, None, None, None, None, None, None, None)

    return (True, False, cid_type, cid_max, oa_repetitions, verbose, profiles, \
            pcap_in, pcap_cmp)


def dump_packet(descr, data):
    if isinstance(data, str) is True:
        dump_packet__str(descr, data)
    elif isinstance(data, bytes) is True:
        dump_packet__bytes(descr, data)
    else:
        raise NotImplementedError()

def dump_packet__bytes(descr, data):
    data_len = len(data)
    max_len = 100
    if data_len < max_len:
        max_len = data_len
    print(descr, "(%i bytes, max %i bytes):" % (data_len, max_len))
    for i in range(0, max_len):
        print("%02x " % data[i], end='')
        if (i + 1) % 16 == 0:
            print()
        elif (i + 1) % 8 == 0:
            print(" ", end='')
        else:
            print(end='')
    if max_len % 16 != 0:
        print()

def dump_packet__str(descr, data):
    data_len = len(data)
    max_len = 100
    if data_len < max_len:
        max_len = data_len
    print(descr, "(%i bytes, max %i bytes):" % (data_len, max_len))
    for i in range(0, max_len):
        print("%02x " % ord(data[i]), end='')
        if (i + 1) % 16 == 0:
            print()
        elif (i + 1) % 8 == 0:
            print(" ", end='')
        else:
            print(end='')
    if max_len % 16 != 0:
        print()


def do_packet_match(buf1_descr, buf1, buf2_descr, buf2):
    do_match = True

    if len(buf1) != len(buf2):
        do_match = False
    elif buf1 != buf2:
        do_match = False

    if do_match is False:
        print("%i-byte %s packet does not match %i-byte %s packet" \
              % (len(buf1), buf1_descr, len(buf2), buf2_descr))
        if len(buf1) <= len(buf2):
            min_len = len(buf1)
        else:
            min_len = len(buf2)
        for i in range(0, min_len, 8):
            for j in range(i, i + 8):
                if j < len(buf1):
                    if isinstance(buf1, str) is True:
                        byte = ord(buf1[j])
                    elif isinstance(buf1, bytes) is True:
                        byte = buf1[j]
                    else:
                        raise NotImplementedError()
                    if j < len(buf2) and buf1[j] != buf2[j]:
                        print("%02x*" % byte, end='')
                    else:
                        print("%02x " % byte, end='')
                else:
                    print("   ", end='')
            print("| ", end='')
            for j in range(i, i + 8):
                if j < len(buf2):
                    if isinstance(buf2, str) is True:
                        byte = ord(buf2[j])
                    elif isinstance(buf2, bytes) is True:
                        byte = buf2[j]
                    else:
                        raise NotImplementedError()
                    if j < len(buf1) and buf1[j] != buf2[j]:
                        print("%02x*" % byte, end='')
                    else:
                        print("%02x " % byte, end='')
                else:
                    print("   ", end='')
            print()

    return do_match


def remove_padding(pkt):
    if isinstance(pkt, str) is True:
        return remove_padding__str(pkt)
    elif isinstance(pkt, bytes) is True:
        return remove_padding__bytes(pkt)
    else:
        raise NotImplementedError()

def remove_padding__bytes(pkt):
    if len(pkt) == (ETHER_FRAME_MIN_LEN - ETHER_HDR_LEN):
        ip_version = (pkt[0] & 0xf0) >> 4
        if ip_version == 4:
            ip_len = (pkt[2] << 8) + pkt[3]
            print("%i bytes of padding removed" % (len(pkt) - ip_len))
            pkt = pkt[:ip_len]
        elif ip_version == 6:
            ip_len = 40 + (pkt[4] << 8) + pkt[5]
            print("%i bytes of padding removed" % (len(pkt) - ip_len))
            pkt = pkt[:ip_len]
    return pkt

def remove_padding__str(pkt):
    if len(pkt) == (ETHER_FRAME_MIN_LEN - ETHER_HDR_LEN):
        ip_version = (ord(pkt[0]) & 0xf0) >> 4
        if ip_version == 4:
            ip_len = (ord(pkt[2]) << 8) + ord(pkt[3])
            print("%i bytes of padding removed" % (len(pkt) - ip_len))
            pkt = pkt[:ip_len]
        elif ip_version == 6:
            ip_len = 40 + (ord(pkt[4]) << 8) + ord(pkt[5])
            print("%i bytes of padding removed" % (len(pkt) - ip_len))
            pkt = pkt[:ip_len]
    return pkt


def create_comp_decomp(cid_type, cid_max, oa_repetitions, profiles, verbose):

    # setup the list of UDP ports for RTP streams
    for udp_port in [1234, 36780, 33238, 5020, 5002, 5006]:
        ret = rohc_comp_add_rtp_port(udp_port)
        if ret is not True:
            print("failed to add the UDP port %i for RTP streams" % udp_port)
            return (False, None, None, None, None)

    print("\ncreate ROHC compressor 1")
    comp1 = RohcCompressor(cid_type, cid_max, oa_repetitions, profiles, verbose)
    if comp1 is None:
        print("failed to create the ROHC compressor 1")
        return (False, None, None, None, None)

    print("create ROHC decompressor 1")
    decomp1 = RohcDecompressor(cid_type, cid_max, ROHC_O_MODE, profiles, verbose)
    if decomp1 is None:
        print("failed to create the ROHC decompressor 1")
        return (False, None, None, None, None)

    print("\ncreate ROHC compressor 2")
    comp2 = RohcCompressor(cid_type, cid_max, oa_repetitions, profiles, verbose)
    if comp2 is None:
        print("failed to create the ROHC compressor 2")
        return (False, None, None, None, None)

    print("create ROHC decompressor 2")
    decomp2 = RohcDecompressor(cid_type, cid_max, ROHC_O_MODE, profiles, verbose)
    if decomp2 is None:
        print("failed to create the ROHC decompressor 2")
        return (False, None, None, None, None)

    return (True, comp1, decomp1, comp2, decomp2)


def compress_decompress(comp1, decomp1, cmp_pkt1, \
                        comp2, decomp2, cmp_pkt2, \
                        nr, uncomp_pkt, feedback_to_send, verbose):
    print("=========== test packet #%i ===========" % nr)

    if verbose is True:
        dump_packet("original uncompressed packet", uncomp_pkt)

    print("------------- comp1 -------------")
    (status, comp_pkt) = comp1.compress(uncomp_pkt)
    if status != ROHC_STATUS_OK:
        print("failed to compress packet: %s (%i)" % \
              (rohc_strerror(status), status))
        return (False, None, None, None)

    # now, prepend the feedback that decompressor 2 would like compressor 1 send
    if feedback_to_send is not None:
        print("preprend", len(feedback_to_send), "bytes of feedback from decompressor #2")
        comp_pkt = feedback_to_send + comp_pkt

    if verbose is True:
        dump_packet("compressed packet", comp_pkt)

    if cmp_pkt1 is not None:
        do_match_ref1 = do_packet_match("reference", cmp_pkt1, "compressed", comp_pkt)
        if do_match_ref1 is not True:
            print("compressed packet does not match reference packet")
        else:
            print("compressed packet matches reference packet")
    else:
        do_match_ref1 = True

    print("------------- decomp1 -------------")
    (status, decomp_pkt, feedback_recv, feedback_to_send) = \
        decomp1.decompress(comp_pkt)
    if status != ROHC_STATUS_OK:
        print("failed to decompress packet: %s (%i)" % \
              (rohc_strerror(status), status))
        return (False, None, None, None)

    if verbose is True:
        dump_packet("decompressed packet", decomp_pkt)
        dump_packet("received feedback", feedback_recv)
        dump_packet("feedback to send", feedback_to_send)

    do_match = do_packet_match("original", uncomp_pkt, "decompressed", decomp_pkt)
    if do_match is not True:
        print("decompressed packet does not match original packet")
    else:
        print("decompressed packet matches original packet")

    # deliver feedback to the associated compressor, ie. comp2
    if len(feedback_recv) > 0:
        status = comp2.deliver_feedback(feedback_recv)
        if status is not True:
            print("failed to deliver feedback received by decompressor 1 to compressor 2")
            return (False, None, None, None)

    print("------------- comp2 -------------")
    (status, comp_pkt) = comp2.compress(decomp_pkt)
    if status != ROHC_STATUS_OK:
        print("failed to compress packet: %s (%i)" % \
              (rohc_strerror(status), status))
        return (False, None, None, None)

    # now, prepend the feedback that decompressor 1 would like compressor 2 send
    print("preprend", len(feedback_to_send), "bytes of feedback from decompressor #1")
    comp_pkt = feedback_to_send + comp_pkt

    if verbose is True:
        dump_packet("compressed packet", comp_pkt)

    if cmp_pkt2 is not None:
        do_match_ref2 = do_packet_match("reference", cmp_pkt2, "compressed", comp_pkt)
        if do_match_ref2 is not True:
            print("compressed packet does not match reference packet")
        else:
            print("compressed packet matches reference packet")
    else:
        do_match_ref2 = True

    print("------------- decomp2 -------------")
    (status, decomp_pkt, feedback_recv, feedback_to_send) = \
        decomp2.decompress(comp_pkt)
    if status != ROHC_STATUS_OK:
        print("failed to decompress packet: %s (%i)" % \
              (rohc_strerror(status), status))
        return (False, None, None, None)

    if verbose is True:
        dump_packet("decompressed packet", decomp_pkt)

    do_match = do_packet_match("original", uncomp_pkt, "decompressed", decomp_pkt)
    if do_match is not True:
        print("decompressed packet does not match original packet")
    else:
        print("decompressed packet matches original packet")

    # deliver feedback to the associated compressor, ie. comp1
    if len(feedback_recv) > 0:
        status = comp1.deliver_feedback(feedback_recv)
        if status is not True:
            print("failed to deliver feedback received by decompressor 2 to compressor 1")
            return (False, None, None, None)


    print("=======================================\n")

    return (do_match and do_match_ref1 and do_match_ref2, \
            len(uncomp_pkt), len(comp_pkt), feedback_to_send)


def run_test(cid_type, cid_max, oa_repetitions, profiles, verbose, pcap_in, pcap_cmp):

    print("test ROHC library, version", rohc_version())

    (status, comp1, decomp1, comp2, decomp2) = \
        create_comp_decomp(cid_type, cid_max, oa_repetitions, profiles, verbose)
    if status is not True:
        print("failed to create the ROHC (de)compressors")
        return False

    if pcap_cmp is not None:
        print("open the compare PCAP file")
        pcap_cmp_reader = pcap.PcapFile(pcap_cmp)
        print("read all the packets from the compare PCAP file")
        pkts_cmp = pcap_cmp_reader.read_all()

    # test with the packets from the network capture
    print("open the source PCAP file")
    pcap_reader = pcap.PcapFile(pcap_in)
    print("read all the packets from the source PCAP file")
    pkts_in = pcap_reader.read_all()
    print("compress then decompress the", len(pkts_in), "packets found in network capture\n")
    pkts_nr = 0
    before_total = 0
    after_total = 0
    feedback_to_send = None
    for pkt_in in pkts_in:

        # prepare comparison packets
        if pcap_cmp is not None:
            print("compare PCAP linktype =", pcap_cmp_reader.linktype)
            pkt_cmp1 = pkts_cmp[pkts_nr * 2][2]
            pkt_cmp2 = pkts_cmp[pkts_nr * 2 + 1][2]
            if pcap_cmp_reader.linktype == pcap.LinkLayerType.LINK_TYPE_ETH:
                print("len(pkt_cmp1) =", len(pkt_cmp1))
                pkt_cmp1 = remove_padding(pkt_cmp1[ETHER_HDR_LEN:])
                pkt_cmp2 = remove_padding(pkt_cmp2[ETHER_HDR_LEN:])
            elif pcap_cmp_reader.linktype == pcap.LinkLayerType.LINK_TYPE_RAW or \
                 pcap_cmp_reader.linktype == pcap.LinkLayerType.LINK_TYPE_IPV4 or \
                 pcap_cmp_reader.linktype == pcap.LinkLayerType.LINK_TYPE_IPV6:
                pkt_cmp1 = remove_padding(pkt_cmp1)
                pkt_cmp2 = remove_padding(pkt_cmp2)
            else:
                print("unknown comparison PCAP link type", pcap_cmp_reader.linktype)
                return False
        else:
            pkt_cmp1 = None
            pkt_cmp2 = None

        # prepare uncompressed packet
        pkt_uncomp = pkt_in[2]
        print("source PCAP linktype =", pcap_reader.linktype)
        if pcap_reader.linktype == pcap.LinkLayerType.LINK_TYPE_ETH:
            pkt_uncomp = remove_padding(pkt_uncomp[ETHER_HDR_LEN:])
        elif pcap_reader.linktype == pcap.LinkLayerType.LINK_TYPE_RAW or \
             pcap_reader.linktype == pcap.LinkLayerType.LINK_TYPE_IPV4 or \
             pcap_reader.linktype == pcap.LinkLayerType.LINK_TYPE_IPV6:
            pkt_uncomp = remove_padding(pkt_uncomp)
        else:
            print("unknown source PCAP link type", pcap_reader.linktype)
            return False

        (status, before, after, feedback_to_send) = \
            compress_decompress(comp1, decomp1, pkt_cmp1, \
                                comp2, decomp2, pkt_cmp2, \
                                pkts_nr + 1, pkt_uncomp, \
                                feedback_to_send, verbose)
        if status is not True:
            print("failed to compress/decompress packet #%i" % (pkts_nr + 1))
            return False
        before_total += before
        after_total += after

        pkts_nr += 1

    gain = 100 - (after_total * 100 / before_total)
    print("statistics:")
    print("\tbefore compression: ", before_total, "bytes")
    if gain < 0:
        less_more = "more"
    else:
        less_more = "less"
    print("\tafter compression: %i bytes (%i%% %s)" % \
          (after_total, abs(gain), less_more))

    return True


if __name__ == "__main__":
    print("This is the Python version of the non-regression test\n\n")

    # parse command line options
    (status, print_version, cid_type, cid_max, oa_repetitions, verbose, profiles, \
     pcap_in, pcap_cmp) = parse_opts(sys.argv[1:])
    if status is not True:
        print("failed to parse options\n")
        usage()
        sys.exit(1)

    if print_version is True:
        print("ROHC non-regression test application, version", rohc_version())
        sys.exit(1)

    # run the non-regression test
    status = run_test(cid_type, cid_max, oa_repetitions, profiles, verbose, \
                      pcap_in, pcap_cmp)
    if status is not True:
        print("\ntest failed :-/")
        sys.exit(1)

    print("\ntest succeeded")
    sys.exit(0)

