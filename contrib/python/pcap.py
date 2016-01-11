#
# Copyright (c) 2015, Liu Dong
# Copyright (c) 2015-2016, Didier Barvaux
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#  - Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  - Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the docume ntation and/or other materials provided with the
#    distribution.
#  - Neither the name of the <ORGANIZATION> nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

#
# Modified version of https://github.com/caoqianli/pcap-parser
#
# Replace Scapy to read PCAP in a way compatible with both Python2
# and Python3.
#

"""
Read PCAP and PCAP-NG packet captures
"""

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from builtins import hex
from future import standard_library
standard_library.install_aliases()

# read and parse pcap file
# see http://wiki.wireshark.org/Development/LibpcapFileFormat
import sys
import io
import struct

class FileFormat(object):
    """The different types of PCAP file formats"""
    PCAP = 0xA1B2C3D4
    PCAP_NG = 0x0A0D0D0A
    UNKNOWN = -1

# see http://www.tcpdump.org/linktypes.html
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixLinkTypes
class LinkLayerType(object):
    """The different types of PCAP Link Layers"""
    LINK_TYPE_ETH  = 1
    LINK_TYPE_RAW  = 12
    LINK_TYPE_IPV4 = 101
    LINK_TYPE_IPV6 = 31


class PcapFile(object):
    def __init__(self, filename):
        self.filename = filename
        self.infile = io.open(filename, 'rb')
        fileformat, head = self.get_file_format()
        if fileformat == FileFormat.PCAP:
            self.pcap = PcapOldFile(self.infile, head)
            self.linktype = self.pcap.link_type
        elif fileformat == FileFormat.PCAP_NG:
            self.pcap = PcapngFile(self.infile, head)
            self.linktype = self.pcap.section_info.link_type
        else:
            return None

    def get_file_format(self):
        """
        get cap file format by magic num.
        return file format and the first byte of string
        :type infile:file
        """
        buf = self.infile.read(4)
        if len(buf) == 0:
            # EOF
            print("empty file", file=sys.stderr)
            return FileFormat.UNKNOWN
        if len(buf) < 4:
            print("file too small", file=sys.stderr)
            return FileFormat.UNKNOWN
        magic_num, = struct.unpack(b'<I', buf)
        if magic_num == 0xA1B2C3D4 or magic_num == 0x4D3C2B1A:
            return FileFormat.PCAP, buf
        elif magic_num == 0x0A0D0D0A:
            return FileFormat.PCAP_NG, buf
        else:
            return FileFormat.UNKNOWN, buf

    def read_packet(self):
        return self.pcap.read_packet()

    def read_all(self):
        packets = []
        packet = self.read_packet()
        while packet is not None:
            packets.append(packet)
            packet = self.read_packet()
        return packets


class PcapOldFile(object):
    def __init__(self, infile, head):
        self.infile = infile
        self.byteorder = b'@'
        self.link_type = None
        # the first 4 byte head has been read by pcap file format checker
        self.head = head

        flag = self.pcap_check()
        if not flag:
            # not a valid pcap file or we cannot handle this file.
            print("Can't recognize this PCAP file format.", file=sys.stderr)
            return None

    # http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
    def pcap_check(self):
        """check the header of cap file, see it is a ledge pcap file.."""

        # default, auto
        # read 24 bytes header
        pcap_file_header_len = 24
        global_head = self.head + self.infile.read(pcap_file_header_len - len(self.head))
        if not global_head:
            return False

        magic_num, = struct.unpack(b'<I', global_head[0:4])
        # judge the endian of file.
        if magic_num == 0xA1B2C3D4:
            self.byteorder = b'<'
        elif magic_num == 0x4D3C2B1A:
            self.byteorder = b'>'
        else:
            return False

        version_major, version_minor, timezone, timestamp, max_package_len, self.link_type \
            = struct.unpack(self.byteorder + b'4xHHIIII', global_head)

        return True

    def read_pcap_pac(self):
        """
        read pcap header.
        return the total package length.
        """
        # package header
        pcap_header_len = 16
        package_header = self.infile.read(pcap_header_len)

        # end of file.
        if not package_header or len(package_header) < pcap_header_len:
            return None, None

        seconds, suseconds, packet_len, raw_len = struct.unpack(self.byteorder + b'IIII',
                                                                package_header)
        micro_second = seconds * 1000000 + suseconds
        # note: packet_len contains padding.
        link_packet = self.infile.read(packet_len)
        if len(link_packet) < packet_len:
            return None, None
        return micro_second, link_packet

    def read_packet(self):
        micro_second, link_packet = self.read_pcap_pac()
        if link_packet:
            return (self.link_type, micro_second, link_packet)
        else:
            return None


class SectionInfo(object):
    def __init__(self):
        self.byteorder = b'@'
        self.length = -1
        self.major = -1
        self.minor = -1
        self.link_type = -1
        self.capture_len = -1
        self.tsresol = 1  # Resolution of timestamps. we use microsecond here
        self.tsoffset = 0  # value that specifies the offset of timestamp. we use microsecond

# read and parse pcapng file
# see
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
# http://wiki.wireshark.org/Development/PcapNg
class PcapngFile(object):
    def __init__(self, infile, head):
        self.infile = infile
        self.section_info = SectionInfo()
        # the first 4 byte head has been read by pcap file format checker
        self.head = head

    def parse_section_header_block(self, block_header):
        """get section info from section header block"""

        # read byte order info first.
        byteorder_magic = self.infile.read(4)
        byteorder_magic, = struct.unpack(b'>I', byteorder_magic)
        if byteorder_magic == 0x1A2B3C4D:
            byteorder = b'>'
        elif byteorder_magic == 0x4D3C2B1A:
            byteorder = b'<'
        else:
            print("Not a byteorder magic num: %d" % byteorder_magic, file=sys.stderr)
            return None

        block_len, = struct.unpack(byteorder + b'4xI', block_header)

        # read version, should be 1, 0
        versions = self.infile.read(4)
        major, minor = struct.unpack(byteorder + b'HH', versions)

        # section len
        section_len = self.infile.read(8)
        section_len, = struct.unpack(byteorder + b'q', section_len)
        if section_len == -1:
            # usually did not have a known section length
            pass

        self.infile.read(block_len - 12 - 16)

        self.section_info.byteorder = byteorder
        self.section_info.major = major
        self.section_info.minor = minor
        self.section_info.length = section_len

    def parse_interface_description_block(self, block_len):
        # read link type and capture size
        buf = self.infile.read(4)
        link_type, = struct.unpack(self.section_info.byteorder + b'H2x', buf)
        buf = self.infile.read(4)
        snap_len = struct.unpack(self.section_info.byteorder + b'I', buf)
        self.section_info.link_type = link_type
        self.section_info.snap_len = snap_len

        # read if_tsresol option to determined how to interpreter the timestamp of packet
        options = self.infile.read(block_len - 12 - 8)
        offset = 0
        while offset < len(options):
            option = options[offset:]
            code, = struct.unpack(self.section_info.byteorder + b'H', option[:2])
            raw_len, = struct.unpack(self.section_info.byteorder + b'H', option[2:4])
            padding_len = raw_len
            if code == 9:
                # if_tsresol
                if_tsresol = ord(option[4])
                sig = (if_tsresol & 0x80)
                count = if_tsresol & 0x7f
                # we use microsecond
                if sig == 0:
                    # the remaining bits indicates the resolution of the timestamp
                    # as as a negative power of 10
                    self.section_info.tsresol = (10 ** -count) * (10 ** 6)
                else:  # sig == 1
                    # the resolution as as negative power of 2
                    self.section_info.tsresol = (2 ** -count) * (10 ** 6)
            elif code == 14:
                # if_tsoffset
                self.section_info.tsoffset, = struct.unpack(self.section_info.byteorder + b'Q',
                                                            option[4:12])
                self.section_info.tsoffset *= 10 ** 6
            elif code == 0:
                # end of option
                break
            mod = raw_len % 4
            if mod != 0:
                padding_len += (4 - mod)
            offset += 4 + padding_len

    def parse_enhanced_packet(self, block_len):
        buf = self.infile.read(4)
        # interface_id, = struct.unpack(self.section_info.byteorder + b'I', buf)

        # skip timestamp
        buf = self.infile.read(8)
        h, l, = struct.unpack(self.section_info.byteorder + b'II', buf)
        timestamp = (h << 32) + l
        if six.is_python2:
            micro_second = long(timestamp * self.section_info.tsresol + self.section_info.tsoffset)
        else:
            micro_second = timestamp * self.section_info.tsresol + self.section_info.tsoffset
        # capture len
        buf = self.infile.read(8)
        capture_len, packet_len = struct.unpack(self.section_info.byteorder + b'II', buf)
        # padded_capture_len = ((capture_len - 1) // 4 + 1) * 4

        # the captured data
        data = self.infile.read(capture_len)

        # skip other optional fields
        self.infile.read(block_len - 12 - 20 - capture_len)
        return micro_second, data

    def parse_block(self):
        """read and parse a block"""
        if self.head is not None:
            block_header = self.head + self.infile.read(8 - len(self.head))
            self.head = None
        else:
            block_header = self.infile.read(8)
        if len(block_header) < 8:
            return None
        block_type, block_len = struct.unpack(self.section_info.byteorder + b'II', block_header)

        data = ''
        micro_second = 0
        if block_type == BlockType.SECTION_HEADER:
            self.parse_section_header_block(block_header)
        elif block_type == BlockType.INTERFACE_DESCRIPTION:
            # read link type and capture size
            self.parse_interface_description_block(block_len)
        elif block_type == BlockType.ENHANCED_PACKET:
            micro_second, data = self.parse_enhanced_packet(block_len)
        elif block_type > 0x80000000:
            # private protocol type, ignore
            data = self.infile.read(block_len - 12)
        else:
            self.infile.read(block_len - 12)
            print("unknown block type:%s, size:%d" % (hex(block_type), block_len), file=sys.stderr)

        # read author block_len
        block_len_t = self.infile.read(4)
        block_len_t, = struct.unpack(self.section_info.byteorder + b'I', block_len_t)
        if block_len_t != block_len:
            print("block_len not equal, header:%d, tail:%d." % (block_len, block_len_t),
                  file=sys.stderr)
        return micro_second, data

    def read_packet(self):
        data = self.parse_block()
        if data is None:
            return
        micro_second, link_packet = data
        if len(link_packet) == 0:
            return
        return (self.section_info.link_type, micro_second, link_packet)
