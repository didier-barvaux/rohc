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
Decompress network packets with the RObust Header Compression (ROHC) scheme
"""

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from builtins import range
from future import standard_library
standard_library.install_aliases()

from rohc import ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, \
                 ROHC_PROFILE_UNCOMPRESSED, ROHC_U_MODE, \
                 ROHC_STATUS_OK, ROHC_STATUS_ERROR, \
                 rohc_decomp_new2, rohc_decomp_set_traces_cb2, \
                 rohc_decomp_enable_profile, rohc_decompress3, \
                 rohc_get_profile_descr, print_rohc_traces, \
                 rohc_ts, rohc_buf
from struct import pack


class RohcDecompressor(object):
    """
    Decompress network packets with the RObust Header Compression (ROHC) scheme
    """

    decomp = None
    mode = None
    cid_type = None
    cid_max = None
    verbose = None

    _buf_max_len = 0xffff
    _buf1 = b""
    _buf2 = b""
    _buf3 = b""

    def __init__(self, cid_type=ROHC_SMALL_CID, cid_max=ROHC_SMALL_CID_MAX, \
                 mode=ROHC_U_MODE, profiles=[ROHC_PROFILE_UNCOMPRESSED], \
                 verbose=False):
        """ Create and return a new ROHC decompressor.

        Keyword arguments:
        cid_type   -- the CID type among ROHC_SMALL_CID and ROHC_LARGE_CID
        cid_max    -- the maximum CID value to use
        mode       -- the ROHC mode of operation to target
        profiles   -- the list of supported profiles
        verbose    -- whether to run the compressor in verbose mode or not (bool)
        """

        self.cid_type = cid_type
        self.cid_max = cid_max
        self.mode = mode
        self.verbose = verbose

        self.decomp = rohc_decomp_new2(self.cid_type, self.cid_max, self.mode)
        if self.decomp is None:
            print("failed to create the ROHC decompressor")
            return None

        if self.verbose is True:
            ret = rohc_decomp_set_traces_cb2(self.decomp, print_rohc_traces, None)
            if ret is not True:
                print("failed to enable traces")
                return None

        for profile in profiles:
            ret = rohc_decomp_enable_profile(self.decomp, profile)
            if ret is not True:
                print("failed to enable profile '%s' (%i)" % \
                      (rohc_get_profile_descr(profile), profile))
                return None

        # create the output buffers
        self._buf1 = b""
        for _ in range(0, self._buf_max_len):
            self._buf1 += b'\0'
        self._buf2 = b""
        for _ in range(0, self._buf_max_len):
            self._buf2 += b'\0'
        self._buf3 = b""
        for _ in range(0, self._buf_max_len):
            self._buf3 += b'\0'

    def decompress(self, comp_pkt):
        """ Decompress the given compressed ROHC packet

        Keyword arguments:
        comp_pkt -- the compressed ROHC packet (str)

        Return tuple:
        status           -- a value among ROHC_STATUS_*
        decomp_pkt       -- the decompressed packet (str) or None wrt status_code
        feedback_recv    -- the feedback (str) received with the compressed packet
        feedback_to_send -- the feedback (str) to send with the associated compressor
        """

        status = ROHC_STATUS_ERROR
        timestamp = rohc_ts(0, 0)

        # create the input buffer for the compressed ROHC packet
        if isinstance(comp_pkt, bytes) is not True:
            raise TypeError("compress(): argument 'comp_pkt' shall be "\
                            "'bytes' not '%s'" % type(comp_pkt))
        comp_pkt_len = len(comp_pkt)
        buf_comp = rohc_buf(comp_pkt, comp_pkt_len, timestamp)
        if buf_comp is None:
            return (status, None, None, None)

        # create the output buffer for the decompressed packet
        buf_decomp = rohc_buf(self._buf1, 0, timestamp)
        if buf_decomp is None:
            return (status, None, None, None)

        # create the buffers for feedbacks
        buf_feedback_recv = rohc_buf(self._buf2, 0, timestamp)
        if buf_feedback_recv is None:
            return (status, None, None, None)
        buf_feedback_to_send = rohc_buf(self._buf3, 0, timestamp)
        if buf_feedback_to_send is None:
            return (status, None, None, None)

        # decompress the ROHC packet
        status = rohc_decompress3(self.decomp, buf_comp, buf_decomp, \
                                  buf_feedback_recv, buf_feedback_to_send)
        if status != ROHC_STATUS_OK:
            return (status, None, None, None)

        return (status, self._buf1[:buf_decomp.len], \
                self._buf2[:buf_feedback_recv.len], \
                self._buf3[:buf_feedback_to_send.len])

