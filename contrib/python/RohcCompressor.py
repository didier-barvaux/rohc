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
Compress network packets with the RObust Header Compression (ROHC) scheme
"""

from rohc import ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, \
                 ROHC_PROFILE_UNCOMPRESSED, \
                 ROHC_STATUS_OK, ROHC_STATUS_ERROR, \
                 rohc_comp_new2, rohc_comp_set_traces_cb2, \
                 rohc_comp_enable_profile, rohc_comp_set_wlsb_window_width, \
                 rohc_comp_set_rtp_detection_cb, rohc_compress4, \
                 rohc_comp_deliver_feedback2, rohc_get_profile_descr, \
                 gen_false_random_num, print_rohc_traces, rohc_comp_rtp_cb, \
                 rohc_ts, rohc_buf


class RohcCompressor(object):
    """
    Compress network packets with the RObust Header Compression (ROHC) scheme
    """

    comp = None
    cid_type = None
    cid_max = None
    wlsb_width = None
    verbose = None

    _buf_max_len = 0xffff * 2
    _buf = b""

    def __init__(self, cid_type=ROHC_SMALL_CID, cid_max=ROHC_SMALL_CID_MAX, \
                 wlsb_width=4, profiles=[ROHC_PROFILE_UNCOMPRESSED], verbose=False):
        """ Create and return a new ROHC ompressor.

        Keyword arguments:
        cid_type   -- the CID type among ROHC_SMALL_CID and ROHC_LARGE_CID
        cid_max    -- the maximum CID value to use
        wlsb_width -- the width of the W-LSB window (power of 2)
        profiles   -- the list of supported profiles
        verbose    -- whether to run the compressor in verbose mode or not (bool)
        """

        self.cid_type = cid_type
        self.cid_max = cid_max
        self.wlsb_width = wlsb_width
        self.verbose = verbose

        self.comp = rohc_comp_new2(self.cid_type, self.cid_max, \
                                   gen_false_random_num, None)
        if self.comp is None:
            print("failed to create the ROHC compressor")
            return None

        if self.verbose is True:
            ret = rohc_comp_set_traces_cb2(self.comp, print_rohc_traces, None)
            if ret is not True:
                print("failed to enable traces")
                return None

        for profile in profiles:
            ret = rohc_comp_enable_profile(self.comp, profile)
            if ret is not True:
                print("failed to enable profile '%s' (%i)" % \
                      (rohc_get_profile_descr(profile), profile))
                return None

        ret = rohc_comp_set_wlsb_window_width(self.comp, self.wlsb_width)
        if ret is not True:
            print("failed to set WLSB width to %i" % self.wlsb_width)
            return None

        ret = rohc_comp_set_rtp_detection_cb(self.comp, rohc_comp_rtp_cb, None)
        if ret is not True:
            print("failed to set the callback RTP detection")
            return None

        # create the output buffers
        self._buf = b""
        for _ in range(0, self._buf_max_len):
            self._buf += b'\x00'

    def compress(self, uncomp_pkt):
        """ Compress the given uncompressed packet

        Keyword arguments:
        uncomp_pkt -- the uncompressed packet (str)

        Return tuple (return_code, compressed_packet):
        status   -- a value among ROHC_STATUS_*
        comp_pkt -- the compressed packet (str) or None wrt status_code
        """

        status = ROHC_STATUS_ERROR

        timestamp = rohc_ts(0, 0)

        # create the input buffer for the uncompressed packet
        if isinstance(uncomp_pkt, bytes) is not True:
            raise TypeError("compress(): argument 'uncomp_pkt' shall be "\
                            "'bytes' not '%s'" % type(uncomp_pkt))
        uncomp_pkt_len = len(uncomp_pkt)
        buf_uncomp = rohc_buf(uncomp_pkt, uncomp_pkt_len, timestamp)
        if buf_uncomp is None:
            return (status, None)

        # create the output buffer for the compressed ROHC packet
        buf_comp = rohc_buf(self._buf, 0, timestamp)
        if buf_comp is None:
            return (status, None)

        # compress the uncompressed packet into one ROHC packet
        status = rohc_compress4(self.comp, buf_uncomp, buf_comp)
        if status != ROHC_STATUS_OK:
            return (status, None)

        return (status, self._buf[:buf_comp.len])

    def deliver_feedback(self, feedback):
        """ Deliver the given feedback packet to the ROHC compressor

        Keyword arguments:
        feedback -- the feedback packet to deliver to the ROHC compressor

        Return whether the feedback packet was successfully delivered to the
        ROHC compressor or not (bool).
        """

        timestamp = rohc_ts(0, 0)

        # create the buffer for the feedback data
        if isinstance(feedback, bytes) is not True:
            raise TypeError("compress(): argument 'feedback' shall be "\
                            "'bytes' not '%s'" % type(feedback))
        feedback_len = len(feedback)
        buf_feedback = rohc_buf(feedback, feedback_len, timestamp)
        if buf_feedback is None:
            return False

        return rohc_comp_deliver_feedback2(self.comp, buf_feedback)

