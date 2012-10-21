################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the common library
################################################################################


TESTS = \
	test_lsb_decode_wraparound.sh \
	test_lsb_decode_packet_loss.sh \
	test_rtp_ts_wraparound.sh


check_PROGRAMS = \
	test_lsb_decode_wraparound \
	test_lsb_decode_packet_loss \
	test_rtp_ts_wraparound


test_lsb_decode_wraparound_SOURCES = test_lsb_decode_wraparound.c
test_lsb_decode_wraparound_LDADD = \
	-lrohc_common
test_lsb_decode_wraparound_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs
test_lsb_decode_wraparound_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common

test_lsb_decode_packet_loss_SOURCES = test_lsb_decode_packet_loss.c
test_lsb_decode_packet_loss_LDADD = \
	-lrohc_common
test_lsb_decode_packet_loss_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs
test_lsb_decode_packet_loss_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common

test_rtp_ts_wraparound_SOURCES = test_rtp_ts_wraparound.c
test_rtp_ts_wraparound_LDADD = \
	-lrohc_common
test_rtp_ts_wraparound_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs
test_rtp_ts_wraparound_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common


EXTRA_DIST = \
	test_lsb_decode_wraparound.sh \
	test_lsb_decode_packet_loss.sh \
	test_rtp_ts_wraparound.sh

