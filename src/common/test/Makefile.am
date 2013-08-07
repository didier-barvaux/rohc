################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the common library
################################################################################


TESTS = \
	test_lsb_decode.sh \
	test_lsb_decode_wraparound.sh \
	test_lsb_decode_packet_loss.sh \
	test_rtp_ts_wraparound.sh

XFAIL_TESTS = test_lsb_decode.sh

check_PROGRAMS = \
	test_lsb_decode \
	test_lsb_decode_wraparound \
	test_lsb_decode_packet_loss \
	test_rtp_ts_wraparound

test_lsb_decode_SOURCES = ../lsb_decode.c test_lsb_decode.c
test_lsb_decode_LDADD = \
	$(CMOCKA_LIBS)
test_lsb_decode_LDFLAGS = \
	$(configure_ldflags) \
	-Wl,--wrap=rohc_f_32bits
test_lsb_decode_CFLAGS = \
	$(configure_cflags) \
	$(CMOCKA_CFLAGS)
test_lsb_decode_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common


test_lsb_decode_wraparound_SOURCES = test_lsb_decode_wraparound.c
test_lsb_decode_wraparound_LDADD = \
	-lrohc_common
test_lsb_decode_wraparound_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs
test_lsb_decode_wraparound_CFLAGS = \
	$(configure_cflags)
test_lsb_decode_wraparound_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common

test_lsb_decode_packet_loss_SOURCES = test_lsb_decode_packet_loss.c
test_lsb_decode_packet_loss_LDADD = \
	-lrohc_common
test_lsb_decode_packet_loss_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs
test_lsb_decode_packet_loss_CFLAGS = \
	$(configure_cflags)
test_lsb_decode_packet_loss_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common

test_rtp_ts_wraparound_SOURCES = test_rtp_ts_wraparound.c
test_rtp_ts_wraparound_LDADD = \
	-lrohc_common
test_rtp_ts_wraparound_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs
test_rtp_ts_wraparound_CFLAGS = \
	$(configure_cflags)
test_rtp_ts_wraparound_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common


EXTRA_DIST = \
	test_lsb_decode.sh \
	test_lsb_decode_wraparound.sh \
	test_lsb_decode_packet_loss.sh \
	test_rtp_ts_wraparound.sh

