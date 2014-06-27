################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: Check behaviour of the encoding and decoding schemes together
################################################################################


TESTS = \
	test_wlsb_wraparound.sh \
	test_wlsb_packet_loss.sh \
	test_rtp_ts_wraparound.sh

check_PROGRAMS = \
	test_wlsb_wraparound \
	test_wlsb_packet_loss \
	test_rtp_ts_wraparound


test_wlsb_wraparound_SOURCES = test_wlsb_wraparound.c
test_wlsb_wraparound_LDADD = \
	$(top_builddir)/src/comp/schemes/librohc_comp_schemes.la \
	$(top_builddir)/src/decomp/schemes/librohc_decomp_schemes.la \
	$(top_builddir)/src/common/librohc_common.la
test_wlsb_wraparound_LDFLAGS = \
	$(configure_ldflags)
test_wlsb_wraparound_CFLAGS = \
	$(configure_cflags)
test_wlsb_wraparound_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp


test_wlsb_packet_loss_SOURCES = test_wlsb_packet_loss.c
test_wlsb_packet_loss_LDADD = \
	$(top_builddir)/src/comp/schemes/librohc_comp_schemes.la \
	$(top_builddir)/src/decomp/schemes/librohc_decomp_schemes.la \
	$(top_builddir)/src/common/librohc_common.la
test_wlsb_packet_loss_LDFLAGS = \
	$(configure_ldflags)
test_wlsb_packet_loss_CFLAGS = \
	$(configure_cflags)
test_wlsb_packet_loss_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp


test_rtp_ts_wraparound_SOURCES = test_rtp_ts_wraparound.c
test_rtp_ts_wraparound_LDADD = \
	$(top_builddir)/src/comp/schemes/librohc_comp_schemes.la \
	$(top_builddir)/src/decomp/schemes/librohc_decomp_schemes.la \
	$(top_builddir)/src/common/librohc_common.la
test_rtp_ts_wraparound_LDFLAGS = \
	$(configure_ldflags)
test_rtp_ts_wraparound_CFLAGS = \
	$(configure_cflags)
test_rtp_ts_wraparound_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp


EXTRA_DIST = \
	test_wlsb_wraparound.sh \
	test_wlsb_packet_loss.sh \
	test_rtp_ts_wraparound.sh

