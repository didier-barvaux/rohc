################################################################################
#	Name       : Makefile.am
#	Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Julien Peyrade <julien.peyrade@toulouse.viveris.com>
#	Description: create the tests for RTP detection (by UDP port or by callback)
################################################################################


TESTS = \
	test_rtp_callback_ignore.sh \
	test_rtp_callback_detect.sh

check_PROGRAMS = \
	test_rtp_callback


test_rtp_callback_SOURCES = test_rtp_callback.c
test_rtp_callback_LDADD = \
	-l$(pcap_lib_name) \
	$(top_builddir)/src/librohc.la \
	$(additional_platform_libs)
test_rtp_callback_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare
test_rtp_callback_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	$(libpcap_includes)
test_rtp_callback_LDFLAGS = \
	$(configure_ldflags)


# extra files for releases
EXTRA_DIST = \
	test_rtp_callback.sh \
	$(TESTS) \
	input

