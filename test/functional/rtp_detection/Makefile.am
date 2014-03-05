################################################################################
#	Name       : Makefile.am
#	Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Julien Peyrade <julien.peyrade@toulouse.viveris.com>
#	Description: create the tests for RTP detection (by UDP port or by callback)
################################################################################


TESTS = \
	test_rtp_ports_context_delete.sh \
	test_rtp_ports_profile_used.sh \
	test_rtp_callback_ignore.sh \
	test_rtp_callback_detect.sh

check_PROGRAMS = \
	test_rtp_ports \
	test_rtp_callback


test_rtp_ports_SOURCES = test_rtp_ports.c
test_rtp_ports_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)
test_rtp_ports_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare
test_rtp_ports_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)
test_rtp_ports_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs


test_rtp_callback_SOURCES = test_rtp_callback.c
test_rtp_callback_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_common
	$(additional_platform_libs)
test_rtp_callback_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare
test_rtp_callback_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	$(libpcap_includes)
test_rtp_callback_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs


# extra files for releases
EXTRA_DIST = \
	test_rtp_ports.sh \
	test_rtp_callback.sh \
	$(TESTS) \
	input

