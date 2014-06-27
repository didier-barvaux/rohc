################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check library features
################################################################################


TESTS = \
	test_feedback2_ack_smallcid_smallsn_crc.sh \
	test_feedback2_ack_smallcid_largesn_sn-crc.sh \
	test_feedback2_ack_largecid_largesn_sn-crc.sh \
	test_feedback2_ack_largecid_smallsn_crc.sh


check_PROGRAMS = \
	test_feedback2


test_feedback2_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_feedback2_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_feedback2_LDFLAGS = \
	-L$(top_builddir)/src/.libs \
	$(configure_ldflags)

test_feedback2_SOURCES = \
	test_feedback2.c

test_feedback2_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_feedback2.sh \
	$(TESTS) \
	inputs

