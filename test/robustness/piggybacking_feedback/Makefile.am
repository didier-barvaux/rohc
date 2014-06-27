################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tool that checks how the compressor handles
#	             feedback piggybacking with compression failures.
################################################################################


TESTS = \
	test_piggybacking_feedback.sh


check_PROGRAMS = \
	test_piggybacking_feedback


test_piggybacking_feedback_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_piggybacking_feedback_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_piggybacking_feedback_LDFLAGS = \
	-L$(top_builddir)/src/.libs \
	$(configure_ldflags)

test_piggybacking_feedback_SOURCES = \
	test_piggybacking_feedback.c

test_piggybacking_feedback_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc \
	$(additional_platform_libs)

EXTRA_DIST = \
	$(TESTS)

