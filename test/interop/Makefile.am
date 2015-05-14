################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create and run the ROHC interoperability tests
################################################################################


TESTS = \
	test_interop_Aeroflex-TM500-1.sh \
	test_interop_Aeroflex-TM500-2.sh


check_PROGRAMS = \
	test_interop


test_interop_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	-Wno-sign-compare

test_interop_CPPFLAGS = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp \
	$(libpcap_includes)

test_interop_LDFLAGS = \
	$(configure_ldflags)

test_interop_SOURCES = \
	test_interop.c

test_interop_LDADD = \
	-l$(pcap_lib_name) \
	$(top_builddir)/src/librohc.la \
	$(additional_platform_libs)


EXTRA_DIST = \
	test_interop.sh \
	$(TESTS) \
	inputs

