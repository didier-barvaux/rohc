################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tool that checks the (de)compression of packets
#	             with empty payloads
################################################################################


TESTS = \
	test_empty_payload_ir.sh \
	test_empty_payload_irdyn.sh \
	test_empty_payload_uo0.sh \
	test_empty_payload_uo1.sh \
	test_empty_payload_uor2.sh

# decompression of ROHC packets with empty payloads currently fails :(
XFAIL_TESTS = \
	$(TESTS)


check_PROGRAMS = \
	test_empty_payload


INCLUDES = \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs


test_empty_payload_SOURCES = test_empty_payload.c
test_empty_payload_LDADD = \
	-lpcap \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp \
	-lm

EXTRA_DIST = \
	test_empty_payload.sh \
	$(TESTS) \
	inputs

