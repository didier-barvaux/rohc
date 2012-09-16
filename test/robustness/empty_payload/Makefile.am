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
	test_empty_payload_uo0_iponlyprofile.sh \
	test_empty_payload_uo0_udpprofile.sh \
	test_empty_payload_uo0_espprofile.sh \
	test_empty_payload_uo1.sh \
	test_empty_payload_uor2.sh


check_PROGRAMS = \
	test_empty_payload


test_empty_payload_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

test_empty_payload_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs

test_empty_payload_SOURCES = \
	test_empty_payload.c

test_empty_payload_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_decomp \
	-lrohc_common \
	$(additional_platform_libs)

EXTRA_DIST = \
	test_empty_payload.sh \
	$(TESTS) \
	inputs

