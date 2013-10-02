################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: Check behaviour of the decoding schemes
################################################################################


TESTS = \
	test_wlsb.sh

check_PROGRAMS = \
	test_wlsb


test_wlsb_SOURCES = ../wlsb.c test_wlsb.c
test_wlsb_LDADD = \
	$(CMOCKA_LIBS)
test_wlsb_LDFLAGS = \
	$(configure_ldflags) \
	-Wl,--wrap=rohc_f_32bits
test_wlsb_CFLAGS = \
	$(configure_cflags) \
	$(CMOCKA_CFLAGS)
test_wlsb_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(srcdir)/..


EXTRA_DIST = \
	test_wlsb.sh

