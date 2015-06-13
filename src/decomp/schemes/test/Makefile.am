################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: Check behaviour of the decoding schemes
################################################################################


TESTS = \
	test_wlsb.sh \
	test_tcp_ts_opt.sh

check_PROGRAMS = \
	test_wlsb \
	test_tcp_ts_opt


test_wlsb_SOURCES = ../decomp_wlsb.c test_wlsb.c
test_wlsb_LDADD = \
	$(CMOCKA_LIBS)
test_wlsb_LDFLAGS = \
	$(configure_ldflags) \
	-Wl,--wrap=rohc_f_32bits
test_wlsb_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	$(CMOCKA_CFLAGS)
test_wlsb_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(srcdir)/..

test_tcp_ts_opt_SOURCES = ../tcp_ts.c test_tcp_ts_opt.c
test_tcp_ts_opt_LDADD = \
	$(CMOCKA_LIBS)
test_tcp_ts_opt_LDFLAGS = \
	$(configure_ldflags) \
	-Wl,--wrap=rohc_f_32bits
test_tcp_ts_opt_CFLAGS = \
	$(configure_cflags) \
	-Wno-unused-parameter \
	$(CMOCKA_CFLAGS)
test_tcp_ts_opt_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/decomp \
	-I$(srcdir)/..


EXTRA_DIST = \
	test_wlsb.sh \
	test_tcp_ts_opt.sh

