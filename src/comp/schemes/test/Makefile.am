################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the comp library
################################################################################


TESTS = \
	test_rfc4996.sh \
	test_tcp_ts_opt.sh


check_PROGRAMS = \
	test_rfc4996 \
	test_tcp_ts_opt


test_rfc4996_SOURCES = \
	$(srcdir)/../comp_wlsb.c \
	$(srcdir)/../rfc4996.c \
	test_rfc4996.c
test_rfc4996_LDADD = \
	-lrohc_common
test_rfc4996_LDFLAGS = \
	-L$(top_builddir)/src/common/
test_rfc4996_CFLAGS = \
	$(configure_cflags)
test_rfc4996_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/common/ \
	-I$(top_srcdir)/src/comp/ \
	-I$(srcdir)/..

test_tcp_ts_opt_SOURCES = \
	$(srcdir)/../tcp_ts.c \
	test_tcp_ts_opt.c
test_tcp_ts_opt_LDADD = \
	$(CMOCKA_LIBS)
test_tcp_ts_opt_LDFLAGS = \
	$(configure_ldflags)
test_tcp_ts_opt_CFLAGS = \
	$(configure_cflags) \
	$(CMOCKA_CFLAGS)
test_tcp_ts_opt_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(srcdir)/..


EXTRA_DIST = \
	test_rfc4996.sh \
	test_tcp_ts_opt.sh

