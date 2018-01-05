################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier@barvaux.org>
# Description: build the encoding schemes for the ROHC compression library
################################################################################

if ROHC_TESTS
COMP_SCHEMES_TESTS_DIR = test
else
COMP_SCHEMES_TESTS_DIR = 
endif

SUBDIRS = . $(COMP_SCHEMES_TESTS_DIR)

noinst_LTLIBRARIES = librohc_comp_schemes.la

librohc_comp_schemes_la_SOURCES = \
	cid.c \
	comp_wlsb.c \
	ip_id_offset.c \
	comp_scaled_rtp_ts.c \
	comp_list.c \
	comp_list_ipv6.c \
	rfc4996.c \
	tcp_sack.c \
	tcp_ts.c \
	ipv6_exts.c

librohc_comp_schemes_la_LIBADD = \
	$(additional_platform_libs)

librohc_comp_schemes_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined

librohc_comp_schemes_la_CFLAGS = \
	$(configure_cflags) \
	$(configure_cflags_for_lib)

librohc_comp_schemes_la_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(srcdir)/..

noinst_HEADERS = \
	cid.h \
	comp_wlsb.h \
	ip_id_offset.h \
	comp_scaled_rtp_ts.h \
	comp_list.h \
	comp_list_ipv6.h \
	rfc4996.h \
	tcp_sack.h \
	tcp_ts.h \
	ipv6_exts.h

