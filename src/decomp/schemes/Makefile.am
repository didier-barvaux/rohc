################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier@barvaux.org>
# Description: build the decoding schemes for the ROHC decompression library
################################################################################

if ROHC_TESTS
DECOMP_SCHEMES_TESTS_DIR = test
else
DECOMP_SCHEMES_TESTS_DIR = 
endif

SUBDIRS = . $(DECOMP_SCHEMES_TESTS_DIR)

noinst_LTLIBRARIES = librohc_decomp_schemes.la

librohc_decomp_schemes_la_SOURCES = \
	wlsb.c \
	ip_id_offset.c \
	scaled_rtp_ts.c \
	list.c \
	list_ipv6.c \
	rfc4996.c

librohc_decomp_schemes_la_LIBADD = \
	$(additional_platform_libs)

librohc_decomp_schemes_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined

librohc_decomp_schemes_la_CFLAGS = \
	$(configure_cflags)

librohc_decomp_schemes_la_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(srcdir)/..

noinst_HEADERS = \
	wlsb.h \
	ip_id_offset.h \
	scaled_rtp_ts.h \
	list.h \
	list_ipv6.h \
	rfc4996.h

