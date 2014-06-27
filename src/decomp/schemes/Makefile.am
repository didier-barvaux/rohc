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
	decomp_wlsb.c \
	ip_id_offset.c \
	decomp_scaled_rtp_ts.c \
	decomp_list.c \
	decomp_list_ipv6.c \
	rfc4996.c

librohc_decomp_schemes_la_LIBADD = \
	$(additional_platform_libs)

librohc_decomp_schemes_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined

librohc_decomp_schemes_la_CFLAGS = \
	$(configure_cflags)

librohc_decomp_schemes_la_CPPFLAGS = \
	-I$(top_srcdir)/src/common \
	-I$(srcdir)/..

noinst_HEADERS = \
	decomp_wlsb.h \
	ip_id_offset.h \
	decomp_scaled_rtp_ts.h \
	decomp_list.h \
	decomp_list_ipv6.h \
	rfc4996.h

