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
	wlsb.c \
	scaled_rtp_ts.c \
	list.c \
	list_ipv6.c \
	rfc4996.c

librohc_comp_schemes_la_LIBADD = \
	$(additional_platform_libs)

librohc_comp_schemes_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined

librohc_comp_schemes_la_CFLAGS = \
	$(configure_cflags)

librohc_comp_schemes_la_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(srcdir)/..

noinst_HEADERS = \
	cid.h \
	wlsb.h \
	scaled_rtp_ts.h \
	list.h \
	list_ipv6.h \
	rfc4996.h

