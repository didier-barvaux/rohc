################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC decompression library
################################################################################

if ROHC_TESTS
DECOMP_TESTS_DIR = test
else
DECOMP_TESTS_DIR = 
endif

SUBDIRS = schemes . $(DECOMP_TESTS_DIR)


noinst_LTLIBRARIES = librohc_decomp.la

librohc_decomp_la_SOURCES = \
	rohc_decomp_detect_packet.c \
	rohc_decomp.c \
	feedback_create.c \
	d_uncompressed.c \
	rohc_decomp_rfc3095.c \
	d_ip.c \
	d_udp.c \
	d_udp_lite.c \
	d_esp.c \
	d_rtp.c \
	d_tcp.c

librohc_decomp_la_LIBADD = \
	$(builddir)/schemes/librohc_decomp_schemes.la \
	$(additional_platform_libs)

librohc_decomp_la_LDFLAGS = \
	$(configure_ldflags)

librohc_decomp_la_CFLAGS = \
	$(configure_cflags)

librohc_decomp_la_CPPFLAGS = \
	-I$(top_srcdir)/src/common

librohc_decomp_la_DEPENDENCIES = \
	$(top_builddir)/src/common/librohc_common.la \
	$(builddir)/schemes/librohc_decomp_schemes.la

pkginclude_HEADERS = rohc_decomp.h

noinst_HEADERS = \
	rohc_decomp_internals.h \
	rohc_decomp_detect_packet.h \
	feedback_create.h \
	rohc_decomp_rfc3095.h \
	d_ip.h \
	d_udp.h

# extra files for releases
EXTRA_DIST = \
	rohc

