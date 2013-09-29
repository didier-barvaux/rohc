################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC decompression library
################################################################################

SUBDIRS = . test


lib_LTLIBRARIES = librohc_decomp.la

librohc_decomp_la_SOURCES = \
	rohc_decomp_detect_packet.c \
	rohc_decomp.c \
	feedback.c \
	d_uncompressed.c \
	d_generic.c \
	d_ip.c \
	d_udp.c \
	d_udp_lite.c \
	d_esp.c \
	d_rtp.c \
	d_tcp.c \
	rfc4996_decoding.c

librohc_decomp_la_LIBADD = \
	-lrohc_common \
	-lrohc_comp \
	$(additional_platform_libs)

librohc_decomp_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined \
	-version-info $(ROHC_API_CURRENT):$(ROHC_API_REVISION):$(ROHC_API_AGE) \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

librohc_decomp_la_CFLAGS = \
	$(configure_cflags)

librohc_decomp_la_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

# fake public headers installed in $includedir to point
# to the real public headers in $includedir/$packagename
include_HEADERS = \
	compat_headers/rohc_decomp.h

pkginclude_HEADERS = rohc_decomp.h

noinst_HEADERS = \
	rohc_decomp_internals.h \
	rohc_decomp_detect_packet.h \
	feedback.h \
	d_uncompressed.h \
	d_generic.h \
	d_ip.h \
	d_udp.h \
	d_udp_lite.h \
	d_esp.h \
	d_rtp.h \
	d_tcp.h \
	rfc4996_decoding.h

# extra files for releases
EXTRA_DIST = \
	rohc

