################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC compression library
################################################################################

SUBDIRS = . test


lib_LTLIBRARIES = librohc_comp.la

librohc_comp_la_SOURCES = \
	rohc_comp.c \
	c_uncompressed.c \
	c_generic.c \
	c_ip.c \
	c_udp.c \
	c_udp_lite.c \
	c_esp.c \
	c_rtp.c \
	c_tcp.c \
	rfc4996_encoding.c

librohc_comp_la_LIBADD = \
	-lrohc_common \
	$(additional_platform_libs)

librohc_comp_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined \
	-version-info $(ROHC_API_CURRENT):$(ROHC_API_REVISION):$(ROHC_API_AGE) \
	-L$(top_builddir)/src/common/.libs

librohc_comp_la_CFLAGS = \
	$(configure_cflags)

librohc_comp_la_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common

# fake public headers installed in $includedir to point
# to the real public headers in $includedir/$packagename
include_HEADERS = \
	compat_headers/rohc_comp.h

pkginclude_HEADERS = \
	rohc_comp.h

noinst_HEADERS = \
	rohc_comp_internals.h \
	c_generic.h \
	c_ip.h \
	c_udp.h \
	c_udp_lite.h \
	c_esp.h \
	c_rtp.h \
	c_tcp.h \
	rfc4996_encoding.h

