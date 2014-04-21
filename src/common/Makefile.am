################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC common library
################################################################################


SUBDIRS = protocols .


lib_LTLIBRARIES = librohc_common.la

sources = \
	rohc_common.c \
	rohc_packets.c \
	rohc_traces_internal.c \
	rohc_utils.c \
	crc.c \
	rohc_add_cid.c \
	interval.c \
	sdvl.c \
	ip.c \
	net_pkt.c \
	comp_list.c \
	rohc_stats.c

public_headers = \
	rohc.h \
	rohc_packets.h \
	rohc_traces.h

# fake public headers installed in $includedir to point
# to the real public headers in $includedir/$packagename
public_compat_headers = \
	compat_headers/rohc.h \
	compat_headers/rohc_packets.h \
	compat_headers/rohc_traces.h

private_headers = \
	rohc_internal.h \
	rohc_bit_ops.h \
	rohc_debug.h \
	rohc_traces_internal.h \
	rohc_time.h \
	rohc_utils.h \
	crc.h \
	rohc_add_cid.h \
	interval.h \
	sdvl.h \
	ip.h \
	net_pkt.h \
	comp_list.h \
	rohc_stats.h

librohc_common_la_SOURCES = $(sources)
librohc_common_la_LIBADD = \
	$(builddir)/protocols/librohc_proto.la \
	$(additional_platform_libs)
librohc_common_la_LDFLAGS = \
	$(configure_ldflags) \
	-export-symbols $(srcdir)/librohc_common.symbols \
	-no-undefined \
	-version-info $(ROHC_API_CURRENT):$(ROHC_API_REVISION):$(ROHC_API_AGE)
librohc_common_la_CFLAGS = \
	$(configure_cflags)
librohc_common_la_CPPFLAGS = \
	-I$(top_srcdir)/src
librohc_common_la_DEPENDENCIES = \
	$(builddir)/protocols/librohc_proto.la \
	$(srcdir)/librohc_common.symbols

include_HEADERS = $(public_compat_headers)
pkginclude_HEADERS = $(public_headers)
noinst_HEADERS = $(private_headers)

# extra files for releases
EXTRA_DIST = \
	librohc_common.symbols \
	rohc

