################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC common library
################################################################################


SUBDIRS = protocols .


noinst_LTLIBRARIES = librohc_common.la

sources = \
	rohc_common.c \
	rohc_packets.c \
	rohc_traces_internal.c \
	rohc_utils.c \
	rohc_buf.c \
	crc.c \
	rohc_add_cid.c \
	interval.c \
	sdvl.c \
	ip.c \
	net_pkt.c \
	rohc_list.c \
	feedback_parse.c

public_headers = \
	rohc.h \
	rohc_packets.h \
	rohc_traces.h \
	rohc_time.h \
	rohc_buf.h

private_headers = \
	rohc_internal.h \
	rohc_bit_ops.h \
	rohc_debug.h \
	rohc_traces_internal.h \
	rohc_time_internal.h \
	rohc_utils.h \
	crc.h \
	rohc_add_cid.h \
	interval.h \
	sdvl.h \
	ip.h \
	net_pkt.h \
	rohc_list.h \
	feedback_parse.h

librohc_common_la_SOURCES = $(sources)
librohc_common_la_LIBADD = \
	$(builddir)/protocols/librohc_proto.la \
	$(additional_platform_libs)
librohc_common_la_LDFLAGS = \
	$(configure_ldflags)
librohc_common_la_CFLAGS = \
	$(configure_cflags)
librohc_common_la_CPPFLAGS = \
	-I$(top_srcdir)/src
librohc_common_la_DEPENDENCIES = \
	$(builddir)/protocols/librohc_proto.la

pkginclude_HEADERS = $(public_headers)
noinst_HEADERS = $(private_headers)

# extra files for releases
EXTRA_DIST = \
	rohc

