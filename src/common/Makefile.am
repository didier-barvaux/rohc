################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC common library
################################################################################


SUBDIRS = protocols . test


lib_LTLIBRARIES = librohc_common.la

sources = \
	rohc_common.c \
	rohc_packets.c \
	rohc_traces_internal.c \
	rohc_utils.c \
	crc.c \
	decode.c \
	ip_id_offset_decode.c \
	interval.c \
	lsb_decode.c \
	sdvl.c \
	wlsb.c \
	ip.c \
	ts_sc_comp.c \
	ts_sc_decomp.c \
	comp_list.c \
	cid.c

public_headers = \
	rohc.h \
	rohc_packets.h \
	rohc_traces.h

private_headers = \
	rohc_bit_ops.h \
	rohc_debug.h \
	rohc_traces_internal.h \
	rohc_time.h \
	rohc_utils.h \
	crc.h \
	decode.h \
	ip_id_offset_decode.h \
	interval.h \
	lsb_decode.h \
	sdvl.h \
	wlsb.h \
	ip.h \
	ts_sc_comp.h \
	ts_sc_decomp.h \
	comp_list.h \
	cid.h

librohc_common_la_SOURCES = $(sources)
librohc_common_la_LIBADD = \
	protocols/librohc_proto.la \
	$(additional_platform_libs)
librohc_common_la_LDFLAGS = \
	$(configure_ldflags) \
	-no-undefined \
	-version-info $(ROHC_API_CURRENT):$(ROHC_API_REVISION):$(ROHC_API_AGE)
librohc_common_la_CFLAGS = \
	$(configure_cflags)
librohc_common_la_CPPFLAGS = \
	-I$(top_srcdir)/src

include_HEADERS = $(public_headers)
noinst_HEADERS = $(private_headers)

