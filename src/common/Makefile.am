################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC common library
################################################################################

lib_LTLIBRARIES = librohc_common.la

sources = \
	rohc.c \
	crc.c \
	decode.c \
	ip_id.c \
	lsb.c \
	sdvl.c \
	wlsb.c \
	ip.c \
	ts_sc_comp.c \
	ts_sc_decomp.c \
	comp_list.c

public_headers = \
	rohc.h

private_headers = \
	rohc_bit_ops.h \
	rohc_debug.h \
	rohc_traces.h \
	rohc_time.h \
	rohc_packets.h \
	crc.h \
	decode.h \
	ip_id.h \
	lsb.h \
	sdvl.h \
	wlsb.h \
	ip.h \
	udp_lite.h \
	rtp.h \
	ts_sc_comp.h \
	ts_sc_decomp.h \
	comp_list.h

librohc_common_la_SOURCES = $(sources)

include_HEADERS = $(public_headers)
noinst_HEADERS = $(private_headers)

INCLUDES =

AM_CFLAGS = -g -Wall -Wstrict-prototypes

