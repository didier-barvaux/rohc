################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@b2i-toulouse.com>
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
	ts_sc_decomp.c 

headers = \
	rohc.h \
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
	ts_sc_decomp.h 

librohc_common_la_SOURCES = $(sources) $(headers)

include_HEADERS = $(headers)

INCLUDES =

AM_CFLAGS = -g -Wall -Wstrict-prototypes -Werror

AM_MAKEFLAGS = -s

