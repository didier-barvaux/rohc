################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: define some protocols and their headers
################################################################################

noinst_HEADERS = \
	ip_numbers.h \
	ipv4.h \
	ipv6.h \
	ip.h \
	udp.h \
	udp_lite.h \
	rtp.h \
	tcp.h \
	esp.h \
	uncomp_pkt_hdrs.h \
	rfc6846.h \
	rfc5225.h

noinst_LTLIBRARIES = librohc_proto.la

librohc_proto_la_SOURCES = \
	ip_numbers.c
librohc_proto_la_LIBADD =
librohc_proto_la_LDFLAGS = $(configure_ldflags)
librohc_proto_la_CFLAGS = \
	$(configure_cflags) \
	$(configure_cflags_for_lib)
librohc_proto_la_CPPFLAGS = -I$(top_srcdir)/src/

