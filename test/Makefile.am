################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC test program
################################################################################

TESTS = \
	test_ipv4fragmented.sh \
	test_ipv4_icmp.sh \
	test_ipv4_icmp+tcp.sh \
	test_ipv4_ipv4_icmp.sh \
	test_ipv4_ipv4_udplite.sh \
	test_ipv4_ipv4_udp_rtp_mp3.sh \
	test_ipv4_ipv4_udp_rtp_video1.sh \
	test_ipv4_ipv4_udp_rtp_video2.sh \
	test_ipv4_ipv4_udp.sh \
	test_ipv4_ipv6ext_udp_rtp_video1.sh \
	test_ipv4_ipv6_icmp.sh \
	test_ipv4_ipv6_udplite.sh \
	test_ipv4_ipv6_udp_rtp_video1.sh \
	test_ipv4_ipv6_udp_rtp_video2.sh \
	test_ipv4_ipv6_udp.sh \
	test_ipv4_udplite.sh \
	test_ipv4_udp_rtp_h323.sh \
	test_ipv4_udp_rtp_misc.sh \
	test_ipv4_udp_rtp_mp3.sh \
	test_ipv4_udp_rtp_rtp+rtp+icmp.sh \
	test_ipv4_udp_rtp_video2.sh \
	test_ipv4_udp_rtp_video3.sh \
	test_ipv4_udp_rtp_video1.sh \
	test_ipv4_udp_rtp_voip.sh \
	test_ipv4_udp_rtp_voip+video.sh \
	test_ipv4_udp.sh \
	test_ipv6ext_icmp.sh \
	test_ipv6ext_ipv6ext_icmp.sh \
	test_ipv6ext_udp_rtp_audio-vlc.sh \
	test_ipv6ext_udp.sh \
	test_ipv6_icmp.sh \
	test_ipv6_ipv6_icmp.sh \
	test_ipv6_ipv6_udplite.sh \
	test_ipv6_ipv6_udp.sh \
	test_ipv6_udplite.sh \
	test_ipv6_udp_rtp_audio-vlc.sh \
	test_ipv6_udp_rtp_video2.sh \
	test_ipv6_udp_rtp_video1.sh \
	test_ipv6_udp.sh


check_PROGRAMS = \
	test


INCLUDES = \
	-I../src/common \
	-I../src/comp \
	-I../src/decomp

AM_CFLAGS = -g -Wall -Wstrict-prototypes -Werror

AM_LDFLAGS = \
	-L../src/common/.libs \
	-L../src/comp/.libs \
	-L../src/decomp/.libs


test_SOURCES = test.c
test_LDADD = \
	-lpcap \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp \
	-lm

