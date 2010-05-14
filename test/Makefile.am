################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC test program
################################################################################

TESTS_SMALLCID = \
	test_ipvx_smallcid.sh \
	test_ipv4fragmented_smallcid.sh \
	test_ipv4_icmp_smallcid.sh \
	test_ipv4_icmp_bug580491_smallcid.sh \
	test_ipv4_icmp+tcp_smallcid.sh \
	test_ipv4_ipv4_icmp_smallcid.sh \
	test_ipv4_ipv4_udplite_smallcid.sh \
	test_ipv4_ipv4_udp_rtp_mp3_smallcid.sh \
	test_ipv4_ipv4_udp_rtp_mp3-variable-pt_smallcid.sh \
	test_ipv4_ipv4_udp_rtp_video1_smallcid.sh \
	test_ipv4_ipv4_udp_rtp_video2_smallcid.sh \
	test_ipv4_ipv4_udp_smallcid.sh \
	test_ipv4_ipv6ext_udp_rtp_video1_smallcid.sh \
	test_ipv4_ipv6_icmp_smallcid.sh \
	test_ipv4_ipv6_udplite_smallcid.sh \
	test_ipv4_ipv6_udp_rtp_video1_smallcid.sh \
	test_ipv4_ipv6_udp_rtp_video2_smallcid.sh \
	test_ipv4_ipv6_udp_smallcid.sh \
	test_ipv4_udplite_smallcid.sh \
	test_ipv4_udp_rtp_h323_smallcid.sh \
	test_ipv4_udp_rtp_misc_smallcid.sh \
	test_ipv4_udp_rtp_mp3_smallcid.sh \
	test_ipv4_udp_rtp_rtp+rtp+icmp_smallcid.sh \
	test_ipv4_udp_rtp_video2_smallcid.sh \
	test_ipv4_udp_rtp_video3_smallcid.sh \
	test_ipv4_udp_rtp_video1_smallcid.sh \
	test_ipv4_udp_rtp_voip_smallcid.sh \
	test_ipv4_udp_rtp_voip+video_smallcid.sh \
	test_ipv4_udp_smallcid.sh \
	test_ipv6ext_icmp_smallcid.sh \
	test_ipv6ext_icmp-large-ipv6-ext_smallcid.sh \
	test_ipv6ext_ipv6ext_icmp_smallcid.sh \
	test_ipv6ext_udp_rtp_audio-vlc_smallcid.sh \
	test_ipv6ext_udp_smallcid.sh \
	test_ipv6_icmp_smallcid.sh \
	test_ipv6_ipv6_icmp_smallcid.sh \
	test_ipv6_ipv6_udplite_smallcid.sh \
	test_ipv6_ipv6_udp_smallcid.sh \
	test_ipv6_udplite_smallcid.sh \
	test_ipv6_udp_rtp_audio-vlc_smallcid.sh \
	test_ipv6_udp_rtp_video2_smallcid.sh \
	test_ipv6_udp_rtp_video1_smallcid.sh \
	test_ipv6_udp_smallcid.sh

TESTS_LARGECID = \
	test_ipvx_largecid.sh \
	test_ipv4fragmented_largecid.sh \
	test_ipv4_icmp_largecid.sh \
	test_ipv4_icmp_bug580491_largecid.sh \
	test_ipv4_icmp+tcp_largecid.sh \
	test_ipv4_ipv4_icmp_largecid.sh \
	test_ipv4_ipv4_udplite_largecid.sh \
	test_ipv4_ipv4_udp_rtp_mp3_largecid.sh \
	test_ipv4_ipv4_udp_rtp_mp3-variable-pt_largecid.sh \
	test_ipv4_ipv4_udp_rtp_video1_largecid.sh \
	test_ipv4_ipv4_udp_rtp_video2_largecid.sh \
	test_ipv4_ipv4_udp_largecid.sh \
	test_ipv4_ipv6ext_udp_rtp_video1_largecid.sh \
	test_ipv4_ipv6_icmp_largecid.sh \
	test_ipv4_ipv6_udplite_largecid.sh \
	test_ipv4_ipv6_udp_rtp_video1_largecid.sh \
	test_ipv4_ipv6_udp_rtp_video2_largecid.sh \
	test_ipv4_ipv6_udp_largecid.sh \
	test_ipv4_udplite_largecid.sh \
	test_ipv4_udp_rtp_h323_largecid.sh \
	test_ipv4_udp_rtp_misc_largecid.sh \
	test_ipv4_udp_rtp_mp3_largecid.sh \
	test_ipv4_udp_rtp_rtp+rtp+icmp_largecid.sh \
	test_ipv4_udp_rtp_video2_largecid.sh \
	test_ipv4_udp_rtp_video3_largecid.sh \
	test_ipv4_udp_rtp_video1_largecid.sh \
	test_ipv4_udp_rtp_voip_largecid.sh \
	test_ipv4_udp_rtp_voip+video_largecid.sh \
	test_ipv4_udp_largecid.sh \
	test_ipv6ext_icmp_largecid.sh \
	test_ipv6ext_icmp-large-ipv6-ext_largecid.sh \
	test_ipv6ext_ipv6ext_icmp_largecid.sh \
	test_ipv6ext_udp_rtp_audio-vlc_largecid.sh \
	test_ipv6ext_udp_largecid.sh \
	test_ipv6_icmp_largecid.sh \
	test_ipv6_ipv6_icmp_largecid.sh \
	test_ipv6_ipv6_udplite_largecid.sh \
	test_ipv6_ipv6_udp_largecid.sh \
	test_ipv6_udplite_largecid.sh \
	test_ipv6_udp_rtp_audio-vlc_largecid.sh \
	test_ipv6_udp_rtp_video2_largecid.sh \
	test_ipv6_udp_rtp_video1_largecid.sh \
	test_ipv6_udp_largecid.sh

TESTS = \
	$(TESTS_SMALLCID) \
	$(TESTS_LARGECID)


check_PROGRAMS = \
	test


INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp \
	-I$(top_srcdir)/src/decomp

AM_CFLAGS = -g -Wall -Wstrict-prototypes

AM_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs \
	-L$(top_builddir)/src/decomp/.libs


test_SOURCES = test.c
test_LDADD = \
	-lpcap \
	-lrohc_common \
	-lrohc_comp \
	-lrohc_decomp \
	-lm

EXTRA_DIST = \
	test.h \
	test.sh \
	$(TESTS_SMALLCID) \
	$(TESTS_LARGECID) \
	report/report.sh \
	report/report.conf \
	report/logs_cmp_ip.xsl \
	report/logs_cmp_rohc.xsl \
	report/logs_comp.xsl \
	report/logs_decomp.xsl \
	report/logs_startup.xsl \
	report/samples

