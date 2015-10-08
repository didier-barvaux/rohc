################################################################################
#	Name       : Makefile
#	Authors    : Mikhail Gruzdev <michail.gruzdev@gmail.com>
#	             Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	             Thales Communications
#	Description: Build a test module for Linux kernel
#	             (for the Linux kernel build system)
################################################################################

rohc_modname = rohc
rohc_test_modname = rohc_test


rohc_common_sources = \
	../../src/common/protocols/ip_numbers.c \
	../../src/common/rohc_common.c \
	../../src/common/rohc_packets.c \
	../../src/common/rohc_traces_internal.c \
	../../src/common/rohc_utils.c \
	../../src/common/crc.c \
	../../src/common/rohc_add_cid.c \
	../../src/common/interval.c \
	../../src/common/sdvl.c \
	../../src/common/ip.c \
	../../src/common/net_pkt.c \
	../../src/common/rohc_list.c \
	../../src/common/feedback_parse.c

rohc_comp_sources = \
	../../src/comp/schemes/cid.c \
	../../src/comp/schemes/ip_id_offset.c \
	../../src/comp/schemes/comp_wlsb.c \
	../../src/comp/schemes/comp_scaled_rtp_ts.c \
	../../src/comp/schemes/comp_list.c \
	../../src/comp/schemes/comp_list_ipv6.c \
	../../src/comp/schemes/rfc4996.c \
	../../src/comp/schemes/tcp_sack.c \
	../../src/comp/schemes/tcp_ts.c \
	../../src/comp/rohc_comp.c \
	../../src/comp/c_uncompressed.c \
	../../src/comp/rohc_comp_rfc3095.c \
	../../src/comp/c_ip.c \
	../../src/comp/c_udp.c \
	../../src/comp/c_udp_lite.c \
	../../src/comp/c_rtp.c \
	../../src/comp/c_esp.c \
	../../src/comp/c_tcp_opts_list.c \
	../../src/comp/c_tcp.c

rohc_decomp_sources = \
	../../src/decomp/schemes/decomp_wlsb.c \
	../../src/decomp/schemes/ip_id_offset.c \
	../../src/decomp/schemes/decomp_scaled_rtp_ts.c \
	../../src/decomp/schemes/decomp_list.c \
	../../src/decomp/schemes/decomp_list_ipv6.c \
	../../src/decomp/schemes/rfc4996.c \
	../../src/decomp/schemes/tcp_ts.c \
	../../src/decomp/schemes/tcp_sack.c \
	../../src/decomp/rohc_decomp_detect_packet.c \
	../../src/decomp/rohc_decomp.c \
	../../src/decomp/feedback_create.c \
	../../src/decomp/d_uncompressed.c \
	../../src/decomp/rohc_decomp_rfc3095.c \
	../../src/decomp/d_ip.c \
	../../src/decomp/d_udp.c \
	../../src/decomp/d_udp_lite.c \
	../../src/decomp/d_rtp.c \
	../../src/decomp/d_esp.c \
	../../src/decomp/d_tcp_static.c \
	../../src/decomp/d_tcp_dynamic.c \
	../../src/decomp/d_tcp_irregular.c \
	../../src/decomp/d_tcp_opts_list.c \
	../../src/decomp/d_tcp.c

rohc_sources = \
	../kmod.c \
	$(rohc_common_sources) \
	$(rohc_comp_sources) \
	$(rohc_decomp_sources)

rohc_objs = $(patsubst %.c,%.o,$(rohc_sources))


EXTRA_CFLAGS += \
	-Wall \
	-I$(M)/../include \
	-I$(M)/../.. \
	-I$(M)/../../src \
	-I$(M)/../../src/common \
	-I$(M)/../../src/comp \
	-I$(M)/../../src/decomp

# Module that exports the ROHC library in kernel land
obj-m += $(rohc_modname).o
$(rohc_modname)-objs = \
	$(rohc_objs)

# Mobule that tests the ROHC library in kernel land
obj-m += $(rohc_test_modname).o
$(rohc_test_modname)-objs = \
	../kmod_test.o

