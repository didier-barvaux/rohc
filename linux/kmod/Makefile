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
	../../src/common/rohc_common.c \
	../../src/common/rohc_packets.c \
	../../src/common/rohc_traces_internal.c \
	../../src/common/crc.c \
	../../src/common/decode.c \
	../../src/common/ip_id_offset_decode.c \
	../../src/common/interval.c \
	../../src/common/lsb_decode.c \
	../../src/common/sdvl.c \
	../../src/common/wlsb.c \
	../../src/common/ip.c \
	../../src/common/ts_sc_comp.c \
	../../src/common/ts_sc_decomp.c \
	../../src/common/comp_list.c \
	../../src/common/cid.c

rohc_comp_sources = \
	../../src/comp/rohc_comp.c \
	../../src/comp/c_uncompressed.c \
	../../src/comp/c_generic.c \
	../../src/comp/c_ip.c \
	../../src/comp/c_udp.c \
	../../src/comp/c_udp_lite.c \
	../../src/comp/c_rtp.c \
	../../src/comp/c_esp.c \
	../../src/comp/rfc4996_encoding.c \
	../../src/comp/c_tcp.c

rohc_decomp_sources = \
	../../src/decomp/rohc_decomp.c \
	../../src/decomp/feedback.c \
	../../src/decomp/d_uncompressed.c \
	../../src/decomp/d_generic.c \
	../../src/decomp/d_ip.c \
	../../src/decomp/d_udp.c \
	../../src/decomp/d_udp_lite.c \
	../../src/decomp/d_rtp.c \
	../../src/decomp/d_esp.c \
	../../src/decomp/rfc4996_decoding.c \
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

