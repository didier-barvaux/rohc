################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the API documentation in HTML for the ROHC library
################################################################################

htmldir = $(docdir)/html


html_DATA = \
	html/*.html \
	html/*.map \
	html/*.css \
	html/*.png


rohc_common_man = \
	man/man3/rohc.h.3
rohc_common_mans = \
	man/man3/rohc_version.3 \
	man/man3/rohc_strerror.3 \
	man/man3/rohc_get_mode_descr.3 \
	man/man3/rohc_get_profile_descr.3 \
	man/man3/rohc_get_packet_descr.3 \
	man/man3/rohc_get_ext_descr.3 \
	man/man3/rohc_buf_append.3 \
	man/man3/rohc_buf_append_buf.3 \
	man/man3/rohc_buf_avail_len.3 \
	man/man3/rohc_buf_data.3 \
	man/man3/rohc_buf_data_at.3 \
	man/man3/rohc_buf_is_empty.3 \
	man/man3/rohc_buf_is_malformed.3 \
	man/man3/rohc_buf_prepend.3 \
	man/man3/rohc_buf_pull.3 \
	man/man3/rohc_buf_push.3 \
	man/man3/rohc_buf_reset.3

rohc_comp_man = \
	man/man3/rohc_comp.h.3
rohc_comp_mans = \
	man/man3/rohc_comp_new2.3 \
	man/man3/rohc_comp_free.3 \
	man/man3/rohc_compress4.3 \
	man/man3/rohc_comp_get_segment2.3 \
	man/man3/rohc_comp_deliver_feedback2.3 \
	man/man3/rohc_comp_profile_enabled.3 \
	man/man3/rohc_comp_enable_profile.3 \
	man/man3/rohc_comp_enable_profiles.3 \
	man/man3/rohc_comp_disable_profile.3 \
	man/man3/rohc_comp_disable_profiles.3 \
	man/man3/rohc_comp_set_features.3 \
	man/man3/rohc_comp_set_traces_cb2.3 \
	man/man3/rohc_comp_set_rtp_detection_cb.3 \
	man/man3/rohc_comp_force_contexts_reinit.3 \
	man/man3/rohc_comp_get_cid_type.3 \
	man/man3/rohc_comp_get_max_cid.3 \
	man/man3/rohc_comp_set_periodic_refreshes.3 \
	man/man3/rohc_comp_set_periodic_refreshes_time.3 \
	man/man3/rohc_comp_set_wlsb_window_width.3 \
	man/man3/rohc_comp_set_list_trans_nr.3 \
	man/man3/rohc_comp_get_mrru.3 \
	man/man3/rohc_comp_set_mrru.3 \
	man/man3/rohc_comp_get_state_descr.3 \
	man/man3/rohc_comp_get_general_info.3 \
	man/man3/rohc_comp_get_last_packet_info2.3

rohc_decomp_man = \
	man/man3/rohc_decomp.h.3
rohc_decomp_mans = \
	man/man3/rohc_decomp_new2.3 \
	man/man3/rohc_decomp_free.3 \
	man/man3/rohc_decompress3.3 \
	man/man3/rohc_decomp_profile_enabled.3 \
	man/man3/rohc_decomp_enable_profile.3 \
	man/man3/rohc_decomp_enable_profiles.3 \
	man/man3/rohc_decomp_disable_profile.3 \
	man/man3/rohc_decomp_disable_profiles.3 \
	man/man3/rohc_decomp_set_features.3 \
	man/man3/rohc_decomp_set_traces_cb2.3 \
	man/man3/rohc_decomp_get_cid_type.3 \
	man/man3/rohc_decomp_get_max_cid.3 \
	man/man3/rohc_decomp_set_mrru.3 \
	man/man3/rohc_decomp_get_mrru.3 \
	man/man3/rohc_decomp_get_state_descr.3 \
	man/man3/rohc_decomp_get_general_info.3 \
	man/man3/rohc_decomp_get_last_packet_info.3

static_man_pages = \
	rohc.7 \
	rohc_protocol.7 \
	rohc_library.7

dynamic_man_pages = \
	$(rohc_common_man) \
	$(rohc_common_mans) \
	$(rohc_comp_man) \
	$(rohc_comp_mans) \
	$(rohc_decomp_man) \
	$(rohc_decomp_mans)

man_MANS = \
	$(static_man_pages) \
	$(dynamic_man_pages)


rohc_all_sources = \
	$(top_srcdir)/src/test/*.c \
	$(top_srcdir)/src/common/*.c \
	$(top_srcdir)/src/common/*.h \
	$(top_srcdir)/src/common/protocols/*.c \
	$(top_srcdir)/src/common/protocols/*.h \
	$(top_srcdir)/src/comp/*.c \
	$(top_srcdir)/src/comp/*.h \
	$(top_srcdir)/src/comp/test/*.c \
	$(top_srcdir)/src/comp/schemes/*.c \
	$(top_srcdir)/src/comp/schemes/*.h \
	$(top_srcdir)/src/comp/schemes/test/*.c \
	$(top_srcdir)/src/decomp/*.c \
	$(top_srcdir)/src/decomp/*.h \
	$(top_srcdir)/src/decomp/test/*.c \
	$(top_srcdir)/src/decomp/schemes/*.c \
	$(top_srcdir)/src/decomp/schemes/*.h \
	$(top_srcdir)/src/decomp/schemes/test/*.c \
	$(top_srcdir)/examples/*.c \
	$(top_srcdir)/app/performance/*.c \
	$(top_srcdir)/app/sniffer/*.c \
	$(top_srcdir)/app/stats/*.c \
	$(top_srcdir)/linux/include/*.h \
	$(top_srcdir)/linux/*.c \
	$(top_srcdir)/test/*.h \
	$(top_srcdir)/test/functional/context_reuse/*.c \
	$(top_srcdir)/test/functional/decompress_feedback_only/*.c \
	$(top_srcdir)/test/functional/feedback2/*.c \
	$(top_srcdir)/test/functional/rtp_detection/*.c \
	$(top_srcdir)/test/functional/packet_types/*.c \
	$(top_srcdir)/test/functional/segment/*.c \
	$(top_srcdir)/test/robustness/damaged_packet/*.c \
	$(top_srcdir)/test/robustness/empty_payload/*.c \
	$(top_srcdir)/test/robustness/lost_packet/*.c \
	$(top_srcdir)/test/robustness/malformed_rohc_packets/*.c \
	$(top_srcdir)/test/robustness/piggybacking_feedback/*.c \
	$(top_srcdir)/test/non_regression/*.c

doxygen: $(rohc_all_sources)
	$(AM_V_GEN)doxygen doxygen.conf
	@touch doxygen


html/*.html: $(rohc_all_sources) | doxygen
html/*.map: $(rohc_all_sources) | doxygen
html/*.css: $(rohc_all_sources) | doxygen
html/*.png: $(rohc_all_sources) | doxygen


rohc_examples_sources = \
	$(top_srcdir)/examples/*.c

doxy2man_options = \
	--out man/man3/ --noseealsoall --nosort --include-prefix "rohc/" \
	--short-pkg "ROHC" --pkg "ROHC library Programmer's Manual"


rohc_common_sources = \
	$(top_srcdir)/src/common/rohc_common.c \
	$(top_srcdir)/src/common/rohc.h \
	$(top_srcdir)/src/common/rohc_packets.c \
	$(top_srcdir)/src/common/rohc_packets.h \
	$(top_srcdir)/src/common/rohc_traces.h \
	$(top_srcdir)/src/common/rohc_time.h \
	$(top_srcdir)/src/common/rohc_buf.h

if BUILD_DOC_MAN
$(rohc_common_man): $(rohc_common_sources) $(rohc_examples_sources) | doxygen
	$(AM_V_GEN)doxy2man $(doxy2man_options) xml/group__rohc.xml
else
$(rohc_common_man):
endif
$(rohc_common_mans):


rohc_comp_sources = \
	$(top_srcdir)/src/comp/rohc_comp.c \
	$(top_srcdir)/src/comp/rohc_comp.h

if BUILD_DOC_MAN
$(rohc_comp_man): $(rohc_comp_sources) $(rohc_examples_sources) | doxygen
	$(AM_V_GEN)doxy2man $(doxy2man_options) xml/group__rohc__comp.xml
else
$(rohc_comp_man):
endif
$(rohc_comp_mans):


rohc_decomp_sources = \
	$(top_srcdir)/src/decomp/rohc_decomp.c \
	$(top_srcdir)/src/decomp/rohc_decomp.h

if BUILD_DOC_MAN
$(rohc_decomp_man): $(rohc_decomp_sources) $(rohc_examples_sources) | doxygen
	$(AM_V_GEN)doxy2man $(doxy2man_options) xml/group__rohc__decomp.xml
else
$(rohc_decomp_man):
endif
$(rohc_decomp_mans):


clean-local:
	-$(RM) doxygen
	-$(RM) -r html/
	-$(RM) -r xml/


# extra files for releases
EXTRA_DIST = \
	doxygen.conf \
	$(dynamic_man_pages)

