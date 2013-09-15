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

if BUILD_DOC_MAN
man_MANS = \
	rohc.7 \
	rohc_protocol.7 \
	rohc_library.7 \
	man/man3/rohc.h.3 \
	man/man3/rohc_version.3 \
	man/man3/rohc_get_mode_descr.3 \
	man/man3/rohc_get_packet_descr.3 \
	man/man3/rohc_get_ext_descr.3 \
	man/man3/rohc_comp.h.3 \
	man/man3/rohc_comp_new.3 \
	man/man3/rohc_comp_free.3 \
	man/man3/rohc_compress3.3 \
	man/man3/rohc_comp_get_segment.3 \
	man/man3/rohc_comp_enable_profile.3 \
	man/man3/rohc_comp_enable_profiles.3 \
	man/man3/rohc_comp_disable_profile.3 \
	man/man3/rohc_comp_disable_profiles.3 \
	man/man3/rohc_comp_set_random_cb.3 \
	man/man3/rohc_comp_set_traces_cb.3 \
	man/man3/rohc_comp_set_rtp_detection_cb.3 \
	man/man3/rohc_comp_add_rtp_port.3 \
	man/man3/rohc_comp_remove_rtp_port.3 \
	man/man3/rohc_comp_reset_rtp_ports.3 \
	man/man3/rohc_comp_force_contexts_reinit.3 \
	man/man3/rohc_comp_get_cid_type.3 \
	man/man3/rohc_comp_get_max_cid.3 \
	man/man3/rohc_comp_set_periodic_refreshes.3 \
	man/man3/rohc_comp_set_wlsb_window_width.3 \
	man/man3/rohc_comp_get_mrru.3 \
	man/man3/rohc_comp_set_mrru.3 \
	man/man3/rohc_comp_get_state_descr.3 \
	man/man3/rohc_comp_get_general_info.3 \
	man/man3/rohc_comp_get_last_packet_info2.3 \
	man/man3/rohc_feedback_avail_bytes.3 \
	man/man3/rohc_feedback_flush.3 \
	man/man3/rohc_feedback_remove_locked.3 \
	man/man3/rohc_feedback_unlock.3 \
	man/man3/rohc_decomp.h.3 \
	man/man3/rohc_decomp_new.3 \
	man/man3/rohc_decomp_free.3 \
	man/man3/rohc_decompress2.3 \
	man/man3/rohc_decomp_enable_profile.3 \
	man/man3/rohc_decomp_enable_profiles.3 \
	man/man3/rohc_decomp_disable_profile.3 \
	man/man3/rohc_decomp_disable_profiles.3 \
	man/man3/rohc_decomp_set_features.3 \
	man/man3/rohc_decomp_set_traces_cb.3 \
	man/man3/rohc_decomp_get_cid_type.3 \
	man/man3/rohc_decomp_get_max_cid.3 \
	man/man3/rohc_decomp_set_mrru.3 \
	man/man3/rohc_decomp_get_mrru.3 \
	man/man3/rohc_decomp_get_state_descr.3 \
	man/man3/rohc_decomp_get_last_packet_info.3 \
	man/man3/rohc_d_statistics.3
else
man_MANS =
endif

html/*.html: html-am
html/*.map: html-am
html/*.css: html-am
html/*.png: html-am

html-am: htmldoc

htmldoc:
	$(AM_V_GEN)doxygen doxygen.conf


man/man3/rohc.h.3: mandoc
man/man3/rohc_version.3: mandoc
man/man3/rohc_get_mode_descr.3: mandoc
man/man3/rohc_get_packet_descr.3: mandoc
man/man3/rohc_get_ext_descr.3: mandoc

man/man3/rohc_comp.h.3: mandoc
man/man3/rohc_comp_new.3: mandoc
man/man3/rohc_comp_free.3: mandoc
man/man3/rohc_compress3.3: mandoc
man/man3/rohc_comp_get_segment.3: mandoc
man/man3/rohc_comp_enable_profile.3: mandoc
man/man3/rohc_comp_enable_profiles.3: mandoc
man/man3/rohc_comp_disable_profile.3: mandoc
man/man3/rohc_comp_disable_profiles.3: mandoc
man/man3/rohc_comp_set_random_cb.3: mandoc
man/man3/rohc_comp_set_traces_cb.3: mandoc
man/man3/rohc_comp_set_rtp_detection_cb.3: mandoc
man/man3/rohc_comp_add_rtp_port.3: mandoc
man/man3/rohc_comp_remove_rtp_port.3: mandoc
man/man3/rohc_comp_reset_rtp_ports.3: mandoc
man/man3/rohc_comp_force_contexts_reinit.3: mandoc
man/man3/rohc_comp_get_cid_type.3: mandoc
man/man3/rohc_comp_get_max_cid.3: mandoc
man/man3/rohc_comp_set_periodic_refreshes.3: mandoc
man/man3/rohc_comp_set_wlsb_window_width.3: mandoc
man/man3/rohc_comp_get_mrru.3: mandoc
man/man3/rohc_comp_set_mrru.3: mandoc
man/man3/rohc_comp_get_state_descr.3: mandoc
man/man3/rohc_comp_get_general_info.3: mandoc
man/man3/rohc_comp_get_last_packet_info2.3: mandoc

man/man3/rohc_feedback_avail_bytes.3: mandoc
man/man3/rohc_feedback_flush.3: mandoc
man/man3/rohc_feedback_remove_locked.3: mandoc
man/man3/rohc_feedback_unlock.3: mandoc

man/man3/rohc_decomp.h.3: mandoc
man/man3/rohc_decomp_new.3: mandoc
man/man3/rohc_decomp_free.3: mandoc
man/man3/rohc_decompress2.3: mandoc
man/man3/rohc_decomp_enable_profile.3: mandoc
man/man3/rohc_decomp_enable_profiles.3: mandoc
man/man3/rohc_decomp_disable_profile.3: mandoc
man/man3/rohc_decomp_disable_profiles.3: mandoc
man/man3/rohc_decomp_set_features.3: mandoc
man/man3/rohc_decomp_set_traces_cb.3: mandoc
man/man3/rohc_decomp_get_cid_type.3: mandoc
man/man3/rohc_decomp_get_max_cid.3: mandoc
man/man3/rohc_decomp_set_mrru.3: mandoc
man/man3/rohc_decomp_get_mrru.3: mandoc
man/man3/rohc_decomp_get_state_descr.3: mandoc
man/man3/rohc_decomp_get_last_packet_info.3: mandoc
man/man3/rohc_d_statistics.3: mandoc

mandoc: htmldoc man-rohc man-rohc-comp man-rohc-decomp

man-rohc:
	$(AM_V_GEN)doxy2man --out man/man3/ --noseealsoall --nosort \
		--short-pkg "ROHC" --pkg "ROHC library Programmer's Manual" \
		xml/group__rohc.xml

man-rohc-comp:
	$(AM_V_GEN)doxy2man --out man/man3/ --noseealsoall --nosort \
		--short-pkg "ROHC" --pkg "ROHC library Programmer's Manual" \
		xml/group__rohc__comp.xml

man-rohc-decomp:
	$(AM_V_GEN)doxy2man --out man/man3/ --noseealsoall --nosort \
		--short-pkg "ROHC" --pkg "ROHC library Programmer's Manual" \
		xml/group__rohc__decomp.xml


clean-local:
	-$(RM) -rf html/
	-$(RM) -rf man/


# extra files for releases
EXTRA_DIST = \
	doxygen.conf


