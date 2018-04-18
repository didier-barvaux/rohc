################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier@barvaux.org>
# Description: build figures for the rohc-lib.org website
################################################################################

ditaa=ditaa --overwrite --transparent

rohc_figures_sources = \
	rohc_only_headers_are_compressed.txt \
	rohc_redundancy.txt \
	rohc_classification.txt \
	rohc_association.txt \
	rohc_umode.txt \
	rohc_omode.txt \
	rohc_rmode.txt \
	rohc_comp_states.txt \
	rohc_decomp_states.txt

rohc_figures = \
	rohc_only_headers_are_compressed.png \
	rohc_redundancy.png \
	rohc_classification.png \
	rohc_association.png \
	rohc_umode.png \
	rohc_omode.png \
	rohc_rmode.png \
	rohc_comp_states.png \
	rohc_decomp_states.png

doc_DATA = \
	$(rohc_figures)

rohc_only_headers_are_compressed.png: rohc_only_headers_are_compressed.txt
	$(AM_V_GEN)$(ditaa) $<

rohc_redundancy.png: rohc_redundancy.txt
	$(AM_V_GEN)$(ditaa) $<

rohc_classification.png: rohc_classification.txt
	$(AM_V_GEN)$(ditaa) $<

rohc_association.png: rohc_association.txt
	$(AM_V_GEN)$(ditaa) $<

rohc_umode.png: rohc_umode.txt
	$(AM_V_GEN)$(ditaa) $<

rohc_omode.png: rohc_omode.txt
	$(AM_V_GEN)$(ditaa) $<

rohc_rmode.png: rohc_rmode.txt
	$(AM_V_GEN)$(ditaa) $<

rohc_comp_states.png: rohc_comp_states.txt
	$(AM_V_GEN)$(ditaa) $<

rohc_decomp_states.png: rohc_decomp_states.txt
	$(AM_V_GEN)$(ditaa) $<

EXTRA_DIST = \
	$(rohc_figures_sources)


