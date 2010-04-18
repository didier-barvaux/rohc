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
	html/*.png \
	html/*.gif

html/*.html: html-am
html/*.map: html-am
html/*.css: html-am
html/*.png: html-am
html/*.gif: html-am

html-am:
	doxygen doxygen.conf

clean-local:
	-$(RM) -rf html/

# extra files for releases
EXTRA_DIST = \
	doxygen.conf

