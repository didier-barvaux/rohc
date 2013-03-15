################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the test tools that check behaviour of the comp library
################################################################################


TESTS = \
	test_rfc4996_encoding.sh


check_PROGRAMS = \
	test_rfc4996_encoding


test_rfc4996_encoding_SOURCES = test_rfc4996_encoding.c
test_rfc4996_encoding_LDADD = \
	-lrohc_comp
test_rfc4996_encoding_LDFLAGS = \
	-L$(top_builddir)/src/comp/.libs
test_rfc4996_encoding_CFLAGS = \
	$(configure_cflags)
test_rfc4996_encoding_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/comp


EXTRA_DIST = \
	test_rfc4996_encoding.sh

