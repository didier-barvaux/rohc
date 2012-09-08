################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#              Didier Barvaux <didier@barvaux.org>
# Description: create the ROHC performance application
################################################################################

sbin_PROGRAMS = \
	rohc_test_performance


rohc_test_performance_CFLAGS = \
	-g -Wall -Wstrict-prototypes \
	-I$(top_srcdir)/src/compat \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/comp

rohc_test_performance_LDFLAGS = \
	-L$(top_builddir)/src/common/.libs \
	-L$(top_builddir)/src/comp/.libs

rohc_test_performance_SOURCES = test_performance.c
rohc_test_performance_LDADD = \
	-l$(pcap_lib_name) \
	-lrohc_comp \
	-lrohc_common \
	$(sched_lib) \
	$(additional_platform_libs)

