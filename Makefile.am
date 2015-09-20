################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the ROHC libraries and the test application
################################################################################

if ROHC_TESTS
TESTS_DIR = test
else
TESTS_DIR = 
endif

if ROHC_LINUX_MODULE
LINUX_MODULE_DIR = linux
else
LINUX_MODULE_DIR =
endif

if BUILD_DOC
DOC_DIR = doc
else
DOC_DIR =
endif

if BUILD_EXAMPLES
EXAMPLES_DIR = examples
else
EXAMPLES_DIR =
endif

SUBDIRS = \
	src \
	$(TESTS_DIR) \
	$(LINUX_MODULE_DIR) \
	app \
	$(DOC_DIR) \
	$(EXAMPLES_DIR) \
	contrib

dist_doc_DATA = \
	README \
	INSTALL \
	COPYING \
	AUTHORS \
	ChangeLog

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = rohc.pc

# directory for dist and distcheck
distdir = $(PACKAGE)-$(VERSION)$(PACKAGE_REVNO)

# configure options for distcheck
DISTCHECK_CONFIGURE_FLAGS = \
	--enable-fail-on-warning \
	--enable-fortify-sources \
	--enable-app-performance \
	--enable-app-sniffer \
	--enable-app-tunnel \
	--enable-rohc-tests \
	--disable-doc \
	--disable-examples

# extra files for releases
EXTRA_DIST = \
	autogen.sh \
	git_ref \
	test/report_code_coverage.sh

# other extra files for releases
dist-hook:
	find $(distdir)/test/non_regression/rfc3095/inputs \
	     $(distdir)/test/non_regression/rfc6846/inputs \
		-type f -and \
		-not -name source.pcap -and \
		-not -name rohc_maxcontexts0_wlsb4_smallcid.pcap -and \
		-not -name rohc_maxcontexts0_wlsb4_largecid.pcap -and \
		-not -name rohc_maxcontexts0_wlsb64_smallcid.pcap -and \
		-not -name rohc_maxcontexts0_wlsb64_largecid.pcap -and \
		-not -name rohc_maxcontexts1_wlsb4_smallcid.pcap -and \
		-not -name rohc_maxcontexts1_wlsb4_largecid.pcap -and \
		-not -name rohc_maxcontexts1_wlsb64_smallcid.pcap -and \
		-not -name rohc_maxcontexts1_wlsb64_largecid.pcap -and \
		-not -name description -and \
		-not -name rohc_maxcontexts0_wlsb4_smallcid.sizes -and \
		-not -name rohc_maxcontexts0_wlsb4_largecid.sizes -and \
		-not -name rohc_maxcontexts0_wlsb64_smallcid.sizes -and \
		-not -name rohc_maxcontexts0_wlsb64_largecid.sizes -and \
		-not -name rohc_maxcontexts1_wlsb4_smallcid.sizes -and \
		-not -name rohc_maxcontexts1_wlsb4_largecid.sizes -and \
		-not -name rohc_maxcontexts1_wlsb64_smallcid.sizes -and \
		-not -name rohc_maxcontexts1_wlsb64_largecid.sizes -and \
		-not -name README \
		-exec $(RM) \{\} \;


if CODE_COVERAGE
TESTS_CODE_COVERAGE = test/report_code_coverage.sh
endif
TESTS = $(TESTS_CODE_COVERAGE)

distclean-local:
	$(RM) output.zcov
	$(RM) -r coverage-report/

# run cppcheck on all sources, apps and tests
cppcheck:
	 $(AM_V_GEN)cppcheck \
		 --quiet --enable=all \
		 --error-exitcode=2 \
		 --std=c89 --std=c99 --std=c11 \
		 -I src/common/protocols/ -I src/common/ \
		 -I src/comp/schemes/ -I src/comp/ \
		 -I src/decomp/schemes/ -I src/decomp/ \
		 -I src/ \
		 -I test/ \
		 -I /usr/include/ \
		 -i linux/ \
		 -D__clang_analyzer__ \
		 --suppress=unusedStructMember:src/comp/c_tcp.c:185 \
		 --suppress=unusedStructMember:src/comp/c_tcp.c:207 \
		 --suppress=unusedStructMember:src/comp/c_tcp.c:242 \
		 --suppress=unusedStructMember:src/comp/c_tcp_opts_list.c:46 \
		 --suppress=unusedStructMember:src/comp/c_tcp_opts_list.c:47 \
		 --suppress=unusedStructMember:src/comp/c_tcp_opts_list.c:48 \
		 --suppress=useClosedFile:test/non_regression/test_non_regression_kernel.c:589 \
		 --suppress=useClosedFile:test/non_regression/test_non_regression_kernel.c:590 \
		 --suppress=useClosedFile:test/non_regression/test_non_regression_kernel.c:591 \
		 --suppress=unusedFunction:src/decomp/schemes/test/test_wlsb.c:40 \
		 .

# run GNU complexity on all sources and apps, but not tests
complexity:
	$(AM_V_GEN)complexity --threshold=20 --horrid-threshold=35 \
		`find src/ app/ -name \*.c -or -name \*.h`

# run all Q&A tests
qa: cppcheck complexity

