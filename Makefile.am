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
	README.md \
	INSTALL \
	INSTALL.md \
	COPYING \
	AUTHORS \
	AUTHORS.md \
	ChangeLog

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = rohc.pc

# directory for dist and distcheck
distdir = $(PACKAGE)-$(VERSION)$(PACKAGE_REVNO)

# configure options for distcheck
DISTCHECK_CONFIGURE_FLAGS = \
	--enable-fail-on-warning \
	--enable-fortify-sources \
	--enable-app-sniffer \
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
	     $(distdir)/test/non_regression/rfc5225/inputs \
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
		-not -name rohcv2_maxcontexts0_wlsb4_smallcid.pcap -and \
		-not -name rohcv2_maxcontexts0_wlsb4_largecid.pcap -and \
		-not -name rohcv2_maxcontexts0_wlsb64_smallcid.pcap -and \
		-not -name rohcv2_maxcontexts0_wlsb64_largecid.pcap -and \
		-not -name rohcv2_maxcontexts1_wlsb4_smallcid.pcap -and \
		-not -name rohcv2_maxcontexts1_wlsb4_largecid.pcap -and \
		-not -name rohcv2_maxcontexts1_wlsb64_smallcid.pcap -and \
		-not -name rohcv2_maxcontexts1_wlsb64_largecid.pcap -and \
		-not -name description -and \
		-not -name rohc_maxcontexts0_wlsb4_smallcid.sizes -and \
		-not -name rohc_maxcontexts0_wlsb4_largecid.sizes -and \
		-not -name rohc_maxcontexts0_wlsb64_smallcid.sizes -and \
		-not -name rohc_maxcontexts0_wlsb64_largecid.sizes -and \
		-not -name rohc_maxcontexts1_wlsb4_smallcid.sizes -and \
		-not -name rohc_maxcontexts1_wlsb4_largecid.sizes -and \
		-not -name rohc_maxcontexts1_wlsb64_smallcid.sizes -and \
		-not -name rohc_maxcontexts1_wlsb64_largecid.sizes -and \
		-not -name rohcv2_maxcontexts0_wlsb4_smallcid.sizes -and \
		-not -name rohcv2_maxcontexts0_wlsb4_largecid.sizes -and \
		-not -name rohcv2_maxcontexts0_wlsb64_smallcid.sizes -and \
		-not -name rohcv2_maxcontexts0_wlsb64_largecid.sizes -and \
		-not -name rohcv2_maxcontexts1_wlsb4_smallcid.sizes -and \
		-not -name rohcv2_maxcontexts1_wlsb4_largecid.sizes -and \
		-not -name rohcv2_maxcontexts1_wlsb64_smallcid.sizes -and \
		-not -name rohcv2_maxcontexts1_wlsb64_largecid.sizes -and \
		-not -name no_loss_robustness_rfc6846_keep_1_on_4 -and \
		-not -name no_loss_robustness_rfc6846_keep_2_on_4 -and \
		-not -name no_loss_robustness_rfc6846_keep_3_on_4 -and \
		-not -name no_loss_robustness_rfc6846_keep_4_on_4 -and \
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
		 --quiet \
		 --enable=warning,performance,portability,information,unusedFunction,missingInclude \
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
		 -DHAVE_PCAP_PCAP_H \
		 -DPY_VERSION_HEX=0x02000001 \
		 -D_ENDIAN_H \
		 -DHAVE_CMOCKA_RUN_GROUP_TESTS=1 \
		 --suppress=*:contrib/python/rohc_wrap.c \
		 --suppress=unusedStructMember:src/comp/c_tcp.c:184 \
		 --suppress=unusedStructMember:src/comp/c_tcp.c:206 \
		 --suppress=unusedStructMember:src/comp/c_tcp.c:241 \
		 --suppress=unusedStructMember:src/comp/c_tcp_opts_list.c:46 \
		 --suppress=unusedStructMember:src/comp/c_tcp_opts_list.c:47 \
		 --suppress=unusedStructMember:src/comp/c_tcp_opts_list.c:48 \
		 --suppress=useClosedFile:test/non_regression/test_non_regression_kernel.c:589 \
		 --suppress=useClosedFile:test/non_regression/test_non_regression_kernel.c:590 \
		 --suppress=useClosedFile:test/non_regression/test_non_regression_kernel.c:591 \
		 --suppress=useClosedFile:test/non_regression/test_non_regression_kernel.c:592 \
		 --suppress=unusedFunction:src/decomp/schemes/test/test_wlsb.c:40 \
		 .

# run GNU complexity on all sources and apps, but not tests
complexity:
	$(AM_V_GEN)complexity --threshold=20 --horrid-threshold=36 \
		`find src/ app/ -name \*.c -or -name \*.h`

# run Linux checkpatch.pl script on kernel modules, but ignore warnings about
# EXPORT_SYMBOL(foo) not following the function declaration because I don't
# want to duplicate function declarations in lib and kmod.
checkpatch:
	$(AM_V_GEN)/usr/src/linux/scripts/checkpatch.pl \
		--ignore EXPORT_SYMBOL \
		--file `find linux/ -name \*.h -or -name \*.c`

# check spelling mistakes with codespell in source files, but also in Markdown
# files and man pages
# https://github.com/lucasdemarchi/codespell
codespell:
	$(AM_V_GEN)codespell \
		--ignore-words-list=uint,fo \
		`find . -name \*.md -or -name \*.7.in -or -name ChangeLog -or -name README` \
		`find . -name configure.ac -or -name Makefile.am` \
		`find . -name \*.c -and -not -name rohc_wrap.c` \
		`find . -name \*.h`

# run all Q&A tests
qa: cppcheck complexity checkpatch codespell

