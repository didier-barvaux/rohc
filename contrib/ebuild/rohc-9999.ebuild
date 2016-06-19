# Copyright 2016 Didier Barvaux
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=5

inherit autotools

if [[ ${PV} == 9999 ]]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/didier-barvaux/rohc.git"
	EGIT_BRANCH="master"
else
	SRC_URI="https://rohc-lib.org/download/${PN}-${PV%[^.]}x/${PV}/${P}.tar.xz"
	KEYWORDS="~x86 ~arm ~amd64 ~ppc"
fi

DESCRIPTION="A free and efficient library for ROHC compression"
HOMEPAGE="https://rohc-lib.org/"

LICENSE="LGPL-2"
SLOT="0"
IUSE="app-perf app-sniffer app-stats debug +doc +examples linux-kernel-mod test test-valgrind"

# running tests within Valgrind requires to first build the tests
REQUIRED_USE="test-valgrind? ( test )"

DEPEND="app-perf? ( net-libs/libpcap )
        app-sniffer? ( net-libs/libpcap )
        app-stats? ( net-libs/libpcap
                     sci-visualization/gnuplot
                     sys-apps/grep )
        doc? ( app-doc/doxygen[dot] )
        test? ( net-libs/libpcap
                dev-util/cmocka
                virtual/awk
                sys-apps/sed )
        test-valgrind? ( dev-util/valgrind
                         dev-libs/libxslt
                         sys-apps/grep )"

src_prepare() {
	if [[ ${PV} == 9999 ]]; then
		eautoreconf
	else
		default
	fi
}

src_configure() {

	local myconf

	myconf="$(use_enable app-perf app-performance)
	        $(use_enable app-sniffer)
	        $(use_enable app-stats)
	        $(use_enable debug rohc-debug)
	        $(use_enable doc)
	        $(use_enable doc doc-man)
	        $(use_enable examples)
	        $(use_enable linux-kernel-mod linux-kernel-module)
	        $(use_enable test rohc-tests)
	        $(use_enable test-valgrind rohc-tests-valgrind)"

	# configure the library
	econf ${myconf} || die "failed to configure library"
}

src_install() {
	default

	# remove useless *.la files
	rm -f ${D}/usr/lib/librohc.la
}

