#!/bin/sh
#
# Copyright 2016 Didier Barvaux
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

OUTPUT_DIR="doc/man/html/"

mkdir -p "${OUTPUT_DIR}"

for manpage_file in \
	doc/*.7 \
	doc/man/man*/* \
	app/*/*.1
do
	manpage="$( basename "${manpage_file}" )"
	manpage_name="$( echo "${manpage}" | gawk -F'.' '{ print $1 }' )"
	manpage_section="$( echo "${manpage}" | gawk -F'.' '{ print $2 }' )"
	mkdir -p "${OUTPUT_DIR}/man${manpage_section}"
	groff -mandoc -Thtml "${manpage_file}" \
		> "${OUTPUT_DIR}/man${manpage_section}/${manpage_name}.${manpage_section}.html"
done

