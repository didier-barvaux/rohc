#!/bin/sh
#
# Copyright 2019 Didier Barvaux
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

#
# Make a release tarball from a Git tag
#
# usage: ./contrib/make_release_tarball.sh <tag>
#

project_name="rohc"
project_version="$1"
project_release="${project_name}-${project_version}"
project_tarball="${project_release}.tar"

if [ -z "${project_version}" ] ; then
	echo "usage: $0 <version>" >&2
	exit 1
fi

echo "${project_version}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'
if [ $? -ne 0 ] ; then
	echo "usage: $0 <version>" >&2
	exit 1
fi



echo "Extract archive of release '${project_release}' from Git..."
git archive \
	--format=tar \
	--prefix="${project_release}/" \
	--output="./${project_tarball}" \
	-- \
	"${project_release}" \
	>/dev/null 2>&1
if [ $? -ne 0 ] ; then
	echo "failed to extract release '${project_release}' from Git" >&2
	rm -f -- "${project_tarball}"
	exit 1
fi

echo "Build dist tarball from Git archive..."
echo -e "\tExtract Git archive..."
tar -xf "${project_tarball}" && \
	rm -f -- "${project_tarball}" && \
	cd -- "${project_release}/"
if [ $? -ne 0 ] ; then
	echo "failed to extract Git archive" >&2
	rm -f -- "${project_tarball}"
	rm -rf -- "${project_release}" 2>/dev/null
	exit 1
fi
echo -e "\tRun autogen.sh..."
./autogen.sh >/dev/null 2>&1
if [ $? -ne 0 ] ; then
	echo "failed to run autogen.sh" >&2
	cd ..
	rm -rf -- "${project_release}" 2>/dev/null
	exit 1
fi
echo -e "\tRun make clean..."
make clean >/dev/null 2>&1
if [ $? -ne 0 ] ; then
	echo "failed to run make clean" >&2
	cd ..
	rm -rf -- "${project_release}" 2>/dev/null
	exit 1
fi
echo -e "\tRun make distcheck..."
make -j10 distcheck >/dev/null 2>&1
if [ $? -ne 0 ] ; then
	echo "failed to run make distcheck" >&2
	cd ..
	rm -rf -- "${project_release}" 2>/dev/null
	exit 1
fi
echo -e "\tSave generated tarball..."
mv -- "${project_tarball}.bz2" ..
if [ $? -ne 0 ] ; then
	echo "failed to run save generated tarball" >&2
	cd ..
	rm -rf -- "${project_release}" 2>/dev/null
	exit 1
fi
echo -e "\tRemove build directory..."
cd .. && \
	rm -rf -- "${project_release}" 2>/dev/null
if [ $? -ne 0 ] ; then
	echo "failed to run save generated tarball" >&2
	cd ..
	rm -f -- "${project_tarball}.bz2"
	rm -rf -- "${project_release}" 2>/dev/null
	exit 1
fi

echo "Convert tarball from bzip2 format to xz format..."
bunzip2 ${project_tarball}.bz2 && \
	xz -9 ${project_tarball}
if [ $? -ne 0 ] ; then
	echo "failed to convert tarball from bzip2 format to xz format" >&2
	rm -f -- "${project_tarball}.bz2"
	rm -f -- "${project_tarball}.xz"
	exit 1
fi

echo "Compute the SHA-256 checksum of the tarball..."
sha256sum -- "${project_tarball}.xz" > "${project_tarball}.xz.sha256" && \
	sha256sum -c -- "${project_tarball}.xz.sha256" >/dev/null 2>&1
if [ $? -ne 0 ] ; then
	echo "failed to compute the SHA-256 checksum of the tarball" >&2
	rm -f -- "${project_tarball}.xz"
	rm -f -- "${project_tarball}.xz.sha256"
	exit 1
fi

echo "Sign the tarball with GPG..."
gpg --armor --sign --detach-sig \
	-u 3B7029D19456ABFE48B6B803D71627AD1B2BB9C1 \
	-- \
	"${project_tarball}.xz" && \
	gpg --verify -- "${project_tarball}.xz.asc"
if [ $? -ne 0 ] ; then
	echo "failed to sign the tarball with GPG" >&2
	exit 1
fi

echo
echo "The release tarball is ready along with its checksum and its signature:"
echo " - tarball:   ${project_tarball}.xz"
echo " - checksum:  ${project_tarball}.xz.sha256"
echo " - signature: ${project_tarball}.xz.asc"
echo

exit 0

