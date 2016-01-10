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

#
# file:        buildbot.sh
# description: Build and test for Python binding for different Python versions
# authors:     Didier Barvaux <didier@barvaux.org>
#

# exit at first failure
set -e

python_binding_dir="$( dirname "$0" )"
cd "${python_binding_dir}"

for use_python_version in $@ ; do

	# build binding
	python${use_python_version} setup.py build

	# run coverage test
	./coverage.sh ${use_python_version}

	# run non-regression tests
	USE_PYTHON=${use_python_version} make -j2 -C ../../test/non_regression/ check

done

