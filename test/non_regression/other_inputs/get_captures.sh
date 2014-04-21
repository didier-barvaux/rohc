#!/bin/sh
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# file:        get_capture.sh
# description: Download test captures from external resources
# author:      Didier Barvaux <didier@barvaux.org>
#
# usage: get_capture.sh
#

URLS="wiki_wireshark|http://wiki.wireshark.org/SampleCaptures\n\
MACCDC|http://www.netresec.com/?page=MACCDC"


print_green()
{
	echo -e "\e[0;32m$@\e[m"
}

print_red()
{
	echo -e "\e[1;31m$@\e[m"
}

print_yellow()
{
	echo -e "\e[0;33m$@\e[m"
}


curdir=$( dirname "$0" )
cd "${curdir}/download/" &>/dev/null || exit 1


for src in $( echo -e "${URLS}" ) ; do
	name=$( echo "${src}" | gawk -F'|' '{ print $1 }' )
	url=$( echo "${src}" | gawk -F'|' '{ print $2 }' )

	echo "retrieve captures from '${url}':"

	echo -en "\tget list... "
	captures=$( lynx -dump "${url}" | \
	            grep -Eh --only-matching 'http://[^ ]+' )
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		echo "failed (${ret})"
		continue
	fi
	if [ "${name}" = "wiki_wireshark" ] ; then
		captures=$( echo -e "${captures}" | \
		            grep AttachFile.*target= | \
		            sed 's/do=view/do=get/' )
		ret=$?
		if [ ${ret} -ne 0 ] ; then
			echo "failed (${ret})"
			continue
		fi
	fi
	captures=$( echo -e "${captures}" | sort | uniq )
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		echo "failed (${ret})"
		continue
	fi
	echo "done"

	nr_captures=$( echo -e "${captures}" | wc -l )
	count_ok=0
	count_skip=0
	count_ko=0
	for capture in ${captures} ; do
		filename="${capture##*/}"
		filename="${filename##*=}"
		filename="${name}_${filename}"
		echo -en "\t$(( ${count_ok} + ${count_skip} + ${count_ko} + 1 )) / ${nr_captures}: ${filename} ... "
		if [ -f "${filename}" ] ; then
			count_skip=$(( ${count_skip} + 1 ))
			print_yellow "skip"
		else
			wget --quiet -O "${filename}" "${capture}" &>/dev/null
			if [ $? -eq 0 ] ; then
				count_ok=$(( ${count_ok} + 1 ))
				print_green "done"
			else
				count_ko=$(( ${count_ko} + 1 ))
				print_red "failed"
			fi
		fi

		mime=$( file --brief --mime-type "${filename}" )
		ret=$?
		if [ ${ret} -ne 0 ] ; then
			print_red "\t\t=> failed to detect MIME type (${ret})"
			continue
		fi
		while [ "${mime}" = "application/x-gzip" ] || \
		      [ "${mime}" = "application/zip" ] || \
		      [ "${mime}" = "application/x-bzip2" ] || \
		      [ "${mime}" = "application/x-tar" ] ; do

			if [ "${mime}" = "application/x-gzip" ] || \
			   [ "${mime}" = "application/zip" ] ; then

				echo -en "\t\t=> decompress '${mime}'... "

				if [ "${mime}" = "application/x-gzip" ] ; then
					new_filename="$( basename "${filename}" ".gz" )"
					if [ "${new_filename}" = "${filename}" ] ; then
						new_filename="$( basename "${filename}" ".tgz" ).tar"
					fi
				elif [ "${mime}" = "application/zip" ] ; then
					new_filename="$( basename "${filename}" ".zip" )"
				else
					print_red "failed (unsupported compressed MIME type '${mime}')"
					break
				fi
				if [ -f "${new_filename}" ] ; then
					print_yellow "skip"

					filename="${new_filename}"
					mime=$( file --brief --mime-type "${filename}" )
					ret=$?
					if [ ${ret} -ne 0 ] ; then
						print_red "\t\t=> failed to detect MIME type (${ret})"
						break
					fi

					break
				fi

				gunzip -f "${filename}" &>/dev/null
				ret=$?
				if [ ${ret} -ne 0 ] ; then
					print_red "failed"
					break
				fi
				touch "${filename}"  # avoid downloading again next time
				print_green "done"

				filename="${new_filename}"

			elif [ "${mime}" = "application/x-bzip2" ] ; then

				echo -en "\t\t=> decompress '${mime}'... "

				new_filename=$( basename "${filename}" ".bz2" )
				if [ -f "${new_filename}" ] ; then
					print_yellow "skip"

					filename="${new_filename}"
					mime=$( file --brief --mime-type "${filename}" )
					ret=$?
					if [ ${ret} -ne 0 ] ; then
						print_red "\t\t=> failed to detect MIME type (${ret})"
						break
					fi

					break
				fi

				bunzip2 -f "${filename}" &>/dev/null
				ret=$?
				if [ ${ret} -ne 0 ] ; then
					print_red "failed"
					break
				fi
				touch "${filename}"  # avoid downloading again next time
				print_green "done"

				filename="${new_filename}"

			elif [ "${mime}" = "application/x-tar" ] ; then

				echo -en "\t\t=> extract '${mime}'... "

				new_filename=$( basename "${filename}" ".tar" )
				if [ -f "${new_filename}" ] ; then
					print_yellow "skip"

					filename="${new_filename}"
					mime=$( file --brief --mime-type "${filename}" )
					ret=$?
					if [ ${ret} -ne 0 ] ; then
						print_red "\t\t=> failed to detect MIME type (${ret})"
						break
					fi

					break
				fi

				tar -xvf "${filename}" &>/dev/null
				ret=$?
				if [ ${ret} -ne 0 ] ; then
					print_red "failed"
					break
				fi
				print_green "done"

				filename="${new_filename}"
			fi

			mime=$( file --brief --mime-type "${filename}" )
			ret=$?
			if [ ${ret} -ne 0 ] ; then
				print_red "\t\t=> failed to detect MIME type (${ret})"
				break
			fi

		done

		if [ "${mime}" != "application/vnd.tcpdump.pcap" ] ; then
			print_red "\t\t=> unsupported MIME type '${mime}'"
			continue
		fi

		echo -en "\t\tcreate link... "
		if [ -f "../external_inputs/${filename}" ] ; then
			print_yellow "skip"
			continue
		fi
		ln -s ../download/${filename} ../external_inputs/${filename} 2>/dev/null
		ret=$?
		if [ ${ret} -ne 0 ] ; then
			print_red "failed (${ret})"
			continue
		fi
		print_green "done"

	done

	echo -e "\t$(( ${count_ok} + ${count_skip} )) / ${nr_captures} successfully retrieved"

	unset count_ok
	unset count_skip
	unset count_ko
	unset nr_captures
	unset captures
	unset name
	unset url
done
unset src

cd - &>/dev/null || exit 1
exit 0

