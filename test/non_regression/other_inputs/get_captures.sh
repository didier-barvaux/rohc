#!/bin/sh
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
# file:        get_capture.sh
# description: Download test captures from external resources
# author:      Didier Barvaux <didier@barvaux.org>
#
# usage: get_capture.sh
#

PAGE_URLS="wiki_wireshark|http://wiki.wireshark.org/SampleCaptures\n\
MACCDC|http://www.netresec.com/?page=MACCDC\n\
ISTS|http://www.netresec.com/?page=ISTS\n\
GTISK_PANDA_Malre|http://panda.gtisc.gatech.edu/malrec/\n\
packetlife_net_1|http://packetlife.net/captures/?page=1\n\
packetlife_net_2|http://packetlife.net/captures/?page=2\n\
packetlife_net_3|http://packetlife.net/captures/?page=3\n\
packetlife_net_4|http://packetlife.net/captures/?page=4\n\
packetlife_net_5|http://packetlife.net/captures/?page=5\n\
packetlife_net_6|http://packetlife.net/captures/?page=6\n\
packetlife_net_7|http://packetlife.net/captures/?page=7"

CAPTURE_URLS="CSAW-2011-LoveLetter|http://shell-storm.org/repo/CTF/CSAW-2011/Networking/LoveLetter%20-%20500%20Points/captured-love-letter.pcap\n\
CSAW-2011-Networking101|http://shell-storm.org/repo/CTF/CSAW-2011/Networking/Networking101%20-%20100%20Points/capture.pcap\n\
CSAW-2011-PatchManagement|http://shell-storm.org/repo/CTF/CSAW-2011/Networking/PatchManagement%20-%20400%20Points/capture.pcap\n\
HackEire_2010|https://github.com/markofu/hackeire/raw/master/2010/pcap/1.pcap\n\
HackEire_2011|https://github.com/markofu/hackeire/raw/master/2011/pcap/c1.pcap\n\
HackEire_2011|https://github.com/markofu/hackeire/raw/master/2011/pcap/c2.pcap\n\
HackEire_2011|https://github.com/markofu/hackeire/raw/master/2011/pcap/c3.pcap\n\
No_cON_Name_2014_CTF_Finals|https://github.com/MarioVilas/write-ups/raw/master/ncn-ctf-2014/Vodka/vodka\n\
snaketrap|http://www.snaketrap.co.uk/pcaps/Ncapture.pcap\n\
snaketrap|http://www.snaketrap.co.uk/pcaps/hbot.pcap\n\
snaketrap|http://www.snaketrap.co.uk/pcap/hptcp.pcap\n\
netresec|http://download.netresec.com/pcap/ponmocup/vm-2.pcap\n\
holisticinfosec|http://holisticinfosec.org/toolsmith/files/nov2k6/toolsmith.pcap\n\
barracudalabs|http://barracudalabs.com/downloads/5f810408ddbbd6d349b4be4766f41a37.pcap\n\
mediafire|http://www.mediafire.com/file/gmmk388vkxcvme6/tbotpcaps.zip\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/09/23/2015-09-23-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/09/11/2015-09-11-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/08/31/2015-08-31-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/08/07/2015-08-07-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/07/24/2015-07-24-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/07/11/2015-07-11-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/06/30/2015-06-30-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/05/29/2015-05-29-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/05/08/2015-05-08-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/05/08/2015-05-08-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/03/24/2015-03-24-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/03/09/2015-03-09-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/03/03/2015-03-03-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/02/24/2015-02-24-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/02/15/2015-02-15-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/02/08/2015-02-08-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/01/18/2015-01-18-traffic-analysis-exercise-1-of-2.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/01/18/2015-01-18-traffic-analysis-exercise-2-of-2.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2015/01/09/2015-01-09-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2014/12/15/2014-12-15-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2014/12/08/2014-12-08-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2014/12/04/2014-12-04-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2014/11/23/2014-11-23-traffic-analysis-exercise.pcap\n\
malware_traffic_analysis|http://malware-traffic-analysis.net/2014/11/16/2014-11-16-traffic-analysis-exercise.pcap"

# torrent downloads:
# https://media.defcon.org/torrent/DEF%20CON%2017%20CTF.torrent
# https://www.defcon.org/html/torrent/DEF%20CON%2018%20CTF.torrent
# https://www.defcon.org/html/torrent/DEF%20CON%2019%20CTF.torrent
# https://www.defcon.org/html/torrent/DEF%20CON%2020%20ctf.torrent
# https://www.defcon.org/html/torrent/DEF%20CON%2021%20ctf%20friday.torrent
# http://www.defcon.org/html/torrent/DEF%20CON%2021%20ctf%20saturday.torrent
# http://www.defcon.org/html/torrent/DEF%20CON%2021%20ctf%20sunday.torrent
# http://www.defcon.org/html/torrent/DEF%20CON%2022%20ctf%20teams.torrent


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

decompress()
{
	if [ -h "${filename}" ] ; then
		echo -en "\t\t=> decompress... "
		print_yellow "skip (already decompressed)"
		return 0
	fi

	mime=$( file --brief --mime-type "${filename}" )
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		print_red "\t\t=> failed to detect MIME type (${ret})"
		return 1
	fi

	#[ "${mime}" = "application/zip" ] ||
	while [ "${mime}" = "application/x-gzip" ] || \
	      [ "${mime}" = "application/x-bzip2" ] || \
	      [ "${mime}" = "application/x-tar" ] ; do

		if [ "${mime}" = "application/x-gzip" ] ; then
			extension="gz"
			decompress_cmd="gunzip -f"
			archive_suppressed=1
			new_filename="$( basename "${filename}" ".gz" )"
			if [ "${new_filename}" = "${filename}" ] ; then
				new_filename="$( basename "${filename}" ".tgz" ).tar"
			fi
#		elif [ "${mime}" = "application/zip" ] ; then
#			extension="zip"
#			decompress_cmd="unzip"
#			archive_suppressed=1
#			new_filename="$( basename "${filename}" ".zip" )"
		elif [ "${mime}" = "application/x-bzip2" ] ; then
			extension="bz2"
			decompress_cmd="bunzip2 -f "
			archive_suppressed=1
			new_filename=$( basename "${filename}" ".bz2" )
		elif [ "${mime}" = "application/x-tar" ] ; then
			extension="tar"
			decompress_cmd="tar -xvf"
			archive_suppressed=0
			new_filename=$( basename "${filename}" ".tar" )
		fi
		if [ "${new_filename}" = "${filename}" ] && \
		   [ ! -f "${filename}.${extension}" ] ; then
			filename="${filename}.${extension}"
			mv -f "${new_filename}" "${filename}"
		fi

		echo -en "\t\t=> decompress '${mime}'... "

		if [ -f "${new_filename}" ] ; then
			print_yellow "skip (already decompressed)"
		else
			if [ ${archive_suppressed} -eq 1 ] ; then
				cp -f -- "${filename}" "${filename}.bak" &>/dev/null
				ret=$?
				if [ ${ret} -ne 0 ] ; then
					print_red "failed (backup creation failed)"
					return 1
				fi
			fi

			${decompress_cmd} "${filename}" &>/dev/null
			ret=$?
			if [ ${ret} -ne 0 ] ; then
				print_red "failed"
				return 1
			fi

			if [ ${archive_suppressed} -eq 1 ] ; then
				mv -f -- "${filename}.bak" "${filename}" &>/dev/null
				ret=$?
				if [ ${ret} -ne 0 ] ; then
					print_red "failed (backup restoration failed)"
					return 1
				fi
			fi

			print_green "done"
		fi
		filename="${new_filename}"

		mime=$( file --brief --mime-type "${filename}" )
		ret=$?
		if [ ${ret} -ne 0 ] ; then
			print_red "\t\t=> failed to detect MIME type (${ret})"
			return 1
		fi

	done

	return 0
}

LYNX="$( which lynx )"
GAWK="$( which gawk )"
WGET="$( which wget )"
if [ -z "${LYNX}" ] || [ ! -x "${LYNX}" ] ; then
	echo "missing prerequisite: lynx not found on system" >&2
	exit 1
fi
if [ -z "${GAWK}" ] || [ ! -x "${GAWK}" ] ; then
	echo "missing prerequisite: gawk not found on system" >&2
	exit 1
fi
if [ -z "${WGET}" ] || [ ! -x "${WGET}" ] ; then
	echo "missing prerequisite: wget not found on system" >&2
	exit 1
fi


curdir=$( dirname "$0" )
mkdir -p "${curdir}/download/" &>/dev/null
mkdir -p "${curdir}/external_inputs/" &>/dev/null
cd "${curdir}/download/" &>/dev/null || exit 1


# download all captures found on the list of pages
for src in $( echo -e "${PAGE_URLS}" ) ; do
	name=$( echo "${src}" | ${GAWK} -F'|' '{ print $1 }' )
	url=$( echo "${src}" | ${GAWK} -F'|' '{ print $2 }' )

	echo "retrieve captures from '${url}':"

	echo -en "\tget list... "
	captures=$( ${LYNX} -dump "${url}" | \
	            grep -Eh --only-matching 'https?://[^ ]+' )
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
	captures=$( echo -e "${captures}" | \
	            sort | \
	            uniq | \
	            grep -vE '^$' | \
	            grep -vE '^\.$' | \
	            grep -vE '\/$' | \
	            grep -vE 'cloudshark\.org' | \
	            grep -vE '\.(mp4|rr|json)$' )
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

		if [ -e "${filename}" ] && [ -s "${filename}" ] ; then
			# file exists and sizes more than 0 byte
			count_skip=$(( ${count_skip} + 1 ))
			print_yellow "skip (already present)"
		else
			${WGET} --quiet -O "${filename}" -- "${capture}" &>/dev/null
			if [ $? -eq 0 ] ; then
				count_ok=$(( ${count_ok} + 1 ))
				print_green "done"
			else
				count_ko=$(( ${count_ko} + 1 ))
				print_red "failed"
				continue
			fi
		fi

		decompress
		ret=$?
		if [ ${ret} -ne 0 ] ; then
			print_red "\t\t=> failed to decompress file (${ret})"
			continue
		fi

		mime=$( file --brief --mime-type "${filename}" )
		ret=$?
		if [ ${ret} -ne 0 ] ; then
			print_red "\t\t=> failed to detect MIME type (${ret})"
			continue
		fi

		file_type=$( file --brief "${filename}" )
		ret=$?
		if [ ${ret} -ne 0 ] ; then
			print_red "\t\t=> failed to detect file type (${ret})"
			continue
		fi

		is_file_supported=0
		if [ "${mime}" = "application/vnd.tcpdump.pcap" ] ; then
			is_file_supported=1
		elif [ "${mime}" = "application/octet-stream" ] ; then
			echo "${file_type}" | grep -Eq "^extended tcpdump capture file"
			etcpdump=$?
			echo "${file_type}" | grep -Eq "^pcap-ng capture file"
			pcapng=$?
			echo "${file_type}" | grep -Eq "^NetXRay capture file"
			netxray=$?
			if [ ${etcpdump} -eq 0 ] || \
			   [ ${pcapng} -eq 0 ] || \
			   [ ${netxray} -eq 0 ] ; then
				is_file_supported=1
			fi
		fi
		if [ ${is_file_supported} -ne 1 ] ; then
			print_red "\t\t=> unsupported file type '${file_type}' / '${mime}'"
			continue
		fi

		echo -en "\t\tcreate link... "
		if [ -f "../external_inputs/${filename}" ] ; then
			print_yellow "skip (already linked)"
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


# download all captures found on the list captures
echo "retrieve separate captures from various URIs:"
nr_captures=$( echo -e "${CAPTURE_URLS}" | wc -l )
count_ok=0
count_skip=0
count_ko=0
for src in $( echo -e "${CAPTURE_URLS}" ) ; do
	name=$( echo "${src}" | ${GAWK} -F'|' '{ print $1 }' )
	url=$( echo "${src}" | ${GAWK} -F'|' '{ print $2 }' )
	filename="${url##*/}"
	filename="${filename##*=}"
	filename="${name}_${filename}"

	echo -en "\t$(( ${count_ok} + ${count_skip} + ${count_ko} + 1 )) / ${nr_captures}: ${url} ... "

	if [ -e "${filename}" ] && [ -s "${filename}" ] ; then
		# file exists and sizes more than 0 byte
		count_skip=$(( ${count_skip} + 1 ))
		print_yellow "skip (already present)"
		continue
	fi

	${WGET} --quiet -O "${filename}" -- "${url}" &>/dev/null
	if [ $? -ne 0 ] ; then
		count_ko=$(( ${count_ko} + 1 ))
		print_red "download failed"
		continue
	fi

	decompress
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		count_ko=$(( ${count_ko} + 1 ))
		print_red "decompress failed (${ret})"
		continue
	fi

	if [ -f "../external_inputs/${filename}" ] ; then
		count_skip=$(( ${count_skip} + 1 ))
		print_yellow "skip (already linked)"
		continue
	fi
	ln -s ../download/${filename} ../external_inputs/${filename} 2>/dev/null
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		count_ko=$(( ${count_ko} + 1 ))
		print_red "link failed (${ret})"
		continue
	fi

	count_ok=$(( ${count_ok} + 1 ))
	print_green "done"

	unset name
	unset url
done
echo -e "\t$(( ${count_ok} + ${count_skip} )) / ${nr_captures} successfully retrieved"
unset count_ok
unset count_skip
unset count_ko
unset nr_captures


cd - &>/dev/null || exit 1
exit 0

