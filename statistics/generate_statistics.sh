#!/bin/sh
#
# file:        generate_statistics.sh
# description: Generate some cool graphs about ROHC library compression
# author:      Didier Barvaux <didier@barvaux.org>
#

# determine the base directory and the application path
SCRIPT="$0"
VERBOSE="$1"
if [ "x$MAKELEVEL" != "x" ] ; then
	BASEDIR="${srcdir}"
	APP="./generate_statistics"
	BUILD_ROOTDIR=".."
else
	BASEDIR=$( dirname "${SCRIPT}" )
	APP="${BASEDIR}/generate_statistics"
	BUILD_ROOTDIR="${BASEDIR}/.."
fi
SRC_ROOTDIR="${BASEDIR}/.."

# Check that the inputs/ directory exists
if [ ! -d "${SRC_ROOTDIR}/statistics/inputs" ] ; then
	echo "Input directory '${SRC_ROOTDIR}/statistics/inputs' does not exist"
	exit 1
fi

# Check that a awk-like tool is available
if [ -z "${AWK}" ] ; then
	echo "no awk-like tool available, please install one of the gawk, mawk, "\
	     "nawk, or awk tool."
	exit 1
fi

# Check that a grep-like tool is available
if [ -z "${GREP}" ] ; then
	echo "no grep-like tool available, please install one of the grep, or "\
	     "ggrep, tool."
	exit 1
fi

# Check that the sed tool is available
if [ -z "${SED}" ] ; then
	echo "sed tool not available, please install it."
	exit 1
fi

# generate statistics for all captures found in the inputs/ subdirectory
for CAPTURE in $(find "${SRC_ROOTDIR}/statistics/inputs/" -name source.pcap | ${GREP} -v bug804552 | sort) ; do

	# determine the name of the stream stored in the capture
	STREAM="./$(dirname ${CAPTURE} | ${SED} -e "s|${SRC_ROOTDIR}/statistics/inputs/||")"

	# check that stream name is not empty
	if [ -z "${STREAM}" ] ; then
		echo "empty stream name for capture ${CAPTURE} !"
		exit 1
	fi

	# run the statistics application and retrieve its output
	OUTPUT=$( ${APP} smallcid ${CAPTURE} 2>/dev/null )
	if [ $? -ne 0 ] ; then
		echo "compression failed for capture ${CAPTURE} !"
		exit 1
	fi

	# determine filename for raw output
	RAW_OUTPUT="${BUILD_ROOTDIR}/statistics/html/${STREAM}/raw.txt"

	# determine type of packet in capture
	PACKET_TYPE=$(echo $STREAM | ${SED} -e 's|^./||' | ${SED} -e 's/_/\//g' | tr '[a-z]' '[A-Z]')

	if [ "${VERBOSE}" = "verbose" ] ; then
		echo "generate statistics for ${PACKET_TYPE} packets:"
	else
		echo "generate statistics for ${PACKET_TYPE} packets"
	fi

	# create the output directory
	mkdir -p "${BUILD_ROOTDIR}/statistics/html/${STREAM}" || exit 1

	# create the raw output
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\trun statistics application... "
	echo -e "${OUTPUT}" | ${GREP} "^STAT" > ${RAW_OUTPUT} || exit 1
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create the graph with context modes
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate graph with context modes... "
	echo -e "set terminal png\n" \
	        "set output '${BUILD_ROOTDIR}/statistics/html/${STREAM}/modes.png'\n" \
	        "set title 'Compression modes for ${PACKET_TYPE} packets'\n" \
	        "set xlabel 'packet number in capture'\n" \
	        "plot [] [0:4] '${RAW_OUTPUT}' using 2:3:yticlabels(4) title columnhead(3)" \
		| gnuplot 2>/dev/null \
		|| exit 1
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create the graph with context states
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate graph with context states... "
	echo -e "set terminal png\n" \
	        "set output '${BUILD_ROOTDIR}/statistics/html/${STREAM}/states.png'\n" \
	        "set title 'Compression states for ${PACKET_TYPE} packets'\n" \
	        "set xlabel 'packet number in capture'\n" \
	        "plot [] [0:4] '${RAW_OUTPUT}' using 2:5:yticlabels(6) title columnhead(5)" \
		| gnuplot 2>/dev/null \
		|| exit 1
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create the graph with packet types
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate graph with packet types... "
	echo -e "set terminal png\n" \
	        "set output '${BUILD_ROOTDIR}/statistics/html/${STREAM}/packet_types.png'\n" \
	        "set title 'ROHC packet types for ${PACKET_TYPE} packets'\n" \
	        "set xlabel 'packet number in capture'\n" \
	        "plot [] [-1:14] '${RAW_OUTPUT}' using 2:7:yticlabels(8) title columnhead(7)" \
		| gnuplot 2>/dev/null \
		|| exit 1
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create the graph with (un)compressed packet sizes
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate graph with (un)compressed packet sizes... "
	echo -e "set terminal png\n" \
	        "set output '${BUILD_ROOTDIR}/statistics/html/${STREAM}/packet_sizes.png'\n" \
	        "set title 'Packet sizes for compression of ${PACKET_TYPE} packets'\n" \
	        "set xlabel 'packet number in capture'\n" \
	        "set ylabel 'packet size (bytes)'\n" \
	        "plot '${RAW_OUTPUT}' using 2:9 title columnhead(9) with lines," \
	        "     '${RAW_OUTPUT}' using 2:11 title columnhead(11) with lines" \
		| gnuplot 2>/dev/null \
		|| exit 1
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create the graph with (un)compressed header sizes
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate graph with (un)compressed header sizes... "
	echo -e "set terminal png\n" \
	        "set output '${BUILD_ROOTDIR}/statistics/html/${STREAM}/header_sizes.png'\n" \
	        "set title 'Header sizes for compression of ${PACKET_TYPE} packets'\n" \
	        "set xlabel 'packet number in capture'\n" \
	        "set ylabel 'header size (bytes)'\n" \
	        "plot '${RAW_OUTPUT}' using 2:10 title columnhead(10) with lines," \
	        "     '${RAW_OUTPUT}' using 2:12 title columnhead(12) with lines" \
		| gnuplot 2>/dev/null \
		|| exit 1
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create context mode counters
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate context mode counters... "
	for CONTEXT_MODE in "U-mode" "O-mode" "R-mode" ; do
		${AWK} "\$4 == \"${CONTEXT_MODE}\" { print \$11 }" \
		       "${RAW_OUTPUT}" \
			| wc -l > ${BUILD_ROOTDIR}/statistics/html/${STREAM}/context_mode_${CONTEXT_MODE}.count \
			|| exit 1
	done
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create context state counters
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate context state counters... "
	for CONTEXT_STATE in "IR" "FO" "SO" ; do
		${AWK} "\$6 == \"${CONTEXT_STATE}\" { print \$11 }" \
		       "${RAW_OUTPUT}" \
			| wc -l > ${BUILD_ROOTDIR}/statistics/html/${STREAM}/context_state_${CONTEXT_STATE}.count \
			|| exit 1
	done
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create packet type counters
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate packet type counters... "
	for PACKET_TYPE in "IR" "IR-DYN" \
	                   "UO-0" \
	                   "UO-1" "UO-1-ID" "UO-1-TS" "UO-1-RTP" \
	                   "UOR-2" "UOR-2-RTP" "UOR-2-ID" "UOR-2-TS" \
	                   "CCE" "CCE(off)" \
	                   "Normal"
	do
		${AWK} "\$8 == \"${PACKET_TYPE}\" { print \$11 }" \
		       "${RAW_OUTPUT}" \
			| wc -l > ${BUILD_ROOTDIR}/statistics/html/${STREAM}/packet_type_${PACKET_TYPE}.count \
			|| exit 1
	done
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create packet compression gain
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate packet compression gain... "
	${AWK} 'BEGIN { uncomp=0 ; comp=0 }\
	        $2 != "\"packet" { uncomp+=$9 ; comp+=$11 }\
	        END { printf "scale=2\n100-" comp "*100/" uncomp "\n" }' \
	     "${RAW_OUTPUT}" \
		| bc > ${BUILD_ROOTDIR}/statistics/html/${STREAM}/packet_compression.gain \
		|| exit 1
	[ "${VERBOSE}" = "verbose" ] && echo "done"

	# create header compression gain
	[ "${VERBOSE}" = "verbose" ] && echo -ne "\tcreate header compression gain... "
	${AWK} 'BEGIN { uncomp=0 ; comp=0 }\
	        $2 != "\"packet" { uncomp+=$10 ; comp+=$12 }\
	        END { printf "scale=2\n100-" comp "*100/" uncomp "\n" }' \
	     "${RAW_OUTPUT}" \
		| bc > ${BUILD_ROOTDIR}/statistics/html/${STREAM}/header_compression.gain \
		|| exit 1
	[ "${VERBOSE}" = "verbose" ] && echo "done"

done

# generate the HTML page which summarize all the results
HTML_OUTPUT="${BUILD_ROOTDIR}/statistics/html/index.html"
echo -n "" > ${HTML_OUTPUT}
echo -e "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">" >> ${HTML_OUTPUT}
echo -e "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">" >> ${HTML_OUTPUT}
echo -e "\t<head>" >> ${HTML_OUTPUT}
echo -e "\t\t<meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\" />" >> ${HTML_OUTPUT}
echo -e "\t\t<title>ROHC compression statistics</title>" >> ${HTML_OUTPUT}
echo -e "\t\t<style type=\"text/css\">" >> ${HTML_OUTPUT}
echo -e "\t\t\tbody { font-size: small; }" >> ${HTML_OUTPUT}
echo -e "\t\t\ttable, tr, th, td { border: solid thin black; border-collapse: collapse; }" >> ${HTML_OUTPUT}
echo -e "\t\t\ttable { width: 95%; }" >> ${HTML_OUTPUT}
echo -e "\t\t</style>" >> ${HTML_OUTPUT}
echo -e "\t</head>" >> ${HTML_OUTPUT}
echo -e "\t<body>" >> ${HTML_OUTPUT}

echo -e "\t\t<h1>ROHC compression statistics</h1>" >> ${HTML_OUTPUT}

echo -e "\t\t<table>" >> ${HTML_OUTPUT}

echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"3\">Type of stream</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"3\">Context modes</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"3\">Context states</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"14\">Packet types</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"2\">Compression gain</th>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}

echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Unidirectional Mode\">U-Mode</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Bidirectional Optimistic Mode\">O-mode</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Bidirectional Reliable Mode\">R-mode</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Initialisation &amp; Refresh\">IR</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"First Order\">FO</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Second Order\">SO</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Initialisation &amp; Refresh\">IR</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Initialisation &amp; Refresh DYNamic\">IR-DYN</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Unidirectional/Optimistic packet type 0\">UO-0</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"4\"><acronym title=\"Unidirectional/Optimistic packet type 1\">UO-1</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th colspan=\"4\"><acronym title=\"Unidirectional/Optimistic/Reliable packet type 2\">UOR-2</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"CCE packet type for UDP-Lite profile\">CCE</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"CCE(off) packet type for UDP-Lite profile\">CCE(off)</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\"><acronym title=\"Normal packet type for Uncompressed profile\">Normal</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\">Packet</th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th rowspan=\"2\">Header</th>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}

echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UO-1 for non-RTP profiles\">-</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UO-1 with IP-ID bits\">ID</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UO-1 with RTP TS bits\">TS</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UO-1 for RTP profile\">RTP</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UOR-2 for non-RTP profiles\">-</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UOR-2 for RTP profile\">RTP</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UOR-2 with IP-ID bits\">ID</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t\t<th><acronym title=\"UOR-2 with TS bits\">TS</acronym></th>" >> ${HTML_OUTPUT}
echo -e "\t\t</tr>" >> ${HTML_OUTPUT}

for CAPTURE in $(find "${SRC_ROOTDIR}/statistics/inputs/" -name source.pcap | sort ) ; do

	STREAM="./$(dirname ${CAPTURE} | ${SED} -e "s|${SRC_ROOTDIR}/statistics/inputs/||")"
	PACKET_TYPE=$(echo $STREAM | ${SED} -e 's|^./||' | ${SED} -e 's/_/\//g' | tr '[a-z]' '[A-Z]')

	echo -e "\t\t<tr>" >> ${HTML_OUTPUT}
	echo -e "\t\t\t<td>${PACKET_TYPE} packets</td>" >> ${HTML_OUTPUT}
	for CONTEXT_MODE in "U-mode" "O-mode" "R-mode" ; do
		echo -e "\t\t\t<td><a href=\"./${STREAM}/modes.png\">$(cat ${BUILD_ROOTDIR}/statistics/html/${STREAM}/context_mode_${CONTEXT_MODE}.count)</a></td>" >> ${HTML_OUTPUT}
	done
	for CONTEXT_STATE in "IR" "FO" "SO" ; do
		echo -e "\t\t\t<td><a href=\"./${STREAM}/states.png\">$(cat ${BUILD_ROOTDIR}/statistics/html/${STREAM}/context_state_${CONTEXT_STATE}.count)</a></td>" >> ${HTML_OUTPUT}
	done
	for PACKET_TYPE in "IR" "IR-DYN" \
	                   "UO-0" \
	                   "UO-1" "UO-1-ID" "UO-1-TS" "UO-1-RTP" \
	                   "UOR-2" "UOR-2-RTP" "UOR-2-ID" "UOR-2-TS" \
	                   "CCE" "CCE(off)" \
	                   "Normal"
	do
		echo -e "\t\t\t<td><a href=\"./${STREAM}/packet_types.png\">$(cat ${BUILD_ROOTDIR}/statistics/html/${STREAM}/packet_type_${PACKET_TYPE}.count)</a></td>" >> ${HTML_OUTPUT}
	done
	echo -e "\t\t\t<td><a href=\"./${STREAM}/packet_sizes.png\">$(cat ${BUILD_ROOTDIR}/statistics/html/${STREAM}/packet_compression.gain)&nbsp;%</a></td>" >> ${HTML_OUTPUT}
	echo -e "\t\t\t<td><a href=\"./${STREAM}/header_sizes.png\">$(cat ${BUILD_ROOTDIR}/statistics/html/${STREAM}/header_compression.gain)&nbsp;%</a></td>" >> ${HTML_OUTPUT}
	echo -e "\t\t</tr>" >> ${HTML_OUTPUT}

done

echo -e "\t\t</table>" >> ${HTML_OUTPUT}
echo -e "\t</body>" >> ${HTML_OUTPUT}
echo -e "</html>" >> ${HTML_OUTPUT}

[ "${VERBOSE}" = "verbose" ] && echo ""
echo "HTML summary was created for you in \"${HTML_OUTPUT}\"."
[ "${VERBOSE}" = "verbose" ] && echo ""

exit 0

