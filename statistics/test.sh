#!/bin/sh
#
# Author: David Moreau from TAS
#

EXEC="../test/test"
PATH="../test/report/samples/"

while read aLine
do
	echo -en $aLine" ..... \e[31m"
	$EXEC $PATH$aLine"/source.pcap" -o $PATH$aLine"/rohc.pcap"> $PATH$aLine"/log.xml"
	if [ "$?" = 0 ]
	then
		echo -e "\e[32m OK"
	fi
	echo -ne "\e[m"
	#/bin/rm -f $PATH$aLine"/log.xml"
done

