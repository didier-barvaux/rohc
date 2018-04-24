#!/bin/bash

print_green()
{
	echo -en "\e[0;32m$@\e[m"
}

print_red()
{
	echo -en "\e[1;31m$@\e[m"
}

print_yellow()
{
	echo -en "\e[0;33m$@\e[m"
}

basedir=$( dirname $0 )

failures_nr=0

for dir in $( find $basedir/rfc3095/inputs/ -type d ) ; do
	if [ -f $dir/source.pcap ] ; then
		v1=$( gawk 'START { sum=0 } { sum+=$9 } END { print sum }' $dir/rohc_maxcontexts0_wlsb4_smallcid.sizes )
		v2=$( gawk 'START { sum=0 } { sum+=$9 } END { print sum }' $dir/rohcv2_maxcontexts0_wlsb4_smallcid.sizes )
		if [ $v1 -lt $v2 ] ; then
			print_red "FAIL: "
			failures_nr=$(( ${failures_nr} + 1 ))
		else
			print_green "PASS: "
		fi
		echo "$dir: v1=$v1 v2=$v2 delta=$(( $v2 - $v1 ))"
	fi
done

exit ${failures_nr}

