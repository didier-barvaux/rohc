#!/bin/sh
#
# This script is a beautifier for curve of decompression errors.
#
# When dealing with packet reordering, a ROHC decompressor may fail to
# decompress some late packets (late packets are packets that are received
# after a packet with a higher sequence number). Decompression errors counter
# that was previously incremented is decremented. Statistics for these packets
# are output out of order in the data file, resulting in an awful curve with
# zigzags.
#
# This script corrects this problem. Decompression statitics are first sorted by
# their sequence number and then some records are discarded so that the curve
# always increases.
#
# Usage: ./create_sorted_decomp_data.sh <DECOMP_FILE> <SORTED_DECOMP_FILE>
#
# The generated data file can of course be used to draw graphics with gnuplot.
# Records in the data file have the same format as in decompression data files.
#
# Author: Didier Barvaux <didier.barvaux@toulouse.viveris.com>

# check arguments
if ! test -f $1 ; then
	echo "bad source file"
	exit 1
elif test -z "$2" ; then
	echo "bad destination file"
	exit 1
fi

# beautify the decompression data records:
#  - the sort call sorts the reordered packets by their sequence number
#  - the gawk call creates the new decompression data file without the records
#    where the number of decompression errors is smaller than the previous
#    numbers of decompression errors
#  - the gawk call also adds two additional records at the beginning to be sure
#    that the curve will start at 0
sort -n $1 \
	| gawk 'BEGIN { count=0 ; print "0\t0\t0\t0" } NR == 1 && $1 > 1 { print $1-1 "\t0\t0\t0" } $4 >= count { print $0 ; count=$4 }' \
	> $2

# add an additional record at the very end of the data file to be sure that the
# curve will cover the full x axis:
#  - find the higher sequence number
#  - find out the count of decompression errors
#  - add a record with the info previously found
sn=`tail -n 1 $1 | gawk '{ print $1 }'`
sn=$((sn + 1))
count=`tail -n 1 $2 | gawk '{ print $4 }'`
echo -e "$sn\t$count\t0\t$count" >> $2

