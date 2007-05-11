#!/bin/sh
#
# This script finds out packets received out of order at decompressor. It
# takes one decompression data file as input and outputs a new data file that
# contains the sequence numbers of reordered packets, as well as the count of
# reordered packets.
#
# Usage: ./create_reorder_data.sh <DECOMP_DATA_FILE> <REORDER_DATA_FILE>
#
# The generated data file can be used to draw graphics with gnuplot. Records
# in the data file have the following format:
# <SEQUENCE NUMBER> <tab> <NUMBER OF REORDERED PACKETS UP TO NOW>
#
# Author: Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#

# check arguments
if ! test -f $1 ; then
	echo "bad source file"
	exit 1
elif test -z "$2" ; then
	echo "bad destination file"
	exit 1
fi

# find out reordered packets:
#  - the first gawk call selects the packets with a higher sequence number than
#    attended
#  - the sort call sorts the reordered packets by their sequence number
#  - the second gawk call creates the reorder data file (it adds two additional
#    records at the beginning to be sure that the curve will start at 0)
gawk 'BEGIN { sn=1 } $1 > sn { print $0 } { sn=sn+1 }' $1 \
	| sort -n \
	| gawk 'BEGIN { print "0\t0" } NR == 1 && $1 > 1 { print $1-1 "\t0" } { print $1 "\t" NR }' \
	> $2

# add an additional record at the very end of the data file to be sure that the
# curve will cover the full x axis:
#  - find the higher sequence number
#  - find out the count of reordered packets
#  - add a record with the info previously found
sn=`tail -n 1 $1 | gawk '{ print $1 }'`
sn=$((sn + 1))
count=`tail -n 1 $2 | gawk '{ print $2 }'`
echo -e "$sn\t$count" >> $2

