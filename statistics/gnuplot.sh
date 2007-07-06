#!/bin/sh
#
# Author: David Moreau from TAS
#


begin=$1
end=$2

cat >>.simu <<EOF
set style data points
set xlabel "nombre de paquets"
set ylabel "Taille de l'en-tete ROHC (octets)"
set xrange [$begin:$end]
plot 'headers_size' using 1:2 title 'en-tete ROHC' 
set ter png
set out 'header_size.png'
replot
EOF
gnuplot .simu
rm -f .simu

cat >>.simu <<EOF
set style data lp
set xlabel "numero du paquet"
set ylabel "Taille du paquet"
set xrange [$begin:$end]
plot 'packets_size' using 1 title 'sans compression', 'packets_size' using 2 title 'compression ROHC' 
set ter png
set out 'packets_size.png'
replot
EOF
gnuplot .simu
rm -f .simu


