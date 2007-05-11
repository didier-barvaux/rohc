set title 'FTP / IPv6 flow (bidirectional)'
set xlabel 'Sent packets'
set ylabel 'Header size (bytes)'
set yrange [0:50]
set terminal png

plot \
	'ftp_ipv6_bi.comp_data' using 1:5 title 'uncompressed headers' with lines, \
	'ftp_ipv6_bi.comp_data' using 1:7 title 'compressed headers' with lines

