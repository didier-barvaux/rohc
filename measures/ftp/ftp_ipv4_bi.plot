set title 'FTP / IPv4 flow (bidirectional)'
set xlabel 'Sent packets'
set ylabel 'Header size (bytes)'
set yrange [0:24]
set terminal png

plot \
	'ftp_ipv4_bi.comp_data' using 1:5 title 'uncompressed headers' with lines, \
	'ftp_ipv4_bi.comp_data' using 1:7 title 'compressed headers' with lines

