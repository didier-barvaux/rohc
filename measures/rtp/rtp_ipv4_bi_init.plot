set title 'RTP / IPv4 flow (bidirectional) (init)'
set xlabel 'Sent packets'
set ylabel 'Header size (bytes)'
set yrange [0:35]
set terminal png

plot [1:25] \
	'rtp_ipv4_bi.comp_data' using 1:5 title 'uncompressed headers' with lines, \
	'rtp_ipv4_bi.comp_data' using 1:7 title 'compressed headers' with lines

