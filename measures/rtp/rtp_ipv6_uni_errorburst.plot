set title 'RTP / IPv6 flow (unidirectional + error bursts)'

set xlabel 'Sent packets'

set ylabel 'Header size (bytes)'
set yrange [0:57]
set ytics nomirror

set y2label 'Lost packets'
set y2range [0:350]
set y2tics

set terminal png

plot \
	'rtp_ipv6_uni_errorburst.comp_data' using 1:5 title 'uncompressed headers' axes x1y1 with lines, \
	'rtp_ipv6_uni_errorburst.comp_data' using 1:7 title 'compressed headers' axes x1y1 with lines, \
	'rtp_ipv6_uni_errorburst.comp_data' using 1:8 title 'lost packets' axes x1y2 with lines, \
	'rtp_ipv6_uni_errorburst.decomp_data' using 1:2 title 'lost packets + decompressor errors' axes x1y2 with lines

