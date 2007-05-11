set title 'RTP / IPv4 flow (bidirectional + error bursts + latency)'

set xlabel 'Sent packets'

set ylabel 'Header size (bytes)'
set yrange [0:35]
set ytics nomirror

set y2label 'Lost packets'
set y2range [0:550]
set y2tics

set terminal png

plot \
	'rtp_ipv4_bi_latency.comp_data' using 1:5 title 'uncompressed headers' axes x1y1 with lines, \
	'rtp_ipv4_bi_latency.comp_data' using 1:7 title 'compressed headers' axes x1y1 with lines, \
	'rtp_ipv4_bi_latency.comp_data' using 1:8 title 'lost packets' axes x1y2 with lines, \
	'rtp_ipv4_bi_latency.decomp_data' using 1:2 title 'lost packets + decompressor errors' axes x1y2 with lines

