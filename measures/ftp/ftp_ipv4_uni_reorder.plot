set title 'FTP / IPv4 flow (unidirectional + latency + packet reordering)'

set xlabel 'Sent packets'
set xrange [0:150]

set ylabel 'Header size (bytes)'
set yrange [0:24]
set ytics nomirror

set y2label 'Reordered packets / decompression errors'
set y2range [0:73]
set y2tics

set terminal png

plot \
	'ftp_ipv4_uni_reorder.comp_data' using 1:5 title 'uncompressed headers' axes x1y1 with lines, \
	'ftp_ipv4_uni_reorder.comp_data' using 1:7 title 'compressed headers' axes x1y1 with lines, \
	'ftp_ipv4_uni_reorder.reorder_data' using 1:2 title 'reordered packets' axes x1y2 with lines, \
	'ftp_ipv4_uni_reorder.decomp_data_sorted' using 1:4 title 'decompressor errors' axes x1y2 with lines

