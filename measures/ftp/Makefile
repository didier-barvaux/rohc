#
# Create the FTP / IPv[46] graphics
#
# Author: Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#

GNUPLOT=gnuplot
SORT=../create_sorted_decomp_data.sh
REORDER=../create_reorder_data.sh

# Create IPv4 and IPv6 graphics by default
all: ipv4 ipv6

# Remove all graphics
clean:
	$(RM) *.png
	$(RM) *.decomp_data_sorted
	$(RM) *.reorder_data
	$(RM) Thumbs.db

#
# Create IPv4 graphics
#

ipv4: \
	ipv4_nominal \
	ipv4_uniform_error \
	ipv4_burst_error \
	ipv4_latency \
	ipv4_reorder

ipv4_nominal:
	$(GNUPLOT) < ftp_ipv4_uni.plot > ftp_ipv4_uni.png
	$(GNUPLOT) < ftp_ipv4_bi.plot > ftp_ipv4_bi.png

ipv4_uniform_error:
	$(GNUPLOT) < ftp_ipv4_uni_error.plot > ftp_ipv4_uni_error.png
	$(GNUPLOT) < ftp_ipv4_bi_error.plot > ftp_ipv4_bi_error.png

ipv4_burst_error:
	$(GNUPLOT) < ftp_ipv4_uni_errorburst.plot > ftp_ipv4_uni_errorburst.png
	$(GNUPLOT) < ftp_ipv4_bi_errorburst.plot > ftp_ipv4_bi_errorburst.png

ipv4_latency:
	$(GNUPLOT) < ftp_ipv4_bi_latency.plot > ftp_ipv4_bi_latency.png

ipv4_reorder:
	$(SORT) ftp_ipv4_uni_reorder.decomp_data ftp_ipv4_uni_reorder.decomp_data_sorted
	$(REORDER) ftp_ipv4_uni_reorder.decomp_data ftp_ipv4_uni_reorder.reorder_data
	$(GNUPLOT) < ftp_ipv4_uni_reorder.plot > ftp_ipv4_uni_reorder.png
	$(SORT) ftp_ipv4_bi_reorder.decomp_data ftp_ipv4_bi_reorder.decomp_data_sorted
	$(REORDER) ftp_ipv4_bi_reorder.decomp_data ftp_ipv4_bi_reorder.reorder_data
	$(GNUPLOT) < ftp_ipv4_bi_reorder.plot > ftp_ipv4_bi_reorder.png

#
# Create IPv6 graphics
#

ipv6: \
	ipv6_nominal \
	ipv6_uniform_error \
	ipv6_burst_error \
	ipv6_latency \
	ipv6_reorder

ipv6_nominal:
	$(GNUPLOT) < ftp_ipv6_uni.plot > ftp_ipv6_uni.png
	$(GNUPLOT) < ftp_ipv6_bi.plot > ftp_ipv6_bi.png

ipv6_uniform_error:
	$(GNUPLOT) < ftp_ipv6_uni_error.plot > ftp_ipv6_uni_error.png
	$(GNUPLOT) < ftp_ipv6_bi_error.plot > ftp_ipv6_bi_error.png

ipv6_burst_error:
	$(GNUPLOT) < ftp_ipv6_uni_errorburst.plot > ftp_ipv6_uni_errorburst.png
	$(GNUPLOT) < ftp_ipv6_bi_errorburst.plot > ftp_ipv6_bi_errorburst.png

ipv6_latency:
	$(GNUPLOT) < ftp_ipv6_bi_latency.plot > ftp_ipv6_bi_latency.png

ipv6_reorder:
	$(SORT) ftp_ipv6_uni_reorder.decomp_data ftp_ipv6_uni_reorder.decomp_data_sorted
	$(REORDER) ftp_ipv6_uni_reorder.decomp_data ftp_ipv6_uni_reorder.reorder_data
	$(GNUPLOT) < ftp_ipv6_uni_reorder.plot > ftp_ipv6_uni_reorder.png
	$(SORT) ftp_ipv6_bi_reorder.decomp_data ftp_ipv6_bi_reorder.decomp_data_sorted
	$(REORDER) ftp_ipv6_bi_reorder.decomp_data ftp_ipv6_bi_reorder.reorder_data
	$(GNUPLOT) < ftp_ipv6_bi_reorder.plot > ftp_ipv6_bi_reorder.png

