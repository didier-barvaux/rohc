#!/usr/bin/perl -w
#
# Author: David Moreau from TAS
#


#############################################
# function search_packet
# parameter 0 : the line to analyse
# paramater 1 : the string to search for
# return 1 if found, else 0
#############################################
sub search_packet {
	my $i = index($_[0],$_[1]);
	if($i > 0) {
		return 1;
	} else {
		return 0;
	}
}



# array which will contain the number of each packet type
$numbers{"IR"} = 0;
$numbers{"IR_DYN"} = 0;
$numbers{"UO_0"} = 0;
$numbers{"UO_1"} = 0;
$numbers{"UO_1_RTP"} = 0;
$numbers{"UO_1_TS"} = 0;
$numbers{"UO_1_ID"} = 0;

$numbers{"UOR_2_NO_EXT"} = 0;
$numbers{"UOR_2_EXT_0"} = 0;
$numbers{"UOR_2_EXT_1"} = 0;
$numbers{"UOR_2_EXT_2"} = 0;
$numbers{"UOR_2_EXT_3"} = 0;

$numbers{"UOR_2_RTP_NO_EXT"} = 0;
$numbers{"UOR_2_RTP_EXT_0"} = 0;
$numbers{"UOR_2_RTP_EXT_1"} = 0;
$numbers{"UOR_2_RTP_EXT_2"} = 0;
$numbers{"UOR_2_RTP_EXT_3"} = 0;

$numbers{"UOR_2_TS_NO_EXT"} = 0;
$numbers{"UOR_2_TS_EXT_0"} = 0;
$numbers{"UOR_2_TS_EXT_1"} = 0;
$numbers{"UOR_2_TS_EXT_2"} = 0;
$numbers{"UOR_2_TS_EXT_3"} = 0;

$numbers{"UOR_2_ID_NO_EXT"} = 0;
$numbers{"UOR_2_ID_EXT_0"} = 0;
$numbers{"UOR_2_ID_EXT_1"} = 0;
$numbers{"UOR_2_ID_EXT_2"} = 0;
$numbers{"UOR_2_ID_EXT_3"} = 0;

# log file name
$name = '/log.xml';
# tests directory
$path = '../test/report/samples/';

# file which contains the tests list
open(LIST,"list.txt");

# file which will contain the headers size
open(HEADER,">headers_size");

# file which will contain the packet_type
open(TYPE,">packet_type");

# file which will contain packets order
open(PACKETS,">packets_order");

# file which will contain packets size
open(PACKETS_SIZE,">packets_size");

$nb_tests = 0;
while(<LIST>) {

	$line = $_;
	$nb_tests++;
	chop($line);

	open(FILE,$path . $line . $name);
	
	$packet_nb = 1;
	$bool = 1;
	$size = 0;
	
	# loop on each line of the log test
	while(<FILE>) {
		$line2 = $_;
		
		################################
		# search for rohc header size
		################################
		if($nb_tests==1) { # in order to analyse only the first test

			#extraction of packets size
			$i = index($line2,'Size of IP packet');
			if($i > 0 && $bool == 1) {
				@t = split(' ',$line2);
				$indice = 0;
				foreach (@t) {
					if(index($_,'=') >= 0) {
						$size = $t[$indice + 1];
						print PACKETS_SIZE "$size ";
					}
					$indice++;
				}
			}
			$i = 0;


			# extraction of header size
			$i = index($line2,'ROHC size');
			#loop on each packet
			if($i > 0) {
				if($bool == 1) {
					@t = split(' ',$line2);
					$indice = 0;
					foreach (@t) {
						if(index($_,'header') >= 0) {
							$size = $t[$indice + 2];
							print HEADER "$packet_nb ";
							print HEADER "$size\n";
						}
						if(index($_,'ROHC') >= 0) {
							$size = $t[$indice + 3];
							print PACKETS_SIZE "$size\n";
						}
						$indice++;
					}
					$packet_nb++;
					$bool = 0;
				} else {
					$bool = 1;
				}
			}
			if($bool == 0) {
				if(search_packet($line2,'code IR packet')==1) {
					print PACKETS "IR ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code IR-DYN packet') == 1) {
					print PACKETS "IR_DYN ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UO-0 packet') == 1) {
					print PACKETS "UO_0 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UO-1 packet') == 1) {
					print PACKETS "UO_1 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UO-1-RTP packet') ==1) {
					print PACKETS "UOR_1_RTP ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UO-1-TS packet') == 1) {
					print PACKETS "UOR_1_TS ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UO-1-ID packet') ==1) {
					print PACKETS "UOR_1_ID ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2 packet with no extension') == 1) {
					print PACKETS "UOR_2_NO_EXT ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2 packet with extension 0') == 1) {
					print PACKETS "UOR_2_EXT_0 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2 packet with extension 1') == 1) {
					print PACKETS "UOR_2_EXT_1 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2 packet with extension 2') == 1) {
					print PACKETS "UOR_2_EXT_2 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2 packet with extension 3') == 1) {
					print PACKETS "UOR_2_EXT_3 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-RTP packet with no extension') == 1) {
					print PACKETS "UOR_2_RTP_NO_EXT ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-RTP packet with extension 0') == 1) {
					print PACKETS "UOR_2_RTP_EXT_0 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-RTP packet with extension 1') == 1) {
					print PACKETS "UOR_2_RTP_EXT_1 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-RTP packet with extension 2') == 1) {
					print PACKETS "UOR_2_RTP_EXT_2 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-RTP packet with extension 3') == 1) {
					print PACKETS "UOR_2_RTP_EXT_3 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-TS packet with no extension') == 1) {
					print PACKETS "UOR_2_TS_NO_EXT ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-TS packet with extension 0') == 1) {
					print PACKETS "UOR_2_TS_EXT_0 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-TS packet with extension 1') == 1) {
					print PACKETS "UOR_2_TS_EXT_1 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-TS packet with extension 2') == 1) {
					print PACKETS "UOR_2_TS_EXT_2 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-TS packet with extension 3') == 1) {
					print PACKETS "UOR_2_TS_EXT_3 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-ID packet with no extension') == 1) {
					print PACKETS "UOR_2_ID_NO_EXT ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-ID packet with extension 0') == 1) {
					print PACKETS "UOR_2_ID_EXT_0 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-ID packet with extension 1') == 1) {
					print PACKETS "UOR_2_ID_EXT_1 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-ID packet with extension 2') == 1) {
					print PACKETS "UOR_2_ID_EXT_2 ";
					print PACKETS "($size bytes)\n";
				}
				if(search_packet($line2,'code UOR-2-ID packet with extension 3') == 1) {
					print PACKETS "UOR_2_ID_EXT_3 ";
					print PACKETS "($size bytes)\n";
				}
			}
		}

		
		#################################
		# search for packet type
		#################################
			
		$numbers{"IR"} += search_packet($line2,'code IR packet');
		$numbers{"IR_DYN"} += search_packet($line2,'code IR-DYN packet');
		$numbers{"UO_0"} += search_packet($line2,'code UO-0 packet');
		$numbers{"UO_1"} += search_packet($line2,'code UO-1 packet');
		$numbers{"UO_1_RTP"} += search_packet($line2,'code UO-1-RTP packet');
		$numbers{"UO_1_TS"} += search_packet($line2,'code UO-1-TS packet');
		$numbers{"UO_1_ID"} += search_packet($line2,'code UO-1-ID packet');

		$numbers{"UOR_2_NO_EXT"} += search_packet($line2,'code UOR-2 packet with no extension');
		$numbers{"UOR_2_EXT_0"} += search_packet($line2,'code UOR-2 packet with extension 0');
		$numbers{"UOR_2_EXT_1"} += search_packet($line2,'code UOR-2 packet with extension 1');
		$numbers{"UOR_2_EXT_2"} += search_packet($line2,'code UOR-2 packet with extension 2');
		$numbers{"UOR_2_EXT_3"} += search_packet($line2,'code UOR-2 packet with extension 3');
		
		$numbers{"UOR_2_RTP_NO_EXT"} += search_packet($line2,'code UOR-2-RTP packet with no extension');
		$numbers{"UOR_2_RTP_EXT_0"} += search_packet($line2,'code UOR-2-RTP packet with extension 0');
		$numbers{"UOR_2_RTP_EXT_1"} += search_packet($line2,'code UOR-2-RTP packet with extension 1');
		$numbers{"UOR_2_RTP_EXT_2"} += search_packet($line2,'code UOR-2-RTP packet with extension 2');
		$numbers{"UOR_2_RTP_EXT_3"} += search_packet($line2,'code UOR-2-RTP packet with extension 3');
		
		$numbers{"UOR_2_TS_NO_EXT"} += search_packet($line2,'code UOR-2-TS packet with no extension');
		$numbers{"UOR_2_TS_EXT_0"} += search_packet($line2,'code UOR-2-TS packet with extension 0');
		$numbers{"UOR_2_TS_EXT_1"} += search_packet($line2,'code UOR-2-TS packet with extension 1');
		$numbers{"UOR_2_TS_EXT_2"} += search_packet($line2,'code UOR-2-TS packet with extension 2');
		$numbers{"UOR_2_TS_EXT_3"} += search_packet($line2,'code UOR-2-TS packet with extension 3');
		
		$numbers{"UOR_2_ID_NO_EXT"} += search_packet($line2,'code UOR-2-ID packet with no extension');
		$numbers{"UOR_2_ID_EXT_0"} += search_packet($line2,'code UOR-2-ID packet with extension 0');
		$numbers{"UOR_2_ID_EXT_1"} += search_packet($line2,'code UOR-2-ID packet with extension 1');
		$numbers{"UOR_2_ID_EXT_2"} += search_packet($line2,'code UOR-2-ID packet with extension 2');
		$numbers{"UOR_2_ID_EXT_3"} += search_packet($line2,'code UOR-2-ID packet with extension 3');
	}

	close(FILE);
}

foreach $type (keys %numbers) {
	$numbers{$type} = $numbers{$type}/2;
	print TYPE "$type $numbers{$type}\n";
}

close(PACKETS);
close(PACKETS_SIZE);
close(TYPE);
close(LIST);
close(HEADER);

