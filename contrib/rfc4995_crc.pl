#!/usr/bin/perl -w
use strict;
#=================================
#
# ROHC CRC demo - Carsten Bormann cabo@tzi.org 2001-08-02
#
# This little demo shows the four types of CRC in use in RFC 3095,
# the specification for robust header compression.  Type your data in
# hexadecimal form and then press Control+D.
#
#---------------------------------
#
# utility
#
sub dump_bytes($) {
    my $x = shift;
    my $i;
    for ($i = 0; $i < length($x); ) {
        printf("%02x ", ord(substr($x, $i, 1)));
        printf("\n") if (++$i % 16 == 0);
    }
    printf("\n") if ($i % 16 != 0);
}

#---------------------------------
#
# The CRC calculation algorithm.
#
sub do_crc($$$) {
    my $nbits = shift;
    my $poly = shift;
    my $string = shift;

    my $crc = ($nbits == 32 ? 0xffffffff : (1 << $nbits) - 1);
    for (my $i = 0; $i < length($string); ++$i) {
      my $byte = ord(substr($string, $i, 1));
      for( my $b = 0; $b < 8; $b++ ) {
        if (($crc & 1) ^ ($byte & 1)) {
          $crc >>= 1;
          $crc ^= $poly;
        } else {
        $crc >>= 1;
        }
        $byte >>= 1;
      }
    }
    printf "%2d bits, ", $nbits;
    printf "CRC: %02x\n", $crc;
}

#---------------------------------
#
# Test harness
#
$/ = undef;
$_ = <>;         # read until EOF
my $string = ""; # extract all that looks hex:
s/([0-9a-fA-F][0-9a-fA-F])/$string .= chr(hex($1)), ""/eg;
dump_bytes($string);

#---------------------------------
#
# 32-bit segmentation CRC
# Note that the text implies this is complemented like for PPP
# (this differs from 8, 7, and 3-bit CRC)
#
#      C(x) = x^0 + x^1 + x^2 + x^4 + x^5 + x^7 + x^8 + x^10 +
#             x^11 + x^12 + x^16 + x^22 + x^23 + x^26 + x^32
#
do_crc(32, 0xedb88320, $string);

#---------------------------------
#
# 8-bit IR/IR-DYN CRC
#
#      C(x) = x^0 + x^1 + x^2 + x^8
#
do_crc(8, 0xe0, $string);

#---------------------------------
#
# 7-bit FO/SO CRC
#
#      C(x) = x^0 + x^1 + x^2 + x^3 + x^6 + x^7
#
do_crc(7, 0x79, $string);

#---------------------------------
#
# 3-bit FO/SO CRC
#
#      C(x) = x^0 + x^1 + x^3
#
do_crc(3, 0x6, $string);

