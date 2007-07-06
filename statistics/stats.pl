#!/usr/bin/perl -w
#
# Author: David Moreau from TAS
#


open(RESULT,">stats.html");
open(TYPE,"packet_type");

while(<TYPE>) {
	@t = split(' ',$_);
	$tab{$t[0]} = $t[1];
}


$nb_UO_1 = $tab{'UO_1'} + $tab{'UO_1_TS'} + $tab{'UO_1_RTP'} + $tab{'UO_1_ID'};
$nb_UOR_2 = $tab{'UOR_2_NO_EXT' } + $tab{'UOR_2_EXT_0'} + $tab{'UOR_2_EXT_1'} + $tab{'UOR_2_EXT_2'} + $tab{'UOR_2_EXT_3'} +
          $tab{'UOR_2_RTP_NO_EXT'} + $tab{'UOR_2_RTP_EXT_0'} + $tab{'UOR_2_RTP_EXT_1'} + $tab{'UOR_2_RTP_EXT_2'} + $tab{'UOR_2_RTP_EXT_3'} +
          $tab{'UOR_2_TS_NO_EXT'} + $tab{'UOR_2_TS_EXT_0'} + $tab{'UOR_2_TS_EXT_1'} + $tab{'UOR_2_TS_EXT_2'} + $tab{'UOR_2_TS_EXT_3'} +
          $tab{'UOR_2_ID_NO_EXT'} + $tab{'UOR_2_ID_EXT_0'} + $tab{'UOR_2_ID_EXT_1'} + $tab{'UOR_2_ID_EXT_2'} + $tab{'UOR_2_ID_EXT_3'};
$nb_all = $tab{'IR'} + $tab{'IR_DYN'} + $tab{'UO_0'} + $nb_UO_1 + $nb_UOR_2;

print RESULT "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n";
print RESULT "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"fr\">";
print RESULT "<head>\n";
print RESULT "<title>Statistiques</title>\n";
print RESULT "<link rel=\"stylesheet\" href=\"./stats.css\" type=\"text/css\" />\n";
print RESULT "<meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\" />";
print RESULT "</head>\n";
print RESULT "<body>\n";

print RESULT "<h1>Statistiques</h1>";


print RESULT "<h2>R&eacute;sultats g&eacute;n&eacute;raux sur l'ensemble des tests effectu&eacute;s</h2>\n";
print RESULT "<table>\n";

print RESULT "<tr>\n";
print RESULT "<td>";

print RESULT "<div id=\"list_test\">\n";
print RESULT "<ul>\n";
open(LIST,"list.txt");
while(<LIST>) {
	$lines = $_;
	$nb_lines++;
	print RESULT "<li>$lines</li>";
}
close(LIST);
print RESULT '</ul>';
print RESULT "</div>\n";
print RESULT "</td>\n";


print RESULT "<td>";
print RESULT "<table class=\"data\">\n";

print RESULT "<tr>\n";
print RESULT "<th>Type du paquet</th>";
print RESULT "<th>Nb. de paquets</th>";
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td>IR</td>";
print RESULT "<td>$tab{'IR'}</td>";
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td>IR-DYN</td>";
print RESULT "<td>$tab{'IR_DYN'}</td>";
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td>UO-0</td>";
print RESULT "<td>$tab{'UO_0'}</td>";
print RESULT "</tr>\n";


print RESULT "<tr>\n";
print RESULT "<td>UO-1</td>";
print RESULT "<td>$nb_UO_1</td>";
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td>UOR-2</td>";
print RESULT "<td>$nb_UOR_2</td>";
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td>All</td>";
print RESULT "<td>$nb_all</td>";
print RESULT "</tr>\n";

print RESULT "</table>\n";

print RESULT "</td>";

print RESULT "<td>";
print RESULT "<table class=\"data\">\n";

print RESULT "<tr>\n";
print RESULT "<th>Type du paquet</th>";
print RESULT "<th>Nombre</th>";
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td>UO-1</td>";
print RESULT "<td>$tab{'UO_1'}</td>";
print RESULT "</tr>";

print RESULT "<tr>\n";
print RESULT "<td>UO-1-RTP</td>";
print RESULT "<td>$tab{'UO_1_RTP'}</td>";
print RESULT "</tr>";

print RESULT "<tr>\n";
print RESULT "<td>UO-1-TS</td>";
print RESULT "<td>$tab{'UO_1_TS'}</td>";
print RESULT "</tr>";

print RESULT "<tr>\n";
print RESULT "<td>UO-1-ID</td>";
print RESULT "<td>$tab{'UO_1_ID'}</td>";
print RESULT "</tr>";
print RESULT "</table>\n";
print RESULT "</td>";

print RESULT "<td>";
print RESULT "<table class=\"data\">\n";

print RESULT "<tr>\n";
print RESULT "<th>Type du paquet</th>";
print RESULT "<th>No Ext.</th>";
print RESULT "<th>Ext. 0</th>";
print RESULT "<th>Ext. 1</th>";
print RESULT "<th>Ext. 2</th>";
print RESULT "<th>Ext. 3</th>";
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td>UOR-2</td>";
print RESULT "<td>$tab{'UOR_2_NO_EXT'}</td>";
print RESULT "<td>$tab{'UOR_2_EXT_0'}</td>";
print RESULT "<td>$tab{'UOR_2_EXT_1'}</td>";
print RESULT "<td>$tab{'UOR_2_EXT_2'}</td>";
print RESULT "<td>$tab{'UOR_2_EXT_3'}</td>";
print RESULT "</tr>";

print RESULT "<tr>\n";
print RESULT "<td>UOR-2-RTP</td>";
print RESULT "<td>$tab{'UOR_2_RTP_NO_EXT'}</td>";
print RESULT "<td>$tab{'UOR_2_RTP_EXT_0'}</td>";
print RESULT "<td>$tab{'UOR_2_RTP_EXT_1'}</td>";
print RESULT "<td>$tab{'UOR_2_RTP_EXT_2'}</td>";
print RESULT "<td>$tab{'UOR_2_RTP_EXT_3'}</td>";
print RESULT "</tr>";

print RESULT "<tr>\n";
print RESULT "<td>UOR-2-TS</td>";
print RESULT "<td>$tab{'UOR_2_TS_NO_EXT'}</td>";
print RESULT "<td>$tab{'UOR_2_TS_EXT_0'}</td>";
print RESULT "<td>$tab{'UOR_2_TS_EXT_1'}</td>";
print RESULT "<td>$tab{'UOR_2_TS_EXT_2'}</td>";
print RESULT "<td>$tab{'UOR_2_TS_EXT_3'}</td>";
print RESULT "</tr>";

print RESULT "<tr>\n";
print RESULT "<td>UOR-2-ID</td>";
print RESULT "<td>$tab{'UOR_2_ID_NO_EXT'}</td>";
print RESULT "<td>$tab{'UOR_2_ID_EXT_0'}</td>";
print RESULT "<td>$tab{'UOR_2_ID_EXT_1'}</td>";
print RESULT "<td>$tab{'UOR_2_ID_EXT_2'}</td>";
print RESULT "<td>$tab{'UOR_2_ID_EXT_3'}</td>";
print RESULT "</tr>";

print RESULT "</table>\n";

print RESULT "</td>";
print RESULT "</tr>";




print RESULT "</table>\n";







#titre
open(LIST,"list.txt");
$nb_lines = 0;
while(<LIST>) {
	$lines = $_;
	$nb_lines++;
	if($nb_lines == 1) {
		print RESULT "<h2>D&eacute;tail du premier test : $lines</h2>";
	}
}
close(LIST);


print RESULT "<table>\n";
print RESULT "<tr>\n";

print RESULT "<td>\n";
print RESULT "<div style=\"text-align:center\" ><img src=\"./header_size.png\" /></div>\n";
print RESULT "</td>\n";


# List of packets
open(PACKETS,"packets_order");
print RESULT "<td>\n";
print RESULT "<div id=\"list_packets\">\n";
print RESULT "<ul>\n";
while(<PACKETS>) {
	print RESULT "<li>$_</li>";
}
print RESULT "</ul>\n";
print RESULT "</div>\n";
print RESULT "</td>\n";
close(PACKETS);

print RESULT "</tr>\n";
print RESULT "</table>\n";






print RESULT "<table>\n";
print RESULT "<tr>\n";

print RESULT "<td>\n";
print RESULT "<div style=\"text-align:center\" ><img src=\"./packets_size.png\" /></div>\n";
print RESULT "</td>\n";

open(PACKETS_SIZE,"packets_size");

$sum_no_compress = 0;
$sum_rohc = 0;
$nb = 0;
while(<PACKETS_SIZE>) {
	@t = split(' ',$_);		
	$sum_no_compress += $t[0];
	$sum_rohc += $t[1];
	$nb++;
}
close(PACKETS_SIZE);

$sum_no_compress = $sum_no_compress / $nb;
$sum_rohc = $sum_rohc / $nb;
$rate = (($sum_no_compress - $sum_rohc)/$sum_no_compress)*100;

print RESULT "<td>\n";

print RESULT "<table>\n";
print RESULT "<tr>\n";
print RESULT "<td class=\"left\">Nombre de paquets :</td>\n";
print RESULT "<td>$nb</td>\n";
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td class=\"left\">Taille moyenne des paquets sans compression :</td>\n";
printf RESULT "<td>%d octets</td>\n",$sum_no_compress;
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td class=\"left\">Taille moyenne des paquets avec ROHC :</td>\n";
printf RESULT "<td>%d octets</td>\n",$sum_rohc;
print RESULT "</tr>\n";

print RESULT "<tr>\n";
print RESULT "<td class=\"left\">Taux de compression : </td>\n";
printf RESULT "<td>%.1f%%</td>\n",$rate;
print RESULT "</tr>\n";

print RESULT "</td>\n";
print RESULT "</tr>\n";
print RESULT "</table>\n";


print RESULT "</body>\n";
print RESULT "</html>";

close(RESULT);

