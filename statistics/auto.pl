#!/usr/bin/perl -w
#
# Author: David Moreau from TAS
#

$cmd = `zenity  --text='Nombre de tests :' --height=150 --width=300 --list --separator=' ' --radiolist --column='Choix' --column='Nom du test' TRUE 'Un test en particulier' FALSE Tous`;

chop($cmd);
if($cmd eq 'Un test en particulier') {
	$cmd = "zenity  --text='Veuillez choisir le test à lancer :' --height=500 --width=300 --list --separator=' ' --checklist --column='Choix' --column='Nom du test'";

	open(LIST_ALL,'list_all.txt');
	while(<LIST_ALL>) {
		chop($_);
		$cmd = $cmd." FALSE $_";
	}
	close(LIST_ALL);

	$res = `$cmd`;


	open(LIST,'>list.txt');
	@t = split(' ',$res);
	foreach (@t) {
		print LIST "$_\n";
	}
	close(LIST);
} else {
	system('cp ./list_all.txt ./list.txt');
}


system('./test.sh < list.txt');
system('./analyse_log.pl');
$res = `wc --lines packets_order`;
@t = split(' ',$res);
$nb = $t[0];
system("./gnuplot.sh 0 $nb");
system('./stats.pl');

`zenity --info --text="Le fichier stats.html a été généré."`;


