use strict;
use warnings;

my $n = @ARGV;
if ($n < 3) {
	print "Usage: tm3_mod.pl [RP IP] [ifname] [fwdPort1] [fwdPort2] ...\n";
	die;
}

print "Remote proxy IP address: $ARGV[0]\n";
print "Interface name: $ARGV[1]\n";

my $pl = "";
for (my $i=2; $i<$n; $i++) {
	my $p = $ARGV[$i];
	die "Invalid port number: $p\n" if ($p <= 0 || $p > 65535);
	$pl = $pl . "$p";
	$pl = $pl . "," if ($i != $n-1);
	print "Port: $p\n";
}

system("rmmod tm3.ko");
system("insmod ./tm3.ko remoteProxyIP=$ARGV[0] fwdInterface=$ARGV[1] portList=\"$pl\"");
