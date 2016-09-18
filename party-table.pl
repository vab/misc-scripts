#!/usr/bin/perl -w
use strict;

# Version: 1.1
# Date:    2001.01.07
# Revised: 2004.04.06
# Author:  V. Alex Brennen <vab@cryptnet.net>
#          http://www.cryptnet.net/people/vab/
# Author:  Gerfried Fuchs <alfie@ist.org>
#          http://alfie.ist.org/alfie/
# License: Public Domain
# Description:
#          This script was written as part of the gpg keysigning
#          party howto.  It generates a checklist for individuals
#          participating in a keysigning party. The keysigning
#          howto lives at:
#               http://cryptnet.net/fdp/crypto/keysigning_party/en/keysigning_party.html

unless($ARGV[0])
{
        print "\nUsage: party-table.pl <keyring> > out_file.html\n" .
              "\nThe keyring should be the keyring where the public keys for the\n" .
              "party participants are stored.\n\n";

	exit;
}

my @fps = `gpg --fingerprint --no-default-keyring --no-options --with-colons --keyring $ARGV[0] | egrep '^(pub|fpr):'`;

print "<!DOCTYPE HTML>\n" .
      "<HTML LANG=\"en\"><HEAD>\n" .
      "<META CHARSET=\"UTF-8\"/>\n" .
      "<STYLE>table, th, td { border: 1px solid gray; }</STYLE>\n" .
      "<TITLE>PGP Keysigning Party Keys</TITLE></HEAD>\n" .
      "<BODY><TABLE>\n" .
      "<TR><TH>Key ID</TH><TH>Owner</TH><TH>Fingerprint</TH>" .
      "<TH>Size</TH><TH>Type</TH><TH>Key Info Matches?</TH><TH>Owner ID Matches?</TH></TR>\n";

while(my $line = shift(@fps))
{
        if($line =~ /^pub/)
	{
                my ($pub,$comptrust,$size,$type,$longid,$date,undef,
                    undef,$settrust,$owner,undef,undef,$flags,undef)
                      = split /:/, $line;
                my $id = substr($longid, 8);
                my ($fpr,undef,undef,undef,undef,undef,undef,undef,undef,$fingerprint)
                      = split /:/, shift(@fps);

                if($type eq '17')
		{
                        $type = 'DSA';
                }
		elsif($type eq '20')
		{
                        $type = 'El Gamal';
                }
		elsif($type eq '1')
		{
                        $type = 'RSA';
                }
                if(length($fingerprint) == 40)
		{
			for my $i (36,32,28,24,20,16,12,8,4)
			{
				substr($fingerprint,$i,0,$i == 20 ? "\n" : ' ');
			}
                }
		elsif (length($fingerprint) == 32)
		{
                        for my $i (30,28,26,24,22,20,18,16,14,12,10,8,6,4,2)
			{
				substr($fingerprint,$i,0,$i == 16 ? "\n" : ' ');
                        }
                }
		$owner =~ s/&/&amp;/;
		$owner =~ s/</&lt\;/;
                $owner =~ s/>/&gt\;/;

                print "<TR><TD><PRE>$id</PRE></TD><TD>$owner</TD>\n" .
		      "<TD><PRE>$fingerprint</PRE></TD><TD>$size</TD>\n" .
                      "<TD>$type</TD><TD>&nbsp;</TD><TD>&nbsp;</TD></TR>\n";
        }
}

print "</TABLE>\n</BODY></HTML>";
