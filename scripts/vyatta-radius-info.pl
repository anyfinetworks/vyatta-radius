#!/usr/bin/perl -w

use File::Basename;
use Format::Human::Bytes;
use JSON;
use warnings;
use strict;

my $path = $ARGV[0];
my $key = basename $path;
my $dir = dirname $path;
my $fname = "$dir/.$key";
my $access = basename $dir;
my ($user, $serv) = split(/@/, $key);
my %sess;

local $/ = undef;
open(my $fh, '<', $fname) or exit 0;
%sess = %{decode_json(<$fh>)};
close $fh;

$access = '-' if $access eq '.allow';

printf("%-20s %-16s %-10s %6s up %6s down %7ds\n",
       $user, $serv, $access,
       Format::Human::Bytes::base2($sess{'upload'}[0]),
       Format::Human::Bytes::base2($sess{'download'}[0]),
       time - $sess{'timestamp'});
