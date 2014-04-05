#!/usr/bin/perl
#
# vyatta-hlr_auc_gw.pl: HLR/AuC testing gateway for SIM authentication
#
# Based on hlr_auc_gw.c copyright (C) 2005-2007, 2012, Jouni Malinen <j@w1.fi>.
#
# Maintainer: Anyfi Networks <eng@anyfinetworks.com>
#
# Copyright (C) 2014 Anyfi Networks AB. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

use lib "/opt/vyatta/share/perl5/";

use strict;
use warnings;
use IO::Socket ();
use Socket qw(SOCK_DGRAM);
use Vyatta::Config;
use POSIX qw(setsid);
use Sys::Syslog qw(:standard :macros);
use Getopt::Long;

my $config_dir = "/etc/hostapd-radius";
my $pid_file;

GetOptions(
    "config-dir=s" => \$config_dir,
    "pid-file=s"   => \$pid_file
);

#
# Load SIM triplets (while we have access to Vyatta::Config):
#

sub load_sim_db
{
    my $config = shift;
    my %imsi2triplets = ();

    $config->setLevel("service radius user local");
    foreach my $imsi ($config->listNodes("sim"))
    {
        my @triplets = $config->returnValues("sim $imsi triplet");

        $imsi2triplets{ $imsi } = \@triplets;
    }

    return(%imsi2triplets);
}

my %sim_db = load_sim_db(new Vyatta::Config());

sub sim_resp_auth
{
    my $imsi = shift;
    my $need = shift;
    my $triplets = $sim_db{ $imsi };

    if (not $triplets) {
        syslog('notice', "received SIM-REQ-AUTH for unknown IMSI: %s", $imsi);
    } elsif (scalar(@{$triplets}) < $need) {
        syslog('warning', "not enough triplets for IMSI %s", $imsi);
    } else {
        syslog('notice', "provided %d triplets for IMSI %s", $need, $imsi);
        return("SIM-RESP-AUTH $imsi " . join(' ', @{$triplets}[0 .. ($need - 1)]));
    }

    return("SIM-RESP-AUTH FAILURE");
}

#
# Daemonize:
#

chdir '/' or die "Can't chdir to /: $!";
open STDIN, '/dev/null' or die "Can't read /dev/null: $!";
open STDOUT, '>>/dev/null' or die "Can't write to /dev/null: $!";
open STDERR, '>>/dev/null' or die "Can't write to /dev/null: $!";
defined(my $pid = fork) or die "Can't fork: $!";
if ($pid) {
    if ($pid_file)
    {
        open(HANDLE, ">", $pid_file) || die("Can't open PID file: $!");
        select(HANDLE);
        print $pid;
        close(HANDLE);
    }
    exit 0;
}
setsid or die "Can't start a new session: $!";
umask 0;

my $continue = 1;
$SIG{TERM} = sub { $continue = 0 };

openlog('vyatta-hlr_auc_gw.pl', 'cons,pid', LOG_DAEMON);

#
# Process SIM-REQ-AUTHs from hostapd:
#

my $socket_path = $config_dir . "/hlr_auc_gw.sock";

unlink($socket_path);

my $sock = IO::Socket::UNIX->new(Local  => $socket_path,
                                 Type   => SOCK_DGRAM,
                                 Listen => 5)
    or die $@;

while ($continue) {
    my $data = undef;

    $sock->recv($data, 1024, 0);
    if ($data) {
        syslog('debug', "received: '%s'", $data);
        my @cmd = split(' ', $data);

        if ($cmd[0] eq "SIM-REQ-AUTH") {
            # Request: SIM-REQ-AUTH <imsi> <# triplets needed>
            my $imsi = $cmd[1];
            my $need = $cmd[2];

            my $reply = sim_resp_auth($imsi, $need);

            # Response: SIM-RESP-AUTH <imsi> <triplet> <triplet> <triplet> ...
            $sock->send($reply);
            syslog('debug', "sent: '%s'", $reply);
        } elsif ($cmd[0] eq "AKA-REQ-AUTH") {
            syslog('warning', "command AKA-REQ-AUTH not supported");
        } elsif ($cmd[0] eq "AKA-AUTS") {
            syslog('warning', "command AKA-AUTS not supported");
        } else {
            syslog('warning', "command %s not supported", $cmd[0]);
        }
    }
}

#
# Clean up:
#

unlink($socket_path);

closelog();

unlink($pid_file);

exit 0;
