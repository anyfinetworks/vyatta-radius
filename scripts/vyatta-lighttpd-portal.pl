#!/usr/bin/perl
#
# vyatta-lighttpd-portal.pl: lighttpd captive portal config generator
#
# Maintainer: Anyfi Networks <eng@anyfinetworks.com>
#
# Copyright (C) 2015 Anyfi Networks AB. All Rights Reserved.
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
use File::Copy;
use Getopt::Long;
use Vyatta::Config;

my $config_file = "/etc/lighttpd.conf";
my $pid_file = "/var/run/lighttpd.pid";
my $instance;

GetOptions(
    "config=s" => \$config_file,
    "pidfile=s" => \$pid_file,
    "instance=s" => \$instance
);

sub error
{
    my $msg = shift;
    print STDERR "Error configuring lighttpd portal: $msg\n";
    exit(1);
}

sub generate_config
{
    my $config = shift;
    my $str ="";

    $config->setLevel("service radius http-portal $instance");

    my $doc = $config->returnValue("document-root") or
        error("must configure document-root");
    my $ip = $config->returnValue("ip-address") or
        error("must configure ip-address");
    my $port = $config->returnValue("tcp-port") // 80;
    error("invalid document-root") if (!-d $doc);

    $str .= "server.document-root = \"$doc\"\n";
    $str .= "server.bind = \"$ip\"\n";
    $str .= "server.port = $port\n";
    $str .= "server.pid-file = \"$pid_file\"\n";

    return $str;
}

my $config = new Vyatta::Config();

copy("/opt/vyatta/share/lighttpd-portal/lighttpd.conf", $config_file)
    or die "Could not copy lighttpd template file";
open(HANDLE, ">>", $config_file)
    or die "Could not open $config_file for writing";
select(HANDLE);
print generate_config($config);
close(HANDLE);
