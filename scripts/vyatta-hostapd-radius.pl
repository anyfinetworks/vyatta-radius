#!/usr/bin/perl
#
# vyatta-hostpad-radius.pl: hostapd-based RADIUS server config generator
#
# Maintainer: Anyfi Networks <eng@anyfinetworks.com>
#
# Copyright (C) 2014 Anyfi Networks AB
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
use File::Basename;
use Getopt::Long;
use Vyatta::Config;

my $config_header  = "### Generated by /opt/vyatta/sbin/vyatta-hostapd-radius.pl ###\n";
my $config_dir     = "/etc/hostapd-radius";

GetOptions(
    "config-dir=s" => \$config_dir
);

my $config_ca = "/opt/vyatta/share/hostapd-radius/ca.pem";
my $config_cert = "/opt/vyatta/share/hostapd-radius/server.pem";
my $config_key = "/opt/vyatta/share/hostapd-radius/server-key.pem";

sub error
{
    my $msg = shift;
    die("Error: $msg");
}

sub basic_setup
{
    my $str = "";

    $str .= "driver=none\n";
    $str .= "eap_server=1\n";
    $str .= "radius_server_clients=$config_dir/radius_clients\n";
    $str .= "eap_user_file=$config_dir/eap_users\n";
    $str .= "radius_server_auth_port=1812\n";

    return($str);
}

sub setup_identity
{
    my $ca = shift;
    my $cert = shift;
    my $key = shift;

    my $str = "";

    $str .= "ca_cert=$ca\n";
    $str .= "server_cert=$cert\n";
    $str .= "private_key=$key\n";

    return($str);
}

# hostapd.conf:

sub generate_config
{
    my $config = shift;
    $config->setLevel("service radius");

    my $config_str = basic_setup();

    # identity:

    my $ca   = $config->returnValue("identity ca-certificate");
    my $cert = $config->returnValue("identity certificate");
    my $key  = $config->returnValue("identity private-key");

    if( !defined($ca) || !defined($cert) || !defined($key) )
    {
        $ca   = $config_ca;
        $cert = $config_cert;
        $key  = $config_key;
    }
    elsif( defined($ca) || defined($cert) || defined($key) )
    {
        error("All (or none) of ca-certificate, certificate and private-key must be defined.");
    }

    $config_str .= setup_identity($ca, $cert, $key);

    # interface:

    my @interfaces = $config->returnValues("interface");
    if( !@interfaces )
    {
        error("Must specify an interface to listen on");
    }

    foreach my $intf (@interfaces)
    {
        $config_str .= "interface=$intf\n";
    }

    return($config_str);
}

# radius_clients:

sub generate_clients
{
    my $config = shift;
    my $clients_str = "";

    $config->setLevel("service radius");
    my @clients = $config->listNodes("client");

    foreach my $client (@clients)
    {
        my $ip_filter = $config->returnValue("client $client ip-filter");
        my $secret = $config->returnValue("client $client secret");

        $clients_str .= "$ip_filter $secret\n";
    }

    return($clients_str);
}

# eap_users:

sub generate_users
{
    my $config = shift;
    my $users_str = "";

    # PEAP-MSCHAPv2:

    $config->setLevel("service radius user local");
    my @users = $config->listNodes("peap-mschapv2");

    foreach my $user (@users)
    {
        my $password = $config->returnValue("peap-mschapv2 $user password");

        $users_str .= "\"$user\"\tPEAP\n";
        $users_str .= "\"$user\"\tMSCHAPV2\t\"$password\"\t[2]\n";
    }

    # SIM:

    $users_str .= "*\tSIM\n";

    return($users_str);
}

my $config = new Vyatta::Config();

open(HANDLE, ">", $config_dir . "/hostapd.conf") || die("Could not open hostapd.conf for writing");
select(HANDLE);
print $config_header;
print generate_config($config, $config_dir);
close(HANDLE);

open(HANDLE, ">", $config_dir . "/radius_clients") || die("Could not open radius_clients for writing");
select(HANDLE);
print $config_header;
print generate_clients($config);
close(HANDLE);

open(HANDLE, ">", $config_dir . "/eap_users") || die("Could not open eap_users for writing");
select(HANDLE);
print $config_header;
print generate_users($config);
close(HANDLE);

