#!/usr/bin/perl
#
# vyatta-hostpad-radius.pl: hostapd-based RADIUS server config generator
#
# Maintainer: Daniil Baturin <daniil@baturin.org>
#
# Copyright (C) 2014 AnyFi Networks
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
#

use lib "/opt/vyatta/share/perl5/";

use strict;
use warnings;
use Vyatta::Config;

my $config_file = "/etc/hostpad-radius.conf";
my $config_header = "### Generated by /opt/vyatta/sbin/vyatta-hostapd-radius.pl ###\n";

sub error
{
    my $msg = shift;
    die("Error: $msg");
}

sub basic_setup
{
    my $str = "driver=none \n";
    $str .= "eap_server=1 \n";
    $str .= "eap_user_file=/etc/hostapd.eap_user \n";
    $str .= "radius_server_clients=/etc/hostapd.radius_clients \n";
    $str .= "radius_server_auth_port=1812 \n";
    return($str);
}

sub setup_interface
{
    my $intf = shift;
    my $str = "interface=$intf \n";
    return($str);
}

sub setup_tls
{
    my $ca = shift;
    my $cert = shift;
    my $key = shift;
    my $str = "ca_cert=$ca \n";
    $str .= "server_cert=$cert \n";
    $str .= "private_key=$key \n";
    return($str);
}

sub setup_identity_name
{
    my $name = shift;
    my $str = "server_id = $name \n";
    return($str);
}

sub generate_config
{
    my $config = shift;
    $config->setLevel("service radius");

    my $config_str = "";

    $config_str .= basic_setup();

    my $cert = $config->returnValue("identity certificate");
    my $ca = $config->returnValue("identity ca-certificate");
    my $key = $config->returnValue("identity private-key");
    if( !defined($cert) || !defined($ca) || !defined($key) )
    {
        error("Must define all of ca-certificate, certificat, and private-key");
    }

    my @interfaces = $config->returnValues("interface");
    if( !@interfaces )
    {
        error("Must specify an interface to listen on");
    }

    foreach my $intf (@interfaces)
    {
        $config_str .= setup_interface($intf);
    }

    my $identity_name = $config->returnValue("identity name");
    if( defined($identity_name) )
    {
        $config_str = setup_identity_name($identity_name);
    }

    return($config_str);
}

my $config = new Vyatta::Config();

# For debug, just print on stdout
#open(HANDLE, ">$config_file") || die("Could not open $config_file for write");
#select(HANDLE);
print $config_header;
print generate_config($config);
#close(HANDLE);


