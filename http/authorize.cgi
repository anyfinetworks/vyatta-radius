#!/usr/bin/perl -w

use CGI;
use JSON;
use File::Touch;
use IO::Select;
use Linux::Inotify2;
use strict;
use warnings;

my $RADIUS_DIR = "/var/radius";
my $DEFAULT_URL = "http://google.com";

my $cgi = new CGI;

if ($cgi->request_method eq 'POST') {
    my $url = $cgi->param('url');
    my $token = $cgi->param('token');
    my $auth = $cgi->param('auth');

    # Read the token file
    my $json = do {
	local $/ = undef;
	open(my $fh, "$RADIUS_DIR/tokens/$token.json")
	    or die "Could not open token file: $!\n";
	<$fh>
    };

    # Parse the JSON data for this token
    my $sess = decode_json($json);

    if ($auth) {
	my $key = $sess->{"user"} . '@' . $sess->{"service"};
	my $path = "$RADIUS_DIR/sessions/$auth";

	my $inotify = new Linux::Inotify2
	    or die "Could not create inotify object: $!\n";
	my $select = IO::Select->new($inotify->fileno)
	    or die "Could not create select object: $!\n";

	# Sanitize and check authorization name
	die "Invalid authorization $auth" unless $auth =~ /[0-9a-zA-Z_]+/;
	die "Invalid authorization $auth" unless -d "$path";

	# Create and watch the confirmation file that the RADIUS server
	# will touch when receiving CoA-ACK for its CoA-Request message.
	touch("$path/.$key") or die "Could not create confirm file: $!\n";
	$inotify->watch("$path/.$key", IN_ATTRIB | IN_MODIFY)
	    or die "Could not set inotify watch: $!\n";

	# Touch the authentication key file for this session, signalling
	# a change of authorization event to the RADIUS server.
	touch("$path/$key") or die "Could not touch session file: $!\n";

	# Wait for confirmation before redirecting the user
	if ($select->can_read(4)) {
	    print $cgi->redirect($url // $DEFAULT_URL);
	    unlink("$RADIUS_DIR/tokens/$token.json");
	}
    }
}
