#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5/";

use Getopt::Long;
use Vyatta::Config;
use Net::CIDR;
use Net::Radius::Dictionary;
use Net::Radius::Packet;
use Digest::HMAC_MD5;
use Linux::Inotify2;
use List::Util qw(min max sum);
use File::Basename;
use File::Touch;
use File::Copy;
use File::Path qw(make_path);
use Scalar::Util qw(looks_like_number);
use Format::Human::Bytes;
use IO::Socket::INET;
use IO::Select;
use POSIX qw(setsid);
use Sys::Syslog qw(:standard :macros);
use sigtrap 'handler' => \&cleanup, 'INT', 'TERM';
use JSON;
use warnings;
use strict;

my $PID_FILE = "/var/run/vyatta-radius.pid";

# The RADIUS authorization directory
my $RADIUS_DIR = "/var/radius";
GetOptions(
    "radius-dir=s" => \$RADIUS_DIR,
);

my $SESSION_DIR = "$RADIUS_DIR/sessions";
my $TOKEN_DIR = "$RADIUS_DIR/tokens";

# The RADIUS dictionaries to load
my $DICTIONARY_DIR = "/opt/vyatta/share/radius";
my @DICTIONARIES = ("$DICTIONARY_DIR/dictionary",
		    "$DICTIONARY_DIR/dictionary.base",
		    "$DICTIONARY_DIR/dictionary.tunnel",
		    "$DICTIONARY_DIR/dictionary.wispr",
		    "$DICTIONARY_DIR/dictionary.microsoft",
		    "$DICTIONARY_DIR/dictionary.cisco");
my $DICTIONARY;

# Attributes to be copied from a RADIUS request to the response
my @ATTRIBUTES = ('Calling-Station-Id',
		  'Called-Station-Id',
		  'User-Name',
		  'NAS-Identifier',
		  'NAS-IP-Address');

# The minumum allowable session duration
my $MIN_DURATION = 5;

# Client configuration
my $SECRET;
my $SUBNET;

# Our addresses
my $AUTH_SERVER;
my $AUTZ_SERVER;
my $ACCT_SERVER;

# Static configuration and session state
my %CONFIGURATION = ();
my %SESSIONS = ();

# Default allow pseudo class
my $ALLOW = '.allow';

### CONFIGURATION #########################################################

sub config_error
{
    print STDERR "Error configuring radius server: ", @_, "\n";
    exit 1;
}

sub check_range
{
    my ($name, $val, $minval, $maxval) = @_;
    if (!looks_like_number($val) || $val < $minval || $val > $maxval) {
	config_error("bad format for $name.");
    }
}

sub check_access
{
    my $ac = $_[0];
    if (defined $ac && !defined $CONFIGURATION{'access'}{$ac}) {
	config_error("bad access class $ac.");
    }
}

# Configure from Vyatta data model.
sub configure
{
    my $config = new Vyatta::Config();

    $config->setLevel("service radius");

    # Configure client
    my @clients = $config->listNodes("client");
    config_error("at least one client required.") if (scalar @clients == 0);
    config_error("only one client may be configured.") if (scalar @clients > 1);
    $SUBNET = $config->returnValue("client " . $clients[0] . " ip-filter") or
	config_error("client ip-filter required.");
    $SECRET = $config->returnValue("client " . $clients[0] . " secret") or
	config_error("client secret required.");

    # Configure access rules
    my @access = $config->listNodes("access");
    foreach my $name (@access) {
	my %rules = ();
	my @attrs = ();
	my $value;

	# WISPr-Bandwidth-Max-Down attribute
	$value = $config->returnValue("access $name max-bandwidth-down");
	if (defined $value) {
	    check_range('max-bandwidth-down', $value, 0, 1024);
	    push(@attrs, ['WISPr-Bandwidth-Max-Down',
			  $value * 1000 * 1000, 'WISPr']);
	}

	# WISPr-Bandwidth-Max-Up attribute
	$value = $config->returnValue("access $name max-bandwidth-up");
	if (defined $value) {
	    check_range('max-bandwidth-up', $value, 0, 1024);
	    push(@attrs, ['WISPr-Bandwidth-Max-Up',
			  $value * 1000 * 1000, 'WISPr']);
	}

	# Tunnel-* attributes
	$value = $config->returnValue("access $name vlan-id");
	if (defined $value) {
	    check_range('vlan-id', $value, 1, 4094);
	    push(@attrs, ['Tunnel-Type', 'VLAN', undef]);
	    push(@attrs, ['Tunnel-Medium-Type', 'IEEE-802', undef]);
	    push(@attrs, ['Tunnel-Private-Group-Id', $value, undef]);
	}

	# NAS-Filter-Rule attribute
	my @whitelist = $config->returnValues("access $name white-list");
	foreach my $ipnet (@whitelist) {
	    push(@attrs, ['NAS-Filter-Rule',
			  "permit in ip from any to $ipnet\0", undef]);
	}
	if ($config->exists("access $name block-non-http")) {
	    push(@attrs, ['NAS-Filter-Rule',
			  "permit in 17 from any to any 53,67\0", undef]);
	    push(@attrs, ['NAS-Filter-Rule',
			  "deny in ip from any to any\0", undef]);
	}

	# Meta attributes
	$value = $config->returnValue("access $name redirect-to");
	if (defined $value) {
	    my $ipaddr = $config->returnValue("http-portal $value ip-address");
	    my $port = $config->returnValue("http-portal $value tcp-port");
	    $rules{'redirect-url'} = "http://$ipaddr:$port";
	}

	$value = $config->returnValue("access $name max-volume-down");
	$rules{'max-download'} = 1024 * 1024 * $value if defined $value;

	$value = $config->returnValue("access $name max-volume-up");
	$rules{'max-upload'} = 1024 * 1024 * $value if defined $value;
	if (defined $rules{'max-upload'} ||
	    defined $rules{'max-download'})
	{
	    push(@attrs, ['Acct-Interim-Interval', 60, undef]);
	}

	$value = $config->returnValue("access $name max-duration");
	$rules{'max-duration'} = $value if defined $value;

	@{$rules{'attributes'}} = @attrs;
	%{$CONFIGURATION{'access'}{$name}} = %rules;
    }

    # Default allow if no access class specified
    %{$CONFIGURATION{'access'}{$ALLOW}} = (
	'attributes' => [],
    );

    # Configure users
    $config->setLevel("service radius user");
    my @peaps = $config->listNodes("local peap-mschapv2");
    foreach my $name (@peaps) {
	my $ac = $config->returnValue("local peap-mschapv2 $name access");
	check_access($ac);
	$CONFIGURATION{'users'}{'name'}{$name} = $ac // $ALLOW;
    }

    my @sims = $config->listNodes("local sim");
    foreach my $name (@sims) {
	my $ac = $config->returnValue("local sim $name access");
	check_access($ac);
	$CONFIGURATION{'users'}{'name'}{$name} = $ac // $ALLOW;
    }

    my @macs = $config->listNodes("local mac");
    foreach my $name (@macs) {
	my $ac = $config->returnValue("local mac $name access");
	check_access($ac);
	$name =~ tr/:/-/;
	$CONFIGURATION{'users'}{'mac'}{$name} = $ac // $ALLOW;
    }

    my @services = $config->listNodes("local service ip-filter");
    foreach my $name (@services) {
	my $ac = $config->returnValue("local service ip-filter $name access");
	check_access($ac);
	$CONFIGURATION{'users'}{'service'}{$name} = $ac // $ALLOW;
    }

    my @nases = $config->listNodes("local nas identifier");
    foreach my $name (@nases) {
	my $ac = $config->returnValue("local nas identifier $name access");
	check_access($ac);
	$CONFIGURATION{'users'}{'nas'}{$name} = $ac // $ALLOW;
    }

    my @subnets = $config->listNodes("local nas ip-filter");
    foreach my $name (@subnets) {
	my $ac = $config->returnValue("local nas ip-filter $name access");
	check_access($ac);
	$CONFIGURATION{'users'}{'nas'}{$name} = $ac // $ALLOW;
    }

    $AUTH_SERVER = pack_sockaddr_in(1814, inet_aton("127.0.0.1"));
    $AUTZ_SERVER = pack_sockaddr_in(1812, inet_aton("127.0.0.1"));
    $ACCT_SERVER = pack_sockaddr_in(1813, inet_aton("127.0.0.1"));
}

sub reload
{
    my $sock = $_[0];
    my @groups = <$SESSION_DIR/*>;

    foreach my $dir (@groups, "$SESSION_DIR/$ALLOW") {
	my @files = <$dir/*>;

	foreach my $file (@files) {
	    my $key = load_session($file);
	    my $sess = $SESSIONS{$key} if defined $key;
	    my $access = $sess->{'access'} if defined $sess;

	    if (defined $access && defined $CONFIGURATION{'access'}{$access}) {
		info("Reauthorizing session $key with access $access");
		handle_authorize($key, undef, $sock);
	    }
	    elsif (defined $key) {
		info("Deauthorizing session $key");
		handle_deauthorize($key, $sock),
	    }
	}
    }
}

### LOGGING ###############################################################

my $LOGLEVEL =  1;
my $LOGWARN  = -1;
my $LOGINFO  =  0;
my $LOGDEBUG =  1;
my $LOGTRACE =  2;

sub warning { syslog('warning', join('', @_, "\n")) if $LOGLEVEL >= $LOGWARN; }
sub info    { syslog('notice', join('', @_, "\n")) if $LOGLEVEL >= $LOGINFO; }
sub debug   { syslog('debug', join(' ', @_, "\n")) if $LOGLEVEL >= $LOGDEBUG; }
sub trace   { syslog('debug', join('', @_, "\n")) if $LOGLEVEL >= $LOGTRACE; }

sub warnmsg  { logmsg('warning', @_) if $LOGLEVEL >= $LOGWARN; }
sub infomsg  { logmsg('notice', @_) if $LOGLEVEL >= $LOGINFO; }
sub debugmsg { logmsg('debug', @_) if $LOGLEVEL >= $LOGDEBUG; }
sub tracemsg
{
    if ($LOGLEVEL >= $LOGTRACE) {
	my $msg = shift;
	my $whence = shift;
	syslog('debug', join('', "Peer ", sintoa($whence), ": ", @_, "\n"));
	$msg->dump;
    }
}

sub logmsg
{
    my $lvl = shift;
    my $msg = shift;
    my $whence = shift;
    my $who = $msg->attr('User-Name') // $msg->attr('Calling-Station-Id');
    my $what = $msg->attr('Called-Station-Id');

    my $str = $msg->code . " ";
    $str .= "for $who " if defined $who;
    $str .= "on $what " if defined $what;
    $str .= join('', "from ", sintoa($whence), ": ", @_, "\n");
    syslog($lvl, $str);
    return;
}

sub sintoa
{
    my $sin = shift;
    my ($port, $ip) = sockaddr_in($sin);
    return inet_ntoa($ip) . ":$port";
}

sub bytestoa { Format::Human::Bytes::base2 $_[0]; }

### UTILITIES #############################################################

# Convert between <user>@<service> key and individual values.
sub get_key     { return $_[0] . '@' . $_[1]; }
sub get_user    { return (split(/@/, $_[0]))[0]; }
sub get_service { return (split(/@/, $_[0]))[1]; }

sub match_cidr
{
    my ($cidr, $ip) = @_;
    return unless is_ip($ip);
    return 1 if $cidr eq $ip;
    return unless is_cidr($cidr);
    return Net::CIDR::cidrlookup($ip, $cidr);
}

# Check if a value is an IPv4 address.
sub is_ip { return $_[0] =~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/; }

# Check if a value is an IPv4 CIDR.
sub is_cidr { return $_[0] =~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/; }

# Check if a value is MAC address.
sub is_mac { return $_[0] =~ /^([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})$/; }

# Get the file system path for a session.
sub get_path { return $SESSION_DIR . '/' . $_[0]->{'access'}; }

# Generate a new session token.
sub get_token
{
    my @charset = ('A'..'Z', 'a'..'z', '0'..'9');
    my $token;
    $token .= $charset[rand @charset] for 1..16;
    return $token;
}

### RADIUS MESSAGE HANDLING ###############################################

# Calculate the Message-Authenticator attribute value for a RADIUS packet.
sub calc_msg_auth
{
    my ($p, $msg, $prauth, $secret) = @_;
    my $auth = $msg->attr('Message-Authenticator');

    if (defined $auth and length($auth) == 16) {
	my $loc = index($p, $auth);
	$auth = Digest::HMAC_MD5::hmac_md5(substr($p, 0, 4) . $prauth .
					   substr($p, 20, $loc - 20) .
					   "\0" x 16 .
					   substr($p, $loc + 16),
					   $secret);
	return ($auth, $loc);
    }
    return;
}

# Generate the Message-Authenticator attribute in a RADIUS packet.
sub auth_msg
{
    my ($p, $msg, $prauth, $secret) = @_;
    my ($auth, $loc) = calc_msg_auth($p, $msg, $prauth, $secret);

    if (defined $auth) {
	substr($p, $loc, 16, $auth);
    }
    return $p;
}

# Verify the Message-Authenticator attribute in a RADIUS packet.
sub auth_msg_verify
{
    my ($p, $msg, $prauth, $secret) = @_;
    my ($auth) = calc_msg_auth($p, $msg, $prauth, $secret);
    return if !defined $auth && defined $msg->attr('EAP-Message');
    return if defined $auth && $auth ne $msg->attr('Message-Authenticator');
    return 1;
}

# Generate the request authenticator in a RADIUS packet.
sub auth_req
{
    auth_resp(@_, 1);
}

# Verify the response authenticator in a RADIUS packet.
sub auth_resp_verify
{
    my ($p, $prauth, $secret) = @_;
    return auth_req_verify($p, $secret, $prauth);
}

# Get the corresponding request authenticator for a response packet.
my %AUTHENTICATORS = ();
sub get_authenticator
{
    my ($p, $whence, $proxy) = @_;
    my $key = ord(substr($p, 1, 1)) + ($proxy << 8);
    return delete $AUTHENTICATORS{$whence}[$key];
}

# Save the request autenticator for a request packet.
sub set_authenticator
{
    my ($p, $whence, $proxy) = @_;
    my $key = ord(substr($p, 1, 1)) + ($proxy << 8);
    return $AUTHENTICATORS{$whence}[$key] = substr($p, 4, 16);
}

# Get the identifer for our requests.
my %IDENTIFIERS = ();
sub get_identifier
{
    my $id = $IDENTIFIERS{$_[0]} // 0;
    $IDENTIFIERS{$_[0]} = ($id + 1) % 256;
    return $id;
}

# Decode our Proxy-State data.
sub decode_state
{
    my $msg = $_[0];

    my $whence = $msg->attr('Proxy-State') or return;
    $msg->unset_attr('Proxy-State', $whence);

    foreach my $attr (reverse @ATTRIBUTES) {
	my $value = $msg->attr('Proxy-State');
	return unless defined $value;
	$msg->unset_attr('Proxy-State', $value);
	$msg->set_attr($attr, $value, 1) if $value ne "";
    }
    return $whence;
}

# Encode our Proxy-State data.
sub encode_state
{
    my ($msg, $whence) = @_;

    foreach my $attr (@ATTRIBUTES) {
	my $value = $msg->attr($attr) // "";
	$msg->set_attr('Proxy-State', $value);
    }
    $msg->set_attr('Proxy-State', $whence);
}

# Decode a binary RADIUS packet into a message.
sub decode_radius
{
    my ($p, $whence) = @_;
    my $msg = new Net::Radius::Packet($DICTIONARY, $p) or return;
    my $origin;

    if ($msg->code eq 'Access-Request') {
	# No validation possible
    }
    elsif ($msg->code eq 'Accounting-Request') {
	# Verify request authenticator
	auth_acct_verify($p, $SECRET)
	    or warnmsg($msg, $whence, "Bad request authenticator") or return;
    }
    elsif ($msg->code eq 'Access-Accept' or
	   $msg->code eq 'Access-Reject' or
	   $msg->code eq 'Access-Challenge')
    {
	# Decode our Proxy-State
	$origin = decode_state($msg)
	    or warnmsg($msg, $whence, "Missing Proxy-State") or return;

	# Fetch request authenticator
	my $prauth = get_authenticator($p, $origin, 1);

	# Verify Message-Authenticator
        auth_msg_verify($p, $msg, $prauth, $SECRET)
	    or warnmsg($msg, $whence, "Bad Message-Authenticator") or return;

	# Verify response authenticator
	auth_resp_verify($p, $prauth, $SECRET)
	    or warnmsg($msg, $whence, "Bad response authenticator") or return;

	# Rewrite attributes
	$msg->set_authenticator($prauth);
    }
    elsif ($msg->code eq 'CoA-ACK' or
	   $msg->code eq 'CoA-NAK' or
	   $msg->code eq 'Disconnect-ACK' or
	   $msg->code eq 'Disconnect-NAK')
    {
	# Fetch request authenticator
	my $prauth = get_authenticator($p, $whence, 0);

	# Verify Message-Authenticator
	auth_msg_verify($p, $msg, $prauth, $SECRET)
	    or warnmsg($msg, $whence, "Bad Message-Authenticator") or return;

	# Verify response authenticator
	auth_resp_verify($p, $prauth, $SECRET)
	    or warnmsg($msg, $whence, "Bad response authenticator") or return;
    }

    return ($msg, $origin);
}

# Encode a RADIUS message into a binary packet.
sub encode_radius
{
    my ($msg, $src, $dest) = @_;
    my $p;

    if ($msg->code eq 'Access-Request') {
	# Store the NAS address in Proxy-State
	encode_state($msg, $src);

	# Generate Message-Authenticator (if present)
	$p = auth_msg($msg->pack, $msg, $msg->authenticator, $SECRET);

	# Store request authenticator
	set_authenticator($p, $src, 1);
    }
    elsif ($msg->code eq 'Access-Accept' or
	   $msg->code eq 'Access-Reject' or
	   $msg->code eq 'Access-Challenge' or
	   $msg->code eq 'Accounting-Response')
    {
	# Generate Message-Authenticator (if present)
	$p = auth_msg($msg->pack, $msg, $msg->authenticator, $SECRET);

	# Generate response authenticator
	$p = auth_resp($p, $SECRET);
    }
    elsif ($msg->code eq 'CoA-Request' or
	   $msg->code eq 'Disconnect-Request')
    {
	# Generate Message-Authenticator (if present)
	$p = auth_msg($msg->pack, $msg, "\0" x 16, $SECRET);

	# Generate request authenticator
	$p = auth_req($p, $SECRET);

	# Store request authenticator
	set_authenticator($p, $dest, 0);
    }
    return $p;
}

# Parse RADIUS identification attributes.
sub parse_radius
{
    my $msg = $_[0];
    my $user = $msg->attr('User-Name') // $msg->attr('Calling-Station-Id');
    my $mac = $msg->attr('Calling-Station-Id');
    my $ap = $msg->attr('Called-Station-Id');
    my $nas = $msg->attr('NAS-Identifier') // $msg->attr('NAS-IP-Address');
    my ($radio, $serv, $ip) = split(':', $ap) if defined $ap;
    return ($user, $mac, $ip // $serv, $nas);
}

# Make a RADIUS response message.
sub make_response
{
    my ($msg, $code) = @_;
    my $resp = new Net::Radius::Packet $DICTIONARY;

    $resp->set_identifier($msg->identifier);
    $resp->set_authenticator($msg->authenticator);
    $resp->set_code($code);
    foreach my $attr (@ATTRIBUTES) {
	my $value = $msg->attr($attr);
	$resp->set_attr($attr, $value) if defined $value;
    }

    return $resp;
}

# Make a RADIUS request message.
sub make_request
{
    my ($key, $whence, $code) = @_;
    my $sess = $SESSIONS{$key} or return;
    my $user = get_user($key);
    my $serv = get_service($key);
    my $msg = new Net::Radius::Packet $DICTIONARY;

    $msg->set_identifier(get_identifier($whence));
    $msg->set_code($code);
    $msg->set_attr('User-Name', $user);
    $msg->set_attr('Calling-Station-Id', $user) if is_mac($user);
    $msg->set_attr('Called-Station-Id', ":$serv");
    $msg->set_attr('NAS-Identifier', $sess->{'nas'});
    $msg->set_attr('Event-Timestamp', time);
    return $msg
}

### SESSION HANDLING ######################################################

# Check the time duration constraints for a session.
sub validate_session_time
{
    my $key = shift;
    my $margin = shift // 0;
    my $sess = defined $key && $SESSIONS{$key} or return;
    my $access = $CONFIGURATION{'access'}{$sess->{'access'}};
    my $limit = $access->{'max-duration'};

    return if (defined $limit &&
	       time - $sess->{'timestamp'} >= $limit - $margin);
    return $key;
}

# Check the data volume constraints for a session.
sub validate_session_volume
{
    my $key = $_[0];
    my $sess = defined $key && $SESSIONS{$key} or return;
    my $access = $CONFIGURATION{'access'}{$sess->{'access'}};

    my $limit = $access->{'max-download'};
    return if (defined $limit && sum(@{$sess->{'download'}}) >= $limit);

    $limit = $access->{'max-upload'};
    return if (defined $limit && sum(@{$sess->{'upload'}}) >= $limit);
    return $key;
}

# Validate all session constraints.
sub validate_session
{
    return validate_session_time(@_) &&
    	   validate_session_volume(@_);
}

# Find the session key for a user and service.
sub find_session
{
    my ($user, $mac, $serv) = @_;
    return unless defined $user and defined $serv;

    my $key = get_key($user, $serv);
    return $key if defined $SESSIONS{$key};
    return;
}

# Create a new session for a user from the configuration.
sub config_session
{
    my ($user, $mac, $serv, $nas, $whence) = @_;
    my $key = get_key($user, $serv);
    my $access;
    my @cred = (
	['name', $user],
	['mac',  $mac],
    );

    foreach my $cr (@cred) {
	my ($type, $id) = @{$cr};
	$access = defined $id && $CONFIGURATION{'users'}{$type}{$id};
	last if defined $access;
    }
    if (!defined $access) {
	foreach my $key  (keys %{$CONFIGURATION{'users'}{'service'}}) {
	    if ($serv eq $key || match_cidr($key, $serv)) {
		$access = $CONFIGURATION{'users'}{'service'}{$key};
		last;
	    }
	}
    }
    if (!defined $access) {
	foreach my $key  (keys %{$CONFIGURATION{'users'}{'nas'}}) {
	    if ($nas eq $key || match_cidr($key, $nas)) {
		$access = $CONFIGURATION{'users'}{'nas'}{$key};
		last;
	    }
	}
    }
    return unless defined $access;
    return create_session($key, $access, $nas, $whence);
}

# Create a new session for a given key and access group.
sub create_session
{
    my ($key, $access, $nas, $whence) = @_;
    my $user = get_user($key);
    my $serv = get_service($key);

    delete_session($key);
    %{$SESSIONS{$key}} = (
	'token' => get_token, # Session token string for HTTP portal
	'access' => $access,  # Access group this session belongs to
	'account' => undef,   # Accounting session (Acct-Session-Id)
	'user' => $user,      # User ID
	'service' => $serv,   # Service ID
	'nas' => $nas,        # NAS ID (NAS-IP-Address or NAS-Identifier)
	'port' => $whence,    # NAS source address (IP + port)
	'upload' => [0, 0],   # Total bytes uploaded(Acct-Input-Octets)
	'download' => [0, 0], # Total bytes downloaded (Acct-Output-Octets)
	'timestamp' => time,  # Session start timestamp
    );

    # Touch session handle out-of-tree so we don't get an inotify event
    move("$SESSION_DIR/$access/$key", "$RADIUS_DIR/.tmp");
    touch("$RADIUS_DIR/.tmp");
    move("$RADIUS_DIR/.tmp", "$SESSION_DIR/$access/$key") or return;

    info("New session $key with access $access");
    return $key;
}

# Delete the session for a key.
sub delete_session
{
    my $key = $_[0];
    my $sess = delete $SESSIONS{$key} or return;
    my $path = get_path($sess);

    # Move the session handle so we don't get an inotify event
    move("$path/$key", "$RADIUS_DIR/.tmp");
    unlink("$path/.$key");
    unlink("$TOKEN_DIR/" . $sess->{'token'} . ".json");

    info("Deleted session $key with access " . $sess->{'access'});
    return $key;
}

# Start an accounting session.
sub start_session
{
    my ($key, $account, $whence) = @_;
    my $user = get_user($key);
    my $serv = get_service($key);
    my $sess = $SESSIONS{$key} or return;

    $sess->{'account'} = $account if defined $account;
    $sess->{'port'} = $whence if defined $whence;
    write_session($key);

    info("Starting accounting session ", $account // "", " for $user");
}

# Stop an accounting session.
sub stop_session
{
    my ($key, $account) = @_;
    my $user = get_user($key);
    my $serv = get_service($key);
    my $sess = $SESSIONS{$key} or return;

    $sess->{'upload'}[0] += $sess->{'upload'}[1];
    $sess->{'download'}[0] += $sess->{'download'}[1];
    $sess->{'upload'}[1] = $sess->{'download'}[1] = 0;

    info("Stopping accounting session $account for $user",
	 " upload ", bytestoa($sess->{'upload'}[0]),
	 " download ", bytestoa($sess->{'download'}[0]));
}

# Write session data to file system.
sub write_session
{
    my $key = $_[0];
    my $sess = $SESSIONS{$key} or return;
    my $token = $sess->{'token'};
    my $fname = get_path($sess) . "/.$key";

    open(my $fh, '>', $fname) or die "Could not open $fname: $!\n";
    print $fh encode_json($sess);
    close $fh;
    symlink($fname, "$TOKEN_DIR/$token.json") if defined $token;

    debug("Wrote session $key to $fname");
    return $key;
}

# Load a session from the file system.
sub load_session
{
    my $path = $_[0];
    my $key = basename $path;
    my $dir = dirname $path;
    my $fname = "$dir/.$key";
    my $access = basename $dir;
    return if defined $SESSIONS{$key};

    local $/ = undef;
    if (open(my $fh, '<', $fname)) {
	eval { %{$SESSIONS{$key}} = %{decode_json(<$fh>)}; };
	close $fh;
    }
    if (!defined $SESSIONS{$key}) {
	unlink($path);
	unlink($fname);
	return;
    }

    debug("Loaded session $key from $fname");
    return $key;
}

# Update an accounting session for a key.
sub update_session
{
    my ($key, $account, $upload, $download) = @_;
    my $user = get_user($key);
    my $serv = get_service($key);
    my $sess = $SESSIONS{$key} or return;

    if ($account eq $sess->{'account'}) {
	debug("Updating accounting session $account for $user upload +" .
	      bytestoa($upload) . " download +" . bytestoa($download));

	$sess->{'upload'}[1] = $sess->{'upload'}[0] + $upload;
	$sess->{'download'}[1] = $sess->{'download'}[0] + $download;
    }
}

# Apply session restrictions to RADIUS message.
sub apply_session
{
    my ($key, $msg) = @_;
    my $sess = $SESSIONS{$key} or return;
    my $access = $CONFIGURATION{'access'}{$sess->{'access'}};
    my $limit = $access->{'max-duration'};
    my $url = $access->{'redirect-url'};

    if (defined $limit) {
	$msg->set_attr('Session-Timeout',
		       max($limit + $sess->{'timestamp'} - time, 1), 1);
    }
    if (defined $url) {
	my $sep = $url =~ /\?/ ? '&' : '?';
	$msg->set_vsattr('WISPr', 'WISPr-Redirection-URL',
			 $url . $sep . "token=" . $sess->{'token'});
    }
    foreach my $at (@{$access->{'attributes'}}) {
	if ($at->[2]) {
	    $msg->set_vsattr($at->[2], $at->[0], $at->[1], 0);
	}
	else {
	    $msg->set_attr($at->[0], $at->[1], 0);
	}
    }
}

### AUTHORIZATION HANDLERS ################################################

sub authenticate
{
    my ($msg, $src, $dest, $sock) = @_;

    if ($msg->code eq 'Access-Request') {
	if ($msg->attr('Service-Type') // "" eq 'Call-Check') {
	    # No authentication: generate Access-Accept
	    my $resp = make_response($msg, 'Access-Accept');
	    handle_radius($resp, $AUTZ_SERVER, $src, $sock);
	}
	elsif (defined $msg->attr('EAP-Message')) {
	    # Forward to EAP authentication server
	    $dest = $AUTH_SERVER;
	    debugmsg($msg, $src, "Forward to " . sintoa($dest));
	}
    }
    elsif ($msg->code eq 'Access-Reject' or
	   $msg->code eq 'Access-Challenge' or
	   $msg->code eq 'Access-Accept')
    {
	if ($msg->code eq 'Access-Accept') {
	    info("AUTHENTICATED ",
		 $msg->attr('Calling-Station-Id') // "", " ",
		 $msg->attr('User-Name') // "");
	}

	# Forward to NAS
	if (defined $dest) {
	    debugmsg($msg, $src, "Forward to " . sintoa($dest));
	}
	else {
	    $dest = $src;
	}
    }

    return $dest;
}

sub authorize
{
    my ($msg, $src, $dest, $sock) = @_;

    if ($msg->code eq 'Access-Accept' or
	$msg->code eq 'CoA-Request')
    {
	my @cred = parse_radius($msg);
	my $key = validate_session(find_session(@cred), $MIN_DURATION) ||
	          config_session(@cred, $dest);
	if ($key) {
	    # Add session attributes
	    info("AUTHORIZED ", $cred[0], " on ", $cred[2],
		 " with access ", $SESSIONS{$key}{'access'});
	    apply_session($key, $msg);
	    if ($msg->code eq 'Access-Accept') {
		start_session($key, undef, $dest);
		write_session($key);
	    }
	}
	else {
	    # Rejected - no session
	    info("REJECTED ", $cred[0], " - no valid session found");
	    if ($msg->code eq 'Access-Accept') {
		$msg->set_code('Access-Reject');
	    }
	    else {
		$msg->set_code('Disconnect-Request');
	    }
	}
	if ($msg->code eq 'CoA-Request' or
	    $msg->code eq 'Disconnect-Request')
	{
	    # Store the session key for ACK/NAK handling
	    $key = find_session(@cred);
	    $msg->set_attr('State', $key) if defined $key;
	}
    }
    elsif ($msg->code eq 'CoA-ACK') {
	my $key = $msg->attr('State');
	if (defined $key) {
	    start_session($key, undef, $src);
	    write_session($key);
	}
    }
    elsif ($msg->code eq 'CoA-NAK' or
	   $msg->code eq 'Disconnect-ACK' or
	   $msg->code eq 'Disconnect-NAK')
    {
	my $key = $msg->attr('State');
	if (defined $key) {
	    stop_session($key);
	    delete_session($key);
	}
    }
    elsif ($msg->code eq 'Accounting-Response') {
	my @cred = parse_radius($msg);
	my $key = find_session(@cred);

	# Validate session
	if ($key && !validate_session_volume($key)) {
	    info("Session $key expired");
	    handle_deauthorize($key, $sock);
	}
    }
    return $dest;
}

sub accounting
{
    my ($msg, $src, $dest, $sock) = @_;

    if ($msg->code eq 'Accounting-Request') {
	my @cred = parse_radius($msg);
	my $key = find_session(@cred);

	if ($key) {
	    # Update session
	    my $account = $msg->attr('Acct-Session-Id');

	    if ($msg->attr('Acct-Status-Type') eq 'Start') {
		start_session($key, $account, $src);
		write_session($key);
	    }

	    my $up = ($msg->attr('Acct-Input-Octets') // 0) +
		     (($msg->attr('Acct-Input-Gigawords') // 0) << 32);
	    my $down = ($msg->attr('Acct-Output-Octets') // 0) +
		      (($msg->attr('Acct-Output-Gigawords') // 0) << 32);
	    update_session($key, $account, $up, $down);

	    if ($msg->attr('Acct-Status-Type') eq 'Stop') {
		stop_session($key, $account);
		write_session($key);
	    }

	    # Send response
	    my $resp = make_response($msg, 'Accounting-Response');
	    handle_radius($resp, $ACCT_SERVER, $src, $sock);
	}
	else {
	    # Rejected - no session
	    info("No session found for ", $cred[0], " on ", $cred[2]);
	}
    }

    return $dest;
}

sub transmit
{
    my ($msg, $src, $dest, $sock) = @_;

    if ($msg->code eq 'Access-Accept' or
	$msg->code eq 'Access-Challenge' or
	$msg->code eq 'Access-Reject' or
	$msg->code eq 'Accounting-Response' or
	$msg->code eq 'CoA-Request' or
	$msg->code eq 'Disconnect-Request')
    {
	my $val = $msg->attr('Called-Station-Id');
	$msg->unset_attr('Called-Station-Id', $val) if defined $val;
    }

    tracemsg($msg, $dest, "Transmitting RADIUS message");
    debugmsg($msg, $src, "Transmit to ", sintoa($dest));
    $sock->send(encode_radius($msg, $src, $dest), 0, $dest);
}

sub handle_radius
{
    my ($msg, $src, $dest, $sock) = @_;

    tracemsg($msg, $src, "Received RADIUS message");
    debugmsg($msg, $src, "Received");

    $dest = authenticate($msg, $src, $dest, $sock);
    $dest = authorize($msg, $src, $dest, $sock);
    $dest = accounting($msg, $src, $dest, $sock);
    transmit($msg, $src, $dest, $sock) if defined $dest;
}

sub handle_authorize
{
    my ($key, $access, $sock) = @_;
    my $sess = $SESSIONS{$key} or return;
    my $whence = sockaddr_in(sockaddr_in($sess->{'port'}));

    my $msg = make_request($key, $whence, 'CoA-Request');
    create_session($key, $access, $sess->{'nas'}, $whence) if $access;
    handle_radius($msg, $AUTZ_SERVER, $whence, $sock);
}

sub handle_deauthorize
{
    my ($key, $sock) = @_;
    my $sess = $SESSIONS{$key} or return;
    my $whence = sockaddr_in(sockaddr_in($sess->{'port'}));

    my $msg = make_request($key, $whence, 'CoA-Request');
    delete_session($key);
    handle_radius($msg, $AUTZ_SERVER, $whence, $sock);
}

sub initialize
{
    # Parse the RADIUS dictionary files
    $DICTIONARY = new Net::Radius::Dictionary @DICTIONARIES
	or die "Could not create RADIUS dictionary: $!";

    my $authfd = IO::Socket::INET->new(LocalPort => 1812,
				       Blocking => 0,
				       Proto => 'udp')
	or die "Could not create UDP socket: $!";

    my $acctfd = IO::Socket::INET->new(LocalPort => 1813,
				       Blocking => 0,
				       Proto => 'udp')
	or die "Could not create UDP socket: $!";

    # Create the inotify object to listen for file system events
    my $inotify = new Linux::Inotify2
	or die "Could not create inotify object: $!";

    # Add watches for each access directory
    foreach my $access (keys %{$CONFIGURATION{'access'}}) {
	my $dir = "$SESSION_DIR/$access";

	if (! -d $dir) {
	    make_path($dir) or die "Could not create $dir: $!";
	}
	$inotify->watch($dir, IN_ATTRIB | IN_DELETE)
	    or die "Could no create inotify watch on $dir: $!";
    }

    # Create the token directory
    if (! -d $TOKEN_DIR) {
	make_path($TOKEN_DIR) or die "Could not create $TOKEN_DIR: $!";
    }

    # Create the select object
    my $select = IO::Select->new()
	or die "Could not create select object";

    $select->add($authfd);
    $select->add($acctfd);
    $select->add($inotify->fileno);

    # Reload active sessions
    reload($authfd);
    return ($authfd, $acctfd, $inotify, $select);
}

sub daemonize
{
    chdir '/' or die "Can't chdir to /: $!";
    open STDIN, '/dev/null' or die "Can't read /dev/null: $!";
    open STDOUT, '>>/dev/null' or die "Can't write to /dev/null: $!";
    open STDERR, '>>/dev/null' or die "Can't write to /dev/null: $!";
    defined(my $pid = fork) or die "Can't fork: $!";
    if ($pid) {
	open(HANDLE, ">", $PID_FILE) or die "Can't open PID file: $!";
	select(HANDLE);
	print $pid;
	close(HANDLE);
	exit 0;
    }
    setsid or die "Can't start a new session: $!";
    umask 0;
}

sub main {
    my ($authfd, $acctfd, $inotify, $select) = @_;
    my @ready;

    info("Starting RADIUS authorization and accounting proxy");

    # Loop forever, receiving packets and replying to them
    while (@ready = $select->can_read) {
	my $fd;

	foreach $fd (@ready) {

	    if ($fd != $inotify->fileno) {
		my ($msg, $whence, $dest, $req);

		$whence = $fd->recv($req, 2048)
		    or die "Could not read from UDP socket: $!";

		my ($port, $ip) = unpack_sockaddr_in($whence);
		if ($whence eq $AUTH_SERVER ||
		    match_cidr($SUBNET, inet_ntoa($ip)))
		{
		    ($msg, $dest) = decode_radius($req, $whence)
			and handle_radius($msg, $whence, $dest, $fd);
		}
		else {
		    warning("Dropping RADIUS request from ", sintoa($whence));
		}
	    }
	    else {
		my @events = $inotify->read;
		my $ev;

		foreach $ev (@events) {
		    my $dir = $ev->{w}->{name};
		    my $key = $ev->{name};
		    my $mask = $ev->{mask};
		    my $access = basename($dir);

		    if ($mask & IN_ATTRIB) {
			handle_authorize($key, $access, $authfd);
		    }
		    elsif ($mask & IN_DELETE) {
			handle_deauthorize($key, $authfd);
		    }
		}
	    }
	}
    }
}

sub cleanup
{
    foreach my $key (keys %SESSIONS) {
	write_session($key);
    }
    exit 0;
}

configure;
my @ARGS = initialize;
daemonize;

while (1) {
    eval { main @ARGS; };
    warning($@);
    info("Respawning in 1 sec...");
    sleep 1;
}
