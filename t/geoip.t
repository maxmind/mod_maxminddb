use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest;
use JSON::XS;
use Data::Printer;

plan tests => 5, need need_module('mod_dir', 'mod_cgid', 'mod_env', 'mod_alias', 'mod_remoteip', 'mod_maxminddb'), need_lwp;

my $url = '/cgi-bin/json-env';

# Allow request to be redirected.
ok my $res = GET $url;

my $srv_env = decode_json $res->content;
#ok $res->content =~ /MMDB/;

ok defined($srv_env->{REMOTE_ADDR});
ok defined($srv_env->{MMDB_ADDR});
ok $srv_env->{REMOTE_ADDR} eq '127.0.0.1';
ok $srv_env->{MMDB_ADDR} eq '127.0.0.1';


#warn $res->content;

warn p $srv_env;

