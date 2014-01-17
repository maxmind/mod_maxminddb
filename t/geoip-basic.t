use strict;
use warnings FATAL => 'all';

use Apache::Test qw(-withtestmore);
use Test::More;
use Apache::TestRequest;
use JSON::XS;
use Data::Printer;

Apache::Test::plan need need_module(
    'mod_dir',      'mod_cgid', 'mod_env', 'mod_alias',
    'mod_remoteip', 'mod_maxminddb'
  ),
  need_lwp;

my $url = '/cgi-bin/json-env';

# Allow request to be redirected.
ok my $res = GET $url;

my $srv_env = decode_json $res->content;

#ok $res->content =~ /MMDB/;

ok (defined( $srv_env->{REMOTE_ADDR}), 'REMOTE_ADDR is defined' );
ok (defined( $srv_env->{MMDB_ADDR}), 'MMDB_ADDR is defined' );
is( $srv_env->{REMOTE_ADDR}, '127.0.0.1', 'REMOTE_ADDR is 127.0.0.1');
is( $srv_env->{MMDB_ADDR}, '127.0.0.1', 'MMDB_ADDR is 127.0.0.1');

#warn $res->content;

warn p $srv_env;
done_testing();

