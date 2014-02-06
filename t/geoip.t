use strict;
use warnings;

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use JSON::XS;

my $url = '/cgi-bin/json-env';

# Allow request to be redirected.
ok my $res = GET $url;
my $srv_env = decode_json $res->content;

ok defined( $srv_env->{REMOTE_ADDR} );
ok defined( $srv_env->{MMDB_ADDR} );
ok $srv_env->{REMOTE_ADDR} eq '127.0.0.1';
ok $srv_env->{MMDB_ADDR} eq '127.0.0.1';

done_testing();
