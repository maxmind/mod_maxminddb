use strict;
use warnings;

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use JSON::XS;

my $url = '/cgi-bin/mod-not-enabled/json-env';

# Allow request to be redirected.
ok my $res = GET $url;
my $env = JSON::XS->new->decode( $res->content );

ok( !exists $env->{MMDB_ADDR}, 'MMDB_ADDR does not exist' );
ok( !exists $env->{MMDB_INFO}, 'MMDB_INFO does not exist' );

done_testing();
