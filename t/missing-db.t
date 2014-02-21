use strict;
use warnings;

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use JSON::XS;

my $url = '/cgi-bin/missing-db/json-env';

ok my $res = GET $url;
my $env = JSON::XS->new->decode( $res->content );

unlike( $env->{MMDB_INFO}, qr/lookup success/, 'no success message' );

done_testing();
