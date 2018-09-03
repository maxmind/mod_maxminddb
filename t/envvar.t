use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use Encode qw( decode_utf8 );
use JSON::XS;
use Test::ModMaxMindDB;

my $url = '/cgi-bin/valid-db/json-env';

my $res = GET $url;
diag "ENVVAR: real IP -------------------";
diag "Result body: " . $res->content;
#my $srv_env = JSON::XS->new->decode( $res->content );
diag "IP: " . $res->{MMDB_ADDR};

$res = GET $url . '?mmdb_addr=160.13.90.206';
diag "ENVVAR: forced IP -------------------";
diag "Result body: " . $res->content;
#$srv_env = JSON::XS->new->decode( $res->content );
diag "IP: " . $res->{MMDB_ADDR};
is( $res->{MMDB_ADDR}, '160.13.90.206', 'IP overwritten: MMDB_ADDR is ' . $res->{MMDB_ADDR} );

done_testing();
