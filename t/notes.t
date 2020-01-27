use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use JSON::XS qw( decode_json );
use Test::ModMaxMindDB;

my $url = '/notes';
my $ip  = '2001:218::';

my $res = GET $url;

my $notes = decode_json $res->content;
is(
    $notes->{MMDB_ADDR}, '127.0.0.1',
    'MMDB_ADDR is 127.0.0.1 with default IP'
);
is(
    $notes->{MMDB_INFO}, 'lookup success',
    'lookup successful but no result found with default IP'
);
isnt(
    $notes->{MM_COUNTRY_CODE}, 'JP',
    'country code is not JP with default IP'
);
is( $notes->{CITY_NETWORK}, '127.0.0.0/8', 'network' );

$res   = GET $url . '?mmdb_addr=' . $ip;
$notes = decode_json $res->content;
is( $notes->{MMDB_ADDR}, $ip, 'MMDB_ADDR is ' . $notes->{MMDB_ADDR} );
is( $notes->{MMDB_INFO}, 'result found', 'result found for IP from env var' );
is( $notes->{MM_COUNTRY_CODE}, 'JP', 'country code is JP with env var IP' );
is( $notes->{CITY_NETWORK}, '2001:218::/32', 'network' );

done_testing();
