use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use JSON::XS qw( decode_json );
use Test::ModMaxMindDB;

my $url = '/cgi-bin/valid-db/json-env';
my $ip = '2001:218::';

my $res = GET $url;
my $srv_env = decode_json $res->content;
is( $srv_env->{MMDB_ADDR}, '127.0.0.1', 'MMDB_ADDR is 127.0.0.1 with default IP' );
is( $srv_env->{MMDB_INFO}, 'lookup success', 'lookup successful but no result found with default IP') ;
isnt( $srv_env->{MM_COUNTRY_CODE}, 'JP', 'country code is not JP with default IP' );

$res = GET $url . '?mmdb_addr='.$ip;
$srv_env = decode_json $res->content;
is( $srv_env->{MMDB_ADDR}, $ip, 'MMDB_ADDR is ' . $srv_env->{MMDB_ADDR} );
is( $srv_env->{MMDB_INFO}, 'result found', 'result found for IP from env var' );
is( $srv_env->{MM_COUNTRY_CODE}, 'JP', 'country code is JP with env var IP' );

done_testing();
