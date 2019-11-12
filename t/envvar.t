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

my @network_tests = (
    {
        ip      => '2001:218::',
        url     => '/cgi-bin/valid-db/json-env',
        network => '2001:218::/32',
        key     => 'CITY_NETWORK',
    },
    {
        ip      => '67.43.156.1',
        url     => '/cgi-bin/valid-db/json-env',
        network => '67.43.156.0/24',
        key     => 'CITY_NETWORK',
    },
    {
        ip      => '1.1.1.1',
        url     => '/cgi-bin/ipv6-32/json-env',
        network => '1.0.0.0/8',
    },
    {
        ip      => '::1:ffff:ffff',
        url     => '/cgi-bin/ipv6-24/json-env',
        network => '::1:ffff:ffff/128',
    },
    {
        ip      => '::2:0:1',
        url     => '/cgi-bin/ipv6-24/json-env',
        network => '::2:0:0/122',
    },
    {
        ip      => '1.1.1.1',
        url     => '/cgi-bin/ipv4-24/json-env',
        network => '1.1.1.1/32',
    },
    {
        ip      => '1.1.1.3',
        url     => '/cgi-bin/ipv4-24/json-env',
        network => '1.1.1.2/31',
    },
    {
        ip      => '1.1.1.3',
        url     => '/cgi-bin/decoder/json-env',
        network => '1.1.1.0/24',
        key     => 'DECODER_DB_NETWORK',
    },
    {
        ip      => '::ffff:1.1.1.128',
        url     => '/cgi-bin/decoder/json-env',
        network => '::ffff:1.1.1.0/120',          # Could be IPv4.
        key     => 'DECODER_DB_NETWORK',
    },
    {
        ip      => '::1.1.1.128',
        url     => '/cgi-bin/decoder/json-env',
        network => '::1.1.1.0/120',               # Could be regular IPv6.
        key     => 'DECODER_DB_NETWORK',
    },
    {
        ip      => '200.0.2.1',
        url     => '/cgi-bin/no-ipv4-search-tree/json-env',
        network => '0.0.0.0/0',                               # Could be IPv6.
    },
    {
        ip      => '::200.0.2.1',
        url     => '/cgi-bin/no-ipv4-search-tree/json-env',
        network => '::/64',
    },
    {
        ip      => '0:0:0:0:ffff:ffff:ffff:ffff',
        url     => '/cgi-bin/no-ipv4-search-tree/json-env',
        network => '::/64',
    },
    {
        ip      => 'ef00::',
        url     => '/cgi-bin/no-ipv4-search-tree/json-env',
        network => '8000::/1',
    },
);

for my $test (@network_tests) {
    subtest $test->{ip} . ' - ' . $test->{url}, sub {
        my $res = GET( $test->{url} . '?mmdb_addr=' . $test->{ip} );
        my $env = decode_json( $res->content );
        my $key = $test->{key} // 'DB_NETWORK';
        is( $env->{$key}, $test->{network}, 'correct network' );
    };
}

done_testing();
