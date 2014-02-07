use strict;
use warnings FATAL => 'all';

use Apache::Test qw(-withtestmore);
use Apache::TestModMaxMindDB;
use Apache::TestRequest;
use DDP;
use Hash::Flatten;
use JSON::XS;

my $url = '/cgi-bin/json-env';

my $get_with_xff_c = sub {

    my ( $code, @ips ) = @_;
    for my $xff_ip (@ips) {

        # Allow request to be redirected.
        my $res = GET $url, 'X-Forwarded-For' => $xff_ip;
        ok( $res, '$res is defined' );
        my $srv_env = decode_json $res->content;

        $code->( $res, $srv_env, $xff_ip );
    }
};

my $test_data = Apache::TestModMaxMindDB->new;
$test_data->city_source_data;

my @private   = '127.0.0.1';
my $public_us = '216.160.83.56';

$get_with_xff_c->(
    sub {
        my ( $res, $srv_env, $xff_ip ) = @_;
        ok(
            defined( $srv_env->{REMOTE_ADDR} ),
            'REMOTE_ADDR is defined'
        );
        ok( defined( $srv_env->{MMDB_ADDR} ), 'MMDB_ADDR is defined' );
        is( $srv_env->{REMOTE_ADDR}, $xff_ip, "REMOTE_ADDR is $xff_ip" );
        is( $srv_env->{MMDB_ADDR},   $xff_ip, "MMDB_ADDR is $xff_ip" );
    },
    @private,
    $public_us
);

my %mm_vars = (
    MM_COUNTRY_CODE         => 'country/iso_code',
    MM_COUNTRY_GEONAME_ID   => 'country/geoname_id',
    MM_COUNTRY_NAME_DE      => 'country/names/de',
    MM_COUNTRY_NAME_EN      => 'country/names/en',
    MM_COUNTRY_NAME_ES      => 'country/names/es',
    MM_COUNTRY_NAME_FR      => 'country/names/fr',
    MM_COUNTRY_NAME_JA      => 'country/names/ja',
    MM_COUNTRY_NAME_PT_BR   => 'country/names/pt-BR',
    MM_COUNTRY_NAME_RU      => 'country/names/ru',
    MM_COUNTRY_NAME_ZH_CN   => 'country/names/zh-CN',
    MM_CONTINENT_CODE       => 'continent/code',
    MM_CONTINENT_GEONAME_ID => 'continent/geoname_id',
    MM_COUNTRY_CODE         => 'country/iso_code',
    MM_COUNTRY_CODE         => 'country/iso_code',
    MM_COUNTRY_NAME         => 'country/names/en',
    MM_LATITUDE             => 'location/latitude',
    MM_LONGITUDE            => 'location/longitude',
);

my $flattener = Hash::Flatten->new( { HashDelimiter => '/' } );

$get_with_xff_c->(
    sub {
        my ( $res, $srv_env, $xff_ip ) = @_;

        my $expected = $flattener->flatten(
            $test_data->city_source_data->{'::216.160.83.56/125'} );

        is( $xff_ip,               $public_us, 'XFF IP is public US IP' );
        is( $srv_env->{MMDB_ADDR}, $public_us, 'MMDB_ADDR is public US ip' );
        is(
            $srv_env->{REMOTE_ADDR}, $public_us,
            'REMOTE_ADDR is public US ip'
        );

        foreach my $mm_key ( sort keys %mm_vars ) {
            is(
                $srv_env->{$mm_key},
                $expected->{ $mm_vars{$mm_key} },
                "$mm_key is " . $expected->{ $mm_vars{$mm_key} }
            );
        }
    },
    $public_us
);

done_testing();

