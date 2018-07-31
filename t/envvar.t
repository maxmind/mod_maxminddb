use strict;
use warnings;

use Apache::Test qw(-withtestmore);
use Apache::TestModMaxMindDB;
use Apache::TestRequest;
use Data::Validate::IP;
use Encode qw( decode_utf8 );
use Hash::Flatten;
use JSON::XS;
use Net::Works::Network;

my $builder = Test::More->builder;
binmode $builder->output,         ":encoding(utf8)";
binmode $builder->failure_output, ":encoding(utf8)";
binmode $builder->todo_output,    ":encoding(utf8)";

my @private   = '127.0.0.1';
my $public_us = '216.160.83.56';

my $url = '/cgi-bin/valid-db/json-env?MMDB_ADDR=$public_us';

my $get_with_xff_c = sub {

    my ( $code, @ips ) = @_;
    for my $xff_ip (@ips) {

        # Allow request to be redirected.
        my $res = GET $url => $xff_ip;
        ok( $res, '$res is defined' );
        my $srv_env = JSON::XS->new->decode( $res->content );

        $code->( $res, $srv_env, $xff_ip );
    }
};

my $test_data = Apache::TestModMaxMindDB->new;
$test_data->city_source_data;

$get_with_xff_c->(
    sub {
        my ( $res, $srv_env, $xff_ip ) = @_;
        ok( defined( $srv_env->{MMDB_ADDR} ), 'MMDB_ADDR is defined' );
        is( $srv_env->{MMDB_ADDR},   $xff_ip, "MMDB_ADDR is $xff_ip" );
    },
    @private,
    $public_us
);

my %mm_vars = (
    MM_CITY_NAME_EN                   => 'city/names/en',
    MM_CONTINENT_CODE                 => 'continent/code',
    MM_CONTINENT_GEONAME_ID           => 'continent/geoname_id',
    MM_CONTINENT_NAME_EN              => 'continent/names/en',
    MM_COUNTRY_CODE                   => 'country/iso_code',
    MM_COUNTRY_GEONAME_ID             => 'country/geoname_id',
    MM_COUNTRY_NAME                   => 'country/names/en',
    MM_COUNTRY_NAME_DE                => 'country/names/de',
    MM_COUNTRY_NAME_EN                => 'country/names/en',
    MM_COUNTRY_NAME_ES                => 'country/names/es',
    MM_COUNTRY_NAME_FR                => 'country/names/fr',
    MM_COUNTRY_NAME_JA                => 'country/names/ja',
    MM_COUNTRY_NAME_PT_BR             => 'country/names/pt-BR',
    MM_COUNTRY_NAME_RU                => 'country/names/ru',
    MM_COUNTRY_NAME_ZH_CN             => 'country/names/zh-CN',
    MM_LOCATION_LATITUDE              => 'location/latitude',
    MM_LOCATION_LONGITUDE             => 'location/longitude',
    MM_LOCATION_TIME_ZONE             => 'location/time_zone',
    MM_POSTAL_CODE                    => 'postal/code',
    MM_REGISTERED_COUNTRY_ISO_CODE    => 'registered_country/iso_code',
    MM_REGISTERED_COUNTRY_NAMES_DE    => 'registered_country/names/de',
    MM_REGISTERED_COUNTRY_NAMES_EN    => 'registered_country/names/en',
    MM_REGISTERED_COUNTRY_NAMES_ES    => 'registered_country/names/es',
    MM_REGISTERED_COUNTRY_NAMES_FR    => 'registered_country/names/fr',
    MM_REGISTERED_COUNTRY_NAMES_JA    => 'registered_country/names/ja',
    MM_REGISTERED_COUNTRY_NAMES_PT_BR => 'registered_country/names/pt_br',
    MM_REGISTERED_COUNTRY_NAMES_RU    => 'registered_country/names/ru',
    MM_REGISTERED_COUNTRY_NAMES_ZH_CN => 'registered_country/names/zh-CN',
    MM_SUBDIVISION_1_GEONAME_ID       => 'subdivisions/:0/geoname_id',
    MM_SUBDIVISION_1_ISO_CODE         => 'subdivisions/:0/iso_code',
    MM_SUBDIVISION_1_NAMES_DE         => 'subdivisions/:0/names/de',
    MM_SUBDIVISION_1_NAMES_EN         => 'subdivisions/:0/names/en',
    MM_SUBDIVISION_1_NAMES_ES         => 'subdivisions/:0/names/es',
    MM_SUBDIVISION_1_NAMES_FR         => 'subdivisions/:0/names/fr',
    MM_SUBDIVISION_1_NAMES_JA         => 'subdivisions/:0/names/ja',
    MM_SUBDIVISION_1_NAMES_PT_BR      => 'subdivisions/:0/names/pt_br',
    MM_SUBDIVISION_1_NAMES_RU         => 'subdivisions/:0/names/ru',
    MM_SUBDIVISION_1_NAMES_ZH_CN      => 'subdivisions/:0/names/zh-CN',
);

my $flattener = Hash::Flatten->new( { HashDelimiter => '/' } );

foreach my $range ( sort keys %{ $test_data->city_source_data } ) {

    my $network = Net::Works::Network->new_from_string( string => $range );
    my $first = $network->first->as_string;
    next unless is_public_ipv4($first) || is_public_ipv6($first);

    if ( $first =~ m{\A::} ) {
        $first = Net::Works::Address->new_from_string(
            string => substr( $first, 2 ) )->as_ipv4_string;
    }

    $get_with_xff_c->(
        sub {
            my ( $res, $srv_env, $xff_ip ) = @_;
            my $expected = $flattener->flatten(
                $test_data->city_source_data->{$range} );

            foreach my $mm_key ( sort keys %mm_vars ) {
                my $value = $srv_env->{$mm_key};
                my $want  = $expected->{ $mm_vars{$mm_key} };
                next if !$want;

                if ( $mm_key =~ m{TUDE} ) {
                    cmp_ok( $value, '==', $want, "$mm_key is $want" );
                }
                else {
                    is( $value, $want, "$mm_key is $want" );
                }
            }
        },
        $first
    );
}

done_testing();

