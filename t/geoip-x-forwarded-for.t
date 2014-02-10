use strict;
use warnings;
use utf8::all;

use Apache::Test qw(-withtestmore);
use Apache::TestModMaxMindDB;
use Apache::TestRequest;
use Cpanel::JSON::XS qw( decode_json );
use DDP;
use Hash::Flatten;
use Net::Works::Network;

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

foreach my $range ( sort keys %{ $test_data->city_source_data } ) {

    my $network = Net::Works::Network->new_from_string( string => $range );

    $get_with_xff_c->(
        sub {
            my ( $res, $srv_env, $xff_ip ) = @_;
            use Data::Dump qw( dump );
            diag p $srv_env;

            my $expected = $flattener->flatten(
                $test_data->city_source_data->{$range} );

            foreach my $mm_key ( sort keys %mm_vars ) {
                my $value = $srv_env->{$mm_key};
                $value += 0 if $mm_key =~ m{TUDE};
                is(
                    $value,
                    $expected->{ $mm_vars{$mm_key} },
                    "$mm_key is "
                        . $expected->{ $mm_vars{$mm_key} . ' ' . $value }
                );
            }
        },
        $network->first->as_string
    );
    last;
}

done_testing();

