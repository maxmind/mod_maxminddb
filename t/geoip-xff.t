use strict;
use warnings FATAL => 'all';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
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

my @private = '127.0.0.1';
my @public_us = ( '24.24.24.24', '8.8.8.8' );

$get_with_xff_c->(
    sub {
        my ( $res, $srv_env, $xff_ip ) = @_;
        ok( defined( $srv_env->{REMOTE_ADDR} ), 'REMOTE_ADDR is defined' );
        ok( defined( $srv_env->{MMDB_ADDR} ),   'MMDB_ADDR is defined' );
        is( $srv_env->{REMOTE_ADDR}, $xff_ip, "REMOTE_ADDR is $xff_ip" );
        is( $srv_env->{MMDB_ADDR},   $xff_ip, "MMDB_ADDR is $xff_ip" );
    },
    @private,
    @public_us
);

$get_with_xff_c->(
    sub {
        my ( $res, $srv_env, $xff_ip ) = @_;
        ok( defined( $srv_env->{REMOTE_ADDR} ), 'REMOTE_ADDR is defined' );
        ok( defined( $srv_env->{MMDB_ADDR} ),   'MMDB_ADDR is defined' );
        is( $srv_env->{REMOTE_ADDR},     $xff_ip, "REMOTE_ADDR is $xff_ip" );
        is( $srv_env->{MMDB_ADDR},       $xff_ip, "MMDB_ADDR is $xff_ip" );
        is( $srv_env->{MM_COUNTRY_CODE}, 'US',    'MM_COUNTRY_CODE is US' );
    },
    @public_us
);

done_testing();

