use strict;
use warnings;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_env );

my $env = get_env( '/cgi-bin/decoder/json-env', '::1.1.1.0' );

like( $env->{MMDB_INFO}, qr/lookup success/, 'success message' );
ok( !exists $env->{MM_CONTINENT_CODE}, 'MM_CONTINENT_CODE does not exist' );

my %expect = (
    MM_ARRAY_0     => 1,
    MM_ARRAY_1     => 2,
    MM_ARRAY_2     => 3,
    MM_DOUBLE      => 42.123456,
    MM_FLOAT       => 1.1,
    MM_INT32       => -268435456,
    MM_UINT128     => '1329227995784915872903807060280344576',
    MM_UINT16      => 100,
    MM_UINT32      => 268435456,
    MM_UINT64      => '1152921504606846976',
    MM_UTF8_STRING => 'unicode! ☯ - ♫',
    MM_MAP_ARRAY_0 => 7,
    MM_MAP_ARRAY_1 => 8,
    MM_MAP_ARRAY_2 => 9,
    MM_MAP_UTF8_STRING => 'hello',
);

foreach my $env_var ( keys %expect ) {
    is( $ENV{$env_var}, $expect{$env_var}, $env_var );
}

# TODO: add test for bytes here

ok( $env->{MM_BOOLEAN}, 'MM_BOOLEAN is true' );

done_testing();
