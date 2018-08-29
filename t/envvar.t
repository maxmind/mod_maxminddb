use strict;
use warnings;
use utf8;

    local $ENV{MMDB_ADDR} = '2001:218::';
use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_env );

{
    my $env = get_env( '/cgi-bin/envvar/json-env' );

    is(
        $env->{MM_COUNTRY_CODE}, 'US',
        'without setting the MMDB_ADDR env var the default IP is used'
    );

    $env = get_env( '/cgi-bin/envvar/json-env' );

    is(
        $env->{MM_COUNTRY_CODE}, 'JP',
        'setting the MMDB_ADDR env var overrides the default IP'
    );
}

done_testing();