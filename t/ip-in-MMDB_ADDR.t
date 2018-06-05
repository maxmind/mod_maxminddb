use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_env );

{
    my $env = get_env( '/cgi-bin/ip-in-MMDB_ADDR/json-env', '216.160.83.56' );

    is(
        $env->{MM_COUNTRY_CODE}, 'CN',
        'MMDB_ADDR env var takes precedence over request IP'
    );
}

done_testing();
