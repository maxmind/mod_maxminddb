use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use JSON::XS;
use Test::More;
use Test::ModMaxMindDB;

my $url = '/cgi-bin/envvar/json-env';

my $res = GET $url;
my $srv_env = decode_json $res->content;
diag "ENVVAR: real IP -------------------"
diag $srv_env->{MM_COUNTRY_CODE}

my $res = GET $url . '?mmdb_addr=2001:218::';
my $srv_env = decode_json $res->content;
is( $srv_env->{MM_COUNTRY_CODE}, 'JP', 'IP overwritten: MM_COUNTRY_CODE is JP' );
diag "ENVVAR: real IP -------------------"
diag $srv_env->{MM_COUNTRY_CODE}

done_testing();

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_env );
{
    my $env = get_env( '/cgi-bin/envvar/json-env' );

    is(
        $env->{MM_COUNTRY_CODE}, 'US',
        'without setting the MMDB_ADDR env var the default IP is used'
    );

    $env = get_env( '/cgi-bin/envvar/json-env?mmdb_addr=2001:218::' );

    is(
        $env->{MM_COUNTRY_CODE}, 'JP',
        'setting the MMDB_ADDR env var overrides the default IP'
    );
}

done_testing();
