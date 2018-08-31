use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use Encode qw( decode_utf8 );
use JSON::XS;
use Test::ModMaxMindDB;

my $url = '/cgi-bin/envvar/json-env';

my $res = GET $url;
my $srv_env = JSON::XS->new->decode( $res->content );
diag "ENVVAR: real IP -------------------";
diag $srv_env->{MM_COUNTRY_CODE};

$res = GET $url . '?mmdb_addr=160.13.90.206';
$srv_env = JSON::XS->new->decode( $res->content );
is( $srv_env->{MM_COUNTRY_CODE}, 'JP', 'IP overwritten: MM_COUNTRY_CODE is JP' );
diag "ENVVAR: real IP -------------------";
diag $srv_env->{MM_COUNTRY_CODE};

done_testing();
