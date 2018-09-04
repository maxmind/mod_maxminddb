use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use JSON::XS qw( decode_json );
use Test::ModMaxMindDB;

my $url = '/cgi-bin/valid-db/json-env';
my $ip = '160.13.90.206';

my $res = GET $url;
diag "ENVVAR: real IP -------------------";
#diag "Result body: " . $res->content;
my $srv_env = decode_json $res->content;
diag "IP: " . $srv_env->{MMDB_ADDR};

$res = GET $url . '?mmdb_addr='.$ip;
diag "ENVVAR: forced IP -------------------";
#my $srv_env = decode_json $res->content;
diag "IP: " . $srv_env->{MMDB_ADDR};
is( $srv_env->{MMDB_ADDR}, $ip, 'IP overwritten: MMDB_ADDR is ' . $srv_env->{MMDB_ADDR} );

done_testing();
