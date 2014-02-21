use strict;
use warnings;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_env );

my $env = get_env('/cgi-bin/mod-not-enabled/json-env');

ok( !exists $env->{MMDB_ADDR},         'MMDB_ADDR does not exist' );
ok( !exists $env->{MMDB_INFO},         'MMDB_INFO does not exist' );
ok( !exists $env->{MM_CONTINENT_CODE}, 'MM_CONTINENT_CODE does not exist' );

done_testing();
