use strict;
use warnings;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_env );

my $env = get_env('/cgi-bin/different-config/json-env');
ok( !exists $env->{MM_CONTINENT_CODE}, 'MM_CONTINENT_CODE does not exist' );
is( $env->{MM_CITY_NAME_EN}, 'États-Unis', 'FR country name clobbers EN city name' );

done_testing();
