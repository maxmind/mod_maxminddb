use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_env );

{
    my $env = get_env( '/cgi-bin/htaccess/json-env', '216.160.83.56' );

    is(
        $env->{MM_CODE}, 'GB',
        'htaccess overwrites config'
    );
}

done_testing();
