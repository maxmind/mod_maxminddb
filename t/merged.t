use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_env );

{
    my $env = get_env( '/cgi-bin/merged/json-env', '1.1.1.0' );

    is( $env->{MM_PARENT}, -268435456, 'parent dir can access parent record' );
    is( $env->{MM_CHILD}, undef, 'parent dir cannot access child record' );
}

{ # normal child
    my $env = get_env( '/cgi-bin/merged/child/json-env', '1.1.1.0' );

    is( $env->{MM_PARENT}, -268435456, 'child dir can access parent record' );
    is( $env->{MM_CHILD}, 268435456, 'child dir can access child record' );
}

{ # disabled child
    my $env = get_env( '/cgi-bin/merged/disabled/json-env', '1.1.1.0' );

    is( $env->{MM_PARENT}, undef, 'disabled child cannot access parent record' );
    is( $env->{MM_DISABLED}, undef, 'disabled child cannot set child record' );
}



done_testing();
