use strict;
use warnings;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use Apache::TestUtil qw( t_finish_error_log_watch t_start_error_log_watch );
use List::MoreUtils qw( any );
use Test::ModMaxMindDB qw( get_env );

# Allow request to be redirected.
t_start_error_log_watch();

my $env = get_env( '/cgi-bin/ipv4-only/json-env', '2001::1' );

like( $env->{MMDB_INFO}, qr/lookup failed/, 'failure message' );

ok any {/IPv6 address in an IPv4-only database/} t_finish_error_log_watch(),
    'Error logged when looking up IPv6 address in IPv4 database';

done_testing();
