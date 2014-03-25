use strict;
use warnings;

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use Apache::TestUtil qw( t_finish_error_log_watch t_start_error_log_watch );
use List::MoreUtils qw( any );

my $url = '/cgi-bin/ipv4-only/json-env';

# Allow request to be redirected.
t_start_error_log_watch();
my $res = GET $url, 'X-Forwarded-For' => '2001::1';
ok any {/IPv6 address in an IPv4-only database/} t_finish_error_log_watch(),
    'Error logged when looking up IPv6 address in IPv4 database';
done_testing();
