use strict;
use warnings;

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use Apache::TestUtil qw( t_finish_error_log_watch t_start_error_log_watch );
use List::MoreUtils qw( any );

my $url = '/cgi-bin/broken-db/json-env';

# Allow request to be redirected.
t_start_error_log_watch();
my $res = GET $url, 'X-Forwarded-For' => '2001:220::';
ok any { /unknown data type or corrupt data/ } t_finish_error_log_watch(),
    'Error logged when looking up corrupt data';
done_testing();
