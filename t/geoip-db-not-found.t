use strict;
use warnings;

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;

my $url = '/cgi-bin/missing-db/json-env';

# Allow request to be redirected.
ok my $res = GET $url;

done_testing();
