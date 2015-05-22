use strict;
use warnings;
use utf8;

use lib 't/lib';

use Apache::Test qw(-withtestmore);
use Test::ModMaxMindDB qw( get_request );

my $req = get_request('/cgi-bin/mod-rewrite/param');

is($req->content, 'US', 'rewrite added country code to param');

done_testing();
