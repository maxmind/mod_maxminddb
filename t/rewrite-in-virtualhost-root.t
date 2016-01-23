use strict;
use warnings;

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;

# I feel like I'm somewhat misusing Apache::Test here, but its "module based"
# virtual hosts feature was the easiest way I found to make it generate the
# apache configuration I needed.
my $url = Apache::TestRequest::module2url(42, {path => '/foo'});

sub get {
    my ($host, $redir) = @_;
    my $res = GET $url, 'X-Forwarded-For' => '175.16.199.0', Host => $host, redirect_ok => 0;
    is $res->header('Location'), "http://$host/foo$redir", "Requests to $host get redirected as expected";
}

get('foo.com', '?country_code=');
get('bar.com', '?country_code=');
get('moo.com', '?country_code=CN');

done_testing;
