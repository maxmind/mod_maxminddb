package Test::ModMaxMindDB;

use strict;
use warnings;

use Apache::TestRequest;
use JSON::XS;

use Sub::Exporter -setup => { exports => ['get_env', 'get_request',] };

sub get_env {
    my $res = get_request(@_);

    return JSON::XS->new->decode( $res->content );
}

sub get_request {
    my $url = shift;
    my $ip = shift || '216.160.83.56';

    return GET $url, 'X-Forwarded-For' => $ip;
}

1;
