package Test::ModMaxMindDB;

use strict;
use warnings;

use Apache::TestRequest;
use JSON::XS;

use Sub::Exporter -setup => { exports => ['get_env'] };

sub get_env {
    my $url = shift;
    my $ip = '216.160.83.56';

    my $res = GET $url, 'X-Forwarded-For' => $ip;
    return JSON::XS->new->decode( $res->content );
}

1;
