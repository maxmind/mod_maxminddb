package Apache::TestModMaxMindDB;

$Apache::TestModMaxMindDB::VERSION = '0.1';

use strict;
use warnings;

use Cpanel::JSON::XS qw( decode_json );
use Path::Tiny qw( path );
use Moo;

has city_source_data => (
    is      => 'ro',
    lazy    => 1,
    builder => '_build_city_source_data',
);

sub _build_city_source_data {
    my $self  = shift;
    my $json  = Cpanel::JSON::XS->new;
    my @lines = path('maxmind-db/source-data/GeoIP2-City-Test.json')->lines;

    # hashref keyed on IP ranges
    return { map { my $record = decode_json($_); shift @{$record} => $record->[0] }
            @lines };
}

1;
