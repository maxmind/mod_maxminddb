package Apache::TestModMaxMindDB;

$Apache::TestModMaxMindDB::VERSION = '0.1';

use strict;
use warnings;

use File::Slurp qw( read_file );
use JSON::XS qw( decode_json );
use Moo;

has city_source_data => (
    is      => 'ro',
    lazy    => 1,
    builder => '_build_city_source_data',
);

sub _build_city_source_data {
    my $self = shift;

    my $file = read_file('maxmind-db/source-data/GeoIP2-City-Test.json');

    return { map { %{$_} } @{ decode_json($file) } };
}

1;
