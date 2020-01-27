package Notes;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO  ();
use APR::Table          ();
use JSON::XS;

use Apache2::Const -compile => 'OK';

sub handler {
    my $r = shift;
    $r->content_type('application/json');
    my %notes;
    for my $key (qw( MMDB_ADDR MMDB_INFO MM_COUNTRY_CODE CITY_NETWORK )) {
        $notes{$key} = $r->notes->get($key);
    }
    $r->print( JSON::XS->new->utf8->ascii->pretty->encode( \%notes ) );
    return Apache2::Const::OK;
}
1;
