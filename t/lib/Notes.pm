package Notes;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO  ();
use JSON::XS;

use Apache2::Const -compile => 'OK';

sub handler {
    my $r = shift;
    $r->content_type('application/json');
    $r->print(
        JSON::XS->new->utf8->ascii->pretty->encode( $r->notes ),
        "Amazing!"
    );
    return Apache2::Const::OK;
}
1;
