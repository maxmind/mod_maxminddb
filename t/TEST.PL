use strict;

use lib qw(lib ../lib);

use warnings FATAL => 'all';

use Apache::TestRun ();

package MyTest;

local $ENV{MMDB_ADDR} = '175.16.199.0';

use vars qw(@ISA);
@ISA = qw(Apache::TestRun);

#subclass new_test_config to add some config vars which will
#be replaced in generated config, see t/conf/extra.conf.in

#'make test' runs -clean by default, so to actually see the replacements:
#perl t/TEST apxs ...
#cat t/conf/extra.conf
#perl t/TEST -clean

sub new_test_config {
    my $self = shift;

    $self->{conf_opts}->{authname}      = 'gold club';
    $self->{conf_opts}->{allowed_users} = 'dougm sterling';

    return $self->SUPER::new_test_config;
}

sub bug_report {
    my $self = shift;

    print <<EOI;
+-----------------------------------------------------+
| To report problems please refer to the SUPPORT file |
+-----------------------------------------------------+
EOI
}

MyTest->new->run( @ARGV );
