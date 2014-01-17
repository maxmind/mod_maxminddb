require 5.6.1;

use ExtUtils::MakeMaker;

use lib qw(../blib/lib lib );

use Apache::TestMM qw(test clean);    #enable 'make test'

# prerequisites
my %require = (
    "Apache::Test" => "",             # any version will do
);
my @scripts = qw(t/TEST);

# accept the configs from command line
Apache::TestMM::filter_args();
Apache::TestMM::generate_script('t/TEST');

WriteMakefile(
    NAME         => 'Apache::Test_mod_maxminddb',
    VERSION_FROM => 'lib/Apache/Test_mod_maxminddb.pm',
    PREREQ_PM    => \%require,
    clean        => {
        FILES => "@{ clean_files() }",
    },
    (
        $] >= 5.005
        ? (
            ABSTRACT_FROM => 'lib/Apache/Test_mod_maxminddb.pm',
            AUTHOR        => 'bz',
          )
        : ()
    ),
);

sub clean_files {
    return [@scripts];
}

