use strict;
use warnings;

use Apache::Test;
use Apache::TestRequest;

plan tests => 1,
    need need_module(
    [
        'mod_dir',      'mod_cgid', 'mod_env', 'mod_alias',
        'mod_remoteip', 'mod_maxminddb', 'mod_rewrite',
    ]
    ),
    need_lwp;

ok( 1, 1, 'all required modules found' );
