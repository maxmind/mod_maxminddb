#Testing

perl Makefile.PL -configure -httpd_conf t/setup/apache2.conf -src_dir /usr/lib/apache2/modules

To run the test suite:

    ./t/TEST

For a complete list of options to pass to t/TEST (or Makefile.PL):

    ./t/TEST --help

As you're running tests, you may find it helpful to track errors in t/logs/error_log

If you're having issues running the CGI scripts:

1. make sure you have any required modules installed

2. change the #!/usr/bin/perl path as appropriate. (In most cases you probably
won't have to change the path to Perl.)
