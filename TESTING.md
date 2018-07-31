#Testing

##Installing Dependencies

### cpanminus

    curl -L http://cpanmin.us | perl - App::cpanminus

### This repository

    git clone https://github.com/maxmind/mod_maxminddb.git
    cd mod_maxminddb
    git submodule update --init --recursive
    cd ..

### maxminddb C library

    git clone git://github.com/maxmind/libmaxminddb
    cd libmaxminddb
    ./bootstrap
    ./configure
    make
    sudo make install
    sudo ldconfig
    cd ..

### Apache 2 (assumes Debian/Ubuntu)

#### 2.2

    sudo apt-get install --assume-yes apache2-mpm-prefork apache2.2-bin apache2.2-common apache2-prefork-dev apache2-utils

#### 2.4

    sudo apt-get install --assume-yes apache2-mpm-prefork apache2-utils apache2-dev

#### mod_remoteip (Apache 2.2 only)
    git clone git://github.com/ttkzw/mod_remoteip-httpd22
    cd mod_remoteip-httpd22
    sudo apxs2 -i -c -n mod_remoteip.so mod_remoteip.c
    cd ..

#### mod_security2
    git clone git://github.com/SpiderLabs/ModSecurity
    cd ModSecurity
    sudo apt-get install --assume-yes libtool libpcre3-dev libexpat1-dev mod_security2
    ./autogen.sh
    ./configure --enable-request-early --disable-rule-id-validation
    make
    sudo make install
    cd ..

### mod_maxminddb install
    sudo apxs2 -i -a -lmaxminddb -Wc,-std=gnu99 -c src/mod_maxminddb.c

### Perl dependencies

    cpanm --installdeps --notest .

### Test scaffolding

    perl Makefile.PL -configure -httpd_conf t/setup/apache2.conf -src_dir /usr/lib/apache2/modules

### Run tests

    ./t/TEST -v

### Apache Troubleshooting

#### Do you have all necessary modules installed?
    sudo apache2ctl -M

#### Check the error log

### CGI Troubleshooting

If you're having issues running the CGI scripts:

1. make sure you have any required modules installed

2. change the #!/usr/bin/perl path as appropriate. (In most cases you probably
won't have to change the path to Perl.)
