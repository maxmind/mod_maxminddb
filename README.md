`mod_maxminddb`
=============

Apache2 module for MaxMindDB database integration


Installation
============

    /usr/local/apache24/bin/apxs -i -a -L/usr/local/lib -I/usr/local/include -lmaxminddb -Wc,-std=gnu99 -c mod_maxminddb.c
