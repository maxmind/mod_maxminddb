`mod_maxminddb`
=============

Apache2.4 module for MaxMindDB database integration

Overview
========

`mod_maxminddb` is an Apache 2.4 module. It uses the `libmaxminddb` library to
preform the lookups.

Requirements
============

 Please make sure apache 2.4 is installed.
`httpd -v` will show the version number.

The library [`libmaxinddb`] (https://github.com/maxmind/libmaxminddb) must be
installed to compile this module.

Install the desired `mmdb` database files either with
[`geoipupdate`](https://github.com/maxmind/geoipupdate)
or download the files [here](http://dev.maxmind.com/geoip/geoip2/geolite2/) and
install them manually.

Installation
============

    /usr/local/apache24/bin/apxs -i -a -L/usr/local/lib -I/usr/local/include -lmaxminddb -Wc,-std=gnu99 -c mod_maxminddb.c

Usage
=====

`mod_maxmindb` uses the current connection IP address for the lookup. This is
not always what you want.
[mod_remoteip](http://httpd.apache.org/docs/current/mod/mod_remoteip.html) is
useful to do this work.


## `MaxMindDBEnable`
Enable and disable the lookup. Can be On or Off.

## `MaxMindDBFile`
Assigns the database file to do the lookup. You can use several databases with
different names.

    MaxMindDBFile NAME database_file.mmdb

## `MaxMindDBEnv`
Assigns the lookup result to the environment variable.

    MaxMindDBEnv MM_COUNTRY_CODE DB/country/iso_code

The environment variable `MM_COUNTRY_CODE` contains the lookup result for
database `DB`'s field `country/iso_code`

Special environment vars
========================

The environment var `MMDB_ADDR` contains the IP address whenever `mod_maxminddb`
is used to lookup something. It is very useful for debugging purpose of your
setup.

Examples
========

This example use one database file and assigns the results to the environment
vars.

    <IfModule mod_maxminddb.c>
	MaxMindDBEnable On
	MaxMindDBFile DB /usr/local/share/GeoIP/GeoLite2-City.mmdb

	MaxMindDBEnv MM_COUNTRY_CODE DB/country/iso_code
	MaxMindDBEnv MM_COUNTRY_NAME DB/country/names/en
	MaxMindDBEnv MM_CITY_NAME DB/city/names/en
	MaxMindDBEnv MM_LONGITUDE DB/location/longitude
	MaxMindDBEnv MM_LATITUDE DB/location/latitude
    </IfModule>

Another example to block users based on their country.

	MaxMindDBEnable On
	MaxMindDBFile DB /usr/local/share/GeoIP/GeoLite2-Country.mmdb
	MaxMindDBEnv MM_COUNTRY_CODE DB/country/iso_code
        ...
        SetEnvIf MM_COUNTRY_CODE ^(RU|DE|FR) BlockCountry
        Deny from env=BlockCountry

/usr/local/apache24/bin/apxs -i -a -L/usr/local/lib -I/usr/local/include -lmaxminddb -Wc,-std=gnu99 -c mod_maxminddb.c
