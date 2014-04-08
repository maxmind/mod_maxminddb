# MaxMind DB Apache Module #

This module allows you to query MaxMind DB files from Apache 2.2+ using the
`libmaxminddb` library.

## Version ##

This is version 0.0.1 of the mod_maxminddb Apache module. This module is still
considered beta, and the API may change before it is considered stable.

## Installation ##

You must install the [libmaxminddb](https://github.com/maxmind/libmaxminddb) C
library before installing this module.

To install the module from the tarball, run the following commands from the
directory with the extracted source:

   ./configure
   make install

If you are compiling the module from
[our GitHub repo](https://github.com/maxmind/mod_maxminddb.git), run the
following commands:

    ./bootstrap
    ./configure
    make install

To use another apache installation, specify a path to the right apxs binary:

    ./configure --with-apxs=/foo/bar/apxs

## Usage ##

To use this module, you must first download or create a MaxMind DB file. We
provide [free GeoLite2 databases](http://dev.maxmind.com/geoip/geoip2/geolite2)
as well as [commercial GeoIP2 databases](http://www.maxmind.com/en/geolocation_landing).

After installing this module and obtaining a database, you must now edit your
Apache configuration file (e.g., `/etc/apache2/apache2.conf`). This file must
contain `MaxMindDBEnable` to enable the module, `MaxMindDBFile` to specify the
database to use, and `MaxMindDBEnv` to bind the desired lookup result to an
environment variable.

This module uses the client IP address for the lookup. This is not always what
you want. If you need to use an IP address specified in a header (e.g., by
your proxy frontend),
[mod_remoteip](http://httpd.apache.org/docs/current/mod/mod_remoteip.html) may
be used to set the client IP address.

### `MaxMindDBEnable` ###

This directive enables or disables the MaxMind DB lookup. Valid settings are
`On` and `Off`.

    MaxMindDBEnable On

### `MaxMindDBFile` ###

This directive associates a name placeholder with a MaxMind DB file on the
disk. You may specify multiple databases, each with its own name.

    MaxMindDBFile COUNTRY_DB /usr/local/share/GeoIP/GeoLite2-Country.mmdb
    MaxMindDBFile CITY_DB    /usr/local/share/GeoIP/GeoLite2-City.mmdb

The name placeholder can be any string that apache parses as a word. We
recommend sticking to letters, numbers, and underscores.

### `MaxMindDBEnv` ###

This directive assigns the lookup result to an environment variable. The first
parameter after the directive is the environment variable. The second
parameter is the name of the database followed by the path to the desired data
using map keys or 0-based array indexes separated by `/`.

    MaxMindDBEnv COUNTRY_CODE COUNTRY_DB/country/iso_code
    MaxMindDBEnv REGION_CODE  CITY_DB/subdivisions/0/iso_code

## Exported Environment Variables ##

In addition to the environment variable specified by `MaxMindDBEnv`, this
module exports `MMDB_ADDR`, which contains the IP address used for lookups by
the module. This is primarily intended for debugging purposes.

## Examples ##

This example uses one database file:

    <IfModule mod_maxminddb.c>
        MaxMindDBEnable On
        MaxMindDBFile DB /usr/local/share/GeoIP/GeoLite2-City.mmdb

        MaxMindDBEnv MM_COUNTRY_CODE DB/country/iso_code
        MaxMindDBEnv MM_COUNTRY_NAME DB/country/names/en
        MaxMindDBEnv MM_CITY_NAME DB/city/names/en
        MaxMindDBEnv MM_LONGITUDE DB/location/longitude
        MaxMindDBEnv MM_LATITUDE DB/location/latitude
    </IfModule>

This example shows how to block users based on their country:

    MaxMindDBEnable On
    MaxMindDBFile DB /usr/local/share/GeoIP/GeoLite2-Country.mmdb
    MaxMindDBEnv MM_COUNTRY_CODE DB/country/iso_code

    SetEnvIf MM_COUNTRY_CODE ^(RU|DE|FR) BlockCountry
    Deny from env=BlockCountry

## Data Output Format ##

All data is provided as a string bound to the specified Apache environment
variable. Floating point numbers are provided to five digits after the decimal
place. All integers types except 128-bit integers are provides as decimal.
128-bit integers are returned as hexadecimal. Booleans are returned as "0" for
false and "1" for true.

## Support ##

Please report all issues with this code using the [GitHub issue tracker]
(https://github.com/maxmind/mod_maxminddb/issues).

If you are having an issue with a commercial MaxMind database that is not
specific to this module, please see [our support
page](http://www.maxmind.com/en/support).

## Requirements ##

This module requires Apache 2.2+.

## Versioning ##

The MaxMind DB Apache module uses [Semantic Versioning](http://semver.org/).

## Copyright and License ##

This software is Copyright (c) 2013-2014 by MaxMind, Inc.

This is free software, licensed under the Apache License, Version 2.0.
