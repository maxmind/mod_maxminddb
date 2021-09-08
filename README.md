# MaxMind DB Apache Module #

This module allows you to query MaxMind DB files from Apache 2.2+ using the
`libmaxminddb` library.

## Requirements ##

This module requires Apache 2.2 or 2.4 to be installed, including any
corresponding "dev" package, such as `apache2-dev` on Ubuntu. You should have
`apxs` or `apxs2` in your `$PATH`.

You also must install the [libmaxminddb](https://github.com/maxmind/libmaxminddb)
C library.

## Installation ##

### From a Named Release Tarball (Recommended) ###

**NOTE:** These instructions are for installation from the _named_ `.tar.gz`
tarballs on the [Releases](https://github.com/maxmind/mod_maxminddb/releases)
page (e.g. `mod_maxminddb-*.tar.gz`).

To install the module from a tarball, run the following commands from the
directory with the extracted source:

    ./configure
    make install

To use another Apache installation, specify a path to the right apxs binary:

    ./configure --with-apxs=/foo/bar/apxs

### From a GitHub "Source Code" Archive / Git Repo Clone (Achtung!) ###

**NOTE:** These instructions are for installation from the GitHub "Source
Code" archives also available on the
[Releases](https://github.com/maxmind/mod_maxminddb/releases) page (e.g.
`X.Y.Z.zip` or `X.Y.Z.tar.gz`), as well as installation directly from a clone
of the Git repo. Installation from these sources are possible but will
present challenges to users not comfortable with manual dependency resolution.

1. Ensure the build tools `automake`, `autoconf` and `libtool` are installed.
2. Extract the archive and switch into the directory containing the extracted
   source.
3. Run `./bootstrap`. Many users will experience challenges here as there are
   several dependencies that need to be present before this can complete
   successfully.
4. Run:

        ./configure
        make install

To use another Apache installation, specify a path to the right apxs binary:

    ./configure --with-apxs=/foo/bar/apxs

## Loading the Module ##

After installing the module, Apache has to load it. Note the installation
does this automatically, so you should not need to do anything. If you're
unsure if the module is loaded, ensure there's a `LoadModule` line
somewhere in your config, such as `LoadModule maxminddb_module
/path/to/mod_maxminddb.so`.

## Usage ##

To use this module, you must first download or create a MaxMind DB file. We
provide [free GeoLite2 databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en)
as well as [commercial GeoIP2 databases](https://www.maxmind.com/en/geoip2-databases).

After installing this module and obtaining a database, you must now set up the
module in your Apache configuration file (e.g., `/etc/apache2/apache2.conf`)
or in an `.htaccess` file. You must set `MaxMindDBEnable` to enable the
module, `MaxMindDBFile` to specify the database to use, and `MaxMindDBEnv` to
bind the desired lookup result to an environment variable.
You can also enable `MaxMindDBSetNotes` if you wish the environment variables
to also be set as Apache notes.

This module uses the client IP address for the lookup. This is not always what
you want. If you need to use an IP address specified in a header (e.g., by
your proxy frontend),
[mod_remoteip](https://httpd.apache.org/docs/current/mod/mod_remoteip.html) may
be used to set the client IP address.

Manually setting the client IP address is also possible. See
[Client IP address lookup control](#client-ip-address-lookup-control).

## Directives ##

All directives may appear either in your server configuration or an
`.htaccess` file. Directives in `<Location>` and `<Directory>` blocks will
also apply to sub-locations and subdirectories. The configuration will be
merged with the most specific taking precedence. For instance, a conflicting
directive set for a subdirectory will be used for the subdirectory rather
than the directive set for the parent location.

Similarly, the main server configuration may set defaults that will be merged
into the configuration provided by individual virtual hosts. However, please
note that currently no configuration merging is performed between server/vhost
and directory configurations.

### `MaxMindDBEnable` ###

This directive enables or disables the MaxMind DB lookup. Valid settings are
`On` and `Off`.

    MaxMindDBEnable On

### `MaxMindDBFile` ###

This directive associates a name placeholder with a MaxMind DB file on the
disk. You may specify multiple databases, each with its own name.

    MaxMindDBFile COUNTRY_DB /usr/local/share/GeoIP/GeoLite2-Country.mmdb
    MaxMindDBFile CITY_DB    /usr/local/share/GeoIP/GeoLite2-City.mmdb

The name placeholder can be any string that Apache parses as a word. We
recommend sticking to letters, numbers, and underscores.

### `MaxMindDBEnv` ###

This directive assigns the lookup result to an environment variable. The first
parameter after the directive is the environment variable. The second
parameter is the name of the database followed by the path to the desired data
using map keys or 0-based array indexes separated by `/`.

    MaxMindDBEnv COUNTRY_CODE COUNTRY_DB/country/iso_code
    MaxMindDBEnv REGION_CODE  CITY_DB/subdivisions/0/iso_code

### `MaxMindDBNetworkEnv` ###

This directive assigns the network associated with the IP address to an
environment variable. The network will be in CIDR format. This directive
may only be used once per database.

    MaxMindDBNetworkEnv COUNTRY_DB COUNTRY_NETWORK
    MaxMindDBNetworkEnv CITY_DB    CITY_NETWORK

### `MaxMindDBSetNotes` ###

This directive enables or disables the setting of Apache notes alongside the
environment variables set via `MaxMindDBEnv`. Valid settings are `On` and `Off`.
It defaults to `Off`.

    MaxMindDBSetNotes On

## Exported Environment Variables ##

In addition to the environment variable specified by `MaxMindDBEnv`, this
module exports `MMDB_ADDR`, which contains the IP address used for lookups by
the module. This is primarily intended for debugging purposes.
If `MaxMindDBSetNotes` is `On`, all environment variables are also exported as
Apache notes.

## Client IP address lookup control ##

In case you want supply your own value for the IP address to lookup, it may be
done by setting the environment variable `MMDB_ADDR`.
This can be done, for instance, with
[ModSecurity](https://github.com/SpiderLabs/ModSecurity/) in (real) phase 1.
Note that mod_setenvif and mod_rewrite cannot be used for this as they are
running after this module. For most usages,
[mod_remoteip](https://httpd.apache.org/docs/current/mod/mod_remoteip.html)
is an easier alternative.

## Examples ##

These examples show how to export data from the database into environment
variables.

### ASN Database ###

    <IfModule mod_maxminddb.c>
        MaxMindDBEnable On
        MaxMindDBFile ASN_DB /usr/local/share/GeoIP/GeoLite2-ASN.mmdb

        MaxMindDBEnv MM_ASN ASN_DB/autonomous_system_number
        MaxMindDBEnv MM_ASORG ASN_DB/autonomous_system_organization

        MaxMindDBNetworkEnv ASN_DB ASN_DB_NETWORK
    </IfModule>

### City Database ###

    <IfModule mod_maxminddb.c>
        MaxMindDBEnable On
        MaxMindDBFile CITY_DB /usr/local/share/GeoIP/GeoLite2-City.mmdb

        MaxMindDBEnv MM_COUNTRY_CODE CITY_DB/country/iso_code
        MaxMindDBEnv MM_COUNTRY_NAME CITY_DB/country/names/en
        MaxMindDBEnv MM_CITY_NAME CITY_DB/city/names/en
        MaxMindDBEnv MM_LONGITUDE CITY_DB/location/longitude
        MaxMindDBEnv MM_LATITUDE CITY_DB/location/latitude

        MaxMindDBNetworkEnv CITY_DB CITY_DB_NETWORK
    </IfModule>

### Connection-Type Database ###

    <IfModule mod_maxminddb.c>
        MaxMindDBEnable On
        MaxMindDBFile CONNECTION_TYPE_DB /usr/local/share/GeoIP/GeoIP2-Connection-Type.mmdb

        MaxMindDBEnv MM_CONNECTION_TYPE CONNECTION_TYPE_DB/connection_type

        MaxMindDBNetworkEnv CONNECTION_TYPE_DB CONNECTION_TYPE_DB_NETWORK
    </IfModule>

### Domain Database ###

    <IfModule mod_maxminddb.c>
        MaxMindDBEnable On
        MaxMindDBFile DOMAIN_DB /usr/local/share/GeoIP/GeoIP2-Domain.mmdb

        MaxMindDBEnv MM_DOMAIN DOMAIN_DB/domain

        MaxMindDBNetworkEnv DOMAIN_DB DOMAIN_DB_NETWORK
    </IfModule>

### ISP Database ###

    <IfModule mod_maxminddb.c>
        MaxMindDBEnable On
        MaxMindDBFile ISP_DB /usr/local/share/GeoIP/GeoIP2-ISP.mmdb

        MaxMindDBEnv MM_ASN ISP_DB/autonomous_system_number
        MaxMindDBEnv MM_ASORG ISP_DB/autonomous_system_organization
        MaxMindDBEnv MM_ISP ISP_DB/isp
        MaxMindDBEnv MM_ORG ISP_DB/organization

        MaxMindDBNetworkEnv ISP_DB ISP_DB_NETWORK
    </IfModule>

### Blocking by Country ###

This example shows how to block users based on their country:

    MaxMindDBEnable On
    MaxMindDBFile COUNTRY_DB /usr/local/share/GeoIP/GeoLite2-Country.mmdb
    MaxMindDBEnv MM_COUNTRY_CODE COUNTRY_DB/country/iso_code

    SetEnvIf MM_COUNTRY_CODE ^(RU|DE|FR) BlockCountry
    Deny from env=BlockCountry

Note that at least the "Deny" or "Allow" directive (or "Require" directive in
Apache 2.4 and above) must be applied within a `<Directory>`, `<Location>` or
`<Files>` container.

## Data Output Format ##

All data is provided as a string bound to the specified Apache environment
variable. Floating point numbers are provided to five digits after the decimal
place. All integers types except 128-bit integers are provided as decimal.
128-bit integers are returned as hexadecimal. Booleans are returned as "0" for
false and "1" for true.

Note that data stored as the "bytes" type in a MaxMind DB database can contain
null bytes and may end up truncated when stored in an environment variable. If
you really need to access this data, we recommend using [one of our
programming language
APIs](https://dev.maxmind.com/geoip/geolocate-an-ip/databases?lang=en) instead.

## Support ##

Please report all issues with this code using the [GitHub issue
tracker](https://github.com/maxmind/mod_maxminddb/issues).

If you are having an issue with a commercial MaxMind database that is not
specific to this module, please see [our support
page](https://www.maxmind.com/en/support).

## Versioning ##

The MaxMind DB Apache module uses [Semantic Versioning](https://semver.org/).

## Copyright and License ##

This software is Copyright (c) 2013-2020 by MaxMind, Inc.

This is free software, licensed under the Apache License, Version 2.0.
