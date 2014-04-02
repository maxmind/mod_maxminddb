AUTOMAKE_OPTIONS = foreign
#ACLOCAL_AMFLAGS = -I m4

#apxs -i -a -L/usr/local/lib -I/usr/local/include -lGeoIP -c mod_geoip.c

#   the default target
all: mod_maxminddb.so
#   compile the DSO file
mod_maxminddb.so: $(TARGET)
#$(APXS) -c $(DEFS) -Wc,"$(CFLAGS)" $(LDFLAGS) $(LIBMAXMINDDB_LDFLAGS) $(LIBS) $(WC) $(APXS_LDFLAGS) mod_maxminddb.c
	$(APXS) -c -Wc,"$(CFLAGS)" $(LDFLAGS) $(LIBMAXMINDDB_LDFLAGS) $(LIBS) $(WC) $(APXS_LDFLAGS) mod_maxminddb.c

install:
	$(APXS) -i -a -n maxminddb .libs/mod_maxminddb.so

clean:
	rm -rf .libs *.o *.so *.lo *.la *.slo *.loT
